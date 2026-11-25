# 28 — A least-privilege exec shield (scoped LSM enforcement)

Chapter 20 governed execve with an LSM `bprm_check_security` program, but left
the verdict at **allow** — an auditor, not an enforcer, because a blanket deny
locks you out of your own machine. This chapter makes the verdict **deny**, and
solves the lock-out problem with **scope**: the shield denies exec only inside a
set of protected cgroups and leaves the rest of the host untouched.

## Why this stops an *unknown* vulnerability

A patch closes one known bug. This shield closes a **technique** instead. A
service like an Nginx worker execs nothing once it is up, so inside its cgroup we
deny every execve. Suppose a zero-day in that service hands an attacker code
execution. The bug is novel and unpatched, but the attacker's next move — spawn
`/bin/sh`, drop a loader, run a shell helper — is an exec, and that exec is
denied. The shield never knew the CVE; it denied the step every exploit needs
*after* it lands. This is least privilege (define what the service may do, deny
the rest) applied at the exec chokepoint.

## What it does

| Part | File | Role |
|---|---|---|
| Shield | `execshield.bpf.c` | `lsm/bprm_check_security`. Looks up the current cgroup id in `protected_cgroups`; if present, returns `-EPERM` (deny) and records the attempt; otherwise returns 0 (allow). |
| Loader | `execshield.c` | Resolves each named cgroup2 directory to its cgroup id, writes the ids into `protected_cgroups` **before** attach, then streams denied/allowed events. |
| Policy map | `protected_cgroups` | `HASH` keyed by cgroup id. Empty = govern nothing (safe default). You opt a service in. |

Same dumb-kernel / smart-userspace split as ch23 and ch26: the kernel enforces,
userspace decides the scope.

## Scope is the safety rail

The in-kernel order is deliberate: **scope check first, verdict second.**

```c
__u64 cg = bpf_get_current_cgroup_id();
if (!bpf_map_lookup_elem(&protected_cgroups, &cg))
    return 0;            /* not our service → allow, always */
...
return -EPERM;           /* only ever reached inside a protected cgroup */
```

cgroup id is the right key: it is an inode number the kernel hands out, survives
fork and re-exec, and cannot be forged from userspace — unlike `comm` (spoofable)
or a bare pid (recycled). The loader populates the map before attach, so the
shield is never live with an empty or wrong scope.

## Build and run

```sh
make                                              # vmlinux.h -> .bpf.o -> skeleton -> execshield
sudo ./execshield /sys/fs/cgroup/system.slice/nginx.service
```

A cgroup id is the inode of its cgroup2 directory; the loader `stat(2)`s each
path you give it. Protect several services by listing several directories.

### The startup caveat

A real service **does** exec during its own launch (systemd → the binary; an
Nginx master → its workers). A deny-all breaks that. Two standard fixes, neither
implemented here (this chapter demonstrates the enforcement primitive, not a
production policy):

- attach the shield *after* the workers are up (load it from a post-start hook), or
- allow an explicit list of launch binaries and deny the rest, by reading
  `bprm->filename` against an allow-map instead of denying unconditionally.

Chapter 25 and 26 show the evasions a filename check misses (memfd, keyring
staging); a production exec shield pairs this hook with those paths.

## Verify

```sh
sudo bash 28-execshield/verify-execshield.sh
```

The script creates a throwaway cgroup, scopes the shield to it alone, shows exec
**denied** inside it and **allowed** everywhere else, then detaches. The
throwaway scope means the self-test cannot lock out your shell even if the policy
were wrong.

## Prerequisite and scope

- **BPF-LSM must be active** (`bpf` in the kernel `lsm=` parameter) — the same
  Chapter 20 wall. The loader checks `/sys/kernel/security/lsm` and points at
  `20-lsm/enable-bpf-lsm.sh` if it is missing. On a host without BPF-LSM the
  program compiles but cannot attach. Built and run on a BPF-LSM kernel in the
  Lima `shirudo-dev` VM (Ubuntu aarch64, `7.0.0-38-generic` with `bpf` added to
  `lsm=`): `verify-execshield.sh` denied exec inside the protected cgroup and
  allowed it outside, as designed. Transcript in [`logs/verify.txt`](logs/verify.txt).
  It also compiles in a `debian:trixie-slim` container, but that linuxkit kernel
  has no `bpf` in `lsm=`, so the attach only happens on the BPF-LSM host.
- **Enforcement, scoped, not a full policy.** This denies all exec in the named
  cgroups. Turning it into a service policy means handling startup (above) and
  pairing it with the egress / file / privilege hooks from the ch28 sketch to
  cover the other moves an exploit makes.
- **Not immunity.** An attacker who stays within allowed behaviour, or who
  exploits the kernel below the LSM layer, is not stopped. This is containment of
  the exploitation technique, not prevention of the bug.
