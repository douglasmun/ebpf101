# 29 — A privilege-escalation shield (deny setuid-to-root, scoped)

Chapter 28 denied the **exec** a landed exploit needs to spawn a shell. This
chapter denies the other move an exploit makes once it is inside a service:
**raising its own privilege to root.** Same scoped-LSM enforcement primitive,
a different chokepoint.

## Why this stops an *unknown* vulnerability

A service like an Nginx worker drops to an unprivileged uid at startup and
never legitimately becomes root again. So inside its cgroup we deny any
credential change whose effective uid would become 0. Suppose a zero-day hands
an attacker code execution as the service uid. The bug is novel and unpatched,
but the attacker's next move — `setuid(0)` after a sudo-style bug, regaining a
dropped root via a saved uid — is a privilege transition, and that transition
is denied. The shield never knew the CVE; it denied the escalation step. This
is the "sudden UID change" signal from the Shirudo note, wired to **deny**
rather than merely log.

## What it does

| Part | File | Role |
|---|---|---|
| Shield | `uidshield.bpf.c` | `lsm/task_fix_setuid`. Looks up the task's cgroup (and its ancestors) in `protected_cgroups`; if in scope AND the change raises euid from non-root to 0, returns `-EPERM` (deny) and records it; otherwise 0 (allow). |
| Loader | `uidshield.c` | Resolves each named cgroup2 directory to its cgroup id, writes the ids into `protected_cgroups` **before** attach, then streams denied events. |
| Policy map | `protected_cgroups` | `HASH` keyed by cgroup id. Empty = govern nothing (safe default). You opt a service in. |
| Trigger | `try-escalate.c` | Test-only: drops to a non-root uid, then attempts `setuid(0)`. Exit 10 = denied (EPERM), 0 = succeeded. |

Same dumb-kernel / smart-userspace split, and the same hierarchical cgroup
scope, as ch28: the kernel enforces, userspace decides the scope, and
protecting a cgroup covers its whole subtree (the workers a service spawns).

## Scope is the safety rail

The in-kernel order is the same as ch28: **scope check first, verdict second.**
A transition in any cgroup that is not protected (or a descendant of one)
returns 0 untouched, so the shield can never lock root out of the host it runs
on. Only *gaining* root is governed: a process that is already root has not
escalated and is left alone (`old_euid == 0 → allow`).

cgroup id is the right key for the same reasons as ch28 — an inode the kernel
hands out, stable across fork and re-exec, unforgeable from userspace.

## Build and run

```sh
make                                              # vmlinux.h -> .bpf.o -> skeleton -> uidshield (+ try-escalate)
sudo ./uidshield /sys/fs/cgroup/system.slice/nginx.service
```

Protect several services by listing several cgroup2 directories.

## Verify

```sh
sudo bash 29-uidshield/verify-uidshield.sh
```

The script creates a throwaway cgroup, scopes the shield to it alone, shows a
setuid-to-root **denied** inside it (and inside a child of it, proving the
hierarchical scope) and the same escalation **allowed** outside, then detaches.
The throwaway scope means the self-test cannot affect real services even if the
policy were wrong, and cleanup confirms the enforcing program is gone before it
removes the cgroup.

## Prerequisite and scope

- **BPF-LSM must be active** (`bpf` in the kernel `lsm=` parameter) — the same
  Chapter 20 wall. The loader checks `/sys/kernel/security/lsm` and points at
  `20-lsm/enable-bpf-lsm.sh` if it is missing. On a host without BPF-LSM the
  program compiles but cannot attach.
- **Status: built and run on a BPF-LSM kernel.** Built and verified in the Lima
  `shirudo-dev` VM (aarch64, kernel `7.0.0-44-generic` with `bpf` in `lsm=`):
  `verify-uidshield.sh` shows a `setresuid` to root (`65534 -> 0`) **denied**
  with EPERM and logged as `DENY` inside a throwaway protected cgroup, **also
  denied in a child** of it (the ancestry walk covers descendants), and the same
  escalation **succeeding** outside the cgroup. Transcript in
  [`logs/verify.txt`](logs/verify.txt).
- **Enforcement, scoped, not a full policy.** This denies only a non-root→root
  euid transition. A service that legitimately re-acquires root during its own
  operation would need that transition allow-listed (by comm, by a launch phase,
  or by pairing with a capability check), just as ch28's deny-all-exec needs a
  startup carve-out.
- **Not immunity.** An attacker who achieves impact without becoming root, or
  who exploits the kernel below the LSM layer, is not stopped. This is
  containment of one escalation technique, not prevention of the bug. Pair it
  with ch28 (exec) and ch30 (sensitive-file read) to cover the other moves an
  exploit makes.
