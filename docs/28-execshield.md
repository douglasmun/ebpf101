# Chapter 28 — A least-privilege exec shield (scoped LSM deny)

**Code:** [`../28-execshield/`](../28-execshield/)
**Build:** `cd 28-execshield && make`
**Run:** `sudo ./28-execshield/execshield /sys/fs/cgroup/system.slice/nginx.service`
**Verify:** `sudo bash 28-execshield/verify-execshield.sh`

## Concept

Chapter 20 attached to `bprm_check_security`, the LSM hook the kernel runs before
every `execve`, and whose **return value is the verdict** — 0 allows, a negative
errno denies. It stopped at audit-only (always return 0) for a good reason: a
blanket deny locks you out of your own machine.

This chapter crosses that line, and the one idea is how it does so safely:

> Turn the verdict to **deny**, but **scope** it to a set of protected cgroups.
> Inside them, no `execve` runs; everywhere else, nothing changes.

### Why deny exec at all — the unknown-vulnerability angle

A patch closes one known bug. This shield closes a **technique**. A service like
an Nginx worker execs nothing once it is up, so inside its cgroup every `execve`
is denied. Suppose a zero-day in that service's request parser hands an attacker
code execution. The bug is novel and unpatched — but the attacker's next move is
an exec:

- spawn `/bin/sh` for a reverse shell → denied
- drop and run a loader → denied
- call a shell helper to pivot → denied

The shield never knew the CVE. It denied the step every exploit needs *after* it
lands. That is least privilege (define what the service may do, deny the rest)
applied at the exec chokepoint, and it is the honest answer to "how does eBPF
stop an unknown threat": not by predicting the bug, but by removing the moves the
bug depends on.

## ch20, and the one line that is different

ch20's program and this one are the same skeleton. The difference is the verdict
and the guard in front of it:

| | ch20 `execguard` | ch28 `execshield` |
|---|---|---|
| hook | `lsm/bprm_check_security` | same |
| scope | every exec on the host | only exec inside protected cgroups |
| verdict | always `return 0` (allow) | `return -EPERM` (deny) inside scope |
| map | ring buffer (events only) | `protected_cgroups` HASH + ring buffer |
| risk | none — observes | locks out the *scoped* service only |

## Building blocks

### Scope before verdict

The in-kernel order is the safety rail, and it is deliberate:

```c
__u64 cg = bpf_get_current_cgroup_id();
if (!bpf_map_lookup_elem(&protected_cgroups, &cg))
    return 0;            /* not our service → allow, always */
...
return -EPERM;           /* only ever reached inside a protected cgroup */
```

Check the cgroup first, return allow for anything not opted in, and `-EPERM` can
never be reached on the host at large. An empty map governs nothing — the safe
default. You deny only what you opt in.

### Why cgroup id, not comm or pid

The scope key has to survive the exploit and resist forgery:

- **comm** is a 16-byte string the task controls; an attacker renames itself out
  of scope.
- **pid** is recycled, and a new process can land on an old number.
- **cgroup id** is an inode number the kernel assigns to the cgroup directory. It
  survives fork and re-exec, applies to every task placed in the cgroup, and
  userspace cannot forge it. It is the same u64 `bpf_get_current_cgroup_id()`
  returns.

The loader `stat(2)`s each cgroup2 directory you name, takes the inode number as
the id, and writes it into `protected_cgroups` **before** attach — so the shield
is never live with an empty or wrong scope.

## The caveat the demo hides

A real service **does** exec during its own launch: systemd execs the binary, an
Nginx master execs its workers. A pure deny-all breaks that. This chapter ships
the enforcement primitive, not a finished policy; a production shield handles
startup one of two standard ways:

- attach the shield *after* the workers are up (load it from a post-start hook), or
- allow an explicit list of launch binaries by reading `bprm->filename` against an
  allow-map, and deny the rest.

And a filename check is not the end of it. Chapters 25 and 26 show the evasions it
misses — `memfd_create` + `execve`, and ELF staged in the kernel keyring with no
exec syscall at all. A real exec shield pairs this hook with those paths.

## Scope and honesty

- **Enforcement, scoped, not immunity.** An attacker who stays within the
  service's allowed behaviour, or who exploits the kernel below the LSM layer, is
  not stopped. This contains the exploitation technique; it does not prevent the
  bug.
- **Scope is hierarchical — descendants are covered.** A service puts its workers
  in child cgroups of its own (systemd delegation, an nginx master spawning
  workers under `nginx.service/<child>`), and those children have different cgroup
  ids. Matching only the task's own (leaf) id would let them exec freely — the
  shield would miss exactly the processes it is meant to contain. So the program
  matches the leaf **and every ancestor** up to the root against the set
  (`bpf_get_current_ancestor_cgroup_id` in a bounded walk): protecting a service's
  cgroup covers its whole subtree. Proven in `verify-execshield.sh`, which protects
  a parent and confirms an exec in an unenrolled child is still denied. This closed
  [issue #6](https://github.com/douglasmun/ebpf101/issues/6); the earlier shipped
  version matched the leaf id only. The walk is capped at 16 levels — deeper than
  any real layout, and a directly protected cgroup is always caught regardless.
- **Needs BPF-LSM.** `bpf` must be in the kernel `lsm=` parameter, the same ch20
  wall; the loader checks `/sys/kernel/security/lsm` and points at
  `20-lsm/enable-bpf-lsm.sh` otherwise.
- **Built and run on a BPF-LSM kernel.** Verified in the Lima `shirudo-dev` VM
  (Ubuntu aarch64, `7.0.0-38-generic` booted with `bpf` added to the `lsm=`
  parameter via a grub drop-in). `verify-execshield.sh` denies `exec /bin/true`
  inside a throwaway protected cgroup (`Operation not permitted`, logged `DENY`)
  and lets `ls`/`id` run outside it — scope and enforcement both proven. Full
  transcript in [`../28-execshield/logs/verify.txt`](../28-execshield/logs/verify.txt).
  The Docker linuxkit kernel compiles both halves but has no `bpf` in `lsm=`, so
  the attach only happens on the BPF-LSM host. Re-run on 2026-11-25 with the
  loader line-buffered (`stdbuf -oL`): the `protecting`/`Shield active` lines then
  print at attach time and the `DENY` event prints during the deny, confirming the
  original transcript's end-of-file clustering was non-tty stdout block-buffering,
  not hand assembly. The shell reports the blocked `exec` as exit 126; the kernel
  cause is `EPERM` and the authoritative proof is the logged `DENY` event.
