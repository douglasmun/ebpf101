# Chapter 29 — A privilege-escalation shield (scoped LSM deny)

**Code:** [`../29-uidshield/`](../29-uidshield/)
**Build:** `cd 29-uidshield && make`
**Run:** `sudo ./29-uidshield/uidshield /sys/fs/cgroup/system.slice/nginx.service`
**Verify:** `sudo bash 29-uidshield/verify-uidshield.sh`

## Concept

Chapter 28 established the pattern: an LSM hook with the verdict turned to
**deny**, made safe by **scope** — only inside a set of protected cgroups, with
a hierarchical ancestry walk so a service's child cgroups are covered too. Read
[chapter 28](28-execshield.md) for the scope rationale; this chapter reuses it
unchanged and moves the enforcement to a different chokepoint.

Chapter 28 denied the **exec** a landed exploit needs. This one denies the other
move it makes once inside: **raising its own privilege to root.**

> On `lsm/task_fix_setuid`, deny a credential change whose effective uid would
> go from non-root to 0, inside a protected cgroup. Everywhere else, nothing
> changes.

## What the Shirudo note calls for

The motivating text lists "detect and contain" signals — a sudden UID change, a
first read of `/etc/shadow`, an unexpected outbound connection — "then kill or
log it." Chapters 29 and 30 take two of those and wire them to **deny** rather
than merely log, using the same signed-in-kernel-LSM primitive the note names.
This chapter is the UID-change one.

## The hook

`task_fix_setuid(struct cred *new, const struct cred *old, int flags)` fires on
the kernel path behind `setuid`/`setreuid`/`setresuid` whenever the uid set is
about to change. Its signature carries **no prior-`ret` argument** — unlike
ch28's `bprm_check_security`, there is no earlier LSM verdict in the chain to
honour, so the program's return is the whole verdict. Return `<0` and the
syscall fails with that errno and the task keeps its old uids.

## The policy: only the gain, only to root

```c
if (new_euid != 0 || old_euid == 0)
    return 0;      /* not an escalation to root → allow */
return -EPERM;     /* non-root → root, inside scope → deny */
```

Two deliberate narrowings:

- **Only a gain to uid 0.** A transition between two non-root uids is not an
  escalation to root and is left alone.
- **Already-root is out of scope.** A process whose old euid is 0 has not
  escalated; governing it would fight the service's own legitimate root
  operations. The shield blocks the *acquisition* of root, not its *use*.

`old`/`new` are read with `BPF_CORE_READ(..., euid.val)` — `kuid_t` wraps the
raw value in a struct, so the `.val` field is the number.

## Why this is the right identity to key on

Scope is keyed on cgroup id for the same reasons as ch28: the kernel hands it
out, it survives fork and re-exec, and it cannot be forged from userspace, unlike
`comm` or a recycled pid. Nothing new here; the novelty is entirely in the hook
and the euid test above.

## Verifying it honestly

A plain `setuid` failure is not proof the shield caused it. `verify-uidshield.sh`
requires **both** facts before it reports PASS: the `try-escalate` trigger exits
10 (its `setresuid(-1, 0, -1)` returned `EPERM`) **and** the loader logged a
`DENY` line for that exact pid. It then runs the identical escalation outside the
protected cgroup and requires it to **succeed** (exit 0), proving the deny is
scoped and not global. The trigger must start privileged (only root may set an
arbitrary uid), drop to a non-root uid with the saved-uid left at 0, then attempt
the climb back — mirroring a setuid-root helper that dropped privilege and a bug
that tries to regain it.

## Status

**Built and run on a BPF-LSM kernel.** Verified in the Lima `shirudo-dev` VM
(Ubuntu aarch64, kernel `7.0.0-44-generic`, `bpf` active in `lsm=`): a `setresuid`
to root is denied with EPERM and logged as `DENY` inside the protected cgroup and
in a child of it (the ancestry walk covers descendants), and the same escalation
succeeds outside the cgroup. Transcript:
[`../29-uidshield/logs/verify.txt`](../29-uidshield/logs/verify.txt).

## Limits

Containment of one escalation technique, not prevention of the bug. An attacker
who achieves impact without becoming root, who rides a path that does not pass
through `task_fix_setuid` (a capability already held, a kernel exploit below the
LSM layer), or who targets a service that legitimately re-acquires root, is not
stopped by this alone. Pair it with ch28 (exec) and ch30 (sensitive-file read).
