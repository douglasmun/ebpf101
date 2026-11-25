# Chapter 30 — A sensitive-file shield (scoped LSM deny)

**Code:** [`../30-fileshield/`](../30-fileshield/)
**Build:** `cd 30-fileshield && make`
**Run:** `sudo ./30-fileshield/fileshield -c /sys/fs/cgroup/system.slice/nginx.service -f /etc/shadow`
**Verify:** `sudo bash 30-fileshield/verify-fileshield.sh`

## Concept

The third in the shield trilogy. Chapter 28 denied the **exec**, chapter 29 the
**privilege gain**; this one denies the **read**. Same scoped-LSM primitive (see
[chapter 28](28-execshield.md) for the scope rationale), a different chokepoint:
`lsm/file_open`, which fires on every open before the task gets a usable fd.

> Inside a protected cgroup, deny opening a guarded file — the motivating case is
> `/etc/shadow`. Everywhere else, and for every other file, nothing changes.

This is the Shirudo note's "first read of `/etc/shadow`" signal wired to **deny**
rather than log.

## The one genuinely new piece: identity by (dev, ino)

Chapters 28 and 29 only needed the cgroup scope key. This chapter must also
identify *which file* is guarded, and the choice of identity is the whole
chapter:

**Match on `(device, inode)`, not on a path string.**

- In-kernel path reconstruction from a `struct file` is fragile and bounded by
  the verifier.
- A path check is trivially evaded: a symlink, a bind mount or a hard link
  reaches the same bytes under a different name. `/etc/shadow` and
  `/tmp/mine → /etc/shadow` are the same file; a path guard on the first misses
  the second.
- `(dev, ino)` is the file's identity. Every name that reaches a file resolves to
  the same inode, so one map entry guards the real object however it is
  approached.

The shield reads `file->f_inode->i_ino` and `file->f_inode->i_sb->s_dev` via
CO-RE. The loader resolves each guarded path with `stat(2)` and builds the same
key — with one trap.

### The dev_t encoding trap

glibc's `st_dev` and the kernel's `inode->i_sb->s_dev` do **not** use the same
bit packing. `s_dev` holds the raw in-kernel `dev_t`, which is
`MKDEV(major, minor)`:

```
(major << 20) | (minor & 0xfffff)
```

This is not the `new_encode_dev()` packing that `stat(2)` exports to userspace,
and it is not glibc's `st_dev` layout either. On an ext4 file at glibc
`st_dev` 64769 (major 253, minor 1) the kernel's `s_dev` is 265289729 —
`(253 << 20) | 1`. If the loader writes glibc's raw `st_dev`, the in-kernel key
never matches and the shield silently allows everything — a load that looks fine
and enforces nothing. So `fileshield.c` decodes `st_dev` with `major()`/`minor()`
and re-encodes with the kernel's `MKDEV`.

This is not hypothetical: the **first** verify run failed exactly here. The load
looked clean, the loader printed the file it was guarding, and the guarded open
was still **allowed** — because the loader had been re-encoding to the
`new_encode_dev` layout, not `MKDEV`, so the two keys differed. The verify
script asserts a real `DENY`, not just a successful attach, so the no-op shield
failed loudly instead of shipping.

### The consequence worth stating

The guard follows the inode. If a guarded file is replaced by a fresh inode — an
atomic rename-over, an editor's save-to-temp-then-rename — the new file has a new
`(dev, ino)` and is not guarded until re-added. For a stable credential store
like `/etc/shadow` this is correct and desirable; for a frequently rewritten
file, re-resolve on change. Said plainly so a reader is not surprised.

## Two maps, both filled before attach

`protected_cgroups` (the ch28 scope map) and `guarded_files` (keyed by
`file_key`). Both empty is the safe default — govern nothing. The loader takes
`-c <cgroup>` and `-f <file>` repeatably and populates both before attach, so the
shield is never live with an empty or half-built policy.

## Verifying it without risking the real system

`verify-fileshield.sh` never touches the real `/etc/shadow`. It creates a
throwaway secret in a temp dir and guards that — the `(dev, ino)` match is
identical on any file — then proves: the guarded open is **denied**
inside the cgroup (open fails **and** a `DENY` is logged for that pid); an
**unguarded** file in the same dir still opens inside the cgroup (the guard is
per-file, not a blanket open deny); the guarded open is **denied in a child** of
the protected cgroup (hierarchical scope); and the guarded file still **opens
outside** the cgroup (scope is not global). Fail-closed cleanup confirms the
enforcing program is gone before removing the cgroup.

## Status

**Built and run on a BPF-LSM kernel.** Verified in the Lima `shirudo-dev` VM
(aarch64, kernel `7.0.0-44-generic`, `bpf` active in `lsm=`): the guarded open is
denied (and logged) inside the protected cgroup and in a child of it, an
unguarded file still opens, and the guarded file still opens outside the cgroup.
The `(dev, ino)` re-encoding was the one real bug the run surfaced — the first
attempt used the wrong `dev_t` layout and allowed the guarded open; it was fixed
to the kernel's `MKDEV` and the re-run passed. Transcript:
[`../30-fileshield/logs/verify.txt`](../30-fileshield/logs/verify.txt).

## Limits

Containment of one read technique, not prevention of the bug. An attacker who
reads the secret through a different inode (a copy made before the shield loaded,
a backup, a snapshot), who never opens the file in-scope, or who exploits the
kernel below the LSM layer, is not stopped. Pair it with ch28 (exec) and ch29
(privilege) for defence in depth across the moves an exploit makes.
