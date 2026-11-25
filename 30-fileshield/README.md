# 30 — A sensitive-file shield (deny the open, scoped)

Chapters 28 and 29 denied the **exec** and the **privilege gain** a landed
exploit needs. This chapter denies the **read** it wants — the first open of a
credential store like `/etc/shadow`. Same scoped-LSM enforcement primitive, a
third chokepoint.

## Why this stops an *unknown* vulnerability

A service like an Nginx worker never legitimately opens `/etc/shadow`. So
inside its cgroup we deny any open of a guarded file. Suppose a zero-day hands
an attacker code execution inside the service. The bug is novel and unpatched,
but the attacker still has to **read** the secret it is after — the shadow
file, a private key, a token store — and that open is denied. The shield never
knew the CVE; it denied the read step. This is the "first read of `/etc/shadow`"
signal from the Shirudo note, wired to **deny**.

## What it does

| Part | File | Role |
|---|---|---|
| Shield | `fileshield.bpf.c` | `lsm/file_open`. If the task is in a protected cgroup (or a descendant) AND the file's `(dev, ino)` is in `guarded_files`, returns `-EPERM` (deny) and records it; otherwise 0 (allow). |
| Loader | `fileshield.c` | Resolves each cgroup to its id and each guarded path to its `(dev, ino)`, writes both maps **before** attach, then streams denied events. |
| Policy maps | `protected_cgroups`, `guarded_files` | Two `HASH` maps. Both empty = govern nothing (safe default). You opt a service in AND name the files to guard. |

Same dumb-kernel / smart-userspace split and hierarchical cgroup scope as
ch28/29: the kernel enforces, userspace decides the scope and the file set.

## Why match on (dev, ino), not a path string

The shield keys the guard on the file's device and inode number, not on a path.
In-kernel path reconstruction is fragile, and a path check is trivially evaded
by a symlink, a bind mount or a hard link to the same file. `(dev, ino)` is the
file's identity: every name that reaches it resolves to the same pair, so one
map entry guards the real object however it is approached. The loader resolves
each path with `stat(2)` and re-encodes `st_dev` into the kernel's in-kernel
`dev_t` (`MKDEV(major, minor) = (major << 20) | minor`, **not** the
`new_encode_dev` packing `stat(2)` exports to userspace) so the userspace key
matches the one the shield builds from the inode. Getting this wrong makes the
shield silently never match — which is exactly what the first verify run caught:
the load looked fine but the open was allowed, because the loader was writing
glibc's `st_dev` encoding instead of the kernel's. The verify script proves a
real deny rather than a successful load, so the mismatch failed loudly instead
of shipping a no-op shield. See the `kernel_encode_dev` note in `fileshield.c`.

A consequence worth stating: the guard follows the inode, so if the guarded
file is replaced by a fresh inode (a rename-over, an editor's atomic save), the
new file is a new `(dev, ino)` and is not guarded until re-added. For a stable
credential store like `/etc/shadow` this is the right behaviour; for churny
files, re-resolve on change.

## Scope is the safety rail

Same order as ch28/29: **scope check first, verdict second.** An open in any
cgroup that is not protected (or a descendant) returns 0 untouched, so a guarded
file stays readable to the rest of the host — only the protected service is
denied.

## Build and run

```sh
make                                              # vmlinux.h -> .bpf.o -> skeleton -> fileshield
sudo ./fileshield -c /sys/fs/cgroup/system.slice/nginx.service -f /etc/shadow
```

Repeat `-c` for several cgroups and `-f` for several files.

## Verify

```sh
sudo bash 30-fileshield/verify-fileshield.sh
```

The script does **not** touch the real `/etc/shadow`. It creates a throwaway
secret file in a temp dir and guards that (the `(dev, ino)` match is identical
on any file), scopes the shield to a throwaway cgroup, then shows: the guarded
open **denied** inside the cgroup and inside a child of it (hierarchical scope),
an unguarded file still **opening** inside the cgroup (the guard is per-file, not
a blanket open deny), and the guarded file still **opening** outside the cgroup.
Cleanup confirms the enforcing program is gone before removing the cgroup.

## Prerequisite and scope

- **BPF-LSM must be active** (`bpf` in the kernel `lsm=` parameter) — the same
  Chapter 20 wall. The loader checks `/sys/kernel/security/lsm` and points at
  `20-lsm/enable-bpf-lsm.sh` if it is missing. On a host without BPF-LSM the
  program compiles but cannot attach.
- **Status: built and run on a BPF-LSM kernel.** Built and verified in the Lima
  `shirudo-dev` VM (aarch64, kernel `7.0.0-44-generic` with `bpf` in `lsm=`):
  `verify-fileshield.sh` shows the guarded open **denied** (and logged as `DENY`)
  inside a throwaway protected cgroup and **in a child** of it, an unguarded file
  still **opening** inside the cgroup (the guard is per-file, not a blanket open
  deny), and the guarded file still **opening** outside the cgroup. The first run
  exposed a real bug — the loader was encoding `st_dev` with the wrong `dev_t`
  layout, so the in-kernel key never matched and the open was allowed; the
  `(dev, ino)` re-encoding was corrected to the kernel's `MKDEV` and the re-run
  passed. Transcript in [`logs/verify.txt`](logs/verify.txt).
- **Enforcement, scoped, not a full policy.** This denies opening a fixed set of
  files. A real policy also decides what counts as sensitive and keeps the set
  current as paths and inodes change.
- **Not immunity.** An attacker who reads the secret through a path the kernel
  resolves to a different inode (a copy made before the shield loaded, a backup),
  or who exploits the kernel below the LSM layer, is not stopped. This is
  containment of one read technique, not prevention of the bug. Pair it with
  ch28 (exec) and ch29 (privilege) to cover the other moves an exploit makes.
```
