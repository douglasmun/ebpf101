# Chapter 26 — Detecting keyring-staged fileless execution

**Code:** [`../26-keyring-detect/`](../26-keyring-detect/)
**Build:** `cd 26-keyring-detect && make` (and `make lsm` for the compile-only enforcement variant)
**Run:** `sudo ./26-keyring-detect/keyring_snoop [min-bytes]`  *(default threshold 4096)*
**Trigger:** with it running, `./26-keyring-detect/stage-key [size]` from another terminal

## Why this chapter exists

Chapter 25 is a lab on fileless execution *detection*, and its detection set has a
blind spot it names but does not close: the kernel keyring. Every rule in ch25
watches an exec syscall (`execve`, `execveat`) or the memfd primitive
(`memfd_create`), or matches a string in `/proc/PID/exe`. The keyring technique —
stage an ELF in a `user` key with `add_key`, read it back with `keyctl`, hand-map
it and jump — uses none of those. Ch25's keyring probe (`FINDINGS.md`, 14 Sep
2026) measured that the staging primitive is real, unprivileged, and survives the
dropper's exit, and concluded: *the detection question is not "watch
`/proc/keys`" but "watch `add_key`/`keyctl` at the syscall boundary," which is
exactly where eBPF reaches and auditd's rule set does not.*

This chapter is that eBPF program. It is the first chapter written as a direct
response to a gap the previous one measured.

## The wall it closes

| | ch25 detection | ch26 |
|---|---|---|
| Hook | exec syscalls, `memfd_create`, `/proc/PID/exe` strings | the **key-creation** path |
| Sees keyring staging? | **no** (no exec, no memfd, no deleted-file inode) | **yes** (`add_key` → `key_create_or_update`) |
| Output | auditd log / Sigma match | ring buffer → user-space policy |

## Design

The same shape as ch23's IDS: a **dumb kernel side** that copies a small fixed
record out per event, and a **user-space brain** that decides. Two programs feed
one ring buffer:

```
  kernel (eBPF)                              user space
  fentry/key_create_or_update   ──ring──▶    per-event policy:
    type + payload size (the detector)        flag user/big_key keys
  tracepoint/sys_enter_add_key   buffer       whose payload is ELF-sized
    the audit-parity view                     (default >= 4096 bytes)
```

Why two hooks? The **fentry** program is the detector — it runs inside the kernel
path with the key type and payload size in hand, and it attaches on any BTF kernel
(no BPF-LSM needed). The **tracepoint** is audit parity: it sees exactly what an
`auditd -S add_key` rule would, and its presence makes the gap concrete — a
syscall rule can log *that* `add_key` happened but records neither the type nor
the size, which are the two fields that separate a credential cache from a staged
payload.

## What the run shows

`logs/demo.txt`: with `keyring_snoop` watching, `stage-key 8192` (a `user` key
large enough to hold a payload) is flagged `<== STAGED PAYLOAD?`; `stage-key 32`
(a tiny key) is not. With tracefs mounted both hooks fire and agree on type
(`user`) and size; on the default lab kernel only fentry does. `stage-key`
itself emits no exec syscall, no memfd, no file descriptor — it is invisible to
every ch25 rule and visible to this one.

## Two things worth keeping

**Same string, two address spaces.** The fentry and tracepoint hooks read the
identical `type`/`description` arguments, but at the tracepoint they are still in
user memory (`bpf_core_read_user_str`) and at the fentry site the kernel has
already copied them in (`bpf_core_read_str`, kernel). A first cut used the user
read in both places and the fentry records came back with an empty type; a
side-by-side probe settled which read works where. Measured, not assumed — the
recurring discipline of this repo.

**Detection reaches; enforcement needs BPF-LSM.** `security_key_alloc` is an LSM
hook with a `bpf_lsm_key_alloc` BTF stub on a BPF-LSM kernel, so an `lsm/key_alloc`
program returning `-EPERM` could *block* the staging. That variant
(`keyring_snoop.lsm.bpf.c`) is written and compiles against real BTF, but it is
compile-only on the lab kernel for the same reason ch20 documents: BPF-LSM must be
enabled at boot (`bpf` in the kernel `lsm=` parameter), and the linuxkit VM does
not enable it (`/sys/kernel/security/lsm` absent). Detection is what runs here;
denial is the documented extension.

## Scope

Detection, not the exploit — there is no ELF loader, only the `add_key`+`keyctl`
staging that `stage-key` performs. The keyring **write** is the only
syscall-visible moment in the whole chain; everything after it (the read-back, the
`mmap`/`mprotect`, the jump) is indistinguishable from ordinary memory work, so a
loader that obtains a key serial without calling `add_key` would evade even this.
Verified on the lab's linuxkit aarch64 container (kernel `7.0.12-linuxkit`); the LSM path is
unavailable there and documented as such rather than run.
