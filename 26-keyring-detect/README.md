# 26 — Detecting keyring-staged fileless execution

Chapter 25 catches fileless execution that transits an exec syscall or a memfd:
its auditd rules key on `memfd_create`/`execveat`/`init_module`/`execve`, and its
Sigma rules key on the `memfd:` or `(deleted)` string in `/proc/PID/exe`. A
different technique defeats all of it — staging the payload in the **kernel
keyring**.

The keyring method (matheuzsecurity, [*Linux Kernel Keyring Fileless
Exec*](https://matheuzsecurity.github.io/hacking/linux-kernel-keyring-fileless-exec/))
writes an ELF into a `user` key with `add_key(2)`, reads it back into an anonymous
mapping with `keyctl(KEYCTL_READ)`, hand-maps its `PT_LOAD` segments and jumps to
the entry point. No `execve`, no `execveat`, no `memfd_create`, no file
descriptor, no inode. Chapter 25's whole detection set sees nothing.

The keyring **write** is the one syscall-visible moment in that chain. This
chapter hooks it.

## What it does

`keyring_snoop` attaches two eBPF programs to the key-creation path and ships one
record per key creation to user space over a ring buffer; user space decides what
is suspicious (same dumb-kernel / smart-userspace split as ch23's IDS).

| Program | Attach | Role |
|---|---|---|
| `on_key_create` | `fentry/key_create_or_update` | **the detector.** Runs inside `add_key`'s kernel path with the key type and payload size known. Plain fentry — needs BTF, not BPF-LSM, so it attaches on any modern CO-RE kernel. Observe-only (fentry cannot deny). |
| `on_sys_add_key` | `tracepoint/syscalls/sys_enter_add_key` | **audit parity.** The syscall-boundary view — exactly what an `auditd -S add_key` rule could see. Included to make the gap concrete. |

The event carries pid, uid, comm, **key type**, **payload size**, and
description. The policy in `keyring_snoop.c` flags a key of type `user` or
`big_key` whose payload is at least a threshold size (default 4096 bytes) — large
enough to be an ELF, above the kilobyte-scale credential keys the system creates
constantly. The threshold is the first argument:

```sh
sudo ./keyring_snoop         # default: flag user/big_key staging >= 4096 bytes
sudo ./keyring_snoop 65536   # only flag payloads that could hold a real binary
```

## Why this hook, and why not LSM

`security_key_alloc` is a real LSM hook, and `bpf_lsm_key_alloc` is present in
this kernel's BTF — so an `lsm/key_alloc` program that returns `-EPERM` could
**deny** the staging outright, not just observe it. That is the enforcement path,
and it is written up in `keyring_snoop.lsm.bpf.c`.

It is **compile-only** here, for the same reason ch20 documents: BPF-LSM must be
enabled at boot (`bpf` listed in the kernel `lsm=` parameter). The lab's
kernel-6.12/linuxkit VM does not enable it — `/sys/kernel/security/lsm` is absent
— so the hook exists but nothing can attach to it. `make lsm` proves the program
compiles against real BTF; running it needs a BPF-LSM host. This mirrors ch25's
gate fragment: shown, not claimed to run.

The fentry hook is the pragmatic choice: it attaches on the lab kernel, and
detection (not blocking) is what this chapter demonstrates. `key_create_or_update`
is the public wrapper `add_key(2)` calls — confirmed in BTF to take
`(keyring_ref, type, description, payload, plen, perm, flags)`, and a global
symbol in kallsyms, so fentry can attach. (The `__`-prefixed inner
`__key_create_or_update` has a different signature with no type string, and is not
the right target.)

### Reading the arg strings — a measured detail

The two hooks read the *same* `type` and `description` strings but from
**different address spaces**, and this was settled by measurement, not assumption.

- At the **tracepoint** the args are the raw syscall arguments, still in user
  memory: `bpf_core_read_user_str`.
- At the **fentry** site the kernel has already copied those strings in, so the
  pointers address kernel memory: `bpf_core_read_str` (kernel). A user read there
  returns nothing.

A first cut used the user read on both and the fentry records came back with an
empty type; a side-by-side probe (`u0k1` — user read failed, kernel read
succeeded) fixed it. The distinction is real and easy to get wrong.

## Build and run

```sh
make            # vmlinux.h -> keyring_snoop.bpf.o -> skeleton -> keyring_snoop
make lsm        # compile-only: prove the LSM enforcement variant builds
sudo ./keyring_snoop &
./stage-key 8192    # stage a 'user' key big enough to hold a payload -> flagged
./stage-key 32      # a tiny key -> not flagged
```

`stage-key.c` is the thing being caught: it runs the `add_key` +
`keyctl(KEYCTL_READ)` + `KEYCTL_REVOKE` half of the technique (no ELF loader),
emitting no exec syscall, no memfd, no fd — invisible to ch25, visible here.

### On the lab kernel

The linuxkit VM does not mount tracefs, so the tracepoint's perf event ID cannot
be resolved and `on_sys_add_key` fails to attach. This is **not fatal**: the
loader attaches the two programs independently and treats a tracepoint failure as
a warning, so the fentry detector runs regardless. `mount -t tracefs nodev
/sys/kernel/tracing` before running enables the audit-parity view too.

Also: Docker's default seccomp profile blocks `add_key` (see ch25's keyring
probe, finding Q0), so triggering `stage-key` in a container needs
`--security-opt seccomp=unconfined`. `keyring_snoop` itself needs `--privileged`
(or `CAP_BPF`/`CAP_PERFMON`) and a BTF kernel bind-mounted at
`/sys/kernel/btf`.

`logs/demo.txt` is a captured run: the 8192-byte staging is flagged, the 32-byte
key is not, both hooks agree on type and size.

## Scope

- **Detection, not the exploit.** No ELF loader; the read-back and manual-map
  stages of the technique are not implemented here. This chapter is the defensive
  answer to ch25's keyring probe, not a working keyring-exec demo.
- **The write is the only syscall-visible moment.** Everything after `add_key`
  (the `KEYCTL_READ`, the `mmap`/`mprotect`, the jump) emits nothing that
  distinguishes it from ordinary memory work. Catching the staging `add_key` is
  the whole opportunity; a loader that never calls `add_key` (receiving a key
  serial another way) would evade even this.
- **Enforcement is an extension.** `keyring_snoop.lsm.bpf.c` sketches the
  `lsm/key_alloc` denial (return `-EPERM` on non-root `user`-key staging), left
  inert; it needs a BPF-LSM host to attach.
- Verified on the lab's kernel-6.12/linuxkit aarch64 container (kernel string
  `7.0.12-linuxkit`). The LSM path is unavailable there and is documented as
  such, not run.
