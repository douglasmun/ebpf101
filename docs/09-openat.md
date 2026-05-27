# Chapter 9 — openat (opensnoop)

**Code:** [`../09-openat/`](../09-openat/)  
**Build:** `cd 09-openat && make`  
**Run:** `sudo ./09-openat/opensnoop`

## Concept

Hook `sys_enter_openat` instead of `sys_enter_execve`.  Every file open —
library loads, config reads, log writes, socket-file touches — fires the probe.
The toolchain (libbpf + CO-RE + ring buffer + skeleton) is identical to ch7/8;
only the `SEC()` annotation and `ctx->args[]` indices change.

## New building blocks

### A different tracepoint — same pattern

```c
// ch7/8
SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx) { … ctx->args[0] … }

// ch9
SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx) { … ctx->args[1] … }
```

The context type is the same (`trace_event_raw_sys_enter`); only the section
name and argument indices differ.  `args[1]` is the filename pointer for
`openat`; `args[2]` is the `O_*` flags integer.

### Flag bitmask decoding

`openat`'s third argument is a bitmask of `O_*` constants:

| Bits | Constant | Meaning |
|------|----------|---------|
| `& 0x3 == 0` | `O_RDONLY` | read-only |
| `& 0x3 == 1` | `O_WRONLY` | write-only |
| `& 0x3 == 2` | `O_RDWR` | read-write |
| `0x40` | `O_CREAT` | create if missing |
| `0x200` | `O_TRUNC` | truncate to zero on open |

We pass the raw integer through the ring buffer and decode it in user space:

```
FLAGS
r       read-only open of an existing file
w       write-only
rw      read-write
wct     write + create + truncate → create-or-overwrite (0x241)
rc      read + create (unusual — "open for reading, create if absent")
```

### Volume and kernel-side filtering

`openat` fires far more than `execve` — every shared library load, every
config-file read, every inotify check.  The BPF program includes a commented
example of the idiomatic kernel-side filter:

```c
// Drop read-only opens before they ever reach the ring buffer:
int flags = (int)ctx->args[2];
if ((flags & O_ACCMODE) == O_RDONLY) return 0;
```

Filtering in kernel is zero-cost for dropped events: they never cross the ring
buffer, never wake user space, never touch the CPU cache.  This is one of the
core performance arguments for eBPF over `strace` (which intercepts every
syscall via ptrace, paying the context-switch cost regardless of filter).

## What the output reveals

- **Library loading**: every `dlopen` and dynamic linker load shows as `r`
  opens against `/usr/lib/…/*.so.*`.
- **Config reads**: editors, browsers, and daemons reading `~/.config/*` on
  startup appear in the first second of a new process.
- **File writes**: `wct` flags mark create-or-overwrite — log rotation, temp
  files, atomic config saves (write to `.tmp`, rename).
- **Pseudo-files**: `/proc/self/status`, `/sys/devices/*`, `/dev/urandom` —
  these look like file opens but never touch a disk; the kernel serves them
  directly.  grep them out if they clutter the view:
  ```bash
  sudo ./opensnoop | grep -v -e /proc -e /sys -e /dev
  ```

## The wall (→ next)

`openat` tells us a file was *opened*, not what happened after.  We don't see:
- Whether the open succeeded (the return value / errno)
- How many bytes were read or written
- Network connections (`connect`, `sendto`, `recvfrom`)

Capturing return values requires `sys_exit_openat` (the exit tracepoint) or a
`kretprobe` / `fexit` program — correlating entry and exit events by PID.
That is the next natural step.
