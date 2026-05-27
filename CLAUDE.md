# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A learning repo working through the Isovalent "Learning eBPF" tutorial
(Liz Rice's book), one chapter per numbered directory (`01-hello-world/`, ...).
The goal is teaching, so code here is written to be read: keep examples small,
heavily commented, and prefer clarity over cleverness.

## Running examples

eBPF programs must be loaded by a privileged process.

**Chapters 1–6** (BCC / Python):
```bash
sudo python3 01-hello-world/hello.py
```
Loading a kprobe/printk example only shows output when the hooked event fires —
e.g. the `execve` hello world prints nothing until some process runs a new
program, so trigger it from a second terminal.

**Chapters 7–11** (C / libbpf):
```bash
cd 07-libbpf && make          # build once, no sudo needed
sudo ./07-libbpf/execsnoop    # load and run
```

Claude note: `sudo` on this machine requires a password, so Claude cannot load
eBPF programs itself. Hand the `sudo …` command to the user to run via `!` in
their session, or ask them to paste the output back.

## Chapter status (as of 2026-05-28)

| Range | Stack | Status |
|-------|-------|--------|
| Ch 1–6 | BCC / Python | ✅ complete |
| Ch 7–11 | C / libbpf | ✅ complete |
| Ch 12 | C / libbpf (first kprobe) | ✅ complete (verified on live IPv6 curl traffic) |
| Ch 13 | C / libbpf (tcp_sock counters) | ✅ complete (verified live; comm-fix confirmed) |
| Ch 14 | C / libbpf (verifier/debugging) | ✅ complete (verified live: all 3 lessons reject then fix-loads; load-time demo, no attach) |
| Ch 15 | C / libbpf (uprobe / bashreadline) | ✅ complete (verified live: traced interactive bash commands incl. a mistyped one) |
| Ch 16 | C / libbpf (bpftool / pinning) | ✅ complete (verified live: pinned, inspected with bpftool; BTF-typed map dumps as decoded JSON) |
| Ch 17 | C / libbpf (XDP, first datapath) | ✅ complete (verified live on wlp3s0; parses IPv4+IPv6 to L4; real ambient traffic is UDP/QUIC + ICMPv6 ND, TCP idle-0) |
| Ch 18 | C / libbpf (tc/BPF, ingress+egress) | ✅ complete (verified live on wlp3s0: egress visible; 639KB in / 2.8KB out download asymmetry) |
| Ch 19 | C / libbpf (tail calls / PROG_ARRAY) | ✅ complete (verified live: ls/echo/sudo → user 2, root 1, miss 0; echo builtin = no execve; sudo's setuid transition visible) |
| Ch 20 | C / libbpf (LSM BPF, verdict) | 🔨 built; prereq-detection verified, but exec-audit NOT live-verified — `bpf` not in this kernel's active `lsm=` (needs GRUB edit + reboot) |
| Ch 21 | C / libbpf (XDP firewall, XDP_DROP) | ✅ complete (verified live: 6 drops on lo:11111). Confirmed lo HAS an eth header → fixed ch17's wrong claim. From the Columbia lecture PDF. |

## Machine constraints (verified, not assumed)

- Kernel 6.8 with BTF at `/sys/kernel/btf/vmlinux` → CO-RE works.
- Installed: BCC (Python), bpftrace, bpftool, gcc, make.
- Installed (added at ch7): clang 18, llvm, libbpf-dev, libelf-dev.
- **Not installed**: `go` (needed for any future Go chapters).
- `trace_pipe` (`/sys/kernel/debug/tracing/trace_pipe`) is root-only; BCC's
  `trace_print()` locates it automatically when run under sudo.

## libbpf chapter conventions (ch7+)

Each C chapter follows a 4-file structure: `name.h`, `name.bpf.c`, `name.c`, `Makefile`.
The Makefile has four steps: `vmlinux.h` → `.bpf.o` → `.skel.h` → binary.

Exception: ch14 (`14-verifier/`) and ch16 (`16-bpftool/`) have **no `name.h`** — they
have no kernel↔user shared struct (ch14 attaches nothing; ch16's map is read by
bpftool, not by user space), so the 3-file layout is intentional, not an omission.

Common traps to check before declaring a chapter done:
- `bpf_ringbuf_reserve` takes 3 args: `(map, size, flags)` — the trailing `, 0` is required.
- Use `bpf_probe_read_user` for pointers from user space (syscall args); `bpf_probe_read_kernel` for kernel memory.
- `O_*`, `AF_*`, and similar constants are preprocessor macros — **not in vmlinux.h**. Define them manually, with `#ifndef` guards in shared headers.
- Key the stash map by full `bpf_get_current_pid_tgid()` (not just `>> 32`) when threads matter.
- `ctx->args[0]` for `sys_enter_execve` is the kernel-verified `filename`, not `argv[0]`.
- For kprobes (ch12+): use `BPF_KPROBE(name, args...)` for typed args, `BPF_CORE_READ()` for kernel struct fields (not `_user`/`_kernel` probe reads). Note TCP state values (`TCP_ESTABLISHED`…) *are* in vmlinux.h as an enum — don't redefine them (unlike `AF_*`/`O_*` macros, which aren't). At a `tcp_set_state` kprobe, `skc_state` is still the *old* state; `comm`/`pid` are only the connection owner on process-context transitions.
- The 512-byte BPF stack limit is enforced by **clang's BPF backend at compile time** (`error: Looks like the BPF stack limit is exceeded`), not just by the verifier — a too-big stack array never produces a `.bpf.o`. To demonstrate a *verifier-only* rejection use an unbounded array index, a NULL map-value deref, or an unbounded loop. Capture verifier logs programmatically via `bpf_object_open_opts.kernel_log_buf/size/level` + `bpf_program__set_autoload()` to isolate one program (ch14).
- A `struct sock *` casts directly to `struct tcp_sock *` (sock is at offset 0 of the tcp_sock nesting), so `BPF_CORE_READ(tp, bytes_acked/bytes_received/srtt_us/total_retrans)` works. `srtt_us` is stored ×8 — right-shift by 3 for microseconds. To fix the softirq `comm` problem, stash pid/comm at `TCP_SYN_SENT` (process context) and reuse at `TCP_CLOSE` (the ch13 / tcplife pattern).

When adding a new chapter, update:
1. `README.md` — chapters table
2. `docs/README.md` — progression table and numbered list
3. `docs/NN-name.md` — new chapter notes
