# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A learning repo that **started** from the Isovalent "Learning eBPF" tutorial
(Liz Rice's book) and has since gone **well beyond** it — one chapter per numbered
directory (`01-hello-world/` … `23-ids/`). The early chapters follow the tutorial
(BCC → libbpf/CO-RE → kprobes/uprobes); the later ones extend into the verifier,
`bpftool`, the XDP/tc datapath, tail calls, LSM BPF, BPF iterators, and two applied
capstones — an XDP firewall (from a Columbia EECS6891 lecture, Yannis Zarkadas,
Spring 2024) and a rule-based IDS (from arXiv:2102.09980). The goal is teaching, so
code here is written to be read: keep examples small, heavily commented, and prefer
clarity over cleverness.

## Running examples

eBPF programs must be loaded by a privileged process.

**Chapters 1–6** (BCC / Python):
```bash
sudo python3 01-hello-world/hello.py
```
Loading a kprobe/printk example only shows output when the hooked event fires —
e.g. the `execve` hello world prints nothing until some process runs a new
program, so trigger it from a second terminal.

**Chapters 7+** (C / libbpf):
```bash
cd 07-libbpf && make          # build once, no sudo needed
sudo ./07-libbpf/execsnoop    # load and run
```
Some chapters ship helper scripts — e.g. `20-lsm/verify-execguard.sh` and
`23-ids/verify-ids.sh` load + exercise + detach hands-free, and
`23-ids/trigger-attacks.sh` generates test traffic. Run the loaders under `sudo`
the same way (the trigger script needs no root — it only sends loopback traffic).

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
| Ch 20 | C / libbpf (LSM BPF, verdict) | ✅ complete (verified live after reboot: `bpf` active in `lsm=`; `verify-execguard.sh` logged `allow` verdicts for ls/id/uname via `bprm_check_security`). |
| Ch 21 | C / libbpf (XDP firewall, XDP_DROP) | ✅ complete (verified live: 6 drops on lo:11111). Confirmed lo HAS an eth header → fixed ch17's wrong claim. From the Columbia lecture PDF. |
| Ch 22 | C / libbpf (BPF iterator, iter/task) | ✅ complete (verified live: dumped ~600 tasks; threading visible — firefox/claude fan out; tool saw itself). Covers the PDF's "iterators". |
| Ch 23 | C / libbpf (rule-based IDS, socket filter) | ✅ complete (verified live on lo via `23-ids/verify-ids.sh`: susp-port 4444, port-scan 21>20, beacon interval~3.0s jitter 0.0%). First `SOCKET_FILTER` attach (`AF_PACKET`+`SO_ATTACH_BPF`). Kernel taps packets → ringbuf; userspace runs C2/anomaly rules. No ML — inspired by arXiv 2102.09980 but the inverse design (rules in userspace, not a DT in-kernel). All 23 chapters now run live. |

## Machine constraints (verified, not assumed)

- Kernel 6.8 with BTF at `/sys/kernel/btf/vmlinux` → CO-RE works.
- Installed: BCC (Python), bpftrace, bpftool, gcc, make.
- Installed (added at ch7): clang 18, llvm, libbpf-dev, libelf-dev.
- **Not installed**: `go` (needed for any future Go chapters); and no Python ML
  libs (`scikit-learn`/`numpy`/`pandas`) — weighed for a ch23 ML-based IDS, then
  dropped in favour of plain user-space rules.
- Traffic generators for the network chapters: `nc` (netcat-openbsd), `curl`,
  `ping` are present; `hping3`/`iperf3`/`nping` are NOT. Bash
  `/dev/udp/<host>/<port>` sends one datagram instantly (used by ch23's triggers
  for jitter-free timing — `nc -u -w1` adds a variable 0–1 s timeout).
- `trace_pipe` (`/sys/kernel/debug/tracing/trace_pipe`) is root-only; BCC's
  `trace_print()` locates it automatically when run under sudo.

## libbpf chapter conventions (ch7+)

Each C chapter follows a 4-file structure: `name.h`, `name.bpf.c`, `name.c`, `Makefile`.
The Makefile has four steps: `vmlinux.h` → `.bpf.o` → `.skel.h` → binary.

Exception: ch14 (`14-verifier/`), ch16 (`16-bpftool/`), and ch22 (`22-iterator/`)
have **no `name.h`** — no kernel↔user shared struct (ch14 attaches nothing; ch16's
map is read by bpftool; ch22 outputs seq_file text), so the 3-file layout is
intentional, not an omission.

Common traps to check before declaring a chapter done:
- `bpf_ringbuf_reserve` takes 3 args: `(map, size, flags)` — the trailing `, 0` is required.
- Use `bpf_probe_read_user` for pointers from user space (syscall args); `bpf_probe_read_kernel` for kernel memory.
- `O_*`, `AF_*`, and similar constants are preprocessor macros — **not in vmlinux.h**. Define them manually, with `#ifndef` guards in shared headers.
- Key the stash map by full `bpf_get_current_pid_tgid()` (not just `>> 32`) when threads matter.
- `ctx->args[0]` for `sys_enter_execve` is the kernel-verified `filename`, not `argv[0]`.
- For kprobes (ch12+): use `BPF_KPROBE(name, args...)` for typed args, `BPF_CORE_READ()` for kernel struct fields (not `_user`/`_kernel` probe reads). Note TCP state values (`TCP_ESTABLISHED`…) *are* in vmlinux.h as an enum — don't redefine them (unlike `AF_*`/`O_*` macros, which aren't). At a `tcp_set_state` kprobe, `skc_state` is still the *old* state; `comm`/`pid` are only the connection owner on process-context transitions.
- The 512-byte BPF stack limit is enforced by **clang's BPF backend at compile time** (`error: Looks like the BPF stack limit is exceeded`), not just by the verifier — a too-big stack array never produces a `.bpf.o`. To demonstrate a *verifier-only* rejection use an unbounded array index, a NULL map-value deref, or an unbounded loop. Capture verifier logs programmatically via `bpf_object_open_opts.kernel_log_buf/size/level` + `bpf_program__set_autoload()` to isolate one program (ch14).
- Socket-filter programs (`SEC("socket")`, `BPF_PROG_TYPE_SOCKET_FILTER`, attached via a raw `AF_PACKET` socket + `setsockopt(SO_ATTACH_BPF)`) get **NO direct packet access** — the verifier's `may_access_direct_pkt_data()` excludes the type, so `skb->data`/`data_end` parsing (the XDP/tc idiom) is rejected at load. Read packet bytes with `bpf_skb_load_bytes(skb, off, &buf, len)` instead (offsets from the Ethernet header on AF_PACKET). `bpf_ktime_get_ns`, ring-buffer helpers, and `skb->len` are all fine for socket filters. The program's return value only caps bytes queued to that socket — it never touches the stack, so it's a pure observer (ch23). Closing the socket detaches the filter. **Loopback double-delivery trap:** an AF_PACKET socket sees every `lo` frame TWICE — once outgoing (`PACKET_OUTGOING`) and once looped back in (`PACKET_HOST`) — which doubles counts and wrecks timing (ch23's beacon read mean 1.5s / jitter ~100% from alternating 0s,3s gaps until fixed). Set `setsockopt(SOL_PACKET, PACKET_IGNORE_OUTGOING, 1)` (Linux ≥4.20) to keep one copy. Also: for clean inter-arrival demos, send UDP via bash `/dev/udp/host/port` (instant) — `nc -u -w1` adds variable 0–1s timeout jitter.
- A `struct sock *` casts directly to `struct tcp_sock *` (sock is at offset 0 of the tcp_sock nesting), so `BPF_CORE_READ(tp, bytes_acked/bytes_received/srtt_us/total_retrans)` works. `srtt_us` is stored ×8 — right-shift by 3 for microseconds. To fix the softirq `comm` problem, stash pid/comm at `TCP_SYN_SENT` (process context) and reuse at `TCP_CLOSE` (the ch13 / tcplife pattern).

When adding a new chapter, update:
1. `README.md` — chapters table, and the "all N chapters run live" footnote/count
2. `docs/README.md` — progression table and numbered list
3. `docs/NN-name.md` — new chapter notes, ending with a `⬅️`/`➡️` link to the
   neighbour; also repoint the previous chapter's closing `➡️` to this one
4. `.gitignore` — add the compiled loader as `NN-name/binary` (loaders have no
   extension, so they're listed by name; `*.bpf.o`/`*.skel.h`/`vmlinux.h` are
   already covered by glob)
5. This file (`CLAUDE.md`) — the chapter-status table above, plus any new trap
   for the conventions list
6. **Do NOT renumber existing chapters** — it breaks doc cross-links and the
   wall→next narrative.

After building, the chapter is `🔨` until the user runs it under `sudo`; reconcile
the docs with the *real* output, then flip to `✅`. Per-chapter helper scripts
(`verify-*.sh`, `trigger-*.sh`) are welcome — keep them runnable hands-free.
