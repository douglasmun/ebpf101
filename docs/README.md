# Learning eBPF — Journey Notes

Study notes for the chapter-by-chapter walk through the
[Isovalent "Learning eBPF" tutorial](https://isovalent.com/labs/ebpf-tutorial/)
(Liz Rice's book). The code in each `NN-*/` directory is heavily commented for
the *how*; these notes capture the *why*, and what each program revealed when we
actually ran it on this machine.

## The one mental model

Every chapter is a variation on the same shape:

```
        attach a hook                 store / send data            read in
   (kprobe or tracepoint)   ───▶   (map or perf/ring buffer)  ───▶  user space
   runs your code in-kernel        the kernel↔userspace bridge      (Python ch1–6 / C ch7+)
   on some event
```

- **Hook** — where your code runs. We used the `execve` (ch1–8: every program
  launch), `openat` (ch9–10: every file open), and `connect` (ch11: every
  outbound connection) tracepoints, then the kernel *function* `tcp_set_state`
  (ch12–13: every TCP state change — our first **kprobe**). Any kernel tracepoint
  or function works; only the `SEC()` annotation changes.
- **Bridge** — how kernel-side code hands data to user space: `bpf_trace_printk`
  → hash map → perf buffer → ring buffer. The bridge is where most of the
  early learning lives; from ch7 onward it stabilises on the ring buffer.

## The progression

Each chapter exists because the previous mechanism hit a wall:

| Ch | Hook | Output mechanism | What we could finally see | Wall it hit |
|----|------|------------------|---------------------------|-------------|
| [01](01-hello-world.md) | kprobe | `bpf_trace_printk` | *that* execve happened | a constant string, no data, one global buffer |
| [02](02-maps.md) | kprobe | `BPF_HASH` map | a running count per user | an aggregate — no per-event detail |
| [03](03-perf-buffer.md) | kprobe | `BPF_PERF_OUTPUT` | per-event PID + UID + caller name | the caller's name, not the launched binary |
| [04](04-tracepoint.md) | **tracepoint** | `BPF_PERF_OUTPUT` | the **actual binary path** (`execsnoop`) | only the path — not the arguments (`argv`) |
| [05](05-argv.md) | tracepoint | per-arg `BPF_PERF_OUTPUT` records | the **full command line** (alias expansion and all) | per-CPU rings, copied data, silent drops |
| [06](06-ringbuf.md) | tracepoint | `BPF_RINGBUF_OUTPUT` | same output; shared ring, zero-copy, explicit back-pressure | still BCC — C compiled at runtime, not portable |
| [07](07-libbpf.md) | tracepoint | libbpf ring buffer (C) | same path output; portable pre-compiled binary, skeleton API | reads only filename — no argv yet |
| [08](08-argv-libbpf.md) | tracepoint | libbpf ring buffer (C) | full command lines from compiled binary; C pending table | only execve — file/network hooks next |
| [09](09-openat.md) | `sys_enter_openat` | libbpf ring buffer (C) | every file open with decoded flags; kernel-side filter pattern | open succeeded? return value? → need exit tracepoint |
| [10](10-openat-ret.md) | `sys_enter/exit_openat` | libbpf hash map + ring buffer | fd or −errno per open; failure diagnosis | pattern generalises — network connect next |
| [11](11-connect.md) | `sys_enter/exit_connect` | libbpf hash map + ring buffer | every outbound TCP/UDP attempt; IP + port + outcome; `bpf_probe_read_user` for sockaddr | only the *attempt* — not whether/when it reached ESTABLISHED, nor its lifecycle |
| [12](12-tcpstates.md) | **kprobe** `tcp_set_state` | libbpf LRU map + ring buffer | every TCP state transition; full 4-tuple via `BPF_CORE_READ` of `struct sock`; per-state duration + handshake latency | `comm` unreliable off process context; no bytes/throughput |
| [13](13-tcplife.md) | same `tcp_set_state` kprobe | libbpf LRU maps + ring buffer | one summary per *closed* connection: bytes tx/rx, RTT, retransmits via `struct tcp_sock`; identity stashed at `SYN_SENT` (fixes ch12's `comm`) | only a postmortem — no live/real-time throughput |

## The running mystery (closed in Ch 5)

A thread runs through the first five chapters: a `run-cups-browse` process
flooding the output on a ~1-second heartbeat, even on an idle machine.

- **Ch 1** — saw the flood, names mostly `<...>` (trace-buffer limitation).
- **Ch 3** — got the name `run-cups-browse`, but not what it was running.
- **Ch 4** — traced it to `/snap/cups/1206/scripts/run-cups-browsed`: CUPS is a
  **snap**, launched by systemd through snapd's sandbox helpers
  (`snap-confine` → `snap-exec`), and the final script calls `/usr/bin/sleep`.
- **Ch 5** — the argument `1` confirmed the period exactly: `sleep 1`.
  Mystery closed.

Two big concepts fell out of watching real output:
- **fork + exec**: one PID appears under several names in a row — a process
  `fork`s (keeps the parent's name) then `execve`s to *replace its own image*,
  possibly several times through a launcher chain. (See Ch 3/4 notes.)
- **privilege boundaries**: we caught a UID flip 103 → 0 as D-Bus exec'd a
  **setuid-root** helper, and caught a `sudo → apt` escalation. This is exactly
  what a tool like `execsnoop` exists to monitor.

## This machine

Kernel 6.8 with BTF (`/sys/kernel/btf/vmlinux`) → CO-RE capable. BCC, bpftrace,
bpftool, gcc, make installed. clang 18, llvm, libbpf-dev, libelf-dev also
installed (added at ch7). `sudo` needs a password, so every example is run by
hand — `sudo python3 …` for ch1–6, `sudo ./program` for ch7+.

## Chapter notes

1. [Hello World](01-hello-world.md) — kprobe + `bpf_trace_printk`
2. [Maps](02-maps.md) — `BPF_HASH`, shared kernel/user state
3. [Perf buffer](03-perf-buffer.md) — `BPF_PERF_OUTPUT`, structured event stream
4. [Tracepoint](04-tracepoint.md) — stable hook + reading a syscall argument (`execsnoop`)
5. [Capturing argv](05-argv.md) — double pointer indirection + multi-record reassembly (full command lines)
6. [Ring Buffer](06-ringbuf.md) — `BPF_RINGBUF_OUTPUT`: shared ring, zero-copy reserve/commit, explicit back-pressure
7. [libbpf + CO-RE](07-libbpf.md) — real C + clang, vmlinux.h, skeleton, portable binary (no LLVM on target)
8. [argv in C](08-argv-libbpf.md) — port the full execsnoop to C: EVENT_ARG/RET protocol + C pending table
9. [openat (opensnoop)](09-openat.md) — first non-execve hook; flags bitmask; kernel-side filter vs strace cost
10. [openat return value](10-openat-ret.md) — entry/exit correlation via BPF hash map; fd vs −errno; failure diagnosis
11. [connect (netsnoop)](11-connect.md) — network visibility: outbound TCP/UDP; `bpf_probe_read_user` for sockaddr; byte-order conversion in BPF
12. [TCP states (tcpstates)](12-tcpstates.md) — first kprobe in C; `BPF_CORE_READ` of kernel `struct sock`; sock-keyed map for per-state durations and SYN→ESTABLISHED latency
13. [TCP life (tcplife)](13-tcplife.md) — per-connection summary at close; read the larger `struct tcp_sock` (bytes/RTT/retransmits); stash identity at `SYN_SENT` to fix the softirq `comm` problem
