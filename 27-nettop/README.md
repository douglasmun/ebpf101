# 27 — Per-process network traffic accounting

Every chapter from 03 onward streams *events*: something happens in the kernel, a
record goes up a ring buffer, userspace prints it. That shape answers "what just
happened". It answers "which process is using my bandwidth right now" badly — at
100k packets a second you are paying a userspace wakeup per packet to compute a
number you only look at once a second.

This chapter is the other shape, and the one real observability agents use:

> The kernel keeps a **running total** in a map. Userspace **polls** it on a
> timer and differentiates two samples to get a rate.

No ring buffer. No per-event userspace cost. Constant memory. A process doing
100k sends a second costs exactly as much to observe as one doing ten.

## What it does

`nettop` accounts bytes per process — TCP and UDP, transmit and receive — and
prints a live table sorted by traffic. A mini `nethogs`.

```
$ sudo ./nettop
attached 7/7 kprobes
sampling every 1.0s — Ctrl-C to stop

14:22:07   3 processes with traffic

PID      COMM                   TX/s       RX/s    RETRANS
4182     curl                  1.2K      8.4M          0
1355     sshd                  3.1K      412B          0
992      chronyd                 76B       76B          0
```

Flags: `-i` interval, `-c` stop after N samples, `-n` row limit, `-C` don't clear
the screen (useful for piping).

## The hooks

Seven kprobes on the socket layer:

| Hook | Role |
|---|---|
| `tcp_sendmsg` | TCP tx — `size` is what userspace asked to send |
| `tcp_cleanup_rbuf` | TCP rx — `copied` is what userspace just read |
| `udp_sendmsg` / `udpv6_sendmsg` | UDP tx, per family |
| `skb_consume_udp` | UDP rx, both families |
| `tcp_retransmit_skb` | TCP resends — softirq, see below |
| `tcp_close` | map cleanup only — no accounting |

Six of the seven run in the calling process's own context, so
`bpf_get_current_pid_tgid()` is simply correct. The seventh is the interesting
one.

## Attribution, and the bug this chapter avoids

`tcp_retransmit_skb` fires from a **timer in softirq context**. "Current" is
whatever thread the interrupt landed on, not the socket's owner — the same trap
ch12 hit and ch13 fixed by stashing identity earlier.

The fix here is ch13's shape: record the owner while we *are* in process context,
look it up later. But there is a subtlety ch13 did not have to face, and which
the tool that prompted this chapter gets wrong.

The stash is keyed on the `struct sock *` pointer. **That pointer is only unique
while the socket is alive.** Free it and the slab allocator can hand the same
address to a brand-new socket owned by a different process; a stale entry then
silently misattributes that process's retransmits. So:

1. **`tcp_close` deletes the entry** the moment the socket dies, and
2. the map is an **`LRU_HASH` anyway**, so sockets that die by paths we do not
   hook get evicted by age instead of wedging the map full.

[pktz](https://github.com/immanuwell/pktz), the Go tool this chapter reworks,
does neither: a plain `HASH`, inserted on every send, never deleted. It fills to
`max_entries`, after which every new socket silently fails to register and
retransmit attribution quietly stops. One map type and one `bpf_map_delete_elem`
are the whole difference — which is exactly why it is worth a chapter.

A smaller one, same family: `nettop` checks the address family *before* touching
any map. These hooks also carry `AF_UNIX` sockets; registering them and then
discarding them burns LRU slots on sockets that can never retransmit, evicting
the TCP ones that can.

## What the byte counters actually mean

**Socket-layer bytes, not wire bytes.** `tcp_sendmsg`'s `size` is what the
process *asked* to send. It excludes TCP/IP headers, and it does not double-count
a retransmitted segment even though the NIC sends those bytes twice. So these
numbers run *below* what a packet capture would show, by a margin that depends on
your MSS and loss rate.

That is the right unit for "which process is eating my bandwidth" — but it is not
what "every byte, no excuses" would imply, and the difference deserves a number
rather than a footnote. `verify-nettop.sh` measures it: it transfers an
exactly-known payload, counts the same traffic with `tc` (ch18's mechanism) as an
independent witness, and prints the gap.

`retrans_pkts` is the honest counterweight — it reports the repetition the byte
columns structurally cannot show. It is deliberately *not* added into `tx_bytes`,
which would mix two units in one column.

## Rates are a userspace concern

The kernel never computes a rate. It only ever adds. Userspace holds the previous
sample and divides:

```c
rate = (now.tx_bytes - prev.tx_bytes) / elapsed_seconds
```

Three jobs the poller owns because the kernel side cannot do them cheaply:

- **hold the previous sample** — BPF maps have no "what was this last time"
- **reap dead PIDs** — a row whose process is no longer visible in `/proc` *and*
  has been idle for 60s can go. Without this the map fills with exited processes
  and refuses new ones. (`kill(pid, 0)` is the obvious check and the wrong one —
  see below.)
- **sort**

Two details that only show up once you run it: the first sample is taken and
discarded before display, or the opening frame shows one enormous fake spike made
of every byte an already-running process sent since boot. And a decrease in a
counter means a recycled PID, not negative traffic — re-baseline rather than
print a negative rate.

## Degrading honestly

`tcp_cleanup_rbuf` and `skb_consume_udp` are internal kernel functions, not
stable ABI. A rename breaks the attach. `nettop` attaches each program
independently and reports `attached N/7`, warning which hook is missing and
therefore which column under-counts — rather than refusing to start, or worse,
silently reporting low numbers.

## Two bugs this chapter's own first run produced

Both were in the *poller*, not the BPF program, and both had the same symptom —
an empty table while `bpftool map dump` showed the map filling correctly. Worth
recording because neither is specific to this program.

**1. `kill(pid, 0)` is the wrong liveness check.** The map is keyed by global
PID: `bpf_get_current_pid_tgid()` returns the tgid in the *initial* PID
namespace. A poller running inside a container is in a different namespace, so
`kill()` answered `ESRCH` for perfectly alive processes and the reaper deleted
every row on its first pass. Replaced with a `/proc/<pid>` check plus an idle
grace period, because failing to see a PID is not proof it is gone.

**2. Baselining on every first sighting hides short-lived processes.** Recording
a new PID's totals as its baseline is right on the *priming* pass and wrong
afterwards. A process that starts, transfers, and exits within two sample
intervals got recorded once as a baseline and never displayed — a 10 MiB `nc`
transfer showed up as nothing at all. A PID first seen *during* the run has
totals that *are* its traffic, so it baselines from zero.

The debugging path is the reusable part: `bpftool map dump` on the live map
separates "the kernel program is wrong" from "the reader is wrong" in one step,
and `bpftrace -e 'kprobe:tcp_sendmsg { @[comm] = count(); }'` confirms a hook
fires at all independently of your code.

## Where this sits

| Ch | Sees | Shape |
|---|---|---|
| 11 | connection *attempts* | event |
| 13 | one summary per connection, **at close** | event |
| 18 | bytes per **interface**, no process | counter (tc) |
| **27** | **live bytes per process**, TCP+UDP | **polled counter** |

## Build and run

```sh
make
sudo ./nettop
```

Needs `clang`, `libbpf-dev`, `bpftool`, and a BTF-capable kernel (the Makefile
generates `vmlinux.h` from `/sys/kernel/btf/vmlinux`).

Verification:

```sh
sudo bash verify-nettop.sh
```

This host is Apple Silicon macOS, so the chapter was built and run in a
privileged `debian:trixie-slim` container on Docker Desktop's kernel-7.0.12
aarch64 VM, as chapters 24–26 were. All 7 kprobes attached; a 10 MiB loopback
transfer was reported as `10.0M` on both the sending and receiving `nc`, each
attributed to its own PID. The transcript is in
[`logs/verify.txt`](logs/verify.txt).
