# Chapter 27 — Per-process traffic accounting (counters, not events)

**Code:** [`../27-nettop/`](../27-nettop/)
**Build:** `cd 27-nettop && make`
**Run:** `sudo ./27-nettop/nettop`
**Verify:** `sudo bash 27-nettop/verify-nettop.sh`

## Concept

Every chapter from ch03 onward streams **events**: something happens, a record
goes up a ring buffer, userspace prints it. That shape answers *"what just
happened"*. It answers *"which process is using my bandwidth right now"* badly —
at 100k packets a second you pay a userspace wakeup per packet to compute a
number you look at once a second.

This chapter is the other shape, and the one real observability agents use:

> The kernel keeps a **running total** in a map. Userspace **polls** it on a
> timer and differentiates two samples to get a rate.

| | event stream (ch03–ch23) | counter/poll (ch27) |
|---|---|---|
| kernel does | formats one record per event | `__sync_fetch_and_add` to a total |
| transport | ring buffer / perf buffer | a hash map read on a timer |
| userspace cost | O(events) | O(processes), once per interval |
| answers | "what happened, in order" | "what is the rate, right now" |
| loses | nothing | ordering, and every individual event |

Neither shape is better. They answer different questions, and the cost model is
the reason to pick one: a process doing 100k sends a second costs exactly as
much to observe here as one doing ten.

## Building blocks

### Seven kprobes, six of them boring

| Hook | Role |
|---|---|
| `tcp_sendmsg` | TCP tx — `size` is what userspace asked to send |
| `tcp_cleanup_rbuf` | TCP rx — `copied` is what userspace just read |
| `udp_sendmsg` / `udpv6_sendmsg` | UDP tx, per family |
| `skb_consume_udp` | UDP rx, both families |
| `tcp_retransmit_skb` | TCP resends — softirq context |
| `tcp_close` | map cleanup only, no accounting |

Six run in the calling process's own context, so `bpf_get_current_pid_tgid()` is
simply correct. The seventh is the whole lesson.

### Attribution across a context switch

`tcp_retransmit_skb` fires from a **timer in softirq context**. "Current" is
whatever thread the interrupt landed on, not the socket's owner — the same trap
ch12 hit and ch13 fixed by stashing identity earlier.

The fix here is ch13's shape: record the owner while we *are* in process context,
look it up later. But there is a subtlety ch13 never faced. The stash is keyed on
`struct sock *`, and **that pointer is only unique while the socket is alive**.
Free it and the slab allocator can hand the same address to a new socket owned by
a different process; a stale entry then silently misattributes that process's
retransmits.

Two mechanisms, because either alone leaks:

1. **`tcp_close` deletes the entry** the moment the socket dies, and
2. the map is an **`LRU_HASH` anyway**, so sockets that die by paths we do not
   hook get evicted by age instead of wedging the map full.

A plain `BPF_MAP_TYPE_HASH` that is never deleted from fills to `max_entries`,
and from then on every new socket **silently** fails to register — `E2BIG`, on a
return value nobody checks — so retransmit attribution quietly stops for exactly
the sockets that are busiest. One map type and one `bpf_map_delete_elem` are the
whole difference.

A smaller one, same family: the address-family check happens **before** any map
write. These hooks also carry `AF_UNIX` sockets, and registering them burns LRU
slots on sockets that can never retransmit, evicting the TCP ones that can.

### Rates are a userspace concern

The kernel never computes a rate. It only ever adds:

```c
rate = (now.tx_bytes - prev.tx_bytes) / elapsed_seconds
```

Three jobs the poller owns: hold the previous sample (BPF maps have no "what was
this last time"), reap dead PIDs, and sort. Two details only show up once you run
it — the first sample is taken and **discarded** before display, or the opening
frame shows one enormous fake spike made of every byte an already-running process
sent since boot; and a *decrease* in a counter means a recycled PID, not negative
traffic, so re-baseline rather than print a negative rate.

## What the byte counters actually mean

**Socket-layer bytes, not wire bytes.** `tcp_sendmsg`'s `size` is what the
process *asked* to send: it excludes TCP/IP headers, and it does not double-count
a retransmitted segment even though the NIC sends those bytes twice. These
numbers therefore run *below* a packet capture, by a margin that depends on MSS
and loss rate.

That is the right unit for "which process is eating my bandwidth", but it is not
what "every byte, no excuses" implies, and the gap deserves a number rather than
a footnote. `verify-nettop.sh` transfers an exactly-known payload and counts the
same traffic with `tc` (ch18's mechanism) as an independent witness. On loopback
a 10 MiB transfer measured **+0.5%** wire overhead — consistent with ~784
segments × 64B of headers at loopback's 64KB MTU.

`retrans_pkts` is the honest counterweight: it reports the repetition the byte
columns structurally cannot show. It is deliberately **not** folded into
`tx_bytes`, which would mix two units in one column.

## Degrading honestly

`tcp_cleanup_rbuf` and `skb_consume_udp` are internal kernel functions, not
stable ABI, and a rename breaks the attach. `nettop` attaches each program
independently and reports `attached N/7`, warning which hook is missing and
therefore which column under-counts — rather than refusing to start, or worse,
silently reporting low numbers.

## Where this sits

| Ch | Sees | Shape |
|---|---|---|
| 11 | connection *attempts* | event |
| 13 | one summary per connection, **at close** | event |
| 18 | bytes per **interface**, no process | counter (tc) |
| **27** | **live bytes per process**, TCP+UDP | **polled counter** |

## Notes

Verified in a privileged `debian:trixie-slim` container on Docker Desktop's
kernel-`7.0.12-linuxkit` aarch64 VM, as chapters 24–26 were: 7/7 kprobes
attached, and a 10 MiB loopback transfer was reported as `10.0M` against both the
sending and receiving `nc`, each attributed to its own PID. Transcript in
[`../27-nettop/logs/verify.txt`](../27-nettop/logs/verify.txt).

Two bugs this chapter's own first run produced are written up in the chapter
[README](../27-nettop/README.md) — both were in the *poller*, not the BPF
program, and both presented as an empty table while `bpftool map dump` showed the
map filling correctly. The debugging path is the reusable part: dumping the live
map separates "the kernel program is wrong" from "the reader is wrong" in one
step, and `bpftrace -e 'kprobe:tcp_sendmsg { @[comm] = count(); }'` confirms a
hook fires at all, independently of your code.

The chapter reworks the accounting idea from [pktz](https://github.com/immanuwell/pktz),
a Go/TUI tool with a different scope; the socket→PID lifetime handling described
above is where the two differ.
