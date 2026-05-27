# Chapter 13 — Per-connection throughput (`tcplife`)

**Code:** [`../13-tcplife/`](../13-tcplife/)  
**Build:** `cd 13-tcplife && make`  
**Run:** `sudo ./13-tcplife/tcplife`

## Concept

Chapter 12 printed every TCP state transition. This chapter hooks the *same*
function (`tcp_set_state`) but says nothing until a connection **ends**, then
emits one summary line — an obituary for the socket: who owned it, where it went,
how long it lived, how many bytes flowed each way, the smoothed RTT, and how many
segments were retransmitted. This is the design of the `tcplife` tool.

So ch12 and ch13 are the two natural readings of one hook: **a transition log**
vs. **a per-connection ledger**.

## Two new ideas, both built on ch12

### 1. Reading the *bigger* struct — `struct tcp_sock`

`struct sock` is only the common front of a much larger
`struct tcp_sock`. The nesting is:

```
struct tcp_sock {
    struct inet_connection_sock inet_conn;   // which begins with…
        struct inet_sock        …            //   …which begins with…
            struct sock         sk;          //     …which is at offset 0
    …
    u64 bytes_acked;       // bytes we sent that the peer ACKed (delivered tx)
    u64 bytes_received;    // bytes received from the peer (rx)
    u32 srtt_us;           // smoothed RTT, stored << 3
    u32 total_retrans;     // segments retransmitted over the connection's life
};
```

Because `sock` sits at offset 0, the `struct sock *` the kernel handed us *is*
the address of the enclosing `tcp_sock`. We cast and read the deep fields with
the same `BPF_CORE_READ` skill from ch12 — CO-RE relocates each offset against
the running kernel's BTF:

```c
struct tcp_sock *tp = (struct tcp_sock *)sk;
e->tx_b    = BPF_CORE_READ(tp, bytes_acked);
e->rx_b    = BPF_CORE_READ(tp, bytes_received);
e->srtt_us = BPF_CORE_READ(tp, srtt_us) >> 3;   /* kernel stores RTT × 8 */
```

> `srtt_us` is a fixed-point value: the kernel keeps smoothed RTT in units of
> ⅛ microsecond, so a right-shift by 3 converts it to microseconds. Reading the
> raw field and forgetting the shift is a classic "my RTTs are 8× too big" bug.

These are the [RFC 4898](https://www.rfc-editor.org/rfc/rfc4898) TCP extended
statistics the kernel maintains for free on every connection. We read them once,
at close, when they hold the connection's final totals.

### 2. Fixing ch12's `comm` problem on purpose

Ch12's blunt lesson was that `comm` at the `→ ESTABLISHED` transition is wrong:
that step runs in **softirq**, so `comm` was `swapper`, not the connecting
process. Ch13 works around it the way `tcplife` does — stash the identity at a
moment we *know* is process context, and reuse it at close:

```c
if (state == TCP_SYN_SENT || state == TCP_LAST_ACK) {
    /* SYN_SENT = active connect(), runs in the caller's own context */
    struct ident who = { .pid = bpf_get_current_pid_tgid() >> 32 };
    bpf_get_current_comm(&who.comm, sizeof(who.comm));
    bpf_map_update_elem(&idents, &id, &who, BPF_ANY);
}
```

At `TCP_CLOSE` we look this up instead of trusting whatever task happens to be
running. The summary line is therefore attributed to `curl`, not `swapper`.

## Lifecycle bookkeeping (three maps, all keyed by the sock pointer)

```
state < FIN_WAIT1 (opening) ─▶ births[sk] = now    (BPF_NOEXIST: first wins → full lifetime)
state == SYN_SENT/LAST_ACK  ─▶ idents[sk] = {pid, comm}   (process-context identity)
state == TCP_CLOSE          ─▶ look up births + idents, read tcp_sock,
                               emit one event, delete both entries
```

`births` uses `BPF_NOEXIST` so the *earliest* opening transition wins: lifetime
spans the whole connection (handshake included), not just the established phase.
A connection that was already open before we attached has no `births` entry, so
it produces no summary — the same honest "we can only report what we saw born"
limitation as ch12, made explicit. Both stash maps are `LRU_HASH` to bound
memory if a socket never reaches `CLOSE`.

## What the output reveals

Real capture on this machine — two `curl`s plus one background app connection
that happened to close while the tool ran (the source address is this host's
own, redacted here to an RFC 3849 documentation address `2001:db8::/32`; IPv6
endpoints are bracketed `[addr]:port`, RFC 3986, so the address colons don't
blur into the port):

```
PID     COMM             AF   LADDR:PORT                                       RADDR:PORT                  TX_KB   RX_KB  RTT_MS  RETR   DUR_MS
4571    HTTP Client      IPv6 [2001:db8:7a31:4c5e:9f02:1d6b:e8a4:3c70]:54606   [2600:1901:0:3084::]:443      0.0     0.0    0.00     0     8.61
5160    curl             IPv6 [2001:db8:7a31:4c5e:9f02:1d6b:e8a4:3c70]:45526   [2a04:4e42::773]:80           0.1     0.6    7.85     0    18.32
5162    curl             IPv6 [2001:db8:7a31:4c5e:9f02:1d6b:e8a4:3c70]:36894   [2a04:4e42:600::773]:80       0.1     0.6    3.56     0    12.77
```

The headline result — **`COMM` reads `curl` and `HTTP Client`, never `swapper`**:
the stash-at-`SYN_SENT` workaround does what ch12 told us we'd need. The
attribution that was wrong in every row of ch12's capture is now right.

Two things in this real data are worth reading closely:

- **The `curl` lines are tiny — `RX_KB` ≈ 0.6, not a whole page.** That is honest:
  `curl http://…` to port 80 gets an **HTTP 301 redirect** to HTTPS, a few
  hundred bytes, and stops. The byte counters report what actually crossed the
  wire, not what we imagined. (`TX_KB` ≈ 0.1 is the request line + headers.)
  `RTT_MS` of 7.85 / 3.56 ms is the kernel's own `srtt_us` — the same order as
  ch12's handshake spans, from an independent source: a clean cross-check.

- **The `HTTP Client` row is all zeros: `0.0/0.0 KB`, `RTT 0.00`, yet `DUR 8.61` ms.**
  A connection that was *born* (so it got a `births` entry at `SYN_SENT`) but
  carried no data and never recorded a round-trip — i.e. it went essentially
  `SYN_SENT → CLOSE` without establishing. `srtt_us == 0` (RTT 0.00) is the
  telltale: the kernel never measured an RTT because the handshake never
  completed. The tool still summarises it, which is the point — **aborted and
  refused connections show up here as zero-byte, zero-RTT obituaries**, something
  no earlier chapter surfaced.

> As in ch12, `dig` (UDP) and `ping` (ICMP) produce no lines — `tcp_set_state` is
> TCP-only — and a connection still open when you `Ctrl-C` is never summarised
> (no `CLOSE` was seen). Output is silent until something *ends*.

## Edge cases accepted for a learning tool

| Scenario | What happens | Production fix |
|----------|-------------|----------------|
| Connection already open when we attach | no `births` entry → no summary | walk `/proc` or the tcp sock table at startup to seed births |
| Passive (server-accepted) connection | identity may be missed (no SYN_SENT in our context) | also hook `inet_csk_accept`'s return to stash the accepting pid |
| `bytes_acked`/`bytes_received` are app-layer counts | exclude headers & retransmits — they measure *useful* throughput, not wire bytes | read `segs_out`/`segs_in` too if you want wire-level counts |
| Extremely short-lived connections at close | LRU could evict birth under churn → one missing summary | size `max_entries` for peak concurrent sockets |

## The wall (→ next)

We now have a full per-connection ledger, but only *after* each connection ends —
a postmortem. We cannot yet see throughput **while it is happening**, rank the
top talkers right now, or watch retransmits climb in real time. That is the
`tcptop` problem: sample the same `tcp_sock` counters periodically (a kprobe on
`tcp_sendmsg`/`tcp_cleanup_rbuf`, or a timer) and diff them per interval. Same
structs, same CO-RE reads — the new ingredient is *sampling over time* rather
than *waiting for an end event*.

➡️ The series then turns from *building tools* to *understanding the platform*:
[Chapter 14](14-verifier.md) meets the verifier head-on.
