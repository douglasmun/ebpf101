# Chapter 12 — TCP state machine tracing (`tcpstates`)

**Code:** [`../12-tcpstates/`](../12-tcpstates/)  
**Build:** `cd 12-tcpstates && make`  
**Run:** `sudo ./12-tcpstates/tcpstates`

## Concept

Chapter 11 saw *that* a connection was attempted and *where*. It could not see
whether the handshake actually completed, how long it took, or what happened to
the socket afterwards. This chapter watches the **whole life** of every TCP
socket by hooking the one kernel function every transition passes through:

```c
void tcp_set_state(struct sock *sk, int state);
```

Each call is one edge in the TCP state machine — `CLOSE → SYN_SENT →
ESTABLISHED → FIN_WAIT1 → … → CLOSE`. Hook it once and you see them all.

## Three new skills

Everything in chapters 7–11 was a **tracepoint** reading syscall arguments out
of **user** space. This chapter changes all three of those.

### 1. A kprobe, not a tracepoint

`tcp_set_state` has no stable tracepoint, so we attach to the kernel *function*
by name:

```c
SEC("kprobe/tcp_set_state")
int BPF_KPROBE(handle_set_state, struct sock *sk, int state)
```

`BPF_KPROBE()` (from `<bpf/bpf_tracing.h>`) unpacks the raw `struct pt_regs`
into named, typed parameters, so the probe reads like the function it hooks.
libbpf attaches it automatically from the `SEC("kprobe/…")` name — no manual
`bpf_program__attach_kprobe` call needed.

> A tracepoint is a stable, named contract the kernel promises not to break. A
> kprobe attaches to a raw function symbol — more powerful (any function, no
> tracepoint required) but more fragile (the signature can change between
> kernels). CO-RE softens that fragility for the *fields* we read, below.

### 2. Reading kernel memory with `BPF_CORE_READ`

In ch11 the data lived in user space (`bpf_probe_read_user`). Here `sk` points
into **kernel** memory, and the fields we want are nested inside
`sk->__sk_common` (a `struct sock_common`). The offsets of those fields differ
between kernel versions, so we can't hard-code them:

```c
__u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
__be32 daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
```

`BPF_CORE_READ` walks the access chain and emits a relocation for each step;
libbpf patches in the real offsets at load time against the running kernel's
BTF. This is CO-RE doing its actual job — the same `.bpf.o` would load on a
kernel whose `sock_common` layout differs, with no recompile.

The 4-tuple we pull out of `sock_common`:

| field | meaning | byte order |
|-------|---------|-----------|
| `skc_family` | `AF_INET` / `AF_INET6` | host |
| `skc_rcv_saddr` / `skc_v6_rcv_saddr` | source address | network |
| `skc_daddr` / `skc_v6_daddr` | dest address | network |
| `skc_num` | source port | **host** (already) |
| `skc_dport` | dest port | network |
| `skc_state` | the socket's **current** state | host |

Note the asymmetry: `skc_num` is stored host-order but `skc_dport` is
network-order. We convert only `skc_dport` (with `bpf_ntohs`) and keep addresses
network-order so userspace hands them straight to `inet_ntop` — a cleaner split
than ch11's swap-and-swap-back.

> **Old vs new state.** At the moment our kprobe fires, `tcp_set_state` has *not
> yet* written the new state, so `skc_state` still holds the **old** one. We
> report `oldstate = skc_state` and `newstate = state` (the argument).

### 3. Keying a map by the `struct sock *`

A connection has no pid stable across its whole life (see the comm caveat
below), but `sk` is constant from birth to close. We use it as a map key:

```c
__u64 id = (__u64)(unsigned long)sk;
```

The map stores the timestamp of the last transition. On each new transition we
subtract to get **how long the socket sat in the state it is leaving**. The span
recorded on the step *into* `ESTABLISHED` is therefore the time spent in
`SYN_SENT` — i.e. the **connect() handshake latency**, for free, from the same
single mechanism.

```
timestamps[sk] = t0   on SYN_SENT
          ...
span = t1 - t0        on ESTABLISHED   ← handshake RTT
```

`skaddr` is also emitted to userspace (as hex) so you can group the several
lines of one connection — it is an *identifier*, not a pointer userspace may
dereference.

> **`skaddr` is unique only between birth and close.** Once a socket reaches
> `CLOSE` the kernel frees its `struct sock`, and the slab allocator readily
> hands that same address to the *next* connection. A real run shows it: two
> back-to-back `curl`s reused one pointer —
> ```
> ffff8c329c0e4600  curl  …  CLOSE       -> SYN_SENT     ([…c06::66]:80)   ← curl #1
> ffff8c329c0e4600  …     …  FIN_WAIT2   -> CLOSE
> ffff8c329c0e4600  curl  …  CLOSE       -> SYN_SENT     ([…4e42:200::773]:80)  ← curl #2, same addr
> ```
> Grouping by `skaddr` is safe because each connection's transitions are
> contiguous and bounded by `CLOSE`; just don't treat the value as a *global*
> connection ID across time. (This is also why ch13 deletes its per-`sk` map
> entries at `CLOSE` — so a recycled pointer can't inherit stale state.)

We use `BPF_MAP_TYPE_LRU_HASH`, not a plain hash: a socket we start watching
mid-life never gives us its opening SYN, and a process killed mid-connection
never reaches `CLOSE`, so entries would otherwise leak. LRU evicts the coldest
entries when full — the exact "stale stash" fix flagged in the ch11 edge-case
table, now applied.

## The comm caveat (worth seeing for real)

`bpf_get_current_comm()` / `pid` report whatever task is **on the CPU when the
probe fires**, which is only sometimes the socket's owner:

| transition | context | is `comm` the connection's process? |
|------------|---------|-------------------------------------|
| `CLOSE → SYN_SENT` (client) | process, inside `connect()` | ✅ yes |
| `SYN_SENT → ESTABLISHED` (client) | **softirq**, SYN-ACK arrived | ❌ no — a kworker / swapper / unrelated victim |
| `LISTEN → SYN_RECV` (server) | softirq, incoming SYN | ❌ no |
| process closes its socket | process | ✅ usually |

This is the classic reason tools like `tcplife` stash the owning pid at the
*first* transition and reuse it. We deliberately do **not** paper over it — the
honest lesson is: **group by `skaddr`, trust `comm` only on the process-context
rows.**

## What the output reveals

Real capture on this machine — `curl google.com` then `curl www.cnn.com`. Both
resolved to AAAA records, so every socket is IPv6; the source address (identical
on every row) is this host's own — redacted here to an RFC 3849 documentation
address (`2001:db8::/32`) — and IPv6 endpoints are bracketed `[addr]:port`
(RFC 3986). Group by SKADDR to read one connection top to bottom:

```
SKADDR             PID    COMM       AF   SADDR:PORT                                       DADDR:PORT                    OLDSTATE       NEWSTATE          MS
ffff8c3264459e00   4969   curl       IPv6 [2001:db8:7a31:4c5e:9f02:1d6b:e8a4:3c70]:0       [2404:6800:4003:c0f::71]:80   CLOSE       -> SYN_SENT          -
ffff8c3264459e00   0      swapper/3  IPv6 [2001:db8:7a31:4c5e:9f02:1d6b:e8a4:3c70]:60836   [2404:6800:4003:c0f::71]:80   SYN_SENT    -> ESTABLISHED   5.049
ffff8c3264459e00   4969   curl       IPv6 [2001:db8:7a31:4c5e:9f02:1d6b:e8a4:3c70]:60836   [2404:6800:4003:c0f::71]:80   ESTABLISHED -> FIN_WAIT1     27.762
ffff8c3264459e00   0      swapper/3  IPv6 [2001:db8:7a31:4c5e:9f02:1d6b:e8a4:3c70]:60836   [2404:6800:4003:c0f::71]:80   FIN_WAIT1   -> FIN_WAIT2      3.860
ffff8c3264459e00   0      swapper/3  IPv6 [2001:db8:7a31:4c5e:9f02:1d6b:e8a4:3c70]:60836   [2404:6800:4003:c0f::71]:80   FIN_WAIT2   -> CLOSE          0.056

ffff8c329c0e0000   4971   curl       IPv6 [2001:db8:7a31:4c5e:9f02:1d6b:e8a4:3c70]:0       [2a04:4e42:200::773]:80       CLOSE       -> SYN_SENT          -
ffff8c329c0e0000   0      swapper/3  IPv6 [2001:db8:7a31:4c5e:9f02:1d6b:e8a4:3c70]:38596   [2a04:4e42:200::773]:80       SYN_SENT    -> ESTABLISHED   6.566
ffff8c329c0e0000   4971   curl       IPv6 [2001:db8:7a31:4c5e:9f02:1d6b:e8a4:3c70]:38596   [2a04:4e42:200::773]:80       ESTABLISHED -> FIN_WAIT1      7.187
ffff8c329c0e0000   0      swapper/3  IPv6 [2001:db8:7a31:4c5e:9f02:1d6b:e8a4:3c70]:38596   [2a04:4e42:200::773]:80       FIN_WAIT1   -> CLOSING        0.484
ffff8c329c0e0000   0      swapper/3  IPv6 [2001:db8:7a31:4c5e:9f02:1d6b:e8a4:3c70]:38596   [2a04:4e42:200::773]:80       CLOSING     -> CLOSE          6.708
```

Everything the design predicted shows up, live:

- **The `comm` caveat is real.** `CLOSE → SYN_SENT` is attributed to `curl`
  (process context, inside `connect()`), but **every** later transition reads
  `swapper/3` — the SYN-ACK and the FINs were all handled in softirq on an idle
  CPU. If you grouped by `comm` you would blame the idle task for the
  connection; group by SKADDR instead.
- **Source port `0` then assigned.** The first row shows port `0` — the kernel
  has not bound an ephemeral port yet. By `ESTABLISHED` it is `60836` / `38596`.
- **`MS` blank on the first row** of each socket: no prior timestamp to subtract.
- **Handshake latency falls out for free**: the span landing in `ESTABLISHED` —
  `5.049` ms (google) and `6.566` ms (cnn) — is the time spent in `SYN_SENT`,
  i.e. the round-trip to complete the handshake. `ESTABLISHED → FIN_WAIT1`
  (`27.762` / `7.187` ms) is how long the request/response actually used the
  connection.
- **IPv6 decoded correctly**, confirming the `BPF_CORE_READ_INTO` of the 16-byte
  `skc_v6_*` structs — both peer addresses print as valid AAAA targets.

### The two connections closed *differently* — and the states say why

This wasn't staged; it's just what the two servers did, and it's the clearest
possible demonstration of why the state machine is worth watching:

| | google (`…c0f::71`) | cnn (`2a04:4e42:200::773`) |
|---|---|---|
| teardown | `FIN_WAIT1 → FIN_WAIT2 → CLOSE` | `FIN_WAIT1 → CLOSING → CLOSE` |
| meaning | **normal active close**: we sent FIN, peer ACKed it (→ FIN_WAIT2), then peer sent its FIN | **simultaneous close**: our FIN and the peer's FIN crossed on the wire, so we never passed through FIN_WAIT2 |

`CLOSING` is the rarely-seen state you reach *only* when both ends call close at
effectively the same instant. A connect-only tracer (ch11) could never tell
these two apart — both were just "a connection that happened." The state machine
makes the difference legible.

On a busier machine the same one hook also surfaces `LISTEN → SYN_RECV →
ESTABLISHED` for local servers accepting, `ESTABLISHED → CLOSE_WAIT` when the
peer closes first, and `SYN_SENT → CLOSE` for a connect that was refused or
timed out before it ever established.

> Tie-in to the ch11 run (curl + ping + dig): a TCP `curl` shows here as the full
> `SYN_SENT → ESTABLISHED → … → CLOSE` arc with timings, but the `dig` (UDP) and
> `ping` (ICMP) traffic does **not** appear at all — this hook is TCP-only, by
> definition of `tcp_set_state`. Ch11's connect tracer caught all three; this one
> trades that breadth for depth on TCP.

## Edge cases accepted for a learning tool

| Scenario | What happens | Production fix |
|----------|-------------|----------------|
| `comm`/`pid` off process context | shows the interrupted task, not the owner | stash owner pid at first transition, reuse it (tcplife) |
| First transition we observe for a socket | `MS` is blank (no prior timestamp) | nothing to fix — inherent to attaching mid-stream |
| Very high connection churn | LRU may evict a hot socket's timestamp → one blank span | size `max_entries` to expected concurrent sockets |
| We want bytes/throughput, not just timing | not captured | also read `tcp_sock` counters (`bytes_acked`, `bytes_received`) |

## The wall (→ next)

We now see the full lifecycle and timing of every TCP connection. We still don't
see **how much data** moved or **how fast**: throughput, retransmits, RTT
estimates. Those live in the larger `struct tcp_sock` (a superset of `sock`) —
`bytes_acked`, `bytes_received`, `srtt_us`, `total_retrans`. Reading them at
`CLOSE` is exactly how `tcplife` produces its per-connection byte counts, and
hooking `tcp_rcv_established` / `tcp_retransmit_skb` is how `tcpretrans` and
RTT tools work. Same kprobe + `BPF_CORE_READ` skills, richer structs.

➡️ That is exactly [Chapter 13](13-tcplife.md).
