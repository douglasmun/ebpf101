# Chapter 23 — A rule-based IDS in eBPF (tap in the kernel, decide in user space)

**Code:** [`../23-ids/`](../23-ids/)
**Build:** `cd 23-ids && make`
**Run:** `sudo ./23-ids/ids [interface]`  *(default: `lo`)*
**Verify hands-free:** `sudo bash 23-ids/verify-ids.sh`  *(loads it, trips all 3 rules, stops)*
**Trigger manually:** with the IDS running, `./23-ids/trigger-attacks.sh [all|beacon|scan|susp]` from another terminal (no sudo — loopback traffic)

## Concept

An **intrusion-detection system** watches traffic and raises alerts on
suspicious patterns — it *detects*, it doesn't block (that would be an IPS). This
chapter builds a small one, and its design is the lesson: a clean split between a
**dumb kernel tap** and a **smart user-space rule engine**.

```
  kernel (eBPF socket filter)            user space (the "brain")
  parse each packet, copy a    ──ring──▶  per-flow state + detection rules
  fixed record out; no state    buffer    (beacon / port-scan / suspicious port)
  no decisions, never blocks              prints alerts
```

Why split it this way? Detection rules are where the thinking — and the
*changing* — happens. Keeping them in ordinary user-space C means they are easy
to read, tune, and extend: plain `if`s, floating-point math, `sqrt()`, growable
tables, none of the kernel's constraints. The kernel side stays a tiny, stable
tap. (This is the opposite choice from the ML-in-eBPF paper that inspired the
chapter — see ["The cost we chose"](#the-cost-we-chose) — and that contrast is
the point.)

## New hook: a socket filter (`AF_PACKET` + `SO_ATTACH_BPF`)

Every datapath chapter so far attached to the *stack* (XDP at the NIC, tc at the
qdisc). This one taps a **raw packet socket** instead — the same mechanism
`tcpdump`, Snort, and Suricata use to see traffic. User space opens the socket
and attaches the BPF program to it:

```c
int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
int prog_fd = bpf_program__fd(skel->progs.ids_tap);
setsockopt(sock, SOL_SOCKET, SO_ATTACH_BPF, &prog_fd, sizeof(prog_fd));
bind(sock, ...sockaddr_ll on the chosen ifindex...);   /* restrict to one NIC */
```

Two properties make it the right hook for an IDS:
- **It can see traffic in both directions.** An `AF_PACKET` socket is delivered
  both received (`PACKET_HOST`) and transmitted (`PACKET_OUTGOING`) frames — on a
  real NIC that is ingress *and* egress, which behavioral rules want. On loopback
  it means every frame arrives *twice*, so this chapter drops the outgoing copy
  (see [the gotcha below](#the-loopback-double-delivery-gotcha)); the looped-back
  copy still carries both ends of the conversation, so nothing is lost there.
- **It is a pure observer.** A socket filter's return value only limits how many
  bytes get queued to *that socket*; it never touches the kernel's own packet
  path. We return `0` (queue nothing; we read everything via the ring buffer),
  so the IDS cannot affect connectivity even by mistake.

### Socket filters get *no* direct packet access

A genuine difference from ch17/18/21: XDP and tc programs read packet bytes
straight through `skb->data` / `data_end`, but the verifier's
`may_access_direct_pkt_data()` **excludes `SOCKET_FILTER`**. So this program
copies the bytes it needs out of the skb with `bpf_skb_load_bytes()`:

```c
struct ethhdr eth; struct iphdr ip; struct { __be16 source, dest; } l4;
bpf_skb_load_bytes(skb, 0, &eth, sizeof(eth));                       /* L2 */
bpf_skb_load_bytes(skb, sizeof(eth), &ip, sizeof(ip));              /* L3 (no opts) */
bpf_skb_load_bytes(skb, sizeof(eth) + sizeof(ip), &l4, sizeof(l4)); /* L4 ports */
```

(One read covers both TCP and UDP because each begins with `source`,`dest`.) The
record — timestamp, 5-tuple, length — is then `bpf_ringbuf_reserve`d and shipped
to user space, all addresses left in network byte order.

## The three rules (all in user space)

The kernel never sees these — they are plain C over the flow records.

1. **Beaconing — the classic C2 tell.** Malware "calls home" on a timer.
   Per `(src → dst:port)` we keep the last few inter-arrival gaps; once we have
   enough, we flag the flow if the timing is *regular* — coefficient of variation
   (stddev/mean) below 10% — and the interval is plausible (1–300 s). We key on
   the **destination** port, not the source, because each callback uses a fresh
   ephemeral source port; grouping by `dst:port` is what makes the rhythm visible.
   (This is how detectors like RITA work.)
2. **Port scan / fan-out.** One source touching many destination ports in a
   short window. Per source IP we track distinct dst ports seen in a 5-second
   sliding window; over ~20 → alert.
3. **Suspicious port (signature).** A built-in list of ports tied to C2 /
   backdoors — 4444 (Metasploit), 31337 (Back Orifice), 6667 (IRC bots), 50050
   (Cobalt Strike), … — alert on any flow to one. A signature rule beside the two
   behavioral ones: real IDSs blend both.

## What the output reveals

Real run on this machine — `sudo bash 23-ids/verify-ids.sh` trips all three
rules on loopback in ~20 s:

```
IDS watching 'lo' — rules: beacon, port-scan, suspicious-port. Ctrl-C to stop.
[02:28:01] ALERT susp-port 127.0.0.1 -> 127.0.0.1:4444  (Metasploit/Meterpreter default)
[02:28:01] ALERT portscan  127.0.0.1 scanned 21 distinct ports within 5s
[02:28:17] ALERT beacon    127.0.0.1 -> 127.0.0.1:9999  interval~3.0s jitter 0.0% (6 callbacks)
```

Reading the lines:
- **susp-port** fired on the very first 4444 datagram — a pure signature match.
- **portscan** says `21` because the rule alerts the *instant* the distinct-port
  count crosses its threshold of 20 (then it suppresses repeats); the scan
  actually touched 81 ports. The alert is about crossing the line, not the total.
- **beacon** fired after the 6th callback (5 gaps = the minimum samples), and
  `jitter 0.0%` is the coefficient of variation: the callbacks were spaced a near
  perfect 3.0 s apart, which is exactly what makes automated traffic stand out
  from human/bursty traffic.

### The loopback double-delivery gotcha

Getting the beacon to read `0.0%` took one fix worth calling out. An `AF_PACKET`
socket sees every frame **twice on `lo`** — once as it is sent
(`PACKET_OUTGOING`) and once as it loops back in (`PACKET_HOST`). That doubled
every count and turned the beacon's clean 3 s spacing into an alternating
`0 s, 3 s, 0 s, …` (mean 1.5 s, jitter ~100%), so it never qualified. The loader
sets **`PACKET_IGNORE_OUTGOING`** to drop the outgoing copies, so each datagram
is counted once. (A second subtlety: on `lo` both endpoints are `127.0.0.1`, so
the per-source view conflates both directions of a conversation — on a real NIC
the source IP is distinct. It does not change whether the rules fire; it is why
the demo lives on `lo` as a convenience.)

## The cost we chose

This IDS ships **one ring-buffer record per packet** to user space. On a quiet
loopback demo that's nothing; on a busy NIC it is real overhead — and it is
*exactly* the cost the paper this chapter riffs on
([Bachl, Fabini, Zseby, *A flow-based IDS using Machine Learning in eBPF*,
arXiv:2102.09980](https://arxiv.org/abs/2102.09980)) sets out to remove. Their
move is the mirror image of ours: push the per-flow logic **into the kernel** (a
decision tree, evaluated in BPF) so packets never have to cross to user space —
at the price of fixed-point integer math, since eBPF has no floating point. We
deliberately took the readable, user-space side of that trade so the *rules* are
the star. Worth knowing both directions exist.

## The wall (→ extensions)

- **In-kernel aggregation** — keep a per-flow hash map in BPF and emit a summary
  (or only first packets), cutting the per-packet event cost. The map-driven step
  toward the paper's design.
- **More rules** — data exfiltration (egress≫ingress byte ratio), DNS tunneling
  (many large port-53 records), long-lived low-and-slow flows, never-before-seen
  destinations.
- **IPv6 + IP options** — parse `ipv6hdr`/`nexthdr` and use `ip->ihl*4` for the
  L4 offset (this chapter assumes IPv4, 20-byte header).
- **Flow eviction** — the user-space tables here never evict; a real tool ages
  flows out (LRU), as the kernel-side ring/LRU maps in earlier chapters do.

⬅️ [Chapter 22](22-iterator.md) was the last of the core mechanisms; this is an
applied chapter built on top of them (like the ch21 firewall).
