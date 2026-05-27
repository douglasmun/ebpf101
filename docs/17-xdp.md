# Chapter 17 — XDP (packet processing in the datapath)

**Code:** [`../17-xdp/`](../17-xdp/)
**Build:** `cd 17-xdp && make`
**Run:** `sudo ./17-xdp/xdpcount <interface>` (e.g. your active NIC)

## Concept

Everything until now *observed* events. **XDP** (eXpress Data Path) is the first
program that runs in the **datapath**: it executes in the NIC driver on the raw
received frame — before the kernel allocates an `sk_buff`, the earliest hook
there is — and returns an **action** that decides the packet's fate:

| Action | Meaning |
|--------|---------|
| `XDP_PASS` | hand the packet up the normal network stack |
| `XDP_DROP` | discard it now (the basis of line-rate DDoS filtering) |
| `XDP_TX` | bounce it back out the same NIC |
| `XDP_REDIRECT` | send it to another NIC/CPU/socket (load balancing, AF_XDP) |

That return value is the leap from *seeing* to *acting*. To keep this chapter
completely safe, `xdpcount` **always returns `XDP_PASS`** — it classifies each
packet by protocol and counts it, and can never disturb traffic.

> **XDP is ingress-only.** It runs on *received* packets, not transmitted ones.
> So the counts are inbound traffic; outbound shaping is `tc/BPF`'s job (a later
> topic).

## Building blocks

### The XDP context and direct packet access

An XDP program gets a `struct xdp_md` with two pointers bracketing the packet:

```c
void *data     = (void *)(long)ctx->data;
void *data_end = (void *)(long)ctx->data_end;
```

You read packet bytes **directly** (fast — no helper call), but the verifier
forces you to prove every read is in bounds *first*. This is exactly the ch14
lesson, now as daily practice:

```c
struct ethhdr *eth = data;
if ((void *)(eth + 1) > data_end)   /* prove the 14-byte eth header is present */
    goto done;                       /* … or the verifier rejects: "invalid access to packet" */
__u16 h_proto = bpf_ntohs(eth->h_proto);
```

Each deeper header repeats the dance — check `(void *)(ip + 1) > data_end`
before touching the IP header. Forget one and the program won't load.

### Per-CPU maps

The counter map is a `BPF_MAP_TYPE_PERCPU_ARRAY`: **every CPU has its own copy**
of each slot. On a multi-queue NIC several CPUs run XDP at once, so a shared map
would need atomics; a per-CPU map lets each CPU do a plain `*c += 1` on its own
slot with no contention. User space reads back one value *per CPU* and sums them:

```c
int ncpu = libbpf_num_possible_cpus();
__u64 vals[ncpu];
bpf_map_lookup_elem(map_fd, &cat, vals);   /* fills ncpu entries */
for (i = 0; i < ncpu; i++) sum += vals[i];
```

### Attaching to an interface (generic vs native mode)

XDP attaches to a **network interface** (by ifindex), not a function:

```c
bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_SKB_MODE, NULL);
```

- **Native (driver) XDP** runs inside the driver's receive routine — fastest, but
  needs driver support.
- **Generic/SKB mode** (`XDP_FLAGS_SKB_MODE`) runs a little later, in the stack,
  and works on *any* interface (virtual NICs, wifi, …). We use generic mode for
  portability; production drop/redirect setups use native.

> **Loopback has no Ethernet header.** On `lo`, generic XDP hands you the packet
> starting at the IP header, so the eth parse misfires and everything lands in
> "other". Use a real NIC to see the protocol breakdown — itself a reminder that
> XDP works at L2 and assumes a link-layer header.

## What the output reveals

The classifier parses **both** families down to L4 (IPv4 via `ip->protocol`,
IPv6 via `ip6->nexthdr`), so `TCP`/`UDP`/`ICMP` aggregate IPv4 **and** IPv6
(ICMP includes ICMPv6); the `*-other` buckets catch protocols we don't name.

Real capture on this machine, wifi (`wlp3s0`), a short idle window:

```
PROTO               PACKETS
other                     0
TCP                       0
UDP                      97
ICMP                      5
IPv4-other                2
IPv6-other               14
ARP                       4
```

This is a more honest — and more *current* — picture than "TCP dominates":

- **UDP dominates (97), TCP is 0.** Ambient traffic in the QUIC era is mostly
  UDP: **HTTP/3 / QUIC** (UDP 443), DNS, mDNS, NTP. Plain TCP only appears when
  something opens a TCP connection; an idle desktop barely does.
- **`ICMP: 5` is essentially ICMPv6 Neighbor Discovery**, and that's also why
  **`ARP: 4` is tiny** — IPv6 replaces ARP with ND (over ICMPv6), so an
  IPv6-first network does almost no ARP.
- **`IPv6-other: 14`** is IPv6 packets whose `nexthdr` is an **extension header**
  (hop-by-hop for multicast/RA, etc.) rather than L4 directly — we stop at the
  first next-header and don't walk the chain (the remaining exercise).

Now make a TCP connection — `curl https://github.com` in another terminal — and
re-capture:

```
PROTO               PACKETS
other                     0
TCP                     525
UDP                     361
ICMP                     22
IPv4-other                4
IPv6-other               61
ARP                      41
```

**`TCP` jumps from 0 to 525** — the response and ACK packets of that connection.
On this IPv6-first host that TCP arrives over IPv6, so it is the new
`ip6->nexthdr` switch (not the IPv4 path) that catches it: direct proof the
IPv6 L4 parse works. Everything else climbs too as the browser stays busy.

> **Before/after of the IPv6 parse.** An earlier version stopped at the ethertype
> and dumped *all* IPv6 into one bucket; on this host that single bucket swallowed
> everything and the L4 columns read zero. Parsing `nexthdr` split it apart — the
> idle mix turned out to be UDP + ICMPv6 (not TCP), and a deliberate `curl` lights
> the `TCP` row up over IPv6. Sometimes the finer measurement changes the
> conclusion.

Totals grow each second, and traffic flows the whole time because every verdict
is `XDP_PASS`.

## The wall (→ next)

We reached the datapath but deliberately only *counted*. The same hook, with a
different return, **acts**: `return XDP_DROP` for a matching source IP is a
DDoS filter; `XDP_REDIRECT` is the heart of XDP load balancers and AF_XDP
userspace networking. From here the advanced track continues with **tc/BPF**
(egress + full `sk_buff` access), **tail calls** (chaining programs to scale
past the 1-million-instruction limit), and **LSM BPF** (kernel security-policy
decisions) — the move from observing the system to governing it.
