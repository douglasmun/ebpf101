# Chapter 21 — An XDP firewall (the drop, and rules from user space)

**Code:** [`../21-firewall/`](../21-firewall/)
**Build:** `cd 21-firewall && make`
**Run:** `sudo ./21-firewall/xdpfw [interface] [port ...]`  *(defaults: `lo 11111`)*

> ⚠️ **This is the first program in the repo that can stop traffic.** It returns
> `XDP_DROP`. The defaults (`lo`, port `11111`) are harmless. Blocking a real
> port (e.g. 443) on a real NIC (e.g. `wlp3s0`) **will cut that traffic** until
> you `Ctrl-C`. Be deliberate about the interface and ports you pass.

## Concept

Chapter 17 watched packets and always `XDP_PASS`ed them. This chapter takes the
**action**: parse each packet, and for a blocked destination port return
**`XDP_DROP`** — the packet is discarded in the driver, before the stack ever
sees it. That is a firewall.

The interesting design choice is *where the rules live*. They are **not**
hard-coded in the BPF program. A `blocklist` map (port → drop count) is filled
by **user space**, so policy changes at runtime with no recompile:

```
user space  ──writes ports──▶  blocklist map  ◀──looks up dest port──  XDP program
(the policy)                   (the rules)                              (the datapath)
```

This is the kernel of how production XDP firewalls work (Meta runs one): user
space encodes arbitrarily complex, mutable rules; the datapath stays a dumb,
fast lookup. It fuses three things you've already met — packet parsing with
verifier bounds checks (ch14, ch17), maps as shared state (ch2, ch16), and an
action return value (ch20's verdict, now applied to packets).

## Building blocks

### Parse to the destination port (with bounds checks)

```c
struct ethhdr *eth = data;
if ((void *)(eth + 1) > data_end) return XDP_PASS;     /* every header: bounds-check first */
if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;

struct iphdr *ip = (void *)(eth + 1);
if ((void *)(ip + 1) > data_end) return XDP_PASS;

void *l4 = (void *)(ip + 1);                           /* assumes no IP options */
if (ip->protocol == IPPROTO_UDP) { struct udphdr *u = l4; if ((void*)(u+1) > data_end) return XDP_PASS; dport = bpf_ntohs(u->dest); }
else if (ip->protocol == IPPROTO_TCP) { struct tcphdr *t = l4; if ((void*)(t+1) > data_end) return XDP_PASS; dport = bpf_ntohs(t->dest); }
else return XDP_PASS;
```

### The rule is a map lookup

```c
__u64 *dropped = bpf_map_lookup_elem(&blocklist, &dport);
if (dropped) {                       /* key present == this port is blocked */
    __sync_fetch_and_add(dropped, 1);/* the value doubles as a per-port hit counter */
    return XDP_DROP;
}
return XDP_PASS;
```

The map's *value* is the drop count, so the same lookup both decides the verdict
and records the hit — user space just reads the value to see how many packets
each rule caught.

### Loopback really does have an Ethernet header

We default to `lo` so you can test the drop locally. That works because **the
loopback interface presents a full 14-byte Ethernet header** for XDP (all-zero
MACs and a real ethertype): `lo` reports `addr_len 6` and
`hard_header_len = ETH_HLEN`. So the exact `eth → IP → L4` parse above works on
`lo`, and a packet to `127.0.0.1:11111` arrives at XDP framed like any other —
**confirmed by the live run below**, which dropped real datagrams on `lo`. (This
corrects ch17's earlier claim that `lo` had no Ethernet header.)

## Test it (safe — loopback only)

```
# terminal 1
sudo ./xdpfw                       # blocks TCP/UDP 11111 on lo

# terminal 2 — send a UDP datagram to the blocked port
echo hi | nc -u -w1 127.0.0.1 11111
#   …or: python3 -c "import socket; socket.socket(2,2).sendto(b'hi',('127.0.0.1',11111))"
```

## What the output reveals

Real run on this machine: `sudo ./xdpfw` (defaults `lo`/`11111`), then a few
datagrams sent to `127.0.0.1:11111` from another terminal:

```
Firewall active on 'lo' — DROPPING TCP/UDP dest port(s): 11111
(Ctrl-C detaches and restores normal traffic.)
...
PORT          DROPPED
11111               6

Detaching XDP from lo (traffic restored)...
```

`DROPPED` rose to **6** — every datagram aimed at the blocked port died in XDP,
on the driver-level receive path, before the stack or any socket saw it. The
count climbs *only* for the blocked port; all other traffic hits
`return XDP_PASS` and flows untouched. (It also proves `lo` is parsed as a normal
Ethernet frame — a zero-`DROPPED` count would have meant the parse missed.)
Change the rule live by passing different ports: `sudo ./xdpfw lo 9999 8080`.

## The wall (→ extensions)

A few natural steps from here, each a small change:
- **More match fields** — source port, source/dest IP, or whole subnets via a
  `BPF_MAP_TYPE_LPM_TRIE` (longest-prefix-match) map for CIDR rules.
- **IPv6** — parse `ipv6hdr` and its `nexthdr` (as ch17 does) so v6 traffic is
  filtered too; on this IPv6-first host that matters.
- **IP options** — use `ip->ihl * 4` for the L4 offset instead of assuming 20.
- **Beyond drop** — `XDP_TX` to bounce a packet back, or `XDP_REDIRECT` to steer
  it to another NIC/CPU/socket: the building block of XDP load balancers and
  AF_XDP. Same hook, richer verdict.

➡️ [Chapter 22](22-iterator.md) turns to the last model we haven't seen — BPF
iterators, which you *pull* by reading.
