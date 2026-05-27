// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * xdpfw.bpf.c — kernel-side, Chapter 21
 *
 * A real (if small) firewall. Where ch17 only COUNTED packets and always
 * returned XDP_PASS, this program takes the action: it returns **XDP_DROP** for
 * packets whose destination port is on a blocklist, so they never reach the
 * stack. This is the first program in the repo that can actually stop traffic —
 * handle with care.
 *
 * The rules are not hard-coded. A `blocklist` map (dest port -> drop count) is
 * filled by user space, so the policy can change at runtime without touching the
 * BPF program. That map-driven design is the seed of production XDP firewalls
 * (e.g. Meta's): user space encodes complex, mutable rules; the datapath just
 * does fast lookups. It combines the packet parsing of ch17 with the map-as-
 * config idea — the same byte-bounds discipline the verifier demands (ch14).
 *
 * Scope: IPv4 TCP/UDP, dest-port match. (IPv6 / source ports / CIDR ranges are
 * natural extensions — see the notes.)
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "xdpfw.h"

/* dest port (host order) -> packets dropped on it. Key present == "block it". */
struct {
    __uint(type,        BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_RULES);
    __type(key,   __u16);
    __type(value, __u64);
} blocklist SEC(".maps");

SEC("xdp")
int xdp_fw(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)              /* bounds check (ch14!) */
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))       /* IPv4 only here */
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)               /* bounds check */
        return XDP_PASS;

    /* L4 starts right after the IP header. We assume no IP options (the common
     * case, 20-byte header) — handling ihl*4 is left as an extension. */
    void *l4 = (void *)(ip + 1);
    __u16 dport;

    if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = l4;
        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;
        dport = bpf_ntohs(udp->dest);
    } else if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = l4;
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;
        dport = bpf_ntohs(tcp->dest);
    } else {
        return XDP_PASS;
    }

    /* Rule lookup: a key in the blocklist means "drop this port". */
    __u64 *dropped = bpf_map_lookup_elem(&blocklist, &dport);
    if (dropped) {
        __sync_fetch_and_add(dropped, 1);          /* tally the hit */
        return XDP_DROP;                           /* the packet dies here */
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
