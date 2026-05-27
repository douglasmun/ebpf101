// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * xdpcount.bpf.c — kernel-side, Chapter 17
 *
 * The first program that runs in the *datapath*. Every chapter before this only
 * observed events; an XDP program runs at the earliest possible point — in the
 * NIC driver, on the raw received frame, before the kernel builds an sk_buff —
 * and returns an ACTION deciding the packet's fate (XDP_PASS, XDP_DROP, XDP_TX,
 * XDP_REDIRECT).
 *
 * To stay completely safe we ALWAYS return XDP_PASS: this is a pure observer
 * that classifies each packet by protocol and counts it. It can never drop or
 * disturb traffic.
 *
 * The new discipline is DIRECT PACKET ACCESS with bounds checks. ctx->data and
 * ctx->data_end bracket the bytes we may touch; before reading any header we
 * must prove to the verifier that the whole header lies within that window —
 * `if ((void *)(hdr + 1) > data_end) bail;`. Skip a check and you get exactly
 * the ch14 rejection: "invalid access to packet". This is where the verifier
 * lessons become daily practice.
 *
 * struct ethhdr / struct iphdr and the IPPROTO_ and XDP_ enums all come from
 * vmlinux.h; only the ETH_P_ ethertypes are macros we define ourselves.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "xdpcount.h"

/*
 * PERCPU_ARRAY: each CPU gets its own copy of every slot, so the hot path needs
 * no atomics or locks — a CPU only ever touches its own counter. User space
 * sums the per-CPU values when it reads. Ideal for a high-rate packet counter.
 */
struct {
    __uint(type,        BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, CAT_MAX);
    __type(key,   __u32);
    __type(value, __u64);
} counts SEC(".maps");

SEC("xdp")
int xdp_count(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u32 cat = CAT_OTHER;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)          /* bounds check before reading eth */
        goto done;

    __u16 h_proto = bpf_ntohs(eth->h_proto);
    if (h_proto == ETH_P_ARP) {
        cat = CAT_ARP;
    } else if (h_proto == ETH_P_IP) {
        struct iphdr *ip = (void *)(eth + 1);
        if ((void *)(ip + 1) > data_end)       /* bounds check before reading ip */
            goto done;
        switch (ip->protocol) {
        case IPPROTO_TCP:  cat = CAT_TCP;        break;
        case IPPROTO_UDP:  cat = CAT_UDP;        break;
        case IPPROTO_ICMP: cat = CAT_ICMP;       break;
        default:           cat = CAT_IPV4_OTHER; break;
        }
    } else if (h_proto == ETH_P_IPV6) {
        struct ipv6hdr *ip6 = (void *)(eth + 1);
        if ((void *)(ip6 + 1) > data_end) {    /* bounds check before reading ip6 */
            cat = CAT_IPV6_OTHER;
            goto done;
        }
        /*
         * nexthdr is the L4 protocol — UNLESS extension headers intervene, in
         * which case it's the first ext-header type and we fall through to
         * IPv6-other. Walking the ext-header chain is left as the exercise.
         */
        switch (ip6->nexthdr) {
        case IPPROTO_TCP:    cat = CAT_TCP;        break;
        case IPPROTO_UDP:    cat = CAT_UDP;        break;
        case IPPROTO_ICMPV6: cat = CAT_ICMP;       break;
        default:             cat = CAT_IPV6_OTHER; break;
        }
    }

done: {
        __u64 *c = bpf_map_lookup_elem(&counts, &cat);
        if (c)
            *c += 1;     /* per-CPU slot: this CPU owns it, so plain += is safe */
    }
    return XDP_PASS;     /* never drop — observe and let the packet through */
}

char LICENSE[] SEC("license") = "GPL";
