// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * tcstat.bpf.c — kernel-side, Chapter 18
 *
 * tc/BPF (BPF_PROG_TYPE_SCHED_CLS) is the *other* datapath hook. Two things make
 * it the natural sequel to XDP (ch17):
 *
 *   1. EGRESS. XDP is receive-only; tc attaches on both ingress AND egress, so
 *      for the first time we can count packets the machine *sends*.
 *   2. struct __sk_buff. By the time tc runs, the kernel has built an sk_buff,
 *      so we get a rich, stable context — including skb->len, the packet length,
 *      which makes byte/throughput accounting trivial (no header parsing).
 *
 * As in ch17 we stay a pure observer: every program returns TC_ACT_OK, so it
 * only counts and never drops, mangles, or reorders a packet.
 *
 * We attach two programs — one at ingress, one at egress — each tallying into
 * its own slot of a per-CPU array. (Same program at both hooks couldn't easily
 * tell the direction apart; two tiny programs keep it obvious.)
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "tcstat.h"

struct {
    __uint(type,        BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, DIR_MAX);
    __type(key,   __u32);
    __type(value, struct datarec);
} stats SEC(".maps");

static __always_inline int account(struct __sk_buff *skb, __u32 dir)
{
    struct datarec *rec = bpf_map_lookup_elem(&stats, &dir);
    if (rec) {
        rec->packets += 1;
        rec->bytes   += skb->len;   /* full L2 frame length, per-CPU slot */
    }
    return TC_ACT_OK;               /* let it through, always */
}

SEC("tc")
int tc_ingress(struct __sk_buff *skb)
{
    return account(skb, DIR_INGRESS);
}

SEC("tc")
int tc_egress(struct __sk_buff *skb)
{
    return account(skb, DIR_EGRESS);
}

char LICENSE[] SEC("license") = "GPL";
