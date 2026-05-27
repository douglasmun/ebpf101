// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * ids.bpf.c — kernel-side, Chapter 23
 *
 * The kernel half of an intrusion-detection system — and it is deliberately
 * DUMB. It is a packet **tap**: parse each frame down to the L4 ports, copy a
 * small fixed record into a ring buffer, and return. It keeps no state, makes no
 * decisions, and never blocks a packet. All the intelligence — the C2 / anomaly
 * detection rules — lives in user space (see ids.c), where it is easy to read
 * and change. This split is the chapter's whole idea.
 *
 * Attach type: a **socket filter** (BPF_PROG_TYPE_SOCKET_FILTER, SEC("socket")).
 * User space opens a raw AF_PACKET socket on an interface and attaches this
 * program with SO_ATTACH_BPF — the classic "tap the wire" model that tools like
 * tcpdump/Snort/Suricata use, and the one attach type the repo hadn't shown yet.
 * The return value of a socket filter only limits how many bytes get queued to
 * *our* socket; it never affects the kernel's own packet path. We return 0
 * (queue nothing — we read everything via the ring buffer instead), which makes
 * this a pure observer: exactly the right semantics for detection, not blocking.
 *
 * NOTE — no direct packet access here. Unlike XDP and tc (ch17/18/21), socket
 * filters are NOT allowed to read packet bytes through skb->data/data_end (the
 * verifier's may_access_direct_pkt_data() excludes this program type). So we
 * copy the bytes we need out of the skb with bpf_skb_load_bytes() instead — a
 * real difference between the datapath hooks and a socket filter.
 *
 * On an AF_PACKET socket the frame starts at the Ethernet header (like a cBPF
 * tcpdump filter), so offsets are measured from there.
 *
 * Scope: IPv4 TCP/UDP. (IPv6 and IP options are noted as extensions.)
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "ids.h"

/* One ring buffer carrying a flow_pkt per observed packet to user space. */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

SEC("socket")
int ids_tap(struct __sk_buff *skb)
{
    struct ethhdr eth;
    struct iphdr  ip;
    struct { __be16 source; __be16 dest; } l4;   /* first 4 bytes of TCP or UDP */

    /* Ethernet: we only care it's IPv4. */
    if (bpf_skb_load_bytes(skb, 0, &eth, sizeof(eth)) < 0)
        return 0;
    if (eth.h_proto != bpf_htons(ETH_P_IP))
        return 0;

    /* IPv4 header (assume 20 bytes, i.e. no options — the common case). */
    if (bpf_skb_load_bytes(skb, sizeof(eth), &ip, sizeof(ip)) < 0)
        return 0;
    if (ip.protocol != IPPROTO_TCP && ip.protocol != IPPROTO_UDP)
        return 0;

    /* L4 source/dest ports sit at the same offsets (0 and 2) in both the TCP and
     * the UDP header, so one 4-byte read covers both. */
    if (bpf_skb_load_bytes(skb, sizeof(eth) + sizeof(ip), &l4, sizeof(l4)) < 0)
        return 0;

    struct flow_pkt *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;                                 /* ring full → drop the record */

    e->ts_ns = bpf_ktime_get_ns();
    e->saddr = ip.saddr;                          /* all left in network order */
    e->daddr = ip.daddr;
    e->sport = l4.source;
    e->dport = l4.dest;
    e->len   = skb->len;
    e->proto = ip.protocol;
    bpf_ringbuf_submit(e, 0);

    return 0;   /* observer: queue nothing to the socket; the stack is untouched */
}

char LICENSE[] SEC("license") = "GPL";
