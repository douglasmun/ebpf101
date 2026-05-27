// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * tcplife.bpf.c — kernel-side, Chapter 13
 *
 * Hook: tcp_set_state(struct sock *sk, int state)   — the same kprobe as ch12.
 *
 * Where ch12 printed every transition, this chapter waits for the *end* of a
 * connection and prints one summary line: who opened it, where to, how long it
 * lived, how many bytes flowed each way, the smoothed RTT, and the retransmit
 * count.  This is the design of the well-known `tcplife` tool.
 *
 * TWO new ideas build directly on ch12:
 *
 *   1. Reading the bigger struct.  `sk` is really the front of a larger
 *      `struct tcp_sock` (tcp_sock embeds inet_connection_sock embeds inet_sock
 *      embeds sock — sock is at offset 0).  So we can cast and, with CO-RE, read
 *      the RFC4898 byte counters and RTT that live deep in tcp_sock:
 *          bytes_acked     — bytes we sent that the peer ACKed (delivered tx)
 *          bytes_received  — bytes received from the peer (rx)
 *          srtt_us         — smoothed RTT, stored << 3 (so >> 3 for microseconds)
 *          total_retrans   — segments retransmitted over the connection's life
 *      Same BPF_CORE_READ skill as ch12, just a richer struct.
 *
 *   2. Fixing ch12's `comm` problem.  In ch12 the move to ESTABLISHED ran in
 *      softirq, so `comm` was `swapper`, not the owning process.  Here we stash
 *      pid+comm at TCP_SYN_SENT — which for an active connect runs in the
 *      connecting process's own context — and reuse that stashed identity when
 *      the connection finally closes.  The summary is correctly attributed.
 *
 * Lifecycle bookkeeping, all keyed by the stable sock pointer:
 *      births[sk]  = ktime at the first opening transition  (BPF_NOEXIST: first wins)
 *      idents[sk]  = {pid, comm} captured in process context
 *      on TCP_CLOSE: look both up, read tcp_sock, emit summary, delete entries.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "tcplife.h"

struct ident {
    __u32 pid;
    char  comm[TASK_COMM_LEN];
};

/* sock pointer → birth timestamp (first opening transition we saw). */
struct {
    __uint(type,        BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key,   __u64);
    __type(value, __u64);
} births SEC(".maps");

/* sock pointer → owning pid/comm, captured in process context. */
struct {
    __uint(type,        BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key,   __u64);
    __type(value, struct ident);
} idents SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

SEC("kprobe/tcp_set_state")
int BPF_KPROBE(handle_set_state, struct sock *sk, int state)
{
    __u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    if (family != AF_INET && family != AF_INET6)
        return 0;

    __u64 id  = (__u64)(unsigned long)sk;
    __u64 now = bpf_ktime_get_ns();

    /*
     * Opening states (ESTABLISHED=1, SYN_SENT=2, SYN_RECV=3 are all < FIN_WAIT1).
     * Stamp the birth once — BPF_NOEXIST means the earliest transition wins, so
     * the lifetime we report spans the whole connection, handshake included.
     */
    if (state < TCP_FIN_WAIT1)
        bpf_map_update_elem(&births, &id, &now, BPF_NOEXIST);

    /*
     * Capture identity where we are in the owning process's context:
     *   TCP_SYN_SENT  — active connect(), runs in the caller.
     *   TCP_LAST_ACK  — a passive-close step that is usually process context too.
     * (ESTABLISHED is NOT in this list precisely because it runs in softirq —
     *  that is the ch12 trap we are working around.)
     */
    if (state == TCP_SYN_SENT || state == TCP_LAST_ACK) {
        struct ident who = {};
        who.pid = bpf_get_current_pid_tgid() >> 32;
        bpf_get_current_comm(&who.comm, sizeof(who.comm));
        bpf_map_update_elem(&idents, &id, &who, BPF_ANY);
    }

    /* Everything below is only for the end of the connection. */
    if (state != TCP_CLOSE)
        return 0;

    __u64 *birth = bpf_map_lookup_elem(&births, &id);
    if (!birth)
        return 0;   /* connection was already open before we attached — skip */

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        goto cleanup;

    e->skaddr  = id;
    e->span_us = (now - *birth) / 1000;
    e->family  = family;

    /* The 4-tuple, exactly as in ch12. */
    e->sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    e->dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
    if (family == AF_INET) {
        __be32 saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
        __be32 daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
        __builtin_memcpy(e->saddr, &saddr, sizeof(saddr));
        __builtin_memcpy(e->daddr, &daddr, sizeof(daddr));
    } else {
        BPF_CORE_READ_INTO(&e->saddr, sk, __sk_common.skc_v6_rcv_saddr);
        BPF_CORE_READ_INTO(&e->daddr, sk, __sk_common.skc_v6_daddr);
    }

    /*
     * sk is the front of a struct tcp_sock — cast and read the deep counters.
     * CO-RE relocates each field offset against the running kernel's BTF.
     */
    struct tcp_sock *tp = (struct tcp_sock *)sk;
    e->tx_b          = BPF_CORE_READ(tp, bytes_acked);
    e->rx_b          = BPF_CORE_READ(tp, bytes_received);
    e->total_retrans = BPF_CORE_READ(tp, total_retrans);
    e->srtt_us       = BPF_CORE_READ(tp, srtt_us) >> 3;  /* stored << 3 */

    /* Reuse the identity stashed in process context; fall back to current. */
    struct ident *who = bpf_map_lookup_elem(&idents, &id);
    if (who) {
        e->pid = who->pid;
        __builtin_memcpy(e->comm, who->comm, sizeof(e->comm));
    } else {
        e->pid = bpf_get_current_pid_tgid() >> 32;
        bpf_get_current_comm(&e->comm, sizeof(e->comm));
    }

    bpf_ringbuf_submit(e, 0);

cleanup:
    bpf_map_delete_elem(&births, &id);
    bpf_map_delete_elem(&idents, &id);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
