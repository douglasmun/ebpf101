// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * tcpstates.bpf.c — kernel-side, Chapter 12
 *
 * Hook: tcp_set_state(struct sock *sk, int state)
 *
 * Every TCP connection moves through a state machine — CLOSE → SYN_SENT →
 * ESTABLISHED → … → CLOSE — and the kernel funnels *every* transition through
 * one function, tcp_set_state().  Hook that one function and you see the whole
 * lifecycle of every TCP socket on the box.
 *
 * THREE things are new here versus the tracepoint chapters (7–11):
 *
 *   1. A kprobe, not a tracepoint.  tcp_set_state has no stable tracepoint, so
 *      we attach to the kernel *function* by name.  The BPF_KPROBE() macro (from
 *      bpf_tracing.h) unpacks the pt_regs into named, typed arguments for us —
 *      so `sk` and `state` read like a normal C function signature.
 *
 *   2. Reading kernel memory with CO-RE.  In ch11 the sockaddr lived in *user*
 *      space (bpf_probe_read_user).  Here `sk` points into *kernel* memory, and
 *      the fields we want are buried in nested structs whose offsets differ
 *      between kernels.  BPF_CORE_READ() walks the chain and lets libbpf relocate
 *      each offset at load time against the running kernel's BTF — the essence
 *      of "compile once, run everywhere".
 *
 *   3. Keying a map by the sock pointer.  A connection has no pid that is stable
 *      across its life (see the comm caveat below), but the `struct sock *` is
 *      constant from birth to close.  We use it as the key for a timestamp map,
 *      which lets us measure how long the socket sat in each state.
 *
 * The 4-tuple lives in sk->__sk_common (a struct sock_common):
 *   skc_family            AF_INET / AF_INET6
 *   skc_rcv_saddr         source IPv4 (network order)   skc_v6_rcv_saddr for v6
 *   skc_daddr             dest   IPv4 (network order)   skc_v6_daddr     for v6
 *   skc_num               source port (HOST order already)
 *   skc_dport             dest   port (network order)
 *   skc_state             the CURRENT state — i.e. the OLD state, because
 *                         tcp_set_state has not written the new one yet
 *
 * comm caveat (a classic, and worth seeing for real):
 *   bpf_get_current_comm() returns whatever task is on the CPU *right now*.
 *   That is the connecting process for transitions it drives itself in process
 *   context — the client's SYN_SENT (inside connect()), a process closing its
 *   socket.  But the client's move to ESTABLISHED happens when the SYN-ACK
 *   arrives, handled in softirq context: comm is then a kworker, swapper, or
 *   some unrelated victim of the interrupt.  Group by skaddr, not by comm.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "tcpstates.h"

/*
 * sock pointer → ktime (ns) of the last transition we recorded for it.
 *
 * LRU_HASH, not plain HASH: a socket we start watching mid-life never gives us
 * its opening SYN, and a process killed mid-connection never reaches CLOSE, so
 * some entries would otherwise leak forever.  LRU silently evicts the coldest
 * entries when full — exactly the "stale stash" fix flagged in the ch11 notes.
 */
struct {
    __uint(type,        BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key,   __u64);   /* (struct sock *) as an integer */
    __type(value, __u64);   /* bpf_ktime_get_ns() at last transition */
} timestamps SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

SEC("kprobe/tcp_set_state")
int BPF_KPROBE(handle_set_state, struct sock *sk, int state)
{
    /* Filter on family first — cheap, and skips non-IP sockets entirely. */
    __u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    if (family != AF_INET && family != AF_INET6)
        return 0;

    __u64 id  = (__u64)(unsigned long)sk;
    __u64 now = bpf_ktime_get_ns();

    /*
     * How long did the socket spend in the state it is leaving?  That is now
     * minus the timestamp of the transition that put it there.  For a SYN_SENT
     * → ESTABLISHED step this span IS the connect() handshake latency.
     */
    __u64 *prev = bpf_map_lookup_elem(&timestamps, &id);
    __u64  span_us = 0;
    __u8   has_span = 0;
    if (prev) {
        span_us  = (now - *prev) / 1000;
        has_span = 1;
    }

    /* CLOSE is the end of the line — drop the timestamp instead of stamping. */
    if (state == TCP_CLOSE)
        bpf_map_delete_elem(&timestamps, &id);
    else
        bpf_map_update_elem(&timestamps, &id, &now, BPF_ANY);

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->skaddr   = id;
    e->span_us  = span_us;
    e->has_span = has_span;
    e->pid      = bpf_get_current_pid_tgid() >> 32;
    e->family   = family;
    e->oldstate = BPF_CORE_READ(sk, __sk_common.skc_state);  /* not yet updated */
    e->newstate = state;
    e->sport    = BPF_CORE_READ(sk, __sk_common.skc_num);              /* host  */
    e->dport    = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport)); /* net→host */
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    if (family == AF_INET) {
        __be32 saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
        __be32 daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
        __builtin_memcpy(e->saddr, &saddr, sizeof(saddr));
        __builtin_memcpy(e->daddr, &daddr, sizeof(daddr));
    } else {
        /* Copy the 16-byte in6_addr structs straight into our byte arrays. */
        BPF_CORE_READ_INTO(&e->saddr, sk, __sk_common.skc_v6_rcv_saddr);
        BPF_CORE_READ_INTO(&e->daddr, sk, __sk_common.skc_v6_daddr);
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
