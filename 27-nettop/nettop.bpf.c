// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * nettop.bpf.c — kernel-side, Chapter 27
 *
 * Per-process network traffic accounting: who is sending and receiving, how
 * much, right now. A mini `nethogs`.
 *
 * Hooks — the socket layer, both protocols, both directions:
 *
 *     kprobe/tcp_sendmsg          TCP tx   (size = bytes userspace asked to send)
 *     kprobe/tcp_cleanup_rbuf     TCP rx   (copied = bytes userspace just read)
 *     kprobe/udp_sendmsg          UDP tx   IPv4
 *     kprobe/udpv6_sendmsg        UDP tx   IPv6
 *     kprobe/skb_consume_udp      UDP rx   both families
 *     kprobe/tcp_retransmit_skb   TCP resends (softirq — see ATTRIBUTION below)
 *     kprobe/tcp_close            socket teardown — map cleanup only
 *
 * WHAT IS NEW vs the chapters this builds on
 *
 *   ch11 traced connection *attempts* and ch13 summarised a connection at its
 *   *close*, reading the byte counters the kernel had already accumulated in
 *   struct tcp_sock. Both are event-driven: something happens, an event goes up
 *   the ring buffer.
 *
 *   This chapter is the other shape, and it is the one real observability
 *   agents use: the kernel keeps a *running total* in a map, and userspace
 *   *polls* it on a timer and differentiates to get rates. No ring buffer, no
 *   per-event cost in userspace, constant memory. A process doing 100k sends a
 *   second costs exactly as much to observe as one doing ten.
 *
 *   It is also the first chapter to account TCP *and* UDP together, and the
 *   first to attribute live byte rates to a PID.
 *
 * ATTRIBUTION — and the bug this chapter is careful to avoid
 *
 *   Five of the six accounting hooks run in the calling process's own context,
 *   so bpf_get_current_pid_tgid() is the right answer. tcp_retransmit_skb is
 *   the exception: it fires from a timer in softirq context, so "current" is
 *   whatever the interrupt landed on — the same trap ch12 hit and ch13 worked
 *   around by stashing identity earlier.
 *
 *   The fix is the same shape as ch13's: remember the owner when we *are* in
 *   process context, look it up later. But ch13 could key that stash on the
 *   sock pointer safely because it deleted the entry at TCP_CLOSE, in the same
 *   hook that created it.
 *
 *   A sock pointer is only unique while that socket is alive. Free it and the
 *   slab can hand the same address to a brand-new socket owned by a different
 *   process — and a stale entry then silently misattributes another process's
 *   retransmits. So this program does two things about it:
 *
 *     1. deletes the entry in tcp_close, the moment the socket goes away, and
 *     2. uses an LRU_HASH anyway, so that sockets that die without passing
 *        through our hook (and there are such paths) get evicted by age
 *        instead of wedging the map full.
 *
 *   Reference implementations of this idea — pktz, the tool that prompted this
 *   chapter — commonly do neither: a plain HASH, inserted on every send, never
 *   deleted. It fills to max_entries, after which every new socket silently
 *   fails to register and retransmit attribution quietly stops working. The map
 *   type and the delete below are the whole difference.
 *
 * SCOPE — this counts socket-layer bytes, not wire bytes. See nettop.h.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "nettop.h"

#define MAX_PROCS   4096
#define MAX_SOCKS  10240

/* pid → running totals. The whole output of this program. */
struct {
    __uint(type,        BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_PROCS);
    __type(key,   __u32);
    __type(value, struct proc_stats);
} proc_stats_map SEC(".maps");

/*
 * sock pointer → owning pid, for the softirq hook only.
 *
 * LRU_HASH, not HASH: see ATTRIBUTION above. Under pressure an LRU map evicts
 * its coldest entry and keeps accepting writes; a plain HASH returns -E2BIG
 * forever and the newest sockets — the ones actually sending — are exactly the
 * ones that lose attribution.
 */
struct {
    __uint(type,        BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_SOCKS);
    __type(key,   __u64);
    __type(value, __u32);
} sock_owner SEC(".maps");

/* Fetch-or-create the per-pid row, then add bytes to one direction. */
static __always_inline void
account(struct sock *sk, __u64 bytes, bool is_tx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid == 0)
        return;                       /* kernel threads — nothing to attribute */

    /*
     * Check the address family FIRST, before touching any map.
     *
     * These hooks also carry AF_UNIX and other non-IP sockets. Registering them
     * in sock_owner and then discarding them — which is easy to do by putting
     * this check after the update, as pktz does — burns LRU slots on sockets
     * that can never retransmit, evicting the TCP sockets that can.
     */
    __u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    if (family != AF_INET && family != AF_INET6)
        return;

    /* We are in process context here, so record the owner for tcp_retransmit_skb. */
    __u64 skaddr = (__u64)(unsigned long)sk;
    bpf_map_update_elem(&sock_owner, &skaddr, &pid, BPF_ANY);

    struct proc_stats *ps = bpf_map_lookup_elem(&proc_stats_map, &pid);
    if (!ps) {
        struct proc_stats init = {};
        bpf_get_current_comm(&init.comm, sizeof(init.comm));
        /* BPF_NOEXIST: lose the insert race gracefully, as in ch16. */
        bpf_map_update_elem(&proc_stats_map, &pid, &init, BPF_NOEXIST);
        ps = bpf_map_lookup_elem(&proc_stats_map, &pid);
        if (!ps)
            return;                   /* map full — drop the sample, do not spin */
    }

    /*
     * Atomic: these hooks run concurrently on every CPU, and a plain += would
     * lose counts under load. Same reason as ch16's counter.
     */
    if (is_tx) {
        __sync_fetch_and_add(&ps->tx_bytes, bytes);
        __sync_fetch_and_add(&ps->tx_calls, 1);
    } else {
        __sync_fetch_and_add(&ps->rx_bytes, bytes);
        __sync_fetch_and_add(&ps->rx_calls, 1);
    }
    ps->last_ns = bpf_ktime_get_ns();
}

/*
 * tcp_sendmsg(sk, msg, size) — size is what the process asked to send.
 * The kernel may segment it, and may resend parts of it later; neither shows
 * up here. That is the syscall-vs-wire gap verify-nettop.sh measures.
 */
SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(handle_tcp_sendmsg, struct sock *sk, struct msghdr *msg, size_t size)
{
    account(sk, (__u64)size, true);
    return 0;
}

/*
 * tcp_cleanup_rbuf(sk, copied) — called when userspace has consumed `copied`
 * bytes from the receive queue. Covers IPv4 and IPv6.
 *
 * Caveat worth knowing: this is an internal kernel function, not a stable ABI.
 * It has been present for many years, but a kprobe on it is a rename away from
 * failing to attach. nettop.c reports which hooks attached rather than dying,
 * so a kernel that has moved on degrades instead of breaking.
 */
SEC("kprobe/tcp_cleanup_rbuf")
int BPF_KPROBE(handle_tcp_cleanup_rbuf, struct sock *sk, int copied)
{
    if (copied <= 0)
        return 0;
    account(sk, (__u64)copied, false);
    return 0;
}

SEC("kprobe/udp_sendmsg")
int BPF_KPROBE(handle_udp_sendmsg, struct sock *sk, struct msghdr *msg, size_t len)
{
    account(sk, (__u64)len, true);
    return 0;
}

SEC("kprobe/udpv6_sendmsg")
int BPF_KPROBE(handle_udpv6_sendmsg, struct sock *sk, struct msghdr *msg, size_t len)
{
    account(sk, (__u64)len, true);
    return 0;
}

SEC("kprobe/skb_consume_udp")
int BPF_KPROBE(handle_skb_consume_udp, struct sock *sk, struct sk_buff *skb, int len)
{
    if (len <= 0)
        return 0;
    account(sk, (__u64)len, false);
    return 0;
}

/*
 * tcp_retransmit_skb — softirq context. bpf_get_current_pid_tgid() here would
 * return whatever thread the timer interrupted, so we look the owner up in
 * sock_owner, which was filled in from process context by account().
 *
 * Note we do NOT add to tx_bytes: this chapter's byte counters are
 * socket-layer, and the process did not ask to send these bytes a second time.
 * Counting them here would quietly mix two different units into one column.
 * The retransmit count is reported as its own number instead.
 */
SEC("kprobe/tcp_retransmit_skb")
int BPF_KPROBE(handle_tcp_retransmit, struct sock *sk, struct sk_buff *skb)
{
    __u64 skaddr = (__u64)(unsigned long)sk;
    __u32 *pid = bpf_map_lookup_elem(&sock_owner, &skaddr);
    if (!pid)
        return 0;                     /* socket predates our attach — skip */

    struct proc_stats *ps = bpf_map_lookup_elem(&proc_stats_map, pid);
    if (!ps)
        return 0;

    __sync_fetch_and_add(&ps->retrans_pkts, 1);
    return 0;
}

/*
 * tcp_close — the cleanup this program exists to demonstrate.
 *
 * Without it, sock_owner grows for the life of the process and its keys go
 * stale as the slab recycles sock pointers. One delete, in the hook that marks
 * the socket dead, and the stale-pointer window closes.
 *
 * (The per-pid rows in proc_stats_map deliberately outlive the process: a
 * process that exits mid-interval should still appear in the final sample.
 * nettop.c reaps them — userspace can check whether a PID still exists, which
 * the kernel side cannot do cheaply.)
 */
SEC("kprobe/tcp_close")
int BPF_KPROBE(handle_tcp_close, struct sock *sk, long timeout)
{
    __u64 skaddr = (__u64)(unsigned long)sk;
    bpf_map_delete_elem(&sock_owner, &skaddr);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
