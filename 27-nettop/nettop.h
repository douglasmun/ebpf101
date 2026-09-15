/* nettop.h — shared between kernel and userspace, Chapter 27 */
#ifndef NETTOP_H
#define NETTOP_H

#define TASK_COMM_LEN 16

/* AF_* are macros, not BTF types — not in vmlinux.h. (Same note as ch13.) */
#ifndef AF_INET
#define AF_INET   2
#endif
#ifndef AF_INET6
#define AF_INET6  10
#endif

/*
 * Per-process traffic counters — the *value* of the accounting map, keyed by
 * PID (tgid).
 *
 * Unlike every chapter from 03 on, nothing here is streamed to userspace. This
 * struct is not an event; it is a running total that the kernel bumps in place
 * and userspace samples on a timer. Rates are a userspace concern: poll, diff
 * against the previous sample, divide by elapsed time. See nettop.c.
 *
 * IMPORTANT — what these bytes actually are. tx_bytes/rx_bytes are counted at
 * the *socket* layer: the length the process handed to (or took from) the
 * kernel. That is NOT what appears on the wire. It excludes TCP/IP headers, and
 * it does not double-count a retransmitted segment, whereas the NIC sends those
 * bytes twice. So socket-layer bytes run *below* wire bytes for the same
 * traffic. verify-nettop.sh measures that gap against tc's counters from ch18
 * rather than pretending it is zero.
 *
 * retrans_pkts is the honest counterweight: it tells you how much the wire had
 * to repeat that these byte counters will never show.
 */
struct proc_stats {
    unsigned long long tx_bytes;      /* bytes handed to the socket layer     */
    unsigned long long rx_bytes;      /* bytes read out of the socket layer   */
    unsigned long long tx_calls;      /* send-side hook firings (not packets) */
    unsigned long long rx_calls;      /* recv-side hook firings (not packets) */
    unsigned long long retrans_pkts;  /* TCP segments the kernel resent       */
    unsigned long long last_ns;       /* ktime of the most recent activity    */
    char comm[TASK_COMM_LEN];
};

#endif /* NETTOP_H */
