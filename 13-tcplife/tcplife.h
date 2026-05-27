/* tcplife.h — shared between kernel and userspace, Chapter 13 */
#ifndef TCPLIFE_H
#define TCPLIFE_H

#define TASK_COMM_LEN 16

/* AF_* are macros, not BTF types — not in vmlinux.h. (TCP_* states ARE.) */
#ifndef AF_INET
#define AF_INET   2
#endif
#ifndef AF_INET6
#define AF_INET6  10
#endif

/*
 * One event per *completed* TCP connection (emitted at TCP_CLOSE), summarising
 * its whole life — not one event per transition like ch12.
 *
 * Same byte-order split as ch12: addresses stay network order (straight into
 * inet_ntop), ports are converted to host order in the BPF program.
 *
 * tx_b/rx_b come from struct tcp_sock's RFC4898 counters; span_us is the time
 * from the socket's first observed open transition to its close.
 */
struct event {
    unsigned long long skaddr;        /* sock pointer as a connection id */
    unsigned long long tx_b;          /* bytes_acked  — sent and ACKed (delivered) */
    unsigned long long rx_b;          /* bytes_received — received from the peer    */
    unsigned long long span_us;       /* connection lifetime, microseconds */
    unsigned int  pid;                /* owner, stashed at SYN_SENT (see .bpf.c) */
    unsigned int  srtt_us;            /* smoothed RTT, microseconds */
    unsigned int  total_retrans;      /* retransmitted segments over the life */
    unsigned short family;            /* AF_INET / AF_INET6 */
    unsigned short sport;             /* local port,  host byte order */
    unsigned short dport;             /* remote port, host byte order */
    unsigned char  saddr[16];         /* local addr,  network byte order (4 for v4) */
    unsigned char  daddr[16];         /* remote addr, network byte order (4 for v4) */
    char           comm[TASK_COMM_LEN];
};

#endif /* TCPLIFE_H */
