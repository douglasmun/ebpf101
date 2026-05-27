/* tcpstates.h — shared between kernel and userspace, Chapter 12 */
#ifndef TCPSTATES_H
#define TCPSTATES_H

#define TASK_COMM_LEN 16

/*
 * Address families are preprocessor constants, not BTF types, so they are not
 * in vmlinux.h.  (The TCP state values *are* in vmlinux.h as an anonymous enum
 * — TCP_ESTABLISHED = 1, … — so the BPF side uses those directly and we do NOT
 * redefine them here, which would clash with the enum.)
 */
#ifndef AF_INET
#define AF_INET   2
#endif
#ifndef AF_INET6
#define AF_INET6  10
#endif

/*
 * One event per TCP state transition (one call to the kernel's tcp_set_state).
 *
 * Byte order, decided once here and honoured on both sides:
 *   - addresses (saddr/daddr) are kept in NETWORK byte order, so userspace can
 *     hand them straight to inet_ntop(3) with no swapping.  (Ch11 swapped to
 *     host order in BPF and back in userspace — this is the cleaner split.)
 *   - ports (sport/dport) are converted to HOST byte order in the BPF program,
 *     so userspace prints them directly.
 *
 * skaddr is the kernel `struct sock *` reinterpreted as an integer.  It is not
 * a pointer userspace can dereference — it is a stable per-connection ID that
 * lets you group the several transitions belonging to one socket.
 */
struct event {
    unsigned long long skaddr;   /* sock pointer as a connection id (hex) */
    unsigned long long span_us;  /* time spent in oldstate, microseconds  */
    unsigned int  pid;
    int           oldstate;      /* TCP_* value before this transition */
    int           newstate;      /* TCP_* value being set now */
    unsigned short family;       /* AF_INET or AF_INET6 */
    unsigned short sport;        /* source port, host byte order */
    unsigned short dport;        /* dest port,   host byte order */
    unsigned char  has_span;     /* 0 = first transition we saw for this sock */
    unsigned char  saddr[16];    /* source addr, network byte order (4 for v4) */
    unsigned char  daddr[16];    /* dest addr,   network byte order (4 for v4) */
    char           comm[TASK_COMM_LEN];
};

#endif /* TCPSTATES_H */
