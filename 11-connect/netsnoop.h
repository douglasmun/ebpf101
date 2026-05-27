/* netsnoop.h — shared between kernel and userspace, Chapter 11 */
#ifndef NETSNOOP_H
#define NETSNOOP_H

#define TASK_COMM_LEN 16

/*
 * Address families — these are preprocessor constants, not BTF types, so
 * they are not in vmlinux.h.  We only need IPv4 and IPv6 here.
 */
#ifndef AF_INET
#define AF_INET   2
#endif
#ifndef AF_INET6
#define AF_INET6  10
#endif

/*
 * One event per connect(2) call.  The kernel side fills everything;
 * the IP and port are already in host byte order (ntohl/ntohs applied
 * in the BPF program so userspace needs no byte-swapping).
 *
 * For IPv6 the address is 16 bytes stored as four 32-bit words; for IPv4
 * only addr4 is meaningful and the rest are zero.
 */
struct event {
    unsigned int  pid;
    unsigned int  uid;
    char          comm[TASK_COMM_LEN];
    unsigned int  family;    /* AF_INET or AF_INET6 */
    unsigned int  addr4;     /* IPv4 address, host byte order */
    unsigned char addr6[16]; /* IPv6 address, network byte order */
    unsigned short port;     /* destination port, host byte order */
    int           ret;       /* return value: 0 = success, -errno = error */
};

#endif /* NETSNOOP_H */
