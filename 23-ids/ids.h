/* ids.h — shared between kernel and userspace, Chapter 23 */
#ifndef IDS_H
#define IDS_H

/* Ethertype is not in vmlinux.h — define it, guarded (the ch7+ macro rule). */
#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

/*
 * One record per observed packet. The kernel-side tap fills this in and ships
 * it to user space over the ring buffer; user space does ALL the detection.
 *
 * Addresses and ports are kept in NETWORK byte order — exactly as they sit in
 * the packet headers. User space converts them (ntohl/ntohs) only when it needs
 * to compare or print. Keeping the kernel side dumb is the whole point: it
 * copies bytes out, it does not interpret them.
 */
struct flow_pkt {
    __u64 ts_ns;     /* bpf_ktime_get_ns(): monotonic, for inter-arrival timing */
    __u32 saddr;     /* source IPv4      (network order) */
    __u32 daddr;     /* destination IPv4 (network order) */
    __u16 sport;     /* source port      (network order) */
    __u16 dport;     /* destination port (network order) */
    __u16 len;       /* L2 frame length (skb->len) */
    __u8  proto;     /* IPPROTO_TCP or IPPROTO_UDP */
};

#endif /* IDS_H */
