/* xdpcount.h — shared between kernel and userspace, Chapter 17 */
#ifndef XDPCOUNT_H
#define XDPCOUNT_H

/*
 * Ethertypes are preprocessor macros (linux/if_ether.h), not BTF types, so they
 * are not in vmlinux.h — define them with guards, like AF_* in ch11.
 * (IPPROTO_* and XDP_* ARE anonymous enums in vmlinux.h, so the BPF side uses
 * those directly and we must NOT redefine them.)
 */
#ifndef ETH_P_IP
#define ETH_P_IP   0x0800
#endif
#ifndef ETH_P_IPV6
#define ETH_P_IPV6 0x86DD
#endif
#ifndef ETH_P_ARP
#define ETH_P_ARP  0x0806
#endif

/*
 * IPPROTO_TCP/UDP/ICMP are in vmlinux.h (use directly), but IPPROTO_ICMPV6 is
 * NOT on this kernel's BTF, so we define it ourselves (value 58).
 */
#ifndef IPPROTO_ICMPV6
#define IPPROTO_ICMPV6 58
#endif

/*
 * Packet categories. Shared so the index the BPF program counts into and the
 * label user space prints always agree. The map is a PERCPU_ARRAY with CAT_MAX
 * slots, indexed by these. TCP/UDP/ICMP aggregate BOTH IPv4 and IPv6 (ICMP
 * includes ICMPv6); the *-other buckets catch L4 protocols we don't classify.
 */
enum pkt_cat {
    CAT_OTHER = 0,      /* non-IP, non-ARP ethertypes */
    CAT_TCP,            /* IPv4 or IPv6 TCP */
    CAT_UDP,            /* IPv4 or IPv6 UDP */
    CAT_ICMP,           /* ICMP or ICMPv6 */
    CAT_IPV4_OTHER,     /* IPv4, some other L4 protocol */
    CAT_IPV6_OTHER,     /* IPv6, some other next-header (incl. extension headers) */
    CAT_ARP,
    CAT_MAX,            /* number of categories — also the map size */
};

#endif /* XDPCOUNT_H */
