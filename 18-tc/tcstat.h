/* tcstat.h — shared between kernel and userspace, Chapter 18 */
#ifndef TCSTAT_H
#define TCSTAT_H

/*
 * TC return codes are macros (linux/pkt_cls.h), not BTF types — not in
 * vmlinux.h. We only need "let the packet through" = TC_ACT_OK (0).
 */
#ifndef TC_ACT_OK
#define TC_ACT_OK 0
#endif

/* Counter slots: one per direction. The map is a PERCPU_ARRAY[DIR_MAX]. */
enum { DIR_INGRESS = 0, DIR_EGRESS = 1, DIR_MAX };

/* Per-direction tally — packets and bytes (bytes is the new trick: skb->len). */
struct datarec {
    unsigned long long packets;
    unsigned long long bytes;
};

#endif /* TCSTAT_H */
