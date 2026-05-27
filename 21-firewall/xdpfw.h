/* xdpfw.h — shared between kernel and userspace, Chapter 21 */
#ifndef XDPFW_H
#define XDPFW_H

/* Ethertype macro (not in vmlinux.h). We handle IPv4 here; see the notes for IPv6. */
#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

#define MAX_RULES 64    /* max blocked ports in the blocklist map */

#endif /* XDPFW_H */
