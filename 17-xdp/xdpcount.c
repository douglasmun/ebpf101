/*
 * xdpcount.c — userspace loader, Chapter 17
 *
 * Attaches the XDP packet counter to a network interface and prints a per-
 * protocol tally once a second. The program only ever returns XDP_PASS, so it
 * never affects traffic — it just counts.
 *
 * New steps versus earlier chapters:
 *   - attach to a NETWORK INTERFACE (by ifindex), not a kernel/user function;
 *   - use GENERIC/SKB mode (XDP_FLAGS_SKB_MODE) so it works on any interface,
 *     including virtual ones, without native driver XDP support;
 *   - read a PERCPU map: one value per CPU, summed here.
 *
 * Build:  make
 * Run:    sudo ./xdpcount [interface]      (defaults to the first non-lo NIC)
 *
 * Note: the loopback interface (lo) carries no Ethernet header, so on `lo`
 * everything classifies as "other" — use a real NIC to see the breakdown.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <net/if.h>          /* if_nametoindex, if_nameindex */
#include <linux/if_link.h>   /* XDP_FLAGS_SKB_MODE */
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "xdpcount.skel.h"
#include "xdpcount.h"

static const char *labels[CAT_MAX] = {
    [CAT_OTHER]      = "other",
    [CAT_TCP]        = "TCP",          /* IPv4 + IPv6 */
    [CAT_UDP]        = "UDP",          /* IPv4 + IPv6 */
    [CAT_ICMP]       = "ICMP",         /* ICMP + ICMPv6 */
    [CAT_IPV4_OTHER] = "IPv4-other",
    [CAT_IPV6_OTHER] = "IPv6-other",
    [CAT_ARP]        = "ARP",
};

static volatile int stop;
static void on_signal(int sig) { stop = 1; }

/* Pick the first non-loopback interface if none was named on the command line. */
static char ifbuf[IF_NAMESIZE];
static const char *default_iface(void)
{
    struct if_nameindex *idx = if_nameindex(), *p;
    const char *chosen = NULL;
    if (idx) {
        for (p = idx; p->if_index != 0 || p->if_name != NULL; p++) {
            if (p->if_name && strcmp(p->if_name, "lo") != 0) {
                snprintf(ifbuf, sizeof(ifbuf), "%s", p->if_name);
                chosen = ifbuf;
                break;
            }
        }
        if_freenameindex(idx);
    }
    return chosen ? chosen : "lo";
}

int main(int argc, char **argv)
{
    const char *ifname = (argc > 1) ? argv[1] : default_iface();
    unsigned int ifindex = if_nametoindex(ifname);
    if (!ifindex) {
        fprintf(stderr, "Unknown interface '%s' (%d)\n", ifname, errno);
        return 1;
    }

    struct xdpcount_bpf *skel;
    int err;

    libbpf_set_print(NULL);

    skel = xdpcount_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open/load BPF skeleton\n");
        return 1;
    }

    /* Generic/SKB mode: portable across interfaces lacking native XDP. */
    err = bpf_xdp_attach(ifindex, bpf_program__fd(skel->progs.xdp_count),
                         XDP_FLAGS_SKB_MODE, NULL);
    if (err) {
        fprintf(stderr, "Failed to attach XDP to %s: %d\n", ifname, err);
        xdpcount_bpf__destroy(skel);
        return 1;
    }

    signal(SIGINT,  on_signal);
    signal(SIGTERM, on_signal);

    int ncpu = libbpf_num_possible_cpus();
    __u64 *vals = calloc(ncpu, sizeof(*vals));
    int map_fd  = bpf_map__fd(skel->maps.counts);

    printf("Counting packets on '%s' in XDP (XDP_PASS — never dropping). Ctrl-C to stop.\n",
           ifname);

    while (!stop) {
        sleep(1);
        printf("\n%-12s %14s\n", "PROTO", "PACKETS");
        for (__u32 cat = 0; cat < CAT_MAX; cat++) {
            if (bpf_map_lookup_elem(map_fd, &cat, vals))
                continue;
            __u64 sum = 0;
            for (int i = 0; i < ncpu; i++)
                sum += vals[i];
            printf("%-12s %14llu\n", labels[cat], (unsigned long long)sum);
        }
    }

    printf("\nDetaching XDP from %s...\n", ifname);
    bpf_xdp_detach(ifindex, XDP_FLAGS_SKB_MODE, NULL);
    free(vals);
    xdpcount_bpf__destroy(skel);
    return 0;
}
