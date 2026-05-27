/*
 * xdpfw.c — userspace loader, Chapter 21
 *
 * Loads the XDP firewall, fills the blocklist map with the ports to drop, and
 * prints a live per-port drop count. The rules live in the map, so they are set
 * here in user space — change them and the datapath policy changes, no BPF
 * recompile.
 *
 * SAFETY: this program DROPS packets. Defaults are deliberately harmless —
 * interface `lo`, port 11111 (nothing uses it) — so it cannot cut real
 * connectivity. Blocking a real port (e.g. 443) on a real NIC (e.g. wlp3s0)
 * WILL break that traffic for as long as it runs. Detach (Ctrl-C) restores it.
 *
 * Build:  make
 * Run:    sudo ./xdpfw [interface] [port ...]      (defaults: lo 11111)
 * Test:   echo hi | nc -u -w1 127.0.0.1 11111      (the packet is dropped)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <net/if.h>
#include <linux/if_link.h>   /* XDP_FLAGS_SKB_MODE */
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "xdpfw.skel.h"
#include "xdpfw.h"

static volatile int stop;
static void on_signal(int sig) { stop = 1; }

int main(int argc, char **argv)
{
    const char *ifname = (argc > 1) ? argv[1] : "lo";
    unsigned int ifindex = if_nametoindex(ifname);
    if (!ifindex) {
        fprintf(stderr, "Unknown interface '%s' (%d)\n", ifname, errno);
        return 1;
    }

    /* Ports to block: argv[2..], or default 11111. */
    __u16 ports[MAX_RULES];
    int nports = 0;
    for (int i = 2; i < argc && nports < MAX_RULES; i++)
        ports[nports++] = (__u16)atoi(argv[i]);
    if (nports == 0)
        ports[nports++] = 11111;

    struct xdpfw_bpf *skel;
    int err = 0;

    libbpf_set_print(NULL);

    skel = xdpfw_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open/load BPF skeleton\n");
        return 1;
    }

    /* Install the rules: each blocked port is a key in the blocklist map. */
    int bl = bpf_map__fd(skel->maps.blocklist);
    for (int i = 0; i < nports; i++) {
        __u64 zero = 0;
        if (bpf_map_update_elem(bl, &ports[i], &zero, BPF_ANY)) {
            fprintf(stderr, "Failed to add rule for port %u: %d\n", ports[i], -errno);
            err = 1; goto cleanup;
        }
    }

    /* Generic/SKB mode (portable; works on lo and virtual NICs), like ch17. */
    err = bpf_xdp_attach(ifindex, bpf_program__fd(skel->progs.xdp_fw),
                         XDP_FLAGS_SKB_MODE, NULL);
    if (err) {
        fprintf(stderr, "Failed to attach XDP to %s: %d\n", ifname, err);
        goto cleanup;
    }

    signal(SIGINT,  on_signal);
    signal(SIGTERM, on_signal);

    printf("Firewall active on '%s' — DROPPING TCP/UDP dest port(s):", ifname);
    for (int i = 0; i < nports; i++) printf(" %u", ports[i]);
    printf("\n(Ctrl-C detaches and restores normal traffic.)\n");

    while (!stop) {
        sleep(1);
        printf("\n%-8s %12s\n", "PORT", "DROPPED");
        for (int i = 0; i < nports; i++) {
            __u64 cnt = 0;
            bpf_map_lookup_elem(bl, &ports[i], &cnt);
            printf("%-8u %12llu\n", ports[i], (unsigned long long)cnt);
        }
    }

    printf("\nDetaching XDP from %s (traffic restored)...\n", ifname);
    bpf_xdp_detach(ifindex, XDP_FLAGS_SKB_MODE, NULL);
cleanup:
    xdpfw_bpf__destroy(skel);
    return err ? 1 : 0;
}
