/*
 * tcstat.c — userspace loader, Chapter 18
 *
 * Attaches the two tc programs (ingress + egress) to an interface via a clsact
 * qdisc, then prints per-direction packet/byte counts once a second. Both
 * programs return TC_ACT_OK, so traffic is never affected.
 *
 * The new step is the tc attach dance with libbpf's TC API:
 *   - bpf_tc_hook_create() installs the `clsact` qdisc on the interface (the
 *     qdisc that hosts BPF at both ingress and egress);
 *   - bpf_tc_attach() attaches a program to one of those hook points.
 * On exit bpf_tc_hook_destroy() removes the clsact qdisc and both filters.
 *
 * Build:  make
 * Run:    sudo ./tcstat [interface]        (defaults to the first non-lo NIC)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <net/if.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "tcstat.skel.h"
#include "tcstat.h"

static const char *dir_label[DIR_MAX] = {
    [DIR_INGRESS] = "ingress",
    [DIR_EGRESS]  = "egress",
};

static volatile int stop;
static void on_signal(int sig) { stop = 1; }

/* Pick the first non-loopback interface if none was named. */
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

    struct tcstat_bpf *skel;
    struct datarec *recs = NULL;
    int err = 0;

    libbpf_set_print(NULL);

    skel = tcstat_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open/load BPF skeleton\n");
        return 1;
    }

    /* Install the clsact qdisc that hosts BPF at ingress and egress. */
    LIBBPF_OPTS(bpf_tc_hook, hook,
                .ifindex      = ifindex,
                .attach_point = BPF_TC_INGRESS | BPF_TC_EGRESS);
    err = bpf_tc_hook_create(&hook);
    if (err && err != -EEXIST) {       /* EEXIST: a clsact qdisc was already there */
        fprintf(stderr, "Failed to create clsact hook on %s: %d\n", ifname, err);
        goto cleanup;
    }
    err = 0;

    LIBBPF_OPTS(bpf_tc_opts, in_opts, .prog_fd = bpf_program__fd(skel->progs.tc_ingress));
    hook.attach_point = BPF_TC_INGRESS;
    err = bpf_tc_attach(&hook, &in_opts);
    if (err) {
        fprintf(stderr, "Failed to attach ingress program: %d\n", err);
        goto cleanup;
    }

    LIBBPF_OPTS(bpf_tc_opts, eg_opts, .prog_fd = bpf_program__fd(skel->progs.tc_egress));
    hook.attach_point = BPF_TC_EGRESS;
    err = bpf_tc_attach(&hook, &eg_opts);
    if (err) {
        fprintf(stderr, "Failed to attach egress program: %d\n", err);
        goto cleanup;
    }

    signal(SIGINT,  on_signal);
    signal(SIGTERM, on_signal);

    int ncpu = libbpf_num_possible_cpus();
    recs = calloc(ncpu, sizeof(*recs));
    int map_fd = bpf_map__fd(skel->maps.stats);

    printf("Counting packets on '%s' (ingress + egress, TC_ACT_OK — never dropping). Ctrl-C to stop.\n",
           ifname);

    while (!stop) {
        sleep(1);
        printf("\n%-9s %14s %16s\n", "DIR", "PACKETS", "BYTES");
        for (__u32 d = 0; d < DIR_MAX; d++) {
            if (bpf_map_lookup_elem(map_fd, &d, recs))
                continue;
            unsigned long long pkts = 0, bytes = 0;
            for (int i = 0; i < ncpu; i++) {
                pkts  += recs[i].packets;
                bytes += recs[i].bytes;
            }
            printf("%-9s %14llu %16llu\n", dir_label[d], pkts, bytes);
        }
    }

    printf("\nRemoving clsact qdisc from %s...\n", ifname);
cleanup:
    /* Destroy the whole clsact hook — removes both filters and the qdisc. */
    hook.attach_point = BPF_TC_INGRESS | BPF_TC_EGRESS;
    bpf_tc_hook_destroy(&hook);
    free(recs);
    tcstat_bpf__destroy(skel);
    return err ? 1 : 0;
}
