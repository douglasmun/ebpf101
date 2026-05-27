/*
 * opencount.c — userspace loader, Chapter 16
 *
 * Loads the per-uid openat counter, attaches it, and PINS the map and program
 * to bpffs (/sys/fs/bpf) so they have stable paths. Then it just waits — the
 * lesson happens in *another* terminal, where you inspect these objects with
 * bpftool. It prints the exact commands to try, with the live IDs filled in.
 *
 * New concept: pinning. A loaded BPF object normally dies when its last user
 * fd closes (i.e. when this process exits). Pinning creates a file under bpffs
 * that holds a reference, giving the object a name and (if you leave the pin)
 * a life beyond the loader. bpftool can then address it by path or by id.
 *
 * On Ctrl-C we unpin and clean up. (Leave the pins in place instead and the
 * counter would keep running after this process exits — that persistence is
 * exactly what pinning buys.)
 *
 * Build:  make
 * Run:    sudo ./opencount
 */
#include <stdio.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "opencount.skel.h"

#define PIN_DIR  "/sys/fs/bpf/ebpf101"
#define MAP_PIN  PIN_DIR "/open_count"
#define PROG_PIN PIN_DIR "/count_open"

static volatile int stop;
static void on_signal(int sig) { stop = 1; }

int main(void)
{
    struct opencount_bpf *skel;
    int err;

    libbpf_set_print(NULL);

    skel = opencount_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open/load BPF skeleton\n");
        return 1;
    }

    err = opencount_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach: %d\n", err);
        goto cleanup;
    }

    /* Pin map + program under a bpffs subdirectory. */
    if (mkdir(PIN_DIR, 0700) && errno != EEXIST)
        fprintf(stderr, "warning: mkdir %s: %d (is bpffs mounted at /sys/fs/bpf?)\n",
                PIN_DIR, -errno);
    if (bpf_map__pin(skel->maps.open_count, MAP_PIN))
        fprintf(stderr, "warning: pin map: %d\n", -errno);
    if (bpf_program__pin(skel->progs.count_open, PROG_PIN))
        fprintf(stderr, "warning: pin prog: %d\n", -errno);

    /* Fetch the kernel-assigned ids so we can print copy-paste commands. */
    struct bpf_map_info  minfo = {}; __u32 mlen = sizeof(minfo);
    struct bpf_prog_info pinfo = {}; __u32 plen = sizeof(pinfo);
    bpf_map_get_info_by_fd(bpf_map__fd(skel->maps.open_count), &minfo, &mlen);
    bpf_prog_get_info_by_fd(bpf_program__fd(skel->progs.count_open), &pinfo, &plen);

    signal(SIGINT,  on_signal);
    signal(SIGTERM, on_signal);

    printf("Loaded & pinned. prog id=%u, map id=%u, pins under %s\n\n",
           pinfo.id, minfo.id, PIN_DIR);
    printf("Explore in another terminal (root). The map fills as the system opens files:\n");
    printf("  sudo bpftool prog show id %u\n", pinfo.id);
    printf("  sudo bpftool map  show id %u\n", minfo.id);
    printf("  sudo bpftool map  dump id %u\n", minfo.id);
    printf("  sudo bpftool map  dump pinned %s\n", MAP_PIN);
    printf("  sudo bpftool prog dump xlated id %u\n", pinfo.id);
    printf("  sudo bpftool prog list | grep -A4 count_open\n");
    printf("\nCtrl-C to detach, unpin, and clean up.\n");

    while (!stop)
        pause();

    printf("\nDetaching and unpinning...\n");
    bpf_map__unpin(skel->maps.open_count, MAP_PIN);
    bpf_program__unpin(skel->progs.count_open, PROG_PIN);
    rmdir(PIN_DIR);
    printf("Bye!\n");

cleanup:
    opencount_bpf__destroy(skel);
    return err < 0 ? 1 : 0;
}
