/*
 * tailcall.c — userspace loader, Chapter 19
 *
 * Loads the dispatcher + two handlers, wires the PROG_ARRAY jump table, and
 * attaches ONLY the dispatcher. Each execve(2) is dispatched by tail call to
 * the user or root handler; we print the running tallies.
 *
 * Two things worth noticing:
 *   - PROG_ARRAY slots are populated here, from user space, with each handler's
 *     program fd. The skeleton loads the programs but can't know which one goes
 *     in which slot — that wiring is the loader's job.
 *   - We attach only `dispatch`. The handlers run via tail call, not via their
 *     own attachment, so calling *__attach() (which would attach every program)
 *     would be wrong; we attach the one entry point by hand.
 *
 * Build:  make
 * Run:    sudo ./tailcall      (then run commands in another terminal)
 */
#include <stdio.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "tailcall.skel.h"
#include "tailcall.h"

static volatile int stop;
static void on_signal(int sig) { stop = 1; }

int main(void)
{
    struct tailcall_bpf *skel;
    struct bpf_link *link = NULL;
    int err = 0;

    libbpf_set_print(NULL);

    skel = tailcall_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open/load BPF skeleton\n");
        return 1;
    }

    /* Wire the jump table: slot -> handler program fd. */
    int jt = bpf_map__fd(skel->maps.jmp_table);
    __u32 key;
    int fd;

    key = IDX_USER; fd = bpf_program__fd(skel->progs.handle_user);
    if (bpf_map_update_elem(jt, &key, &fd, BPF_ANY)) {
        err = -errno; fprintf(stderr, "set user slot: %d\n", err); goto cleanup;
    }
    key = IDX_ROOT; fd = bpf_program__fd(skel->progs.handle_root);
    if (bpf_map_update_elem(jt, &key, &fd, BPF_ANY)) {
        err = -errno; fprintf(stderr, "set root slot: %d\n", err); goto cleanup;
    }

    /* Attach only the dispatcher (handlers are reached via tail call). */
    link = bpf_program__attach(skel->progs.dispatch);
    if (!link) {
        err = -errno; fprintf(stderr, "attach dispatch: %d\n", err); goto cleanup;
    }

    signal(SIGINT,  on_signal);
    signal(SIGTERM, on_signal);

    int cf = bpf_map__fd(skel->maps.counts);
    printf("Dispatching execve() by tail call. Run commands in another terminal. Ctrl-C to stop.\n");

    while (!stop) {
        sleep(1);
        __u64 u = 0, r = 0, m = 0;
        __u32 k;
        k = IDX_USER; bpf_map_lookup_elem(cf, &k, &u);
        k = IDX_ROOT; bpf_map_lookup_elem(cf, &k, &r);
        k = IDX_MISS; bpf_map_lookup_elem(cf, &k, &m);
        printf("\nexecve dispatched by tail call:\n");
        printf("  user (uid != 0) : %llu\n", (unsigned long long)u);
        printf("  root (uid == 0) : %llu\n", (unsigned long long)r);
        printf("  dispatch miss   : %llu   (tail call fell through — should stay 0)\n",
               (unsigned long long)m);
    }

    printf("\nDetaching. Bye!\n");
cleanup:
    bpf_link__destroy(link);
    tailcall_bpf__destroy(skel);
    return err ? 1 : 0;
}
