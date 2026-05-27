/*
 * bashreadline.c — userspace loader, Chapter 15
 *
 * Attaches a uretprobe to readline() in the bash binary and prints every
 * command typed at any interactive bash prompt on the system.
 *
 * The new step versus earlier chapters is the *manual* uprobe attach: we name
 * the target binary path and symbol explicitly. libbpf resolves "readline" via
 * the binary's ELF symbol table (it lives in bash's .dynsym), turns it into a
 * file offset, and installs the uretprobe there.
 *
 * pid = -1 means "every process that maps this binary, now and in the future" —
 * so a bash started after we attach is traced too.
 *
 * Build:  make
 * Run:    sudo ./bashreadline                 (defaults to /usr/bin/bash)
 *         sudo ./bashreadline /bin/bash        (override the bash path)
 * Then type commands in a SECOND terminal's bash and watch them appear.
 */
#include <stdio.h>
#include <signal.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include "bashreadline.skel.h"
#include "bashreadline.h"

#define DEFAULT_BASH "/usr/bin/bash"

static volatile int stop;
static void on_signal(int sig) { stop = 1; }

static int handle_event(void *ctx, void *data, size_t len)
{
    const struct event *e = data;
    printf("%-8u %-16s %s\n", e->pid, e->comm, e->line);
    return 0;
}

int main(int argc, char **argv)
{
    const char *bash_path = argc > 1 ? argv[1] : DEFAULT_BASH;
    struct bashreadline_bpf *skel;
    struct ring_buffer *rb = NULL;
    struct bpf_link *link  = NULL;
    int err;

    libbpf_set_print(NULL);

    skel = bashreadline_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open/load BPF skeleton\n");
        return 1;
    }

    /* Manual uprobe attach: bash_path:readline, return probe, all PIDs (-1). */
    LIBBPF_OPTS(bpf_uprobe_opts, uopts,
                .func_name = "readline",
                .retprobe  = true);
    link = bpf_program__attach_uprobe_opts(skel->progs.bash_readline,
                                           -1, bash_path, 0, &uopts);
    if (!link) {
        err = -errno;
        fprintf(stderr,
                "Failed to attach uretprobe to %s:readline (%d).\n"
                "  Check the symbol exists:  nm -D %s | grep ' readline'\n",
                bash_path, err, bash_path);
        goto cleanup;
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.events),
                          handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        err = 1;
        goto cleanup;
    }

    signal(SIGINT,  on_signal);
    signal(SIGTERM, on_signal);

    printf("Tracing %s:readline — type commands in another bash. Ctrl-C to stop.\n",
           bash_path);
    printf("%-8s %-16s %s\n", "PID", "COMM", "COMMAND");

    while (!stop) {
        err = ring_buffer__poll(rb, 100);
        if (err == -EINTR) { err = 0; break; }
        if (err < 0) {
            fprintf(stderr, "ring_buffer__poll: %d\n", err);
            break;
        }
    }

    printf("\nDetached. Bye!\n");
cleanup:
    ring_buffer__free(rb);
    bpf_link__destroy(link);
    bashreadline_bpf__destroy(skel);
    return err < 0 ? 1 : 0;
}
