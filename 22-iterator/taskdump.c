/*
 * taskdump.c — userspace loader, Chapter 22
 *
 * Loads the task iterator, then drives it: attaching an iterator gives a link;
 * bpf_iter_create() turns that link into a readable fd; read()ing the fd runs
 * the kernel's task walk, invoking the BPF program per task, and returns the
 * seq_file text it printed. We just copy that to stdout — a snapshot `ps`.
 *
 * Read-only: this iterator only reads kernel task state and prints it. It never
 * attaches to an event and changes nothing.
 *
 * Build:  make
 * Run:    sudo ./taskdump
 */
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "taskdump.skel.h"

int main(void)
{
    struct taskdump_bpf *skel;
    struct bpf_link     *link = NULL;
    int iter_fd = -1;
    int err = 0;

    libbpf_set_print(NULL);

    skel = taskdump_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open/load BPF skeleton\n");
        return 1;
    }

    /* Attach the iterator program → a link; then materialise a readable fd. */
    link = bpf_program__attach_iter(skel->progs.dump_task, NULL);
    if (!link) {
        err = -errno;
        fprintf(stderr, "Failed to attach iterator: %d\n", err);
        goto cleanup;
    }

    iter_fd = bpf_iter_create(bpf_link__fd(link));
    if (iter_fd < 0) {
        err = iter_fd;
        fprintf(stderr, "Failed to create iterator fd: %d\n", err);
        goto cleanup;
    }

    /* Each read() advances the kernel's walk and returns the text our program
     * printed for those tasks; loop until EOF (the whole snapshot). */
    char buf[16 * 1024];
    ssize_t n;
    while ((n = read(iter_fd, buf, sizeof(buf))) > 0)
        fwrite(buf, 1, (size_t)n, stdout);
    if (n < 0) {
        err = -errno;
        fprintf(stderr, "read(iterator): %d\n", err);
    }

cleanup:
    if (iter_fd >= 0)
        close(iter_fd);
    bpf_link__destroy(link);
    taskdump_bpf__destroy(skel);
    return err ? 1 : 0;
}
