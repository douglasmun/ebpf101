// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * keyring_snoop.c — userspace loader + policy, Chapter 26
 *
 * Loads keyring_snoop.bpf.o (fentry + tracepoint on the keyring write path),
 * reads key_event records off the ring buffer, and flags the suspicious ones.
 * The kernel side is dumb; the judgement is here — same split as ch23.
 *
 * Policy: a payload staged in a "user" (or "big_key") key that is large enough
 * to be an ELF is the signal. Ordinary keyring use — session keyrings, DNS
 * resolver keys, credential caches — is small and/or of other types. The
 * threshold is deliberately conservative and printed so a reader can tune it.
 */
#include <argp.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "keyring_snoop.h"
#include "keyring_snoop.skel.h"

/* An ELF header is 64 bytes; anything staged above this in a user key is worth
 * a second look. Small enough to catch a tiny loader, large enough to skip the
 * kilobyte-scale credential keys the system creates constantly. */
static unsigned suspicious_bytes = 4096;
static volatile sig_atomic_t stop;
static void on_signal(int sig) { (void)sig; stop = 1; }

static int is_stageable_type(const char *t)
{
    return strcmp(t, "user") == 0 || strcmp(t, "big_key") == 0;
}

static int handle_event(void *ctx, void *data, size_t len)
{
    (void)ctx; (void)len;
    const struct key_event *e = data;
    const char *src = e->source == 0 ? "fentry" : "tracep";

    int suspicious = e->source == 0 &&
                     is_stageable_type(e->type) &&
                     e->datalen >= suspicious_bytes;

    printf("%-6s pid=%-7u uid=%-6u type=%-8s len=%-8u %-20s%s\n",
           src, e->pid, e->uid,
           e->type[0] ? e->type : "-",
           e->datalen,
           e->desc[0] ? e->desc : "-",
           suspicious ? "  <== STAGED PAYLOAD?" : "");
    fflush(stdout);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc > 1)
        suspicious_bytes = (unsigned)strtoul(argv[1], NULL, 0);

    libbpf_set_print(NULL);

    struct keyring_snoop_bpf *skel = keyring_snoop_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "open/load skeleton failed: %s\n", strerror(errno));
        return 1;
    }
    /*
     * Attach the two programs INDEPENDENTLY. The fentry detector is the one that
     * matters and attaches on any BTF kernel. The sys_enter_add_key tracepoint
     * needs tracefs mounted (/sys/kernel/tracing) to resolve its perf event ID;
     * on a stripped-down kernel (the lab's linuxkit VM) that mount is absent, so
     * a tracepoint attach failure is a WARNING, not fatal — the detector still
     * runs on fentry alone. Bulk keyring_snoop_bpf__attach() would abort on the
     * first failure, which is exactly the wrong behaviour here.
     */
    if (!bpf_program__attach(skel->progs.on_key_create)) {
        fprintf(stderr, "fentry attach failed: %s\n", strerror(errno));
        fprintf(stderr, "  (fentry needs a BTF kernel; run as root)\n");
        keyring_snoop_bpf__destroy(skel);
        return 1;
    }
    if (!bpf_program__attach(skel->progs.on_sys_add_key))
        fprintf(stderr,
                "note: tracepoint sys_enter_add_key unavailable (%s) — "
                "audit-parity view off, fentry detector still active. "
                "Mount tracefs to enable it.\n", strerror(errno));

    struct ring_buffer *rb =
        ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "ring_buffer__new failed\n");
        keyring_snoop_bpf__destroy(skel);
        return 1;
    }

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    printf("watching key creation (add_key); flag >= %u bytes in user/big_key. Ctrl-C to stop.\n",
           suspicious_bytes);
    printf("%-6s %-11s %-10s %-13s %-20s\n", "src", "pid", "uid", "type/len", "description");

    while (!stop) {
        int n = ring_buffer__poll(rb, 100);
        if (n < 0 && n != -EINTR) {
            fprintf(stderr, "ring_buffer__poll: %d\n", n);
            break;
        }
    }

    ring_buffer__free(rb);
    keyring_snoop_bpf__destroy(skel);
    return 0;
}
