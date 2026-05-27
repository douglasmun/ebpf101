/*
 * netsnoop.c — userspace loader, Chapter 11
 *
 * Prints every outbound connect(2) call with its destination IP and port.
 * IPv4 addresses are printed as dotted-quad; IPv6 as colon-hex (abbreviated
 * with inet_ntop(3) — same function used by tools like ss and netstat).
 *
 * The BPF side already converted addresses to host byte order, so this file
 * does no byte-swapping: it just formats and prints.
 *
 * Build:  make
 * Run:    sudo ./netsnoop
 */
#include <stdio.h>
#include <signal.h>
#include <errno.h>
#include <arpa/inet.h>   /* inet_ntop */
#include <bpf/libbpf.h>
#include "netsnoop.skel.h"
#include "netsnoop.h"

static volatile int stop;
static void on_signal(int sig) { stop = 1; }

/* ── event handler ──────────────────────────────────────────────────────── */

static int handle_event(void *ctx, void *data, size_t len)
{
    const struct event *e = data;
    char addr_str[INET6_ADDRSTRLEN];

    if (e->family == AF_INET) {
        /*
         * inet_ntop expects the address in network byte order, but we
         * already converted to host byte order in the BPF program.
         * Convert back before formatting.
         */
        unsigned int naddr = htonl(e->addr4);
        inet_ntop(AF_INET, &naddr, addr_str, sizeof(addr_str));
    } else {
        /*
         * IPv6 address was kept in network byte order by the BPF program
         * (only the port was byte-swapped).  inet_ntop wants network order,
         * so pass addr6 directly.
         */
        inet_ntop(AF_INET6, e->addr6, addr_str, sizeof(addr_str));
    }

    /*
     * ret == 0          → connected (or connection initiated for TCP)
     * ret == -EINPROGRESS → non-blocking socket, connection in progress (normal)
     * ret < 0 (other)   → error: -ECONNREFUSED, -ETIMEDOUT, -ENETUNREACH, …
     */
    const char *status;
    if (e->ret == 0)
        status = "ok";
    else if (e->ret == -115)  /* EINPROGRESS */
        status = "inprogress";
    else
        status = "err";

    printf("%-8u %-6u %-16s %-6s %-42s %5u %s(%d)\n",
           e->pid, e->uid, e->comm,
           e->family == AF_INET ? "IPv4" : "IPv6",
           addr_str, e->port,
           status, e->ret);

    return 0;
}

/* ── main ───────────────────────────────────────────────────────────────── */

int main(void)
{
    struct netsnoop_bpf *skel;
    struct ring_buffer  *rb;
    int err;

    libbpf_set_print(NULL);

    skel = netsnoop_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open/load BPF skeleton\n");
        return 1;
    }

    err = netsnoop_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach: %d\n", err);
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

    printf("%-8s %-6s %-16s %-6s %-42s %5s %s\n",
           "PID", "UID", "COMM", "PROTO", "DEST-ADDR", "PORT", "STATUS");
    printf("%.110s\n",
           "----------------------------------------------"
           "----------------------------------------------"
           "-------------------");

    while (!stop) {
        err = ring_buffer__poll(rb, 100);
        if (err == -EINTR) { err = 0; break; }
        if (err < 0) {
            fprintf(stderr, "ring_buffer__poll: %d\n", err);
            break;
        }
    }

    printf("\nDetached. Bye!\n");
    ring_buffer__free(rb);
cleanup:
    netsnoop_bpf__destroy(skel);
    return err < 0 ? 1 : 0;
}
