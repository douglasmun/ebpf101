/*
 * tcpstates.c — userspace loader, Chapter 12
 *
 * Prints every TCP state transition on the machine: the connection 4-tuple,
 * the OLD → NEW state, and how long the socket sat in the old state.  Group the
 * lines by SKADDR to read one connection's life top to bottom; the SYN_SENT row
 * carries the connect() handshake latency in its successor's MS column.
 *
 * The BPF side kept addresses in network byte order (straight into inet_ntop)
 * and converted ports to host order, so this file does no byte-swapping.
 *
 * Build:  make
 * Run:    sudo ./tcpstates
 */
#include <stdio.h>
#include <signal.h>
#include <errno.h>
#include <arpa/inet.h>   /* inet_ntop */
#include <bpf/libbpf.h>
#include "tcpstates.skel.h"
#include "tcpstates.h"

static volatile int stop;
static void on_signal(int sig) { stop = 1; }

/*
 * TCP state names, indexed by the kernel's enum value (TCP_ESTABLISHED == 1).
 * Index 0 is unused — the kernel has no state 0.
 */
static const char *tcp_state_name(int s)
{
    static const char *names[] = {
        [1]  = "ESTABLISHED",
        [2]  = "SYN_SENT",
        [3]  = "SYN_RECV",
        [4]  = "FIN_WAIT1",
        [5]  = "FIN_WAIT2",
        [6]  = "TIME_WAIT",
        [7]  = "CLOSE",
        [8]  = "CLOSE_WAIT",
        [9]  = "LAST_ACK",
        [10] = "LISTEN",
        [11] = "CLOSING",
        [12] = "NEW_SYN_RECV",
        [13] = "BOUND_INACTIVE",
    };
    if (s >= 1 && s <= 13 && names[s])
        return names[s];
    return "?";
}

/* Format "addr:port" into buf; addr bytes are in network order, port in host. */
static void fmt_endpoint(char *buf, size_t buflen,
                         unsigned short family,
                         const unsigned char *addr, unsigned short port)
{
    char ip[INET6_ADDRSTRLEN];
    inet_ntop(family, addr, ip, sizeof(ip));
    /* Bracket IPv6 (RFC 3986) so the address colons don't blur into the port. */
    if (family == AF_INET6)
        snprintf(buf, buflen, "[%s]:%u", ip, port);
    else
        snprintf(buf, buflen, "%s:%u", ip, port);
}

static int handle_event(void *ctx, void *data, size_t len)
{
    const struct event *e = data;
    char src[INET6_ADDRSTRLEN + 10];
    char dst[INET6_ADDRSTRLEN + 10];

    fmt_endpoint(src, sizeof(src), e->family, e->saddr, e->sport);
    fmt_endpoint(dst, sizeof(dst), e->family, e->daddr, e->dport);

    /*
     * span column: blank on the first transition we observed for this socket
     * (we had no earlier timestamp to subtract); otherwise milliseconds spent
     * in the old state.  The handshake latency shows up on the row that lands
     * in ESTABLISHED (its old state is SYN_SENT).
     */
    char ms[16];
    if (e->has_span)
        snprintf(ms, sizeof(ms), "%.3f", e->span_us / 1000.0);
    else
        snprintf(ms, sizeof(ms), "%s", "-");

    printf("%-18llx %-7u %-16s %-4s %-48s %-48s %-14s -> %-14s %10s\n",
           e->skaddr, e->pid, e->comm,
           e->family == AF_INET ? "IPv4" : "IPv6",
           src, dst,
           tcp_state_name(e->oldstate), tcp_state_name(e->newstate),
           ms);

    return 0;
}

int main(void)
{
    struct tcpstates_bpf *skel;
    struct ring_buffer   *rb;
    int err;

    libbpf_set_print(NULL);

    skel = tcpstates_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open/load BPF skeleton\n");
        return 1;
    }

    err = tcpstates_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach (is tcp_set_state probe-able?): %d\n", err);
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

    printf("%-18s %-7s %-16s %-4s %-48s %-48s %-14s    %-14s %10s\n",
           "SKADDR", "PID", "COMM", "AF", "SADDR:PORT", "DADDR:PORT",
           "OLDSTATE", "NEWSTATE", "MS");

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
    tcpstates_bpf__destroy(skel);
    return err < 0 ? 1 : 0;
}
