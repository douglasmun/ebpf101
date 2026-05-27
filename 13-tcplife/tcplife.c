/*
 * tcplife.c — userspace loader, Chapter 13
 *
 * Prints one line per *closed* TCP connection: owner, endpoints, bytes sent and
 * received, smoothed RTT, retransmits, and how long the connection lived.
 *
 * Unlike ch12 (a line per state transition), output appears only when a
 * connection ends — so an idle window is silent, and each line is a complete
 * obituary for one socket.
 *
 * Build:  make
 * Run:    sudo ./tcplife
 */
#include <stdio.h>
#include <signal.h>
#include <errno.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include "tcplife.skel.h"
#include "tcplife.h"

static volatile int stop;
static void on_signal(int sig) { stop = 1; }

/* Format "addr:port"; addr bytes are network order, port is host order. */
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

    /* Bytes as KiB, RTT and lifetime as milliseconds. */
    printf("%-7u %-16s %-4s %-48s %-48s %9.1f %9.1f %8.2f %5u %10.2f\n",
           e->pid, e->comm,
           e->family == AF_INET ? "IPv4" : "IPv6",
           src, dst,
           e->tx_b / 1024.0, e->rx_b / 1024.0,
           e->srtt_us / 1000.0, e->total_retrans,
           e->span_us / 1000.0);

    return 0;
}

int main(void)
{
    struct tcplife_bpf *skel;
    struct ring_buffer *rb;
    int err;

    libbpf_set_print(NULL);

    skel = tcplife_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open/load BPF skeleton\n");
        return 1;
    }

    err = tcplife_bpf__attach(skel);
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

    printf("%-7s %-16s %-4s %-48s %-48s %9s %9s %8s %5s %10s\n",
           "PID", "COMM", "AF", "LADDR:PORT", "RADDR:PORT",
           "TX_KB", "RX_KB", "RTT_MS", "RETR", "DUR_MS");

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
    tcplife_bpf__destroy(skel);
    return err < 0 ? 1 : 0;
}
