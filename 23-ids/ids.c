/*
 * ids.c — userspace loader + rule engine, Chapter 23
 *
 * This is the "brain". The kernel tap (ids.bpf.c) streams one flow_pkt per
 * packet over a ring buffer; here we keep per-flow state and run plain,
 * readable detection rules over it. Because this runs in user space we are NOT
 * bound by the kernel's limits — we can use floating point, sqrt(), unbounded
 * loops, and grow tables freely. (The Bachl/Fabini/Zseby paper this chapter
 * riffs on pushes the logic the other way — into the kernel, to avoid the
 * per-packet copy you see here — and pays for it with fixed-point integer math.
 * The notes discuss that trade-off.)
 *
 * Three rules, three common malicious patterns:
 *   1. BEACONING  — near-regular callbacks to one dst:port (the classic C2 tell).
 *   2. PORT SCAN  — one source touching many destination ports in a short window.
 *   3. SUSP PORT  — traffic to a known C2 / backdoor port (signature match).
 *
 * Build:  make
 * Run:    sudo ./ids [interface]        (default: lo)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <math.h>
#include <stdarg.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>      /* ETH_P_ALL */
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "ids.skel.h"
#include "ids.h"

#ifndef SO_ATTACH_BPF
#define SO_ATTACH_BPF 50
#endif
#ifndef SOL_PACKET
#define SOL_PACKET 263
#endif
#ifndef PACKET_IGNORE_OUTGOING        /* Linux >= 4.20 */
#define PACKET_IGNORE_OUTGOING 23
#endif

/* ---- rule tunables (toy values for a quiet loopback demo) ---------------- */
#define MAX_FLOWS            1024
#define MAX_GAPS                8      /* inter-arrival samples kept per flow   */
#define BEACON_MIN_SAMPLES      5      /* need this many gaps before judging    */
#define BEACON_CV_MAX        0.10      /* jitter < 10% of the mean = "regular"  */
#define BEACON_MIN_INTERVAL   1.0      /* seconds: ignore sub-second chatter    */
#define BEACON_MAX_INTERVAL 300.0      /* seconds: ignore very slow flows       */

#define MAX_SCAN_SRC           64
#define MAX_SCAN_PORTS        256
#define SCAN_WINDOW_NS  (5ULL * 1000000000ULL)   /* 5-second sliding window     */
#define SCAN_PORT_THRESH       20      /* distinct dst ports in window = scan   */
#define SCAN_COOLDOWN_NS (10ULL * 1000000000ULL) /* re-alert at most this often */

/* Signature list: ports strongly associated with C2 frameworks / backdoors. */
static const struct { __u16 port; const char *name; } suspicious[] = {
    { 1337,  "leet — common backdoor"           },
    { 4444,  "Metasploit/Meterpreter default"   },
    { 5555,  "ADB / common Android RAT"          },
    { 6667,  "IRC (classic botnet C2)"           },
    { 12345, "NetBus backdoor"                   },
    { 31337, "Back Orifice backdoor"             },
    { 50050, "Cobalt Strike team server default" },
};

/* ---- per-flow state (keyed by src, dst, dst-port, proto) ----------------- *
 * Note: we deliberately DON'T key on the source port. A real beacon opens a
 * fresh connection (new ephemeral source port) for each callback, so grouping
 * by dst:port is what makes the periodicity visible. */
struct flow {
    int    used;
    __u32  saddr, daddr;
    __u16  dport;
    __u8   proto;
    __u64  last_ts;
    double gaps[MAX_GAPS];
    int    ngaps;                  /* total gaps seen (samples = ngaps capped) */
    int    beacon_alerted;
    int    susp_alerted;
};
static struct flow flows[MAX_FLOWS];

/* ---- per-source state for the port-scan rule ----------------------------- */
struct scan_src {
    int   used;
    __u32 saddr;
    struct { __u16 port; __u64 ts; } seen[MAX_SCAN_PORTS];
    int   n;
    __u64 last_alert_ts;
};
static struct scan_src scans[MAX_SCAN_SRC];

static int g_debug;            /* set by IDS_DEBUG env: print every beacon-flow's stats */
static volatile int stop;
static void on_signal(int sig) { stop = 1; }

/* Format a network-order IPv4 into the caller's buffer (>= INET_ADDRSTRLEN). */
static const char *ip4(__u32 net_addr, char *buf)
{
    struct in_addr a = { .s_addr = net_addr };
    return inet_ntop(AF_INET, &a, buf, INET_ADDRSTRLEN);
}

static void alert(const char *rule, const char *fmt, ...)
{
    char ts[16];
    time_t now = time(NULL);
    strftime(ts, sizeof(ts), "%H:%M:%S", localtime(&now));
    printf("[%s] ALERT %-9s ", ts, rule);

    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    printf("\n");
    fflush(stdout);
}

/* Rule 1 + 3 share the flow table. Returns the flow for this packet. */
static struct flow *flow_get(const struct flow_pkt *p)
{
    struct flow *free_slot = NULL;
    for (int i = 0; i < MAX_FLOWS; i++) {
        struct flow *f = &flows[i];
        if (!f->used) { if (!free_slot) free_slot = f; continue; }
        if (f->saddr == p->saddr && f->daddr == p->daddr &&
            f->dport == p->dport && f->proto == p->proto)
            return f;
    }
    if (!free_slot)             /* table full: a real IDS would evict; we skip */
        return NULL;
    free_slot->used  = 1;
    free_slot->saddr = p->saddr;
    free_slot->daddr = p->daddr;
    free_slot->dport = p->dport;
    free_slot->proto = p->proto;
    free_slot->last_ts = 0;
    free_slot->ngaps = 0;
    free_slot->beacon_alerted = 0;
    free_slot->susp_alerted = 0;
    return free_slot;
}

/* Rule 1 — beaconing: low-jitter, regularly-spaced callbacks to one dst:port. */
static void rule_beacon(struct flow *f, const struct flow_pkt *p)
{
    if (f->last_ts) {
        double gap = (double)(p->ts_ns - f->last_ts) / 1e9;
        f->gaps[f->ngaps % MAX_GAPS] = gap;
        f->ngaps++;
    }
    f->last_ts = p->ts_ns;

    int n = f->ngaps < MAX_GAPS ? f->ngaps : MAX_GAPS;
    if (n < 1)                                 /* need at least one gap to judge */
        return;

    /* Mean and coefficient of variation (stddev/mean) of the recent gaps. */
    double sum = 0;
    for (int i = 0; i < n; i++) sum += f->gaps[i];
    double mean = sum / n;
    double var = 0;
    for (int i = 0; i < n; i++) var += (f->gaps[i] - mean) * (f->gaps[i] - mean);
    double cv = mean > 0 ? sqrt(var / n) / mean : 1.0;

    if (g_debug) {
        char s[INET_ADDRSTRLEN], d[INET_ADDRSTRLEN];
        fprintf(stderr, "[dbg] beacon-flow %s -> %s:%u  samples=%d mean=%.2fs cv=%.0f%%\n",
                ip4(f->saddr, s), ip4(f->daddr, d), ntohs(f->dport), n, mean, cv * 100.0);
    }

    if (f->beacon_alerted || n < BEACON_MIN_SAMPLES)
        return;
    if (mean < BEACON_MIN_INTERVAL || mean > BEACON_MAX_INTERVAL)
        return;                                /* too fast or too slow to be a beacon */
    if (cv > BEACON_CV_MAX)
        return;                                /* too jittery — not a steady beacon */

    char s[INET_ADDRSTRLEN], d[INET_ADDRSTRLEN];
    alert("beacon", "%s -> %s:%u  interval~%.1fs jitter %.1f%% (%d callbacks)",
          ip4(f->saddr, s), ip4(f->daddr, d), ntohs(f->dport),
          mean, cv * 100.0, n + 1);
    f->beacon_alerted = 1;
}

/* Rule 3 — signature: traffic to a known C2 / backdoor port. */
static void rule_suspicious_port(struct flow *f, const struct flow_pkt *p)
{
    if (f->susp_alerted)
        return;
    __u16 dport = ntohs(p->dport);
    for (size_t i = 0; i < sizeof(suspicious) / sizeof(suspicious[0]); i++) {
        if (suspicious[i].port == dport) {
            char s[INET_ADDRSTRLEN], d[INET_ADDRSTRLEN];
            alert("susp-port", "%s -> %s:%u  (%s)",
                  ip4(p->saddr, s), ip4(p->daddr, d), dport, suspicious[i].name);
            f->susp_alerted = 1;
            return;
        }
    }
}

/* Rule 2 — port scan: one source hitting many dst ports in a short window. */
static void rule_portscan(const struct flow_pkt *p)
{
    struct scan_src *sc = NULL, *free_slot = NULL;
    for (int i = 0; i < MAX_SCAN_SRC; i++) {
        if (!scans[i].used) { if (!free_slot) free_slot = &scans[i]; continue; }
        if (scans[i].saddr == p->saddr) { sc = &scans[i]; break; }
    }
    if (!sc) {
        if (!free_slot) return;
        sc = free_slot;
        sc->used = 1; sc->saddr = p->saddr; sc->n = 0; sc->last_alert_ts = 0;
    }

    /* Drop entries older than the window, compacting the array. */
    int w = 0;
    for (int i = 0; i < sc->n; i++)
        if (p->ts_ns - sc->seen[i].ts < SCAN_WINDOW_NS)
            sc->seen[w++] = sc->seen[i];
    sc->n = w;

    /* Record this dst port (refresh its timestamp if already present). */
    int found = 0;
    for (int i = 0; i < sc->n; i++)
        if (sc->seen[i].port == p->dport) { sc->seen[i].ts = p->ts_ns; found = 1; break; }
    if (!found && sc->n < MAX_SCAN_PORTS) {
        sc->seen[sc->n].port = p->dport;
        sc->seen[sc->n].ts   = p->ts_ns;
        sc->n++;
    }

    if (sc->n > SCAN_PORT_THRESH &&
        (sc->last_alert_ts == 0 || p->ts_ns - sc->last_alert_ts > SCAN_COOLDOWN_NS)) {
        char s[INET_ADDRSTRLEN];
        alert("portscan", "%s scanned %d distinct ports within %llus",
              ip4(p->saddr, s), sc->n, (unsigned long long)(SCAN_WINDOW_NS / 1000000000ULL));
        sc->last_alert_ts = p->ts_ns;
    }
}

static int handle_event(void *ctx, void *data, size_t len)
{
    const struct flow_pkt *p = data;

    struct flow *f = flow_get(p);
    if (f) {
        rule_beacon(f, p);
        rule_suspicious_port(f, p);
    }
    rule_portscan(p);
    return 0;
}

int main(int argc, char **argv)
{
    const char *ifname = (argc > 1) ? argv[1] : "lo";
    unsigned int ifindex = if_nametoindex(ifname);
    if (!ifindex) {
        fprintf(stderr, "Unknown interface '%s' (%d)\n", ifname, errno);
        return 1;
    }

    libbpf_set_print(NULL);
    g_debug = getenv("IDS_DEBUG") != NULL;     /* IDS_DEBUG=1 → print beacon-flow stats */

    struct ids_bpf *skel = ids_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open/load BPF skeleton\n");
        return 1;
    }

    int err = 0, sock = -1;
    struct ring_buffer *rb = NULL;

    /* A raw packet socket is the "wire tap"; attach our filter to it, then bind
     * it to the chosen interface so we only see that interface's traffic. */
    sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) {
        fprintf(stderr, "socket(AF_PACKET): %d (need root)\n", errno);
        err = 1; goto cleanup;
    }

    /* Loopback delivers every frame TWICE to an AF_PACKET socket — once as it is
     * sent (PACKET_OUTGOING) and once as it loops back in (PACKET_HOST) — which
     * would double every count and destroy the beacon's timing regularity. Ask
     * the kernel to drop the outgoing copies so each datagram is seen once. (On
     * loopback the remaining "incoming" copy still carries both ends of a
     * conversation. Harmless on a real NIC; needs Linux >= 4.20.) */
    int ignore_out = 1;
    if (setsockopt(sock, SOL_PACKET, PACKET_IGNORE_OUTGOING, &ignore_out, sizeof(ignore_out)))
        fprintf(stderr, "warning: PACKET_IGNORE_OUTGOING failed (%d) — counts may double on lo\n",
                errno);

    int prog_fd = bpf_program__fd(skel->progs.ids_tap);
    if (setsockopt(sock, SOL_SOCKET, SO_ATTACH_BPF, &prog_fd, sizeof(prog_fd))) {
        fprintf(stderr, "SO_ATTACH_BPF: %d\n", errno);
        err = 1; goto cleanup;
    }

    struct sockaddr_ll sll = {
        .sll_family   = AF_PACKET,
        .sll_protocol = htons(ETH_P_ALL),
        .sll_ifindex  = ifindex,
    };
    if (bind(sock, (struct sockaddr *)&sll, sizeof(sll))) {
        fprintf(stderr, "bind to %s: %d\n", ifname, errno);
        err = 1; goto cleanup;
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        err = 1; goto cleanup;
    }

    signal(SIGINT,  on_signal);
    signal(SIGTERM, on_signal);

    printf("IDS watching '%s' — rules: beacon, port-scan, suspicious-port. Ctrl-C to stop.\n",
           ifname);

    while (!stop) {
        int n = ring_buffer__poll(rb, 100);
        if (n == -EINTR)
            break;
        if (n < 0) {
            fprintf(stderr, "ring_buffer__poll: %d\n", n);
            err = 1;
            break;
        }
    }

    printf("\nStopped.\n");
cleanup:
    if (rb) ring_buffer__free(rb);
    if (sock >= 0) close(sock);          /* closing the socket detaches the filter */
    ids_bpf__destroy(skel);
    return err;
}
