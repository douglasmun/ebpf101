// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * nettop.c — userspace, Chapter 27
 *
 * Loads the accounting program, then loops: sample the map, diff against the
 * previous sample, print a rate table sorted by traffic. Ctrl-C to stop.
 *
 * This is the part that makes the chapter different from ch03 onward. There is
 * no ring buffer and no callback — the kernel never pushes anything. We pull,
 * on a timer, and the *rate* is computed here from two totals and the interval
 * between them:
 *
 *     rate = (now.tx_bytes - prev.tx_bytes) / elapsed_seconds
 *
 * That is the whole trick, and it is why this design costs the same whether the
 * traced process sends ten packets a second or a hundred thousand.
 *
 * Three things userspace does here that the kernel side cannot do cheaply:
 *   - hold the previous sample (BPF maps have no "what was this last time")
 *   - decide a PID is gone (via /proc) and reap its row
 *   - sort
 */
#include <argp.h>
#include <errno.h>
#include <signal.h>
#include <sys/types.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "nettop.h"
#include "nettop.skel.h"

#define MAX_ROWS 4096

/*
 * How long a row must be idle before an unseeable PID is treated as dead.
 * See the reaper in sample() for why "unseeable" is not the same as "gone".
 */
#define REAP_IDLE_NS (60ULL * 1000000000ULL)

/* One line of output: a pid, its comm, and per-second rates. */
struct row {
    unsigned int       pid;
    char               comm[TASK_COMM_LEN];
    double             tx_bps, rx_bps;
    unsigned long long tx_total, rx_total;
    unsigned long long retrans;
};

/* Previous sample, kept so we can differentiate. */
struct prev_entry {
    unsigned int       pid;
    unsigned long long tx_bytes, rx_bytes, retrans;
    int                seen;         /* set each pass; clears the reaper */
};

static struct prev_entry prev[MAX_ROWS];
static int  prev_n;
static volatile sig_atomic_t exiting;

static void on_sigint(int sig) { (void)sig; exiting = 1; }

static struct env {
    double interval;
    int    count;
    int    top;
    int    clear;
} env = { .interval = 1.0, .count = 0, .top = 20, .clear = 1 };

const char *argp_program_version = "nettop 1.0";
static const char argp_doc[] =
    "nettop — per-process network traffic accounting with eBPF.\n"
    "\n"
    "Counts socket-layer bytes per process (TCP and UDP, both directions) into\n"
    "a BPF hash map, polls it on an interval, and prints live rates.\n"
    "\n"
    "NOTE: these are bytes as handed to/from the socket layer, not bytes on the\n"
    "wire — no headers, and retransmits are counted separately rather than\n"
    "added in. See verify-nettop.sh, which measures that gap against tc.\n";

static const struct argp_option opts[] = {
    { "interval", 'i', "SECONDS", 0, "Sample interval (default 1.0)" },
    { "count",    'c', "N",       0, "Stop after N samples (default: run forever)" },
    { "top",      'n', "N",       0, "Show at most N processes (default 20)" },
    { "no-clear", 'C', NULL,      0, "Do not clear the screen between samples" },
    {}
};

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
    switch (key) {
    case 'i':
        env.interval = strtod(arg, NULL);
        if (env.interval <= 0) {
            fprintf(stderr, "interval must be > 0\n");
            argp_usage(state);
        }
        break;
    case 'c': env.count = atoi(arg); break;
    case 'n': env.top   = atoi(arg); break;
    case 'C': env.clear = 0;         break;
    default:  return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static const struct argp argp = { opts, parse_opt, NULL, argp_doc };

static int libbpf_print_fn(enum libbpf_print_level level, const char *fmt, va_list args)
{
    if (level == LIBBPF_DEBUG)
        return 0;
    return vfprintf(stderr, fmt, args);
}

/* Human-readable rate: 1536 -> "1.5K". Keeps columns narrow. */
static void fmt_rate(double bps, char *buf, size_t len)
{
    static const char *unit[] = { "B", "K", "M", "G", "T" };
    int u = 0;
    while (bps >= 1024.0 && u < 4) { bps /= 1024.0; u++; }
    if (u == 0)
        snprintf(buf, len, "%.0f%s", bps, unit[u]);
    else
        snprintf(buf, len, "%.1f%s", bps, unit[u]);
}

/*
 * Is this PID visible to us right now?
 *
 * Deliberately /proc-based rather than kill(pid, 0): see the reaper in
 * sample(). A false negative here is safe — it only delays reaping — whereas a
 * false positive would keep dead rows forever.
 */
static int pid_alive(unsigned int pid)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%u", pid);
    return access(path, F_OK) == 0;
}

/* CLOCK_MONOTONIC in nanoseconds — same base as the kernel's bpf_ktime_get_ns. */
static unsigned long long mono_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (unsigned long long)ts.tv_sec * 1000000000ULL + (unsigned long long)ts.tv_nsec;
}

static struct prev_entry *prev_find(unsigned int pid)
{
    for (int i = 0; i < prev_n; i++)
        if (prev[i].pid == pid)
            return &prev[i];
    return NULL;
}

/* Sort: busiest first (tx+rx), then by pid so ties do not jitter between frames. */
static int by_traffic(const void *a, const void *b)
{
    const struct row *x = a, *y = b;
    double xt = x->tx_bps + x->rx_bps, yt = y->tx_bps + y->rx_bps;
    if (xt > yt) return -1;
    if (xt < yt) return  1;
    return (x->pid > y->pid) - (x->pid < y->pid);
}

/*
 * Walk the whole map with bpf_map_get_next_key, diff each row against the
 * previous sample, and collect printable rows.
 *
 * Iterating a hash map that the kernel is concurrently updating gives a fuzzy
 * snapshot — a row can be inserted or bumped mid-walk. For rate display that is
 * fine; it self-corrects on the next sample, since we always diff totals rather
 * than accumulating our own.
 */
static int sample(int map_fd, double elapsed, struct row *rows, int max_rows, int priming)
{
    unsigned int key = 0, next_key;
    struct proc_stats val;
    unsigned long long now_ns = mono_ns();
    int n = 0;

    for (int i = 0; i < prev_n; i++)
        prev[i].seen = 0;

    while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
        key = next_key;

        if (bpf_map_lookup_elem(map_fd, &key, &val) != 0)
            continue;

        /*
         * Reap rows for processes that have exited. The kernel side cannot do
         * this cheaply, so the poller owns it.
         *
         * Liveness is checked with /proc/<pid>, NOT kill(pid, 0). The map keys
         * are global PIDs — bpf_get_current_pid_tgid() returns the tgid in the
         * *initial* PID namespace. A nettop running inside a container (which
         * is how this chapter is verified) lives in a different namespace, so
         * kill() reports ESRCH for perfectly alive processes and the reaper
         * deletes every row on its first pass. The table then stays empty while
         * `bpftool map dump` shows the map filling up correctly — which is
         * exactly the symptom this chapter's first run produced.
         *
         * /proc has the same namespace caveat, so a row is only reaped once it
         * has also been idle for a while: a lookup failure alone is not proof
         * the process is gone, only that we cannot see it from here.
         */
        if (!pid_alive(key)) {
            unsigned long long idle_ns = now_ns > val.last_ns ? now_ns - val.last_ns : 0;
            if (idle_ns > REAP_IDLE_NS) {
                bpf_map_delete_elem(map_fd, &key);
                continue;
            }
        }

        struct prev_entry *p = prev_find(key);
        if (!p) {
            if (prev_n >= MAX_ROWS)
                continue;

            p = &prev[prev_n++];
            p->pid = key;
            p->seen = 1;

            /*
             * A PID we have never seen before falls into two cases, and the
             * difference decides whether its traffic is displayable.
             *
             *   priming pass — every process on the box is "new", and its
             *     totals are however much it sent since boot. Baseline against
             *     those totals and show nothing, or the first frame is one huge
             *     fake spike.
             *
             *   any later pass — the process appeared *during* our run, so its
             *     totals ARE its traffic for this interval. Baseline from zero
             *     and let it print.
             *
             * Getting this wrong hides every short-lived process: baseline
             * against current totals on every pass and a command that starts,
             * transfers, and exits inside two sample intervals is recorded once
             * as a baseline and never shown — which is exactly what the first
             * run of this chapter did to a 10 MiB `nc` transfer.
             */
            if (priming) {
                p->tx_bytes = val.tx_bytes;
                p->rx_bytes = val.rx_bytes;
                p->retrans  = val.retrans_pkts;
                continue;
            }
            p->tx_bytes = 0;
            p->rx_bytes = 0;
            p->retrans  = 0;
        }

        /*
         * Counters only ever go up, but a pid can be recycled — in which case
         * the "new" total is below the stored one. Treat any decrease as a new
         * process and re-baseline rather than printing a negative rate.
         */
        unsigned long long dtx = val.tx_bytes >= p->tx_bytes ? val.tx_bytes - p->tx_bytes : 0;
        unsigned long long drx = val.rx_bytes >= p->rx_bytes ? val.rx_bytes - p->rx_bytes : 0;
        unsigned long long dre = val.retrans_pkts >= p->retrans ? val.retrans_pkts - p->retrans : 0;

        p->tx_bytes = val.tx_bytes;
        p->rx_bytes = val.rx_bytes;
        p->retrans  = val.retrans_pkts;
        p->seen     = 1;

        if (dtx == 0 && drx == 0 && dre == 0)
            continue;                 /* idle this interval — do not list it */

        if (n >= max_rows)
            continue;

        struct row *r = &rows[n++];
        r->pid = key;
        memcpy(r->comm, val.comm, TASK_COMM_LEN);
        r->comm[TASK_COMM_LEN - 1] = '\0';
        r->tx_bps   = (double)dtx / elapsed;
        r->rx_bps   = (double)drx / elapsed;
        r->tx_total = val.tx_bytes;
        r->rx_total = val.rx_bytes;
        r->retrans  = dre;
    }

    /* Compact out previous-sample entries whose pid no longer appears. */
    int w = 0;
    for (int i = 0; i < prev_n; i++)
        if (prev[i].seen)
            prev[w++] = prev[i];
    prev_n = w;

    qsort(rows, n, sizeof(*rows), by_traffic);
    return n;
}

static void print_sample(struct row *rows, int n)
{
    char txb[16], rxb[16];
    time_t now = time(NULL);
    struct tm tm;
    char ts[16];

    localtime_r(&now, &tm);
    strftime(ts, sizeof(ts), "%H:%M:%S", &tm);

    if (env.clear)
        printf("\033[H\033[J");       /* home + clear, so the table redraws in place */

    printf("%s   %d process%s with traffic\n\n", ts, n, n == 1 ? "" : "es");
    printf("%-8s %-16s %10s %10s %10s\n", "PID", "COMM", "TX/s", "RX/s", "RETRANS");

    int shown = n < env.top ? n : env.top;
    for (int i = 0; i < shown; i++) {
        fmt_rate(rows[i].tx_bps, txb, sizeof(txb));
        fmt_rate(rows[i].rx_bps, rxb, sizeof(rxb));
        printf("%-8u %-16s %10s %10s %10llu\n",
               rows[i].pid, rows[i].comm, txb, rxb, rows[i].retrans);
    }
    if (n > shown)
        printf("... %d more\n", n - shown);
    fflush(stdout);
}

/*
 * Attach every program, but do not die if one fails.
 *
 * tcp_cleanup_rbuf and skb_consume_udp are internal functions, not stable ABI.
 * If a kernel has renamed one, the honest behaviour is to say which hook is
 * missing — and therefore which column is under-counting — rather than refuse
 * to run or, worse, silently report low numbers.
 */
static int attach_all(struct nettop_bpf *skel)
{
    struct { const char *name; struct bpf_program *prog; struct bpf_link **link; } h[] = {
        { "tcp_sendmsg",        skel->progs.handle_tcp_sendmsg,      &skel->links.handle_tcp_sendmsg      },
        { "tcp_cleanup_rbuf",   skel->progs.handle_tcp_cleanup_rbuf, &skel->links.handle_tcp_cleanup_rbuf },
        { "udp_sendmsg",        skel->progs.handle_udp_sendmsg,      &skel->links.handle_udp_sendmsg      },
        { "udpv6_sendmsg",      skel->progs.handle_udpv6_sendmsg,    &skel->links.handle_udpv6_sendmsg    },
        { "skb_consume_udp",    skel->progs.handle_skb_consume_udp,  &skel->links.handle_skb_consume_udp  },
        { "tcp_retransmit_skb", skel->progs.handle_tcp_retransmit,   &skel->links.handle_tcp_retransmit   },
        { "tcp_close",          skel->progs.handle_tcp_close,        &skel->links.handle_tcp_close        },
    };
    int attached = 0, n = sizeof(h) / sizeof(h[0]);

    for (int i = 0; i < n; i++) {
        *h[i].link = bpf_program__attach(h[i].prog);
        if (!*h[i].link) {
            fprintf(stderr, "warning: could not attach kprobe/%s (%s) — "
                            "its traffic will be missing\n", h[i].name, strerror(errno));
            continue;
        }
        attached++;
    }

    if (attached == 0) {
        fprintf(stderr, "no kprobes attached at all — nothing to report\n");
        return -1;
    }
    fprintf(stderr, "attached %d/%d kprobes\n", attached, n);
    return 0;
}

int main(int argc, char **argv)
{
    struct nettop_bpf *skel = NULL;
    struct row *rows = NULL;
    int err, map_fd, samples = 0;
    struct timespec t_prev, t_now;

    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err)
        return err;

    libbpf_set_print(libbpf_print_fn);
    signal(SIGINT,  on_sigint);
    signal(SIGTERM, on_sigint);

    rows = calloc(MAX_ROWS, sizeof(*rows));
    if (!rows) {
        fprintf(stderr, "out of memory\n");
        return 1;
    }

    skel = nettop_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "failed to open/load BPF skeleton\n");
        free(rows);
        return 1;
    }

    if (attach_all(skel) != 0) {
        err = 1;
        goto cleanup;
    }

    map_fd = bpf_map__fd(skel->maps.proc_stats_map);

    fprintf(stderr, "sampling every %.1fs — Ctrl-C to stop\n", env.interval);

    /*
     * Prime the previous-sample table before the first display, so the opening
     * frame shows real rates instead of one huge fake spike made of every byte
     * sent since boot by an already-running process.
     */
    clock_gettime(CLOCK_MONOTONIC, &t_prev);
    sample(map_fd, env.interval, rows, MAX_ROWS, 1);

    while (!exiting) {
        struct timespec req = {
            .tv_sec  = (time_t)env.interval,
            .tv_nsec = (long)((env.interval - (double)(time_t)env.interval) * 1e9),
        };
        if (nanosleep(&req, NULL) != 0 && errno == EINTR)
            break;                    /* Ctrl-C during the sleep */

        clock_gettime(CLOCK_MONOTONIC, &t_now);
        double elapsed = (double)(t_now.tv_sec - t_prev.tv_sec)
                       + (double)(t_now.tv_nsec - t_prev.tv_nsec) / 1e9;
        t_prev = t_now;
        if (elapsed <= 0)
            elapsed = env.interval;   /* clock went backwards — do not divide by it */

        int n = sample(map_fd, elapsed, rows, MAX_ROWS, 0);
        print_sample(rows, n);

        if (env.count && ++samples >= env.count)
            break;
    }

    err = 0;

cleanup:
    nettop_bpf__destroy(skel);
    free(rows);
    return err;
}
