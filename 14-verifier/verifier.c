/*
 * verifier.c — userspace driver, Chapter 14
 *
 * Walks a set of "lessons". For each, it loads a deliberately-broken BPF
 * program, captures the kernel verifier's rejection, prints it, then loads the
 * corrected version to show it passes.
 *
 * The interesting technique here is getting the verifier log programmatically:
 *   - open the skeleton with kernel_log_buf / kernel_log_level set,
 *   - autoload exactly ONE program (so the log is about that program),
 *   - bpf_object__load() and read the captured log on failure.
 *
 * Loading BPF requires privilege, so run under sudo. There is nothing to
 * attach and no event stream — the whole lesson is at load time.
 *
 * Build:  make
 * Run:    sudo ./verifier
 */
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include "verifier.skel.h"

static char logbuf[128 * 1024];

struct lesson {
    const char *title;
    const char *bad;     /* program (function) name expected to be REJECTED */
    const char *good;    /* corrected program expected to load */
    const char *fix;
};

static struct lesson lessons[] = {
    { "Unchecked map lookup (possible NULL dereference)",
      "bad_null_deref", "good_null_deref",
      "bpf_map_lookup_elem may return NULL; test it before dereferencing." },
    { "Unbounded loop (termination not provable)",
      "bad_unbounded_loop", "good_bounded_loop",
      "Bound the loop with a compile-time constant (or use bpf_loop())." },
    { "Out-of-bounds access (unbounded array index)",
      "bad_oob_index", "good_oob_index",
      "Constrain the index to the buffer size (mask with a constant)." },
};

/* Print the last `n` non-empty lines of the verifier log, indented. */
static void print_log_tail(const char *log, int n)
{
    if (!log || !log[0]) {
        printf("      (no verifier log captured)\n");
        return;
    }
    /* Walk back from the end collecting up to n line starts. */
    int len = strlen(log);
    const char *starts[64];
    int count = 0;
    const char *line = log;
    for (const char *p = log; p <= log + len; p++) {
        if (*p == '\n' || *p == '\0') {
            if (p > line) {              /* skip blank lines */
                if (count < 64) starts[count++] = line;
            }
            line = p + 1;
        }
    }
    int from = count > n ? count - n : 0;
    for (int i = from; i < count; i++) {
        const char *end = strchr(starts[i], '\n');
        int l = end ? (int)(end - starts[i]) : (int)strlen(starts[i]);
        printf("      | %.*s\n", l, starts[i]);
    }
}

/* Load the object with only `only` autoloaded; capture the verifier log when
 * want_log is set. Returns 0 on successful load, negative on failure. */
static int load_only(const char *only, int want_log)
{
    LIBBPF_OPTS(bpf_object_open_opts, opts);
    if (want_log) {
        logbuf[0] = '\0';
        opts.kernel_log_buf   = logbuf;
        opts.kernel_log_size  = sizeof(logbuf);
        opts.kernel_log_level = 1;
    }

    struct verifier_bpf *skel = verifier_bpf__open_opts(&opts);
    if (!skel)
        return -errno;

    struct bpf_program *p;
    bpf_object__for_each_program(p, skel->obj)
        bpf_program__set_autoload(p, strcmp(bpf_program__name(p), only) == 0);

    int err = bpf_object__load(skel->obj);
    verifier_bpf__destroy(skel);
    return err;
}

int main(void)
{
    libbpf_set_print(NULL);   /* silence libbpf's own logging; we print the log */

    printf("Chapter 14 — the verifier in action.\n");
    printf("Each lesson loads a broken program (expect REJECTED), then its fix.\n");
    printf("============================================================\n\n");

    int n = sizeof(lessons) / sizeof(lessons[0]);
    for (int i = 0; i < n; i++) {
        struct lesson *L = &lessons[i];
        printf("Lesson %d: %s\n", i + 1, L->title);

        int err = load_only(L->bad, 1);
        if (err) {
            printf("  [%s] ❌ REJECTED by the verifier (load err %d). Tail of log:\n",
                   L->bad, err);
            print_log_tail(logbuf, 12);
        } else {
            printf("  [%s] ⚠ unexpectedly loaded — this kernel accepted it.\n",
                   L->bad);
        }

        printf("  Fix: %s\n", L->fix);

        int err2 = load_only(L->good, 0);
        printf("  [%s] %s\n\n", L->good,
               err2 == 0 ? "✓ corrected version loads cleanly"
                         : "❌ corrected version unexpectedly failed");
    }

    printf("Done. (No programs were attached — loading is where the verifier runs.)\n");
    return 0;
}
