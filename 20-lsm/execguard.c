/*
 * execguard.c — userspace loader, Chapter 20
 *
 * Loads the LSM bprm_check program and prints the verdict it returns for every
 * program execution (always "allow" — this is an auditor, not a blocker).
 *
 * LSM BPF requires "bpf" to be an ACTIVE LSM, set via the kernel `lsm=` boot
 * parameter. If it isn't, an LSM program cannot attach — so we check first and
 * explain how to enable it, instead of failing with a cryptic error.
 *
 * Build:  make
 * Run:    sudo ./execguard          (then run commands in another terminal)
 */
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include "execguard.skel.h"
#include "execguard.h"

static volatile int stop;
static void on_signal(int sig) { stop = 1; }

/* Return 1 if "bpf" is among the active LSMs; print the list either way. */
static int bpf_lsm_active(void)
{
    char buf[256] = {};
    FILE *f = fopen("/sys/kernel/security/lsm", "r");
    if (!f)
        return 0;
    if (!fgets(buf, sizeof(buf), f)) { fclose(f); return 0; }
    fclose(f);

    /* Tokenise the comma-separated list and look for an exact "bpf". */
    int found = 0;
    char tmp[256];
    snprintf(tmp, sizeof(tmp), "%s", buf);
    for (char *tok = strtok(tmp, ",\n"); tok; tok = strtok(NULL, ",\n"))
        if (strcmp(tok, "bpf") == 0)
            found = 1;

    if (!found)
        fprintf(stderr,
            "BPF LSM is not active. Current LSMs: %s\n"
            "Enable it (CONFIG_BPF_LSM is already =y, so only a boot param + reboot):\n"
            "  1. add 'bpf' to the lsm= list in /etc/default/grub, e.g.\n"
            "     GRUB_CMDLINE_LINUX=\"... lsm=lockdown,capability,landlock,yama,apparmor,bpf\"\n"
            "  2. sudo update-grub && sudo reboot\n"
            "Then re-run this program.\n", buf);
    return found;
}

static int handle_event(void *ctx, void *data, size_t len)
{
    const struct event *e = data;
    printf("%-8u %-7s %-16s %s\n",
           e->pid,
           e->verdict == 0 ? "allow" : "DENY",
           e->comm, e->filename);
    return 0;
}

int main(void)
{
    struct execguard_bpf *skel;
    struct ring_buffer   *rb;
    int err;

    if (!bpf_lsm_active())
        return 0;   /* prerequisite not met — message already printed */

    libbpf_set_print(NULL);

    skel = execguard_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open/load BPF skeleton\n");
        return 1;
    }

    err = execguard_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach LSM program: %d\n", err);
        goto cleanup;
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        err = 1;
        goto cleanup;
    }

    signal(SIGINT,  on_signal);
    signal(SIGTERM, on_signal);

    printf("Auditing exec via LSM bprm_check (always allowing). Ctrl-C to stop.\n");
    printf("%-8s %-7s %-16s %s\n", "PID", "VERDICT", "COMM", "PROGRAM");

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
    execguard_bpf__destroy(skel);
    return err < 0 ? 1 : 0;
}
