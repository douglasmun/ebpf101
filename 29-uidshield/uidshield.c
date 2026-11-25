/*
 * uidshield.c — userspace loader, Chapter 29
 *
 * Resolves each named cgroup to its kernel cgroup id, writes those ids into the
 * `protected_cgroups` map, then attaches the LSM shield. From that point any
 * setuid transition to root (uid 0) inside a protected cgroup is denied
 * (-EPERM); privilege changes everywhere else are untouched.
 *
 * A cgroup id is the inode number of its directory under the cgroup2 mount
 * (/sys/fs/cgroup/...). stat(2) on that directory gives it — the same u64 the
 * kernel returns from bpf_get_current_cgroup_id(). Populate the map BEFORE
 * attach, so the shield is never live with an empty, mis-scoped policy.
 *
 * LSM BPF requires "bpf" to be an ACTIVE LSM (kernel `lsm=` boot param), the
 * Chapter 20 prerequisite; we check it first and explain how to enable it.
 *
 * Build:  make
 * Run:    sudo ./uidshield /sys/fs/cgroup/system.slice/nginx.service
 *         (one or more cgroup2 directory paths)
 */
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <sys/stat.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "uidshield.skel.h"
#include "uidshield.h"

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

/* cgroup id = inode number of the cgroup2 directory. */
static int cgroup_id(const char *path, unsigned long long *id)
{
    struct stat st;
    if (stat(path, &st) != 0) {
        fprintf(stderr, "stat(%s): %s\n", path, strerror(errno));
        return -1;
    }
    *id = st.st_ino;
    return 0;
}

/* The shield emits an event only when it DENIES (the BPF side never reserves one
 * on the allow path), so every event here is a deny; `verdict` is kept in the
 * struct as the explicit record of what was returned to the kernel. */
static int handle_event(void *ctx, void *data, size_t len)
{
    const struct event *e = data;
    printf("%-8u %-7s %-16s %u -> %u\n",
           e->pid, "DENY", e->comm, e->old_euid, e->new_euid);
    return 0;
}

int main(int argc, char **argv)
{
    struct uidshield_bpf *skel;
    struct ring_buffer   *rb;
    int err, map_fd;

    if (argc < 2) {
        fprintf(stderr,
            "usage: %s <cgroup2-dir> [<cgroup2-dir> ...]\n"
            "e.g.:  %s /sys/fs/cgroup/system.slice/nginx.service\n",
            argv[0], argv[0]);
        return 1;
    }

    if (!bpf_lsm_active())
        return 0;   /* prerequisite not met — message already printed */

    libbpf_set_print(NULL);

    skel = uidshield_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open/load BPF skeleton\n");
        return 1;
    }

    /* Populate the policy map BEFORE attach: resolve each cgroup to its id and
     * write it in. The shield must never be live with the wrong scope. */
    map_fd = bpf_map__fd(skel->maps.protected_cgroups);
    for (int i = 1; i < argc; i++) {
        unsigned long long id;
        __u8 one = 1;
        if (cgroup_id(argv[i], &id) != 0) {
            err = 1;
            goto cleanup;
        }
        if (bpf_map_update_elem(map_fd, &id, &one, BPF_ANY)) {
            fprintf(stderr, "map update for %s (id %llu): %s\n",
                    argv[i], id, strerror(errno));
            err = 1;
            goto cleanup;
        }
        printf("protecting %s (cgroup id %llu)\n", argv[i], id);
    }

    err = uidshield_bpf__attach(skel);
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

    printf("\nShield active: escalation to root (uid 0) is DENIED inside the "
           "protected cgroup(s). Ctrl-C to stop.\n");
    printf("%-8s %-7s %-16s %s\n", "PID", "VERDICT", "COMM", "EUID");

    while (!stop) {
        err = ring_buffer__poll(rb, 100);
        if (err == -EINTR) { err = 0; break; }
        if (err < 0) {
            fprintf(stderr, "ring_buffer__poll: %d\n", err);
            break;
        }
    }

    printf("\nDetached — privilege changes allowed again. Bye!\n");
    ring_buffer__free(rb);
cleanup:
    uidshield_bpf__destroy(skel);
    return err < 0 ? 1 : 0;
}
