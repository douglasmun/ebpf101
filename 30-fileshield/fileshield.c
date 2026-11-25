/*
 * fileshield.c — userspace loader, Chapter 30
 *
 * Resolves each named cgroup to its cgroup id and each guarded file to its
 * (device, inode), writes both into their maps, then attaches the LSM shield.
 * From that point any open of a guarded file inside a protected cgroup is
 * denied (-EPERM); opens everywhere else, and of any other file, are untouched.
 *
 * Two resolutions, both from stat(2):
 *   - cgroup id   = st_ino of the cgroup2 directory (as in ch28/29).
 *   - guarded file= (st_dev, st_ino) of the file.
 *
 * The dev_t encoding gotcha: glibc's st_dev and the kernel's inode->i_sb->s_dev
 * do NOT use the same bit packing. s_dev holds the raw in-kernel dev_t,
 * MKDEV(major, minor) = (major << 20) | minor — not the new_encode_dev() packing
 * stat(2) exports. We decode st_dev with major()/minor() and re-encode with
 * MKDEV so the key the shield builds in-kernel matches the key we write here.
 * Getting this wrong makes the shield silently never match — so the verify
 * script proves a real deny, not just a load. (It caught exactly this: the first
 * run encoded with the wrong layout and the guarded open was allowed.)
 *
 * LSM BPF requires "bpf" to be an ACTIVE LSM (kernel `lsm=` boot param), the
 * Chapter 20 prerequisite; we check it first and explain how to enable it.
 *
 * Build:  make
 * Run:    sudo ./fileshield -c /sys/fs/cgroup/system.slice/nginx.service \
 *                           -f /etc/shadow [-f <path> ...]
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>          /* getopt(), optarg */
#include <sys/stat.h>
#include <sys/sysmacros.h>   /* major(), minor() */
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "fileshield.skel.h"
#include "fileshield.h"

static volatile int stop;
static void on_signal(int sig) { stop = 1; }

/*
 * What inode->i_sb->s_dev actually holds. s_dev is the raw in-kernel dev_t
 * (kdev_t), which is MKDEV(major, minor) = (major << 20) | minor — NOT the
 * new_encode_dev() packing that stat(2) exports to userspace. glibc's st_dev
 * uses yet another layout, so we decode st_dev with the glibc major()/minor()
 * accessors and re-encode with the kernel's MKDEV so our map key matches the
 * (dev, ino) the BPF program builds from the inode. (Verified against
 * bpf_printk: an ext4 file at glibc st_dev 64769 shows s_dev 265289729 in
 * kernel, i.e. (253 << 20) | 1.)
 */
#define KERNEL_MINORBITS 20
static unsigned long long kernel_encode_dev(dev_t st_dev)
{
    unsigned int maj = major(st_dev);
    unsigned int min = minor(st_dev);
    return ((unsigned long long)maj << KERNEL_MINORBITS) | (unsigned long long)min;
}

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

static int add_cgroup(int map_fd, const char *path)
{
    struct stat st;
    if (stat(path, &st) != 0) {
        fprintf(stderr, "stat cgroup %s: %s\n", path, strerror(errno));
        return -1;
    }
    unsigned long long id = st.st_ino;
    __u8 one = 1;
    if (bpf_map_update_elem(map_fd, &id, &one, BPF_ANY)) {
        fprintf(stderr, "map update (cgroup %s): %s\n", path, strerror(errno));
        return -1;
    }
    printf("protecting cgroup %s (id %llu)\n", path, id);
    return 0;
}

static int add_file(int map_fd, const char *path)
{
    struct stat st;
    if (stat(path, &st) != 0) {
        fprintf(stderr, "stat file %s: %s\n", path, strerror(errno));
        return -1;
    }
    struct file_key key = {
        .dev = kernel_encode_dev(st.st_dev),
        .ino = st.st_ino,
    };
    __u8 one = 1;
    if (bpf_map_update_elem(map_fd, &key, &one, BPF_ANY)) {
        fprintf(stderr, "map update (file %s): %s\n", path, strerror(errno));
        return -1;
    }
    printf("guarding file %s (dev %llu, ino %llu)\n", path, key.dev, key.ino);
    return 0;
}

/* The shield emits an event only when it DENIES (the BPF side never reserves one
 * on the allow path), so every event here is a deny; `verdict` is kept in the
 * struct as the explicit record of what was returned to the kernel. */
static int handle_event(void *ctx, void *data, size_t len)
{
    const struct event *e = data;
    printf("%-8u %-7s %-16s dev=%llu ino=%llu\n",
           e->pid, "DENY", e->comm, e->dev, e->ino);
    return 0;
}

static void usage(const char *p)
{
    fprintf(stderr,
        "usage: %s -c <cgroup2-dir> [-c ...] -f <file> [-f ...]\n"
        "e.g.:  %s -c /sys/fs/cgroup/system.slice/nginx.service -f /etc/shadow\n",
        p, p);
}

int main(int argc, char **argv)
{
    struct fileshield_bpf *skel;
    struct ring_buffer    *rb;
    int err = 0, opt;
    const char *cgroups[64]; int n_cg = 0;
    const char *files[64];   int n_f  = 0;

    while ((opt = getopt(argc, argv, "c:f:")) != -1) {
        switch (opt) {
        case 'c': if (n_cg < 64) cgroups[n_cg++] = optarg; break;
        case 'f': if (n_f  < 64) files[n_f++]   = optarg; break;
        default:  usage(argv[0]); return 1;
        }
    }
    if (n_cg == 0 || n_f == 0) { usage(argv[0]); return 1; }

    if (!bpf_lsm_active())
        return 0;   /* prerequisite not met — message already printed */

    libbpf_set_print(NULL);

    skel = fileshield_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open/load BPF skeleton\n");
        return 1;
    }

    /* Populate BOTH maps BEFORE attach, so the shield is never live with an
     * empty or mis-scoped policy. */
    int cg_fd = bpf_map__fd(skel->maps.protected_cgroups);
    int f_fd  = bpf_map__fd(skel->maps.guarded_files);
    for (int i = 0; i < n_cg; i++)
        if (add_cgroup(cg_fd, cgroups[i]) != 0) { err = 1; goto cleanup; }
    for (int i = 0; i < n_f; i++)
        if (add_file(f_fd, files[i]) != 0) { err = 1; goto cleanup; }

    err = fileshield_bpf__attach(skel);
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

    printf("\nShield active: opening a guarded file is DENIED inside the "
           "protected cgroup(s). Ctrl-C to stop.\n");
    printf("%-8s %-7s %-16s %s\n", "PID", "VERDICT", "COMM", "FILE");

    while (!stop) {
        err = ring_buffer__poll(rb, 100);
        if (err == -EINTR) { err = 0; break; }
        if (err < 0) {
            fprintf(stderr, "ring_buffer__poll: %d\n", err);
            break;
        }
    }

    printf("\nDetached — guarded files open normally again. Bye!\n");
    ring_buffer__free(rb);
cleanup:
    fileshield_bpf__destroy(skel);
    return err < 0 ? 1 : 0;
}
