/*
 * opensnoop.c — userspace loader, Chapter 9
 *
 * Receives one event per openat syscall and prints it with decoded flags.
 *
 * Flag decoding (the raw integer is a bitmask):
 *
 *   Access mode (lowest 2 bits, O_ACCMODE = 0x3):
 *     O_RDONLY = 0  → "r"
 *     O_WRONLY = 1  → "w"
 *     O_RDWR   = 2  → "rw"
 *
 *   Modifiers (ORed in):
 *     O_CREAT  = 0x40  → append "c"  (create if missing)
 *     O_TRUNC  = 0x200 → append "t"  (truncate to zero on open)
 *
 *   Examples:
 *     0x0   → "r"    (read-only open of an existing file)
 *     0x241 → "wct"  (write + create + truncate = create-or-overwrite)
 *     0x42  → "rwc"  (read-write + create)
 *
 * Volume: openat fires on *every* file open, including /proc reads,
 * library loads, and inotify internals.  Pipe through grep to focus:
 *
 *     sudo ./opensnoop | grep -v /proc
 *     sudo ./opensnoop | grep "wc\|wct"   # writes only
 *
 * Build:  make
 * Run:    sudo ./opensnoop
 */
#include <stdio.h>
#include <signal.h>
#include <fcntl.h>     /* O_RDONLY, O_WRONLY, O_RDWR, O_CREAT, O_TRUNC */
#include <errno.h>
#include <bpf/libbpf.h>
#include "opensnoop.skel.h"
#include "opensnoop.h"

static volatile int stop;
static void on_signal(int sig) { stop = 1; }

/* Decode the raw O_* flags integer into a compact human-readable string. */
static const char *decode_flags(int flags, char *buf, size_t bufsz)
{
	const char *acc;
	switch (flags & O_ACCMODE) {
	case O_RDONLY: acc = "r";  break;
	case O_WRONLY: acc = "w";  break;
	case O_RDWR:   acc = "rw"; break;
	default:       acc = "?";  break;
	}
	snprintf(buf, bufsz, "%s%s%s",
		 acc,
		 (flags & O_CREAT) ? "c" : "",
		 (flags & O_TRUNC) ? "t" : "");
	return buf;
}

static int handle_event(void *ctx, void *data, size_t len)
{
	const struct event *e = data;
	char fbuf[8];
	printf("%-8u %-6u %-16s %-5s %s\n",
	       e->pid, e->uid, e->comm,
	       decode_flags(e->flags, fbuf, sizeof(fbuf)),
	       e->filename);
	return 0;
}

int main(void)
{
	struct opensnoop_bpf *skel;
	struct ring_buffer   *rb;
	int err;

	libbpf_set_print(NULL);

	skel = opensnoop_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open/load BPF skeleton\n");
		return 1;
	}

	err = opensnoop_bpf__attach(skel);
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

	printf("%-8s %-6s %-16s %-5s %s\n",
	       "PID", "UID", "COMM", "FLAGS", "FILENAME");
	printf("%.78s\n",
	       "------------------------------------------------------------------------------");

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
	opensnoop_bpf__destroy(skel);
	return err < 0 ? 1 : 0;
}
