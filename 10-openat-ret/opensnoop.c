/*
 * opensnoop.c — userspace loader, Chapter 10
 *
 * Receives one event per *completed* openat and prints:
 *
 *   PID      UID    COMM             RET    FLAGS FILENAME
 *   18932    1000   chrome             3    r     /etc/passwd
 *   18933    1000   vim               -2    r     /nonexistent
 *   18934    1000   vim                7    wct   /tmp/.vimswap
 *
 * RET column:
 *   ≥ 0  the file descriptor number (success)
 *   < 0  −errno; common values:
 *          -2   ENOENT  (no such file or directory)
 *          -13  EACCES  (permission denied)
 *          -17  EEXIST  (file already exists, O_CREAT|O_EXCL)
 *
 * Tip: to see only failures, pipe through:
 *   sudo ./opensnoop | awk '$4 < 0'
 *
 * Build:  make
 * Run:    sudo ./opensnoop
 */
#include <stdio.h>
#include <signal.h>
#include <fcntl.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include "opensnoop.skel.h"
#include "opensnoop.h"

static volatile int stop;
static void on_signal(int sig) { stop = 1; }

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
	printf("%-8u %-6u %-16s %6ld  %-5s %s\n",
	       e->pid, e->uid, e->comm,
	       e->ret,
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

	/* attach() pins both trace_enter and trace_exit in one call. */
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

	printf("%-8s %-6s %-16s %6s  %-5s %s\n",
	       "PID", "UID", "COMM", "RET", "FLAGS", "FILENAME");
	printf("%.80s\n",
	       "--------------------------------------------------------------------------------");

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
