/*
 * execsnoop.c — userspace loader, Chapter 8
 *
 * Ports the Python pending-dict from ch5/6 to C.
 *
 * Python used a dict keyed by PID:
 *
 *     pending = {}
 *     if event.type == EVENT_ARG:
 *         pending.setdefault(pid, {..., "argv": []})["argv"].append(arg)
 *     else:
 *         slot = pending.pop(pid); print(" ".join(slot["argv"]))
 *
 * C equivalent: a fixed-size table of slots indexed by pid % TABLE_SIZE.
 * Collision caveat: if two active PIDs map to the same slot the older one
 * is overwritten.  For an execve monitor this is rare and inconsequential
 * (we might lose one command line), acceptable for a learning tool.
 *
 * Build:  make
 * Run:    sudo ./execsnoop
 */
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include "execsnoop.skel.h"
#include "execsnoop.h"

/* ── pending table ──────────────────────────────────────────────────────── */

#define TABLE_SIZE 4096   /* power of 2; index = pid % TABLE_SIZE */

struct pending {
	int          active;
	unsigned int pid;
	unsigned int uid;
	char         comm[16];
	char         argv[MAXARGS][ARGSIZE];
	int          argc;
};

static struct pending table[TABLE_SIZE];   /* zero-initialised (BSS) */

static struct pending *get_slot(unsigned int pid)
{
	return &table[pid % TABLE_SIZE];
}

/* ── event handler ──────────────────────────────────────────────────────── */

static volatile int stop;
static void on_signal(int sig) { stop = 1; }

static int handle_event(void *ctx, void *data, size_t len)
{
	const struct event *e = data;
	struct pending     *p = get_slot(e->pid);

	if (e->type == EVENT_ARG) {
		/* Start a new slot or append to the existing one for this PID. */
		if (!p->active || p->pid != e->pid) {
			memset(p, 0, sizeof(*p));
			p->active = 1;
			p->pid    = e->pid;
			p->uid    = e->uid;
			memcpy(p->comm, e->comm, sizeof(p->comm));
		}
		if (p->argc < MAXARGS) {
			strncpy(p->argv[p->argc], e->arg, ARGSIZE - 1);
			p->argv[p->argc][ARGSIZE - 1] = '\0';
			p->argc++;
		}
	} else {  /* EVENT_RET — print and clear */
		if (!p->active || p->pid != e->pid)
			return 0;

		printf("%-8u %-6u %-16s", p->pid, p->uid, p->comm);
		for (int i = 0; i < p->argc; i++)
			printf(" %s", p->argv[i]);
		printf("\n");

		p->active = 0;
	}
	return 0;
}

/* ── main ───────────────────────────────────────────────────────────────── */

int main(void)
{
	struct execsnoop_bpf *skel;
	struct ring_buffer   *rb;
	int err;

	libbpf_set_print(NULL);

	skel = execsnoop_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open/load BPF skeleton\n");
		return 1;
	}

	err = execsnoop_bpf__attach(skel);
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

	printf("%-8s %-6s %-16s %s\n", "PID", "UID", "COMM", "COMMAND LINE");
	printf("%.70s\n",
	       "----------------------------------------------------------------------");

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
	execsnoop_bpf__destroy(skel);
	return err < 0 ? 1 : 0;
}
