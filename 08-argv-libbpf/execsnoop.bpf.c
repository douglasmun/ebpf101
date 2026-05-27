// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * execsnoop.bpf.c — kernel-side, Chapter 8
 *
 * This is a direct port of the Chapter 5/6 BCC program to native C + libbpf.
 * The logic is identical; only the syntax changes:
 *
 *   BCC                                  libbpf (this file)
 *   ──────────────────────────────────────────────────────
 *   BPF_RINGBUF_OUTPUT(events, 1<<4)     BTF map struct { … } events
 *   events.ringbuf_reserve(sizeof(*s))   bpf_ringbuf_reserve(&events, …)
 *   events.ringbuf_submit(s, 0)          bpf_ringbuf_submit(s, 0)
 *   TRACEPOINT_PROBE(syscalls, …)        SEC("tracepoint/syscalls/…") int fn(…)
 *   args->argv                           (const char *const *)ctx->args[1]
 *
 * Protocol (unchanged from ch 5/6):
 *   For each execve: emit one EVENT_ARG record per argv string, then
 *   one EVENT_RET record as an end-of-command marker.
 *   User space accumulates args per PID in a table, prints on EVENT_RET.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "execsnoop.h"

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx)
{
	unsigned int pid = bpf_get_current_pid_tgid() >> 32;
	unsigned int uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
	char comm[16];
	bpf_get_current_comm(comm, sizeof(comm));

	const char *const *argv = (const char *const *)ctx->args[1];

	#pragma unroll
	for (int i = 0; i < MAXARGS; i++) {
		const char *argp = NULL;
		/* Read #1: copy the i-th pointer out of the argv array. */
		bpf_probe_read_user(&argp, sizeof(argp), &argv[i]);
		if (!argp)
			break;  /* NULL terminator */

		struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
		if (!e) return 0;   /* ring full — drop remaining args */
		e->pid  = pid;
		e->uid  = uid;
		__builtin_memcpy(e->comm, comm, sizeof(e->comm));
		e->type = EVENT_ARG;
		/* Read #2: copy the string the pointer points to. */
		bpf_probe_read_user_str(e->arg, sizeof(e->arg), argp);
		bpf_ringbuf_submit(e, 0);
	}

	/* End-of-command marker — tells user space to print and clear. */
	struct event *ret = bpf_ringbuf_reserve(&events, sizeof(*ret), 0);
	if (!ret) return 0;
	ret->pid    = pid;
	ret->uid    = uid;
	__builtin_memcpy(ret->comm, comm, sizeof(ret->comm));
	ret->type   = EVENT_RET;
	ret->arg[0] = '\0';
	bpf_ringbuf_submit(ret, 0);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
