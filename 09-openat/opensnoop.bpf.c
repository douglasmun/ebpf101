// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * opensnoop.bpf.c — kernel-side, Chapter 9
 *
 * First hook beyond execve: sys_enter_openat fires on every file open.
 *
 * The tracepoint has four arguments (ctx->args[]):
 *   [0] dfd      — directory fd (AT_FDCWD = -100 means "relative to cwd")
 *   [1] filename — pointer to the path string in user space
 *   [2] flags    — O_RDONLY / O_WRONLY / O_RDWR / O_CREAT / O_TRUNC …
 *   [3] mode     — permission bits for newly created files
 *
 * We skip dfd and mode; filename + flags tell us what was opened and why.
 *
 * The BPF side is intentionally minimal — one record per openat, no
 * filtering.  User space receives everything and can grep for patterns.
 * Filtering in kernel (e.g., skip read-only opens) is straightforward to
 * add; it is shown as a comment below as the idiomatic next step.
 *
 * Toolchain note: identical to ch7/8 — only the SEC() annotation and the
 * args[] indices change.  The same vmlinux.h, skeleton, and ring buffer
 * pattern applies to every tracepoint in the kernel.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "opensnoop.h"

/* O_* constants are preprocessor macros, not BTF types, so they are not
 * in vmlinux.h.  Define the ones referenced in the filter example below. */
#define O_ACCMODE  3     /* mask for the access-mode bits (lowest 2 bits) */
#define O_RDONLY   0
#define O_WRONLY   1
#define O_RDWR     2
#define O_CREAT    0x40
#define O_TRUNC    0x200

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx)
{
	struct event *e;

	/*
	 * Kernel-side filter example (uncomment to show only write opens):
	 *
	 *   int flags = (int)ctx->args[2];
	 *   if ((flags & O_ACCMODE) == O_RDONLY) return 0;
	 *
	 * Doing this in the kernel means zero cost for dropped events —
	 * they never cross the ring buffer at all.
	 */

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) return 0;

	e->pid   = bpf_get_current_pid_tgid() >> 32;
	e->uid   = bpf_get_current_uid_gid() & 0xFFFFFFFF;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	e->flags = (int)ctx->args[2];
	bpf_probe_read_user_str(e->filename, sizeof(e->filename),
				(const char *)ctx->args[1]);

	bpf_ringbuf_submit(e, 0);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
