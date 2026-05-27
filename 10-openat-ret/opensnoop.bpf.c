// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * opensnoop.bpf.c — kernel-side, Chapter 10
 *
 * New pattern: entry/exit correlation.
 *
 * Chapter 9 hooked sys_enter_openat and could see what was being opened,
 * but not whether it succeeded.  The return value (fd number or −errno) only
 * exists at the *exit* tracepoint.  To print both together we need two
 * cooperating BPF programs sharing state through a map:
 *
 *   sys_enter_openat  ──┐  stash { filename, flags } keyed by pid
 *                        │
 *   sys_exit_openat   ──┘  look up stash, add ret, emit to ring buffer
 *
 * The stash map is a BPF_MAP_TYPE_HASH: a kernel-resident hash table
 * keyed by u32 pid.  Both programs run in the same kernel context so they
 * share the map naturally.  User space only reads from the ring buffer;
 * it never touches the stash map.
 *
 * Two BPF programs in one object file is normal: bpftool gen skeleton
 * generates one attach function per SEC(), and opensnoop_bpf__attach()
 * pins both in a single call.
 *
 * Edge cases we accept for a learning tool:
 *   - If enter fires but exit never does (process killed mid-syscall),
 *     the stash entry leaks until a future pid-reuse overwrites it.
 *   - On a very busy system, bpf_map_update_elem with BPF_ANY silently
 *     overwrites a stale entry for a reused PID.
 * Production tools (bcc's opensnoop, libbpf-tools) handle these with a
 * per-thread key (pid<<32 | tid) and a bounded map with LRU eviction.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "opensnoop.h"

/* Stash map: pid → { filename, flags } saved at enter, consumed at exit. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key,   __u32);
	__type(value, struct entry_t);
} stash SEC(".maps");

/* Ring buffer: one record per *completed* openat (emitted at exit). */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

/* ── enter: save filename + flags, keyed by pid ───────────────────────── */
SEC("tracepoint/syscalls/sys_enter_openat")
int trace_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	struct entry_t e = {};

	e.flags = (int)ctx->args[2];
	bpf_probe_read_user_str(e.filename, sizeof(e.filename),
				(const char *)ctx->args[1]);

	/* BPF_ANY: insert or overwrite (handles PID reuse silently). */
	bpf_map_update_elem(&stash, &pid, &e, BPF_ANY);
	return 0;
}

/* ── exit: look up stash, combine with return value, emit ────────────── */
SEC("tracepoint/syscalls/sys_exit_openat")
int trace_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	struct entry_t *ep;
	struct event   *out;

	/* If there's no stash entry we missed the enter (e.g., we loaded
	 * the program after the enter had already fired). */
	ep = bpf_map_lookup_elem(&stash, &pid);
	if (!ep)
		return 0;

	out = bpf_ringbuf_reserve(&events, sizeof(*out), 0);
	if (!out) {
		bpf_map_delete_elem(&stash, &pid);
		return 0;
	}

	out->pid   = pid;
	out->uid   = bpf_get_current_uid_gid() & 0xFFFFFFFF;
	bpf_get_current_comm(&out->comm, sizeof(out->comm));
	out->flags = ep->flags;
	out->ret   = ctx->ret;   /* fd (≥0) or −errno (<0) */
	__builtin_memcpy(out->filename, ep->filename, sizeof(out->filename));

	bpf_map_delete_elem(&stash, &pid);
	bpf_ringbuf_submit(out, 0);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
