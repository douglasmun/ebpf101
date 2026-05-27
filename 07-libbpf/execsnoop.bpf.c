// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * execsnoop.bpf.c — kernel-side eBPF program, Chapter 7
 *
 * Compare to chapters 1-6 (BCC):
 *
 *   BCC                            libbpf (this chapter)
 *   ─────────────────────────────────────────────────────
 *   Embedded C string in Python    Real .c file compiled by clang
 *   Compiled at load time (LLVM)   Compiled at *build* time → portable .o
 *   Kernel types via runtime BTF   Kernel types via vmlinux.h (CO-RE)
 *   BPF_RINGBUF_OUTPUT macro       BPF_MAP_TYPE_RINGBUF BTF map
 *   events.ringbuf_reserve(…)      bpf_ringbuf_reserve(…)
 *
 * CO-RE (Compile Once, Run Everywhere): vmlinux.h embeds every kernel type
 * with BTF annotations.  At load time libbpf patches field offsets against
 * the *running* kernel's BTF — the binary works on any BTF-enabled kernel
 * without recompilation.
 *
 * This program is simpler than ch5/6: one fixed-size record per execve
 * (pid, uid, comm, filename) — no multi-record argv reassembly.
 * That pattern is added in ch8 once the libbpf toolchain feels familiar.
 */
#include "vmlinux.h"          /* all kernel types, generated from BTF */
#include <bpf/bpf_helpers.h>  /* bpf_get_current_pid_tgid, etc.       */
#include <bpf/bpf_tracing.h>  /* SEC() macro                          */
#include "execsnoop.h"

/* Ring buffer map: one shared buffer for all CPUs.
 * max_entries is the buffer size in bytes (must be a multiple of page size).
 */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);  /* 256 KB */
} events SEC(".maps");

/*
 * Attach to the sys_enter_execve tracepoint.
 *
 * ctx is trace_event_raw_sys_enter (from vmlinux.h), which has:
 *   long args[6]  — the raw syscall register values (one per argument)
 * For execve:
 *   args[0] = filename  — char*  the binary path being executed
 *   args[1] = argv      — char** the argument vector (NULL-terminated array)
 *   args[2] = envp      — char** the environment vector
 * We only read args[0] here; ch8 adds argv reading.
 */
SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx)
{
	struct event *e;

	/* Reserve a slot directly inside the ring buffer — no BPF-stack copy. */
	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;  /* ring full — drop this event */

	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	/* Copy the filename string from user space into the ring slot. */
	bpf_probe_read_user_str(e->filename, sizeof(e->filename),
				(const char *)ctx->args[0]);

	bpf_ringbuf_submit(e, 0);  /* commit: make visible to user space */
	return 0;
}

/* Every libbpf program needs a license string so the kernel can verify
 * that helper calls are permitted for the declared license. */
char LICENSE[] SEC("license") = "GPL";
