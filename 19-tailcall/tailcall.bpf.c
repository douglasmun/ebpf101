// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * tailcall.bpf.c — kernel-side, Chapter 19
 *
 * A TAIL CALL lets one BPF program hand control to another. It is the in-kernel
 * equivalent of `goto`/`exec`, not a function call: bpf_tail_call() replaces the
 * running program with the target, reusing the same stack and context, and
 * **never returns** to the caller. Code after a successful tail call does not
 * run. Tail calls are how large eBPF systems split work into stages and scale
 * past the 1-million-instruction verifier limit (each program is verified
 * separately).
 *
 * The target is chosen at runtime from a PROG_ARRAY "jump table", indexed like a
 * switch. Here a dispatcher, on each execve, jumps to a per-privilege handler:
 *
 *      execve ─▶ dispatch ─tail_call(jmp_table[idx])─▶ handle_user  (uid != 0)
 *                                                  └──▶ handle_root  (uid == 0)
 *
 * The jump table is filled from user space (the loader inserts each handler's
 * program fd at its slot) — see tailcall.c.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "tailcall.h"

/* The jump table: slot -> handler program. Only loaders write to it. */
struct {
    __uint(type,        BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 2);            /* IDX_USER, IDX_ROOT */
    __type(key,   __u32);
    __type(value, __u32);              /* a program fd */
} jmp_table SEC(".maps");

/* Tallies, read by user space. */
struct {
    __uint(type,        BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, IDX_MAX);
    __type(key,   __u32);
    __type(value, __u64);
} counts SEC(".maps");

static __always_inline void bump(__u32 idx)
{
    __u64 *c = bpf_map_lookup_elem(&counts, &idx);
    if (c)
        __sync_fetch_and_add(c, 1);
}

SEC("tracepoint/syscalls/sys_enter_execve")
int dispatch(void *ctx)
{
    __u32 uid = bpf_get_current_uid_gid();          /* low 32 bits */
    __u32 idx = (uid == 0) ? IDX_ROOT : IDX_USER;

    /* Jump to the matching handler. On success, execution transfers there and
     * the lines below NEVER run. */
    bpf_tail_call(ctx, &jmp_table, idx);

    /* Reached only if the tail call FAILED (empty slot / over the tail-call
     * depth limit of 33). With both slots populated this stays at zero — which
     * is itself the proof that the jump succeeded. */
    bump(IDX_MISS);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int handle_user(void *ctx)
{
    bump(IDX_USER);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int handle_root(void *ctx)
{
    bump(IDX_ROOT);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
