// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * verifier.bpf.c — kernel-side, Chapter 14
 *
 * Unlike every other chapter, this file is NOT a working tool. Each program
 * here is a teaching specimen: a `bad_*` program written to be REJECTED by the
 * verifier, paired with a `good_*` program showing the fix. Nothing is attached
 * and nothing streams to user space — the lesson happens entirely at *load*
 * time, which is when the verifier runs.
 *
 * Key idea: clang compiles all of these without complaint. The verifier is a
 * separate gate, inside the kernel, that runs when the program is loaded. It
 * proves — before letting your code run — that the program is safe: every
 * memory access is in bounds, every pointer is checked, and every path
 * terminates. These specimens each violate one of those guarantees.
 *
 * The SEC() is "kprobe/do_nanosleep" for all of them only so they have a valid
 * program type to load; we never attach, so the target function is irrelevant.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key,   __u32);
    __type(value, __u64);
} counts SEC(".maps");

/* ── Lesson 1: a map lookup can return NULL ──────────────────────────────────
 *
 * bpf_map_lookup_elem returns a pointer to the value OR NULL (key absent). The
 * verifier types the result "map_value_or_null" and refuses to let you touch it
 * until you have proven it is not NULL. This is the single most common beginner
 * rejection.
 */
SEC("kprobe/do_nanosleep")
int bad_null_deref(void *ctx)
{
    __u32 key = 0;
    __u64 *val = bpf_map_lookup_elem(&counts, &key);
    *val += 1;                 /* BUG: val may be NULL */
    return 0;
}

SEC("kprobe/do_nanosleep")
int good_null_deref(void *ctx)
{
    __u32 key = 0;
    __u64 *val = bpf_map_lookup_elem(&counts, &key);
    if (!val)                  /* FIX: prove non-NULL before dereferencing */
        return 0;
    *val += 1;
    return 0;
}

/* ── Lesson 2: every loop must provably terminate ────────────────────────────
 *
 * The verifier walks all execution paths; a back-edge it cannot bound is a
 * potential infinite loop, which it rejects. A constant upper bound (or
 * bpf_loop()) gives it the proof it needs.
 */
SEC("kprobe/do_nanosleep")
int bad_unbounded_loop(void *ctx)
{
    int cnt = 0;
    /* BUG: a runtime condition the verifier can't bound — may never end */
    while (bpf_get_prandom_u32() & 1)
        cnt++;
    return cnt;
}

SEC("kprobe/do_nanosleep")
int good_bounded_loop(void *ctx)
{
    int cnt = 0;
    for (int i = 0; i < 64; i++)   /* FIX: constant bound the verifier can walk */
        cnt += i;
    return cnt;
}

/* ── Lesson 3: every memory access must be provably in bounds ────────────────
 *
 * A variable index into a buffer could point anywhere, so the verifier refuses
 * it until the index is constrained to the buffer's size. Masking with a
 * constant (here & 0xf, i.e. 0..15) gives the proof; a bare runtime value does
 * not.
 *
 * (Contrast with the 512-byte BPF stack limit: that one is caught even earlier,
 * by clang's own BPF backend, so a too-big stack array never even compiles —
 * see the chapter notes. This lesson is a genuinely verifier-only rejection.)
 */
SEC("kprobe/do_nanosleep")
int bad_oob_index(void *ctx)
{
    char buf[16] = {};
    __u32 i = bpf_get_prandom_u32();     /* BUG: unbounded index, 0 .. 2^32-1 */
    buf[i] = 1;
    return buf[0];
}

SEC("kprobe/do_nanosleep")
int good_oob_index(void *ctx)
{
    char buf[16] = {};
    __u32 i = bpf_get_prandom_u32() & 0xf;   /* FIX: mask to a valid 0..15 */
    buf[i] = 1;
    return buf[0];
}

char LICENSE[] SEC("license") = "GPL";
