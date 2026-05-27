// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * opencount.bpf.c — kernel-side, Chapter 16
 *
 * This chapter is about the *operational* side of eBPF — inspecting what is
 * loaded and running with `bpftool` — so the BPF program itself is deliberately
 * tiny. It counts openat(2) calls per user ID into a hash map. Nothing is
 * streamed to user space; the whole point is that `bpftool` reads the map for
 * us from the command line.
 *
 * Like ch14, there is no shared `name.h`: user space never reads the map
 * (bpftool does), so there is no kernel↔user struct to share — the 3-file
 * layout is intentional.
 *
 * The loader pins this map and program under /sys/fs/bpf so they have stable
 * paths bpftool can address; see opencount.c and the chapter notes.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type,        BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key,   __u32);   /* uid */
    __type(value, __u64);   /* number of openat() calls by that uid */
} open_count SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_openat")
int count_open(void *ctx)
{
    __u32 uid = bpf_get_current_uid_gid();   /* low 32 bits = uid */

    __u64 *cnt = bpf_map_lookup_elem(&open_count, &uid);
    if (cnt) {
        __sync_fetch_and_add(cnt, 1);        /* atomic bump across CPUs */
    } else {
        __u64 init = 1;
        /* BPF_NOEXIST: lose the race gracefully if another CPU just inserted */
        bpf_map_update_elem(&open_count, &uid, &init, BPF_NOEXIST);
    }
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
