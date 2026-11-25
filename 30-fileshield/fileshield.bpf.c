// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * fileshield.bpf.c — kernel-side, Chapter 30
 *
 * A sensitive-file shield. Chapters 28 and 29 denied the exec and the privilege
 * gain an exploit needs; this chapter denies the READ it wants — the first open
 * of a credential store like /etc/shadow. Same scoped-LSM enforcement, a third
 * chokepoint.
 *
 * The idea: a service like an Nginx worker never legitimately opens
 * /etc/shadow. So inside its cgroup we deny any open of a guarded file. A novel
 * RCE that lands in the service still has to READ the secret it is after — the
 * shadow file, a private key, a token store — and that open dies here, with no
 * knowledge of the bug that let the attacker in. This is the "first read of
 * /etc/shadow" signal from the Shirudo note, wired to DENY.
 *
 * Hook: lsm/file_open fires on every file open, before the opening task gets a
 * usable fd. Returning <0 vetoes the open, so open(2) fails with the errno we
 * return. We match the file by (device, inode) — not by a path string — so the
 * guard holds whatever name reached the file: a symlink, a bind mount, a hard
 * link all resolve to the same (dev, ino). The loader resolves each guarded
 * path to its (dev, ino) and writes it in before attach.
 *
 * Scope is the safety rail, identical to ch28/29: only opens inside a protected
 * cgroup (or a descendant — the hierarchical walk, issue #6) are governed;
 * everything else returns 0 (allow). So this program can never make a guarded
 * file unreadable to the rest of the host, only to the protected service.
 *
 * Prerequisite: "bpf" must be an active LSM (kernel `lsm=` boot param), the
 * same wall as Chapter 20. The loader checks it; see fileshield.c.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "fileshield.h"

#ifndef EPERM
#define EPERM 1
#endif

char LICENSE[] SEC("license") = "GPL";

#define CGROUP_WALK_DEPTH 16

/* Guarded files: key = (dev, ino), value = 1. Populated from userspace before
 * attach. Empty = guard nothing (safe default). */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct file_key);
    __type(value, __u8);
} guarded_files SEC(".maps");

/* Protected cgroups: key = cgroup id (u64), value = 1. Scope the shield to a
 * service, exactly as in ch28/29. Empty = govern nothing. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, __u8);
} protected_cgroups SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

/* True if the task is in a protected cgroup or any descendant of one (the ch28
 * ancestry walk verbatim). */
static __always_inline bool in_protected_scope(void)
{
    __u64 cg = bpf_get_current_cgroup_id();
    if (bpf_map_lookup_elem(&protected_cgroups, &cg))
        return true;

    for (int level = 0; level < CGROUP_WALK_DEPTH; level++) {
        __u64 anc = bpf_get_current_ancestor_cgroup_id(level);
        if (!anc || anc == cg)
            break;
        if (bpf_map_lookup_elem(&protected_cgroups, &anc))
            return true;
    }
    return false;
}

SEC("lsm/file_open")
int BPF_PROG(file_shield, struct file *file)
{
    /* SCOPE FIRST — never govern an open outside a protected subtree, so a
     * guarded file stays readable everywhere else on the host. */
    if (!in_protected_scope())
        return 0;

    /* Identify the file by (device, inode), read from its inode via CO-RE.
     * i_sb->s_dev is the kernel's dev_t; the loader encodes its stat() result
     * to match (see the makedev note in fileshield.c). */
    struct inode *inode = BPF_CORE_READ(file, f_inode);
    if (!inode)
        return 0;

    struct file_key key = {};
    key.ino = BPF_CORE_READ(inode, i_ino);
    key.dev = BPF_CORE_READ(inode, i_sb, s_dev);

    if (!bpf_map_lookup_elem(&guarded_files, &key))
        return 0;                           /* not a guarded file → allow */

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (e) {
        e->pid     = bpf_get_current_pid_tgid() >> 32;
        e->verdict = -EPERM;
        e->dev     = key.dev;
        e->ino     = key.ino;
        bpf_get_current_comm(&e->comm, sizeof(e->comm));
        bpf_ringbuf_submit(e, 0);
    }

    /* THE VERDICT: deny the open. Safe only because of the scope check above —
     * outside a protected cgroup, the guarded file opens normally. */
    return -EPERM;
}
