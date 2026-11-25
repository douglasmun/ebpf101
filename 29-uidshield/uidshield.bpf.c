// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * uidshield.bpf.c — kernel-side, Chapter 29
 *
 * A least-privilege privilege-escalation shield. Chapter 28 denied the exec a
 * landed exploit needs to spawn a shell; this chapter denies the OTHER move an
 * exploit makes once it is inside: raising its own privilege to root.
 *
 * The idea: a service like an Nginx worker drops to an unprivileged uid at
 * startup and never legitimately becomes root again. So inside its cgroup we
 * deny any credential change that would set the effective uid to 0. A novel RCE
 * that gives an attacker code execution as the service uid still has to escalate
 * — call setuid(0) after a sudo-style bug, or ride a capability — and that
 * transition dies here, with no knowledge of the bug that let the attacker in.
 * The policy is on the TECHNIQUE (becoming root), not on any one vulnerability.
 * This is the "sudden UID change" signal the Shirudo note names, wired to DENY.
 *
 * Hook: lsm/task_fix_setuid fires whenever a task's uid set is about to change
 * (setuid/setreuid/setresuid and the kernel paths they reach). `new` and `old`
 * are the proposed and current credentials; returning <0 vetoes the change, so
 * the syscall fails with the errno we return and the task keeps its old uids.
 *
 * Scope is the safety rail, identical to ch28: the loader writes the protected
 * cgroup ids into `protected_cgroups`; transitions in any other cgroup return 0
 * (allow) untouched, so this program can never lock root out of the host. Scope
 * is HIERARCHICAL — we match the task's leaf cgroup AND every ancestor, so
 * protecting a service covers the workers it spawns in child cgroups (ebpf101
 * issue #6, the same walk ch28 uses).
 *
 * Prerequisite: "bpf" must be an active LSM (kernel `lsm=` boot param), the
 * same wall as Chapter 20. The loader checks it; see uidshield.c.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "uidshield.h"

/* vmlinux.h carries no errno macros and a BPF program cannot include
 * <linux/errno.h>; define the one value we return by hand (ch28's idiom). */
#ifndef EPERM
#define EPERM 1
#endif

char LICENSE[] SEC("license") = "GPL";

/* Same bound and rationale as ch28: cgroup hierarchies are shallow; 16 covers
 * systemd slices plus several layers of delegation. A compile-time constant is
 * required or the verifier rejects the loop. */
#define CGROUP_WALK_DEPTH 16

/* Protected cgroups: key = cgroup id (u64), value = 1. Populated from userspace
 * before attach. Empty = govern nothing (the safe default). */
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

/* True if the task is in a protected cgroup or any descendant of one. The walk
 * is the ch28 pattern verbatim: leaf first, then ancestors toward the root. */
static __always_inline bool in_protected_scope(void)
{
    __u64 cg = bpf_get_current_cgroup_id();
    if (bpf_map_lookup_elem(&protected_cgroups, &cg))
        return true;

    for (int level = 0; level < CGROUP_WALK_DEPTH; level++) {
        __u64 anc = bpf_get_current_ancestor_cgroup_id(level);
        if (!anc || anc == cg)              /* root reached, or past the leaf */
            break;
        if (bpf_map_lookup_elem(&protected_cgroups, &anc))
            return true;
    }
    return false;
}

SEC("lsm/task_fix_setuid")
int BPF_PROG(uid_shield, struct cred *new, const struct cred *old, int flags)
{
    /* No prior-`ret` parameter here: unlike bprm_check_security (ch28), the
     * task_fix_setuid hook signature carries no earlier LSM's verdict to honour,
     * so the program's return is the whole verdict. */

    /* SCOPE FIRST — never govern anything outside a protected subtree, so this
     * program can never lock root out of the host it runs on. */
    if (!in_protected_scope())
        return 0;

    /* The policy: deny a transition whose NEW effective uid is root (0) when the
     * OLD one was not. A service that is already root is out of scope for this
     * shield (it has not escalated); we only block the privilege GAIN. */
    __u32 old_euid = BPF_CORE_READ(old, euid.val);
    __u32 new_euid = BPF_CORE_READ(new, euid.val);

    if (new_euid != 0 || old_euid == 0)
        return 0;                           /* not an escalation to root → allow */

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (e) {
        e->pid      = bpf_get_current_pid_tgid() >> 32;
        e->verdict  = -EPERM;
        e->old_euid = old_euid;
        e->new_euid = new_euid;
        bpf_get_current_comm(&e->comm, sizeof(e->comm));
        bpf_ringbuf_submit(e, 0);
    }

    /* THE VERDICT: deny the privilege gain. Safe only because of the scope check
     * above — outside a protected cgroup, root transitions are untouched. */
    return -EPERM;
}
