// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * execshield.bpf.c — kernel-side, Chapter 28
 *
 * A least-privilege exec shield. Chapter 20 governed exec with an audit-only
 * bprm_check verdict; this chapter makes the verdict DENY, but scopes it to a
 * set of protected cgroups so a mistake cannot lock out the whole machine.
 *
 * The idea: a service (an Nginx worker, say) execs nothing after it is up. So
 * inside its cgroup we deny every execve. A novel RCE that gives an attacker
 * code execution inside the service still has to spawn /bin/sh, a dropper or a
 * shell helper to do anything — and that exec dies here, with no knowledge of
 * the bug that let the attacker in. The policy is on the TECHNIQUE (exec),
 * not on any one vulnerability.
 *
 * Scope is the safety rail. The loader writes the protected cgroup ids into
 * `protected_cgroups`; execs in any other cgroup return 0 (allow) untouched.
 * cgroup id is the right key: it survives fork and re-exec and cannot be
 * forged from userspace, unlike comm or a recycled pid.
 *
 * Scope is HIERARCHICAL. A real service puts its workers in child cgroups of
 * its own (systemd delegation, an Nginx master spawning workers under
 * nginx.service/<child>). Matching only the task's own (leaf) cgroup id would
 * let those children exec freely — the shield would miss exactly the processes
 * it is meant to contain. So we match the task's leaf cgroup AND every ancestor
 * up to the root against the set: protecting a service's cgroup covers its whole
 * subtree. (ebpf101 issue #6.)
 *
 * Prerequisite: "bpf" must be an active LSM (kernel `lsm=` boot param), the
 * same wall as Chapter 20. The loader checks it; see execshield.c.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "execshield.h"

/*
 * vmlinux.h is generated from BTF and carries no userspace headers, so the
 * errno macros are absent, and a BPF program cannot pull in <linux/errno.h>
 * either. Define the one value we return by hand — the standard libbpf idiom.
 * ch20 never needed it because it only ever returned 0 (allow).
 */
#ifndef EPERM
#define EPERM 1
#endif

char LICENSE[] SEC("license") = "GPL";

/*
 * Depth we walk from the task's cgroup toward the root. cgroup hierarchies are
 * shallow in practice (a handful of levels); 16 covers systemd slices plus
 * several layers of delegation with room to spare. The loop MUST be bounded by
 * a compile-time constant or the verifier rejects it. A subtree deeper than
 * this is not a miss in the dangerous direction: the leaf and the nearest 16
 * ancestors are still checked, so a directly protected cgroup is always caught;
 * only a protected cgroup more than 16 levels ABOVE the task would be missed,
 * which does not occur in real layouts.
 */
#define CGROUP_WALK_DEPTH 16

/*
 * Protected cgroups: key = cgroup id (u64), value = 1 (presence is the policy).
 * Populated from userspace before attach. An empty map governs nothing, which
 * is the safe default — the shield denies only what you opt in.
 */
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

SEC("lsm/bprm_check_security")
int BPF_PROG(exec_shield, struct linux_binprm *bprm, int ret)
{
    /* Respect a denial an earlier LSM in the chain already returned. */
    if (ret != 0)
        return ret;

    /* SCOPE FIRST. Only govern a protected cgroup OR any descendant of one;
     * everything else is allowed, so this program can never lock you out of the
     * host it runs on.
     *
     * Walk from the task's own cgroup toward the root. bpf_get_current_cgroup_id()
     * is the leaf; bpf_get_current_ancestor_cgroup_id(level) is the ancestor at
     * each hierarchy level (level 0 = root, rising to the leaf). Match on the
     * leaf or ANY ancestor → the task is inside a protected subtree → govern it. */
    __u64 cg = bpf_get_current_cgroup_id();
    bool protected = bpf_map_lookup_elem(&protected_cgroups, &cg) != NULL;

    for (int level = 0; !protected && level < CGROUP_WALK_DEPTH; level++) {
        __u64 anc = bpf_get_current_ancestor_cgroup_id(level);
        if (!anc || anc == cg)              /* root reached, or past the leaf */
            break;
        if (bpf_map_lookup_elem(&protected_cgroups, &anc))
            protected = true;
    }

    if (!protected)
        return 0;                           /* not our service subtree → allow */

    /* Inside a protected cgroup: deny the exec and record it. */
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (e) {
        e->pid     = bpf_get_current_pid_tgid() >> 32;
        e->verdict = -EPERM;
        bpf_get_current_comm(&e->comm, sizeof(e->comm));
        bpf_probe_read_kernel_str(&e->filename, sizeof(e->filename),
                                  BPF_CORE_READ(bprm, filename));
        bpf_ringbuf_submit(e, 0);
    }

    /* THE VERDICT: deny. This is the one line that separates Chapter 20's
     * auditor from an enforcer. It is safe here only because of the scope
     * check above. */
    return -EPERM;
}
