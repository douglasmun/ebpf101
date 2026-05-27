// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * execguard.bpf.c — kernel-side, Chapter 20
 *
 * The final step: from observing the kernel to GOVERNING it. An LSM BPF program
 * attaches to a Linux Security Module hook, and — uniquely — its **return value
 * is a verdict**: return 0 to allow the operation, or a negative errno (e.g.
 * -EPERM) to DENY it. This is how eBPF enforces policy instead of just watching.
 *
 * We hook bprm_check_security, the LSM check the kernel runs before letting a
 * program execute (every execve passes through it). For safety this tool is an
 * AUDITOR, not a blocker: it records who is exec'ing what and ALWAYS returns 0
 * (allow). The one-line change that would turn it into a blocker is marked
 * below — and is exactly why you must be careful with LSM BPF.
 *
 * LSM hook signature (BPF_PROG appends the running verdict `ret`):
 *   int bprm_check_security(struct linux_binprm *bprm);
 *
 * Prerequisite: "bpf" must be an active LSM (kernel `lsm=` boot param). The
 * loader checks this and explains how to enable it; see execguard.c.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "execguard.h"

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

SEC("lsm/bprm_check_security")
int BPF_PROG(exec_check, struct linux_binprm *bprm, int ret)
{
    /* Respect a denial already returned by an earlier LSM in the chain. */
    if (ret != 0)
        return ret;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;                       /* can't record → fail open (allow) */

    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    /* bprm->filename is the path being executed (kernel memory). */
    const char *fname = BPF_CORE_READ(bprm, filename);
    bpf_probe_read_kernel_str(&e->filename, sizeof(e->filename), fname);

    /*
     * THE VERDICT. We allow everything.
     *
     *   e->verdict = 0;  return 0;   →  allow (what we do)
     *
     * To BLOCK matching execs you would set e->verdict = -EPERM and
     * `return -EPERM;` here. Doing that without a tight, correct condition can
     * lock you out of your own system — which is the whole point of this being
     * an audit-only demo.
     */
    e->verdict = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
