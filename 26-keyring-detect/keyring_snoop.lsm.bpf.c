// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * keyring_snoop.lsm.bpf.c — the ENFORCEMENT variant, Chapter 26
 *
 * COMPILE-ONLY on the lab's test kernel. This program attaches to the LSM hook
 * security_key_alloc via SEC("lsm/key_alloc"), where the return value is a
 * VERDICT — return -EPERM and the key is never created. That is the difference
 * between the fentry detector (observe-only) and this one: fentry cannot deny;
 * an LSM program can.
 *
 * Why it is not the chapter's default:
 *   BPF-LSM must be enabled at boot (bpf listed in the kernel `lsm=` parameter),
 *   exactly the prerequisite ch20 documents. The lab's kernel-6.12/linuxkit VM
 *   does NOT enable it — /sys/kernel/security/lsm is absent — so bpf_lsm_key_alloc
 *   is present in BTF (the hook exists) but nothing can attach to it here. This
 *   file therefore compiles against real BTF and is kept as a reference for a
 *   host where BPF-LSM is on, in the spirit of ch25's gate fragment: shown, not
 *   claimed to run.
 *
 * The hook fires at ALLOCATION, before the payload is linked, so datalen is not
 * yet known here — a real policy would pair this with the fentry detector (which
 * sees the size) or move enforcement to a hook that sees plen. The point of this
 * file is the verdict mechanism, not a production policy.
 *
 * security_key_alloc(struct key *key, const struct cred *cred,
 *                    unsigned long flags) -> int
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

/*
 * Example policy sketch (disabled): deny "user"-type keys created by non-root.
 * Left returning 0 (allow) so that, on a BPF-LSM host, merely loading this does
 * not break the system's own keyring use while a reader experiments. Flip the
 * commented block on deliberately.
 */
SEC("lsm/key_alloc")
int BPF_PROG(key_alloc_guard, struct key *key, const struct cred *cred,
             unsigned long flags, int ret)
{
    if (ret)                       /* respect an earlier LSM's denial */
        return ret;

    /* --- enforcement sketch, deliberately inert ---------------------------
     * const char *tname = BPF_CORE_READ(key, type, name);
     * char t[8] = {};
     * bpf_core_read_str(&t, sizeof(t), tname);
     * u32 uid = bpf_get_current_uid_gid() & 0xffffffff;
     * if (uid != 0 && t[0]=='u' && t[1]=='s' && t[2]=='e' && t[3]=='r')
     *         return -EPERM;      // block non-root "user"-key staging
     * ---------------------------------------------------------------------- */

    return 0;
}
