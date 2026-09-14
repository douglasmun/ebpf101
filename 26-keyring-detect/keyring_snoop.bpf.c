// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * keyring_snoop.bpf.c — kernel-side, Chapter 26
 *
 * Detects keyring-STAGED fileless execution at the moment it is visible: the
 * add_key(2) that writes a payload into the kernel keyring. The technique
 * (matheuzsecurity, "Linux Kernel Keyring Fileless Exec") stages an ELF in a
 * "user" key, reads it back with keyctl(KEYCTL_READ) into an anonymous mapping,
 * hand-maps its PT_LOAD segments and jumps to the entry point — no execve, no
 * execveat, no memfd_create, no file descriptor, no inode. Chapter 25's whole
 * detection set (auditd on exec/memfd syscalls; Sigma on the "memfd:"/"(deleted)"
 * string in /proc/PID/exe) therefore sees NOTHING. The keyring WRITE is the only
 * syscall-visible moment in the chain, so that is where this program hooks.
 *
 * Two hooks, one ring buffer:
 *
 *   1. fentry/__key_create_or_update  (source=0, the real detector)
 *      Runs inside add_key's kernel path with struct key already allocated and
 *      preparsed, so type->name and datalen are populated — we can report that a
 *      704 KB blob was staged as a "user" key, which is the signal that matters.
 *      Plain fentry: needs BTF, not BPF-LSM, so it attaches on any modern CO-RE
 *      kernel. It CANNOT deny (fentry is observe-only) — see the LSM variant in
 *      keyring_snoop.lsm.bpf.c for the enforcement path.
 *
 *   2. tracepoint/syscalls/sys_enter_add_key  (source=1, audit parity)
 *      The syscall-boundary view: exactly what an auditd -S add_key rule could
 *      see. Included to make the gap concrete — auditd can see THAT add_key was
 *      called but records neither the key type nor the payload size, the two
 *      fields that separate credential caching from payload staging.
 *
 * Pure observer, like ch23. All policy lives in user space.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "keyring_snoop.h"

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

static __always_inline void fill_ids(struct key_event *e)
{
    e->ts_ns = bpf_ktime_get_ns();
    e->pid   = bpf_get_current_pid_tgid() >> 32;
    e->uid   = bpf_get_current_uid_gid() & 0xffffffff;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
}

/*
 * key_create_or_update(key_ref_t keyring_ref, const char *type,
 *                      const char *description, const void *payload,
 *                      size_t plen, key_perm_t perm, unsigned long flags)
 *
 * This is the PUBLIC wrapper add_key(2) calls, not the __-prefixed inner routine
 * (whose signature is (key, prep, keyring, authkey, edit) — no type string at
 * all). Confirmed against this kernel's BTF: type and description are const char*,
 * plen the payload size. It is a global symbol in kallsyms, so fentry can attach.
 *
 * By the time add_key's syscall handler reaches this wrapper, the kernel has
 * already copied the type and description strings IN from user space, so the
 * pointers here address KERNEL memory: bpf_core_read_str (kernel) is correct and
 * bpf_core_read_user_str returns nothing (measured — see README, "reading the
 * arg strings"). The tracepoint below sees the raw syscall args and uses the
 * _user_ variant instead. Same strings, two address spaces, two read helpers.
 */
SEC("fentry/key_create_or_update")
int BPF_PROG(on_key_create, unsigned long keyring_ref, const char *type,
             const char *description, const void *payload, __u64 plen)
{
    struct key_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    fill_ids(e);
    e->source  = 0;
    e->datalen = (__u32)plen;
    e->type[0] = '\0';
    e->desc[0] = '\0';
    if (type)
        bpf_core_read_str(&e->type, sizeof(e->type), type);
    if (description)
        bpf_core_read_str(&e->desc, sizeof(e->desc), description);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/*
 * sys_enter_add_key: long add_key(const char *type, const char *description,
 *                                 const void *payload, size_t plen, key_serial_t);
 * The tracepoint args land in ctx->args[]. This is the audit-parity record.
 */
SEC("tracepoint/syscalls/sys_enter_add_key")
int on_sys_add_key(struct trace_event_raw_sys_enter *ctx)
{
    struct key_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    fill_ids(e);
    e->source  = 1;
    e->datalen = (__u32)ctx->args[3];      /* plen */
    e->type[0] = '\0';
    e->desc[0] = '\0';
    bpf_core_read_user_str(&e->type, sizeof(e->type), (const char *)ctx->args[0]);
    bpf_core_read_user_str(&e->desc, sizeof(e->desc), (const char *)ctx->args[1]);

    bpf_ringbuf_submit(e, 0);
    return 0;
}
