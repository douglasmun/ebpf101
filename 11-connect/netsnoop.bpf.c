// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * netsnoop.bpf.c — kernel-side, Chapter 11
 *
 * Hook: sys_enter_connect fires whenever a process calls connect(2).
 *
 * connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
 *   args[0] = sockfd
 *   args[1] = addr  (pointer into *user* space — must use bpf_probe_read_user)
 *   args[2] = addrlen
 *
 * The new skill here is reading a kernel struct through a user-space pointer.
 * The sockaddr family of structs lives in the calling process's address space;
 * to read it safely across the kernel/user boundary we use bpf_probe_read_user
 * (the _user variant, not _kernel — wrong variant = verifier error or crash).
 *
 * Structs used:
 *   struct sockaddr     { sa_family_t sa_family; char sa_data[14]; }
 *   struct sockaddr_in  { sa_family_t; uint16_t sin_port; struct in_addr sin_addr; }
 *   struct sockaddr_in6 { sa_family_t; uint16_t sin6_port; uint32_t sin6_flowinfo;
 *                         struct in6_addr sin6_addr; ... }
 *
 * These structs are in vmlinux.h (they are kernel types with BTF).  We don't
 * need to define them manually.
 *
 * Entry/exit correlation (same pattern as ch10):
 *   sys_enter_connect → stash map (pid → sockaddr copy)
 *   sys_exit_connect  → look up stash, emit ring-buffer record with ret value
 *
 * This lets us report whether the connection succeeded (ret == 0), is in
 * progress (ret == -EINPROGRESS for non-blocking sockets), or failed.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "netsnoop.h"

/*
 * stash map: pid → saved sockaddr bytes.
 *
 * We save a raw 128-byte buffer — enough for both sockaddr_in (16 bytes) and
 * sockaddr_in6 (28 bytes) — rather than a typed struct, because we don't know
 * the family until we read it.  The exit hook re-interprets the saved bytes.
 */
struct addr_buf {
    unsigned char bytes[128];
};

struct {
    __uint(type,        BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key,   __u32);           /* pid */
    __type(value, struct addr_buf); /* raw sockaddr bytes */
} stash SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

/* ── entry: save the sockaddr ─────────────────────────────────────────────── */

SEC("tracepoint/syscalls/sys_enter_connect")
int trace_enter(struct trace_event_raw_sys_enter *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    const void *uaddr = (const void *)ctx->args[1];
    struct addr_buf buf = {};

    if (!uaddr)
        return 0;

    /*
     * bpf_probe_read_user copies bytes from a user-space pointer.
     * We read sizeof(buf) bytes; the exit hook interprets only as many as
     * the actual family requires.  Reading more than addrlen is harmless —
     * the extra bytes are zeroes from buf's initialisation.
     */
    bpf_probe_read_user(&buf, sizeof(buf), uaddr);

    /*
     * Peek at the first two bytes to check the address family before stashing.
     * sa_family is the first field (2 bytes) in every sockaddr variant.
     */
    __u16 family = *(__u16 *)buf.bytes;
    if (family != AF_INET && family != AF_INET6)
        return 0;   /* skip Unix sockets, Netlink, etc. */

    bpf_map_update_elem(&stash, &pid, &buf, BPF_ANY);
    return 0;
}

/* ── exit: combine stash + return value → ring buffer ─────────────────────── */

SEC("tracepoint/syscalls/sys_exit_connect")
int trace_exit(struct trace_event_raw_sys_exit *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    long  ret = ctx->ret;

    struct addr_buf *saved = bpf_map_lookup_elem(&stash, &pid);
    if (!saved)
        return 0;   /* no matching entry — different AF was filtered out */

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        bpf_map_delete_elem(&stash, &pid);
        return 0;
    }

    e->pid = pid;
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->ret = (int)ret;

    __u16 family = *(__u16 *)saved->bytes;
    e->family = family;

    if (family == AF_INET) {
        /*
         * struct sockaddr_in layout:
         *   offset 0: sa_family  (2 bytes)
         *   offset 2: sin_port   (2 bytes, network byte order)
         *   offset 4: sin_addr   (4 bytes, network byte order)
         */
        __u16 nport;
        __u32 naddr;
        bpf_probe_read_kernel(&nport, sizeof(nport), saved->bytes + 2);
        bpf_probe_read_kernel(&naddr, sizeof(naddr), saved->bytes + 4);
        e->port  = bpf_ntohs(nport);
        e->addr4 = bpf_ntohl(naddr);
    } else {
        /*
         * struct sockaddr_in6 layout:
         *   offset 0: sa_family   (2 bytes)
         *   offset 2: sin6_port   (2 bytes, network byte order)
         *   offset 4: sin6_flowinfo (4 bytes)
         *   offset 8: sin6_addr   (16 bytes, network byte order)
         */
        __u16 nport;
        bpf_probe_read_kernel(&nport, sizeof(nport), saved->bytes + 2);
        e->port = bpf_ntohs(nport);
        /* Copy the 16-byte IPv6 address as-is (network byte order) */
        bpf_probe_read_kernel(e->addr6, sizeof(e->addr6), saved->bytes + 8);
    }

    bpf_map_delete_elem(&stash, &pid);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
