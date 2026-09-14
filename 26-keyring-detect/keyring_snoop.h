/* keyring_snoop.h — shared between kernel and userspace, Chapter 26 */
#ifndef KEYRING_SNOOP_H
#define KEYRING_SNOOP_H

#define TYPE_LEN 16   /* key_type->name is short ("user", "big_key", "keyring") */
#define DESC_LEN 64   /* key description, truncated */
#define COMM_LEN 16   /* TASK_COMM_LEN */

/*
 * One record per key-creation event. The kernel side copies these fields out of
 * struct key / the syscall args and ships the record over the ring buffer; user
 * space decides what is suspicious. Same dumb-kernel / smart-userspace split as
 * ch23.
 *
 * `source` says which hook produced the record:
 *   0  fentry/key_create_or_update    — type and payload length (plen) in hand
 *   1  tracepoint/sys_enter_add_key   — the audit-parity view (syscall args)
 */
struct key_event {
    __u64 ts_ns;
    __u32 pid;
    __u32 uid;
    __u64 datalen;            /* payload size in bytes — the field auditd discards */
    __u8  source;
    char  comm[COMM_LEN];
    char  type[TYPE_LEN];     /* "user", "big_key", ... ("" for the tracepoint) */
    char  desc[DESC_LEN];
};

#endif /* KEYRING_SNOOP_H */
