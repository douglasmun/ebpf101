/* fileshield.h — shared between kernel and userspace, Chapter 30 */
#ifndef FILESHIELD_H
#define FILESHIELD_H

#define TASK_COMM_LEN 16

/*
 * A file is identified by (device, inode) — the same pair stat(2) returns and
 * the kernel carries on every inode. Matching on this, not on a path string,
 * means the shield guards the real file regardless of the name used to reach it
 * (a symlink, a bind mount, a hard link): all resolve to one (dev, ino).
 */
struct file_key {
    unsigned long long dev;    /* kernel dev_t of the containing filesystem */
    unsigned long long ino;    /* inode number */
};

/*
 * One event per governed open: an attempt inside a protected cgroup to open a
 * file in the guarded set. `verdict` is what the BPF program returned: 0 =
 * allow, <0 = deny (-EPERM). Opens outside every protected cgroup, and opens of
 * files not in the guarded set, are not governed and emit no event.
 */
struct event {
    unsigned int       pid;
    int                verdict;              /* 0 = allow; <0 = deny (-EPERM) */
    unsigned long long dev;                  /* the guarded file that was touched */
    unsigned long long ino;
    char               comm[TASK_COMM_LEN];  /* who attempted the open */
};

#endif /* FILESHIELD_H */
