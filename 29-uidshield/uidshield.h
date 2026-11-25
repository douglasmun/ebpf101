/* uidshield.h — shared between kernel and userspace, Chapter 29 */
#ifndef UIDSHIELD_H
#define UIDSHIELD_H

#define TASK_COMM_LEN 16

/*
 * One event per governed setuid transition: a credential change inside a
 * protected cgroup that would raise the effective uid to root (0). `verdict`
 * is what the BPF program returned to the kernel: 0 = allow, <0 = deny
 * (-EPERM). Transitions outside every protected cgroup, and transitions that
 * do not reach uid 0, are not governed and emit no event.
 */
struct event {
    unsigned int pid;
    int          verdict;              /* 0 = allow; <0 = deny (-EPERM) */
    unsigned int old_euid;             /* effective uid before the change */
    unsigned int new_euid;             /* effective uid the change asked for */
    char         comm[TASK_COMM_LEN];  /* who attempted the transition */
};

#endif /* UIDSHIELD_H */
