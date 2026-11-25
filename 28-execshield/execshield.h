/* execshield.h — shared between kernel and userspace, Chapter 28 */
#ifndef EXECSHIELD_H
#define EXECSHIELD_H

#define TASK_COMM_LEN 16
#define PATH_MAX_LEN  256

/*
 * One event per governed exec: an execve inside a protected cgroup that the
 * shield allowed or denied. `verdict` is what the BPF program returned to the
 * kernel: 0 = allow, <0 = deny (-EPERM). Execs outside every protected cgroup
 * are not governed and emit no event.
 */
struct event {
    unsigned int pid;
    int          verdict;                 /* 0 = allow; <0 = deny (-EPERM) */
    char         comm[TASK_COMM_LEN];     /* who tried to exec */
    char         filename[PATH_MAX_LEN];  /* the program being exec'd */
};

#endif /* EXECSHIELD_H */
