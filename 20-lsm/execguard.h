/* execguard.h — shared between kernel and userspace, Chapter 20 */
#ifndef EXECGUARD_H
#define EXECGUARD_H

#define TASK_COMM_LEN 16
#define PATH_MAX_LEN  256

/*
 * One event per program-execution check (the LSM bprm_check hook). `verdict` is
 * what the BPF program returned to the kernel: 0 = allow. A negative errno
 * (e.g. -EPERM) would DENY the exec — this tool always allows and only logs.
 */
struct event {
    unsigned int pid;
    int          verdict;                 /* 0 = allow; <0 = would deny */
    char         comm[TASK_COMM_LEN];     /* who is exec'ing */
    char         filename[PATH_MAX_LEN];  /* the program being exec'd */
};

#endif /* EXECGUARD_H */
