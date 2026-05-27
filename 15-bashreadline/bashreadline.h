/* bashreadline.h — shared between kernel and userspace, Chapter 15 */
#ifndef BASHREADLINE_H
#define BASHREADLINE_H

#define TASK_COMM_LEN 16
#define MAX_LINE      200      /* longer command lines are truncated */

/*
 * One event per line returned by bash's readline() — i.e. per command a user
 * finished typing at an interactive prompt. `line` is the user-space string the
 * function returned, copied across the boundary with bpf_probe_read_user_str.
 */
struct event {
    unsigned int pid;
    char         comm[TASK_COMM_LEN];
    char         line[MAX_LINE];
};

#endif /* BASHREADLINE_H */
