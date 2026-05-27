/* tailcall.h — shared between kernel and userspace, Chapter 19 */
#ifndef TAILCALL_H
#define TAILCALL_H

/*
 * Indices used two ways:
 *  - jmp_table (PROG_ARRAY) slots 0/1 hold the user/root handler programs;
 *  - counts (ARRAY) slots 0/1/2 hold the user/root/miss tallies.
 */
enum {
    IDX_USER = 0,   /* execve by a non-root uid */
    IDX_ROOT = 1,   /* execve by uid 0 */
    IDX_MISS = 2,   /* dispatcher fell through (tail call failed) — should stay 0 */
    IDX_MAX,
};

#endif /* TAILCALL_H */
