// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * taskdump.bpf.c — kernel-side, Chapter 22
 *
 * Every program so far was triggered by an EVENT — a syscall, a packet, an exec.
 * A BPF ITERATOR is different: the kernel walks one of its own data structures
 * (here, the list of every task/thread) and calls our program ONCE PER ELEMENT.
 * It's a pull, not a push — user space reads the iterator and the walk happens
 * on demand, producing a consistent snapshot. This is a tiny `ps`.
 *
 * Output is also new: instead of a ring buffer or map, an iterator writes to a
 * seq_file with bpf_seq_printf (here via the BPF_SEQ_PRINTF macro). User space
 * gets that text by read()ing the iterator fd.
 *
 * The ctx carries:
 *   ctx->meta->seq      — the seq_file to print into
 *   ctx->meta->seq_num  — 0 on the first element (handy for a header)
 *   ctx->task           — the current task_struct, or NULL on the final call
 *
 * task_struct fields are read by direct (BTF/CO-RE) access — the iterator hands
 * us a trusted kernel pointer, so the verifier allows it.
 *
 * No shared name.h: the output is plain text in the seq_file, so there is no
 * kernel<->user struct to share (the 3-file layout is intentional, as in ch14/16).
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

SEC("iter/task")
int dump_task(struct bpf_iter__task *ctx)
{
    struct seq_file    *seq  = ctx->meta->seq;
    struct task_struct *task = ctx->task;

    if (task == NULL)               /* final call, after the last task */
        return 0;

    if (ctx->meta->seq_num == 0)    /* first element → print a header */
        BPF_SEQ_PRINTF(seq, "%-8s %-8s %s\n", "TGID", "PID", "COMM");

    /* tgid = the process id; pid = the thread id; comm = the name. */
    BPF_SEQ_PRINTF(seq, "%-8d %-8d %s\n", task->tgid, task->pid, task->comm);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
