// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * bashreadline.bpf.c — kernel-side, Chapter 15
 *
 * The new mechanism: a UPROBE. Every probe so far has been kernel-side —
 * tracepoints (ch4–11) and a kprobe on a kernel function (ch12–13). A uprobe
 * (and its return form, uretprobe) instead attaches to a function in a *user
 * space* binary or shared library, identified by path + symbol.
 *
 * Here we hook the RETURN of bash's readline(). readline() returns the line the
 * user just finished typing (a malloc'd char* in the bash process), so a
 * uretprobe on it sees every interactive command on the whole system.
 *
 *   char *readline(const char *prompt);   ← we want its return value
 *
 * The attach target (binary path "/usr/bin/bash", symbol "readline") is chosen
 * in user space, not here — this program just says "I am a uretprobe" via its
 * SEC() and reads the returned pointer. BPF_KRETPROBE hands us the return value
 * as a normal argument.
 *
 * Reading the string: the returned char* lives in bash's address space, so we
 * cross the boundary with bpf_probe_read_user_str — the _user variant, exactly
 * as in ch11 (a kernel-memory read here would fault or return garbage).
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bashreadline.h"

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

/*
 * SEC("uretprobe") with no path means "this is a uretprobe, attach me from user
 * space" — the loader picks /usr/bin/bash:readline. The single argument of
 * BPF_KRETPROBE is the function's return value: the char* line.
 */
SEC("uretprobe")
int BPF_KRETPROBE(bash_readline, const void *ret)
{
    if (!ret)                  /* readline() returns NULL on EOF (Ctrl-D) */
        return 0;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    /* Copy the returned user-space string. Returns bytes copied incl. NUL. */
    long n = bpf_probe_read_user_str(&e->line, sizeof(e->line), ret);
    if (n <= 1) {              /* empty line (bare Enter) or read error */
        bpf_ringbuf_discard(e, 0);   /* hand the reservation back unused */
        return 0;
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
