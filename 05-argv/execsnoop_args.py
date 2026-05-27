#!/usr/bin/env python3
"""
Capturing argv — Chapter 5  (execsnoop, completed)
===================================================

Chapter 4 logged the binary path (/usr/bin/ls) but not the arguments — we saw
`ls`, never `ls -la`; `apt`, never `apt install clang`. This chapter reads the
full command line. It's the hardest data-reading we've done, for two reasons:

1) DOUBLE INDIRECTION.  execve's argv is a pointer to an *array of pointers*,
   and every one of those lives in USER-SPACE memory:

       args->argv ─▶ [ argv[0] ─▶ "ls"    ]
                     [ argv[1] ─▶ "-la"   ]
                     [ argv[2] ─▶ NULL    ]   (NULL terminates the array)

   So per argument we do TWO user-space reads: first copy the pointer out of
   the array (bpf_probe_read_user), then copy the string it points to
   (bpf_probe_read_user_str).

2) VARIABLE LENGTH over a FIXED-SIZE channel.  A perf-buffer record has a fixed
   size, but a command line has an unknown number of args. The real execsnoop's
   trick (which we copy): send each argument as its OWN small record, then
   reassemble them in user space. An EVENT_RET marker says "this command's args
   are done — print it."

The verifier forbids unbounded loops, so we #pragma unroll a fixed MAXARGS cap.

Run it (root required to load eBPF):

    sudo python3 05-argv/execsnoop_args.py

Run commands with arguments in another window (`ls -la`, `grep -r foo .`) and
watch full command lines appear. Ctrl-C to stop.
"""

from bcc import BPF

# Must match the enum order in the C program below.
EVENT_ARG = 0
EVENT_RET = 1

program = r"""
#define MAXARGS  20      // cap on args we read (verifier needs a bounded loop)
#define ARGSIZE  128     // max bytes per single argument

enum event_type { EVENT_ARG, EVENT_RET };

struct data_t {
    u32 pid;
    u32 uid;
    char comm[16];       // the caller (e.g. "bash")
    int type;            // EVENT_ARG (arg follows) or EVENT_RET (end marker)
    char arg[ARGSIZE];   // one argument string; only meaningful for EVENT_ARG
};

BPF_PERF_OUTPUT(events);

// Copy one argument string from user space and ship it as its own record.
// ctx is void* so we don't depend on the generated tracepoint struct's name.
static int submit_arg(void *ctx, const char *ptr, struct data_t *data) {
    bpf_probe_read_user_str(data->arg, sizeof(data->arg), ptr);
    events.perf_submit(ctx, data, sizeof(*data));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    struct data_t data = {};

    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.type = EVENT_ARG;

    // args->argv: a user-space pointer to an array of user-space char*.
    const char *const *argv = (const char *const *)(args->argv);

    #pragma unroll
    for (int i = 0; i < MAXARGS; i++) {
        const char *argp = NULL;
        // Read #1: copy the i-th POINTER out of the argv array.
        bpf_probe_read_user(&argp, sizeof(argp), &argv[i]);
        if (argp == NULL)
            goto done;                  // NULL terminator -> end of argv
        // Read #2 (inside submit_arg): copy the STRING that pointer points to.
        submit_arg(args, argp, &data);
    }
    // Fell out of the loop without a NULL: the command had > MAXARGS args.
    // (Our user-space side will just show the first MAXARGS.)

done:
    data.type = EVENT_RET;              // tell user space: command complete
    events.perf_submit(args, &data, sizeof(data));
    return 0;
}
"""

b = BPF(text=program)

print(f"{'PID':<8} {'UID':<6} {'COMM':<16} COMMAND LINE")
print("-" * 70)

# Reassembly buffer: pid -> {uid, comm, argv:[...]} accumulated across records,
# flushed and printed when the matching EVENT_RET arrives.
pending = {}


def print_event(cpu, data, size):
    event = b["events"].event(data)
    if event.type == EVENT_ARG:
        slot = pending.setdefault(
            event.pid,
            {"uid": event.uid, "comm": event.comm.decode("utf-8", "replace"), "argv": []},
        )
        slot["argv"].append(event.arg.decode("utf-8", "replace"))
    else:  # EVENT_RET — this command's args are all in; print and clear.
        slot = pending.pop(event.pid, None)
        if slot is None:
            return
        cmdline = " ".join(slot["argv"])
        print(f"{event.pid:<8} {slot['uid']:<6} {slot['comm']:<16} {cmdline}")


b["events"].open_perf_buffer(print_event)
try:
    while True:
        b.perf_buffer_poll()
except KeyboardInterrupt:
    print("\nDetached. Bye!")
