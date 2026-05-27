#!/usr/bin/env python3
"""
Ring Buffer — Chapter 6
=======================

Chapter 5 used BPF_PERF_OUTPUT: a *per-CPU* channel where the kernel copies
a struct from the BPF stack into one ring per CPU, and user space drains each
CPU's ring independently:

    CPU 0: [ev][ev][ev]   ← drained separately from …
    CPU 1: [ev][ev]       ← … CPU 1 — ordering across CPUs is lost

BPF_RINGBUF_OUTPUT replaces it with ONE shared ring (kernel ≥ 5.8):

    ALL CPUs → [ev][ev][ev][ev][ev]   ← single buffer, globally ordered

Three concrete wins:

  1. IN-ORDER DELIVERY.  One buffer, one consumer — events arrive in the
     order they were submitted, across all CPUs, not per-CPU.

  2. RESERVE/COMMIT, NOT COPY.  With the perf buffer we built a struct on
     the BPF stack and then copied it in:

         struct data_t data = {};   // lives on the BPF stack
         data.pid = ...;
         events.perf_submit(ctx, &data, sizeof(data));  // COPY into ring

     With the ring buffer, ringbuf_reserve() hands us a pointer DIRECTLY
     INTO the ring.  We fill it in-place and commit — zero extra copy,
     lower stack pressure:

         struct data_t *slot = events.ringbuf_reserve(sizeof(*slot));
         if (!slot) return 0;   // explicit back-pressure (ring full)
         slot->pid = ...;
         events.ringbuf_submit(slot, 0);  // just flips a flag

  3. EXPLICIT BACK-PRESSURE.  When the ring is full, reserve() returns
     NULL — the program can detect the drop and react.  The perf buffer
     silently discarded events without any signal to the kernel-side code.

Everything else — tracepoint, data_t layout, the EVENT_ARG / EVENT_RET
multi-record protocol, the per-PID reassembly dict — is unchanged from
Chapter 5.  Only the kernel→userspace bridge changes.

Run it (root required to load eBPF):

    sudo python3 06-ringbuf/execsnoop_ringbuf.py

Trigger output by running commands in another terminal.  Ctrl-C to stop.
"""

from bcc import BPF

EVENT_ARG = 0
EVENT_RET = 1

program = r"""
#define MAXARGS  20
#define ARGSIZE  128

enum event_type { EVENT_ARG, EVENT_RET };

struct data_t {
    u32  pid;
    u32  uid;
    char comm[16];
    int  type;
    char arg[ARGSIZE];
};

// Single shared ring buffer (64 KB = 16 pages).
// Ch 5 used BPF_PERF_OUTPUT which allocates one ring PER CPU.
BPF_RINGBUF_OUTPUT(events, 1 << 4);

TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    u32  pid = bpf_get_current_pid_tgid() >> 32;
    u32  uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    char comm[16];
    bpf_get_current_comm(comm, sizeof(comm));

    const char *const *argv = (const char *const *)(args->argv);

    #pragma unroll
    for (int i = 0; i < MAXARGS; i++) {
        const char *argp = NULL;
        // Read #1: copy the i-th pointer out of the argv array.
        bpf_probe_read_user(&argp, sizeof(argp), &argv[i]);
        if (argp == NULL)
            break;   // NULL terminator — end of argv

        // Reserve space INSIDE the ring (no stack copy).
        struct data_t *slot = events.ringbuf_reserve(sizeof(*slot));
        if (!slot) return 0;   // ring full — drop remaining args and bail
        slot->pid  = pid;
        slot->uid  = uid;
        __builtin_memcpy(slot->comm, comm, sizeof(slot->comm));
        slot->type = EVENT_ARG;
        // Read #2: copy the string the pointer points to.
        bpf_probe_read_user_str(slot->arg, sizeof(slot->arg), argp);
        events.ringbuf_submit(slot, 0);
    }

    // End-of-command marker — tells user space to print and clear.
    struct data_t *ret = events.ringbuf_reserve(sizeof(*ret));
    if (!ret) return 0;
    ret->pid    = pid;
    ret->uid    = uid;
    __builtin_memcpy(ret->comm, comm, sizeof(ret->comm));
    ret->type   = EVENT_RET;
    ret->arg[0] = '\0';
    events.ringbuf_submit(ret, 0);
    return 0;
}
"""

b = BPF(text=program)

print(f"{'PID':<8} {'UID':<6} {'COMM':<16} COMMAND LINE")
print("-" * 70)

# Per-PID accumulator: pid -> {uid, comm, argv:[...]}
# Flushed and printed when the matching EVENT_RET arrives.
pending = {}


# Note: ring buffer callback receives (ctx, data, size) — no CPU number,
# since there is no per-CPU identity on a shared ring.
def print_event(ctx, data, size):
    event = b["events"].event(data)
    if event.type == EVENT_ARG:
        slot = pending.setdefault(
            event.pid,
            {"uid": event.uid, "comm": event.comm.decode("utf-8", "replace"), "argv": []},
        )
        slot["argv"].append(event.arg.decode("utf-8", "replace"))
    else:  # EVENT_RET — all args received; print and clear.
        slot = pending.pop(event.pid, None)
        if slot is None:
            return
        cmdline = " ".join(slot["argv"])
        print(f"{event.pid:<8} {slot['uid']:<6} {slot['comm']:<16} {cmdline}")


b["events"].open_ring_buffer(print_event)
try:
    while True:
        b.ring_buffer_poll()
except KeyboardInterrupt:
    print("\nDetached. Bye!")
