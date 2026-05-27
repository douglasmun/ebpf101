#!/usr/bin/env python3
"""
Perf Buffer — Chapter 3
=======================

Chapter 2's map gave us an aggregate: "how many" per user. But it threw away
every detail — which command, which PID, in what order. A counter can't tell
you a story.

A **perf buffer** can. It's a different kind of map, purpose-built for
*streaming events*: the kernel program fills in a struct per event and
"submits" it; user space receives those records as a live, ordered stream.

  Chapter 2 (hash map):   kernel increments a number  ->  user polls the total
  Chapter 3 (perf buffer): kernel pushes one record per event -> user reads the stream

What this program does:
  On every execve, the kernel program captures the PID, the user ID, and the
  actual command name (bpf_get_current_comm), packs them into a struct, and
  submits it to the perf buffer. Python receives each event and prints a line.
  Now we finally know *who ran what*, per event, in order.

Run it (root required to load eBPF):

    sudo python3 03-perf-buffer/exec_stream.py

Run commands in another window and watch real, named events stream by.
Ctrl-C to stop.
"""

from bcc import BPF

# --- The eBPF program -------------------------------------------------------
# BPF_PERF_OUTPUT(name) declares the streaming channel to user space.
# We define a struct describing one event; the kernel fills one per execve.
program = r"""
BPF_PERF_OUTPUT(events);

struct data_t {
    u32 pid;
    u32 uid;
    char command[16];   // task comm is max 16 bytes (TASK_COMM_LEN)
};

int hello(void *ctx) {
    struct data_t data = {};

    // pid_tgid packs the thread group id (the "PID" you see in ps) in the
    // high 32 bits; shift to get it.
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    // The real command name of the calling process — the detail we lacked
    // in chapters 1 and 2.
    bpf_get_current_comm(&data.command, sizeof(data.command));

    // Push this record onto the perf buffer for user space to pick up.
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""

# Compile + load, then hook execve as before.
b = BPF(text=program)
syscall = b.get_syscall_fnname("execve")
b.attach_kprobe(event=syscall, fn_name="hello")

print(f"{'PID':<8} {'UID':<6} COMMAND")
print("-" * 30)


def print_event(cpu, data, size):
    """Called once per event the kernel submits."""
    # b["events"].event() casts the raw bytes back into our struct.
    event = b["events"].event(data)
    print(f"{event.pid:<8} {event.uid:<6} {event.command.decode('utf-8', 'replace')}")


# Register the callback and poll the buffer forever.
b["events"].open_perf_buffer(print_event)
try:
    while True:
        b.perf_buffer_poll()
except KeyboardInterrupt:
    print("\nDetached. Bye!")
