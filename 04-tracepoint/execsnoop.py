#!/usr/bin/env python3
"""
Tracepoint + filename — Chapter 4  (a mini "execsnoop")
=======================================================

Chapter 3 left us with a catch: bpf_get_current_comm() runs at execve *entry*,
so it returns the name of the program *calling* execve (the one being replaced)
— never the binary about to be launched. We saw `bash`, never `/usr/bin/ls`.

To log the actual program, we read execve's first argument: the filename. And
to do that cleanly we switch from a kprobe to a **tracepoint**.

  kprobe (ch 1-3): hooks a kernel *function* by name (__x64_sys_execve). The
                   name and arguments are an internal detail that can change
                   between kernel versions — fragile.
  tracepoint:      a *stable*, kernel-defined hook (syscalls:sys_enter_execve)
                   with a documented argument layout. The kernel maintainers
                   promise not to break it. Prefer tracepoints when one exists.

With BCC, the TRACEPOINT_PROBE(category, event) macro attaches automatically —
no get_syscall_fnname(), no attach_kprobe(). Inside, `args` holds the
tracepoint's fields; for sys_enter_execve, `args->filename` is the path.

That filename pointer lives in *user-space* memory (the calling process's
address space), so we can't just dereference it — we copy it in with
bpf_probe_read_user_str().

The result is essentially `execsnoop`: a real tool that logs every program
executed on the machine, by path. We print COMM (the caller) next to FILENAME
(the launched binary) so you can see the difference Chapter 3 hid from us.

Run it (root required to load eBPF):

    sudo python3 04-tracepoint/execsnoop.py

Run commands in another window and watch the real paths stream by. Ctrl-C stops.
"""

from bcc import BPF

# --- The eBPF program -------------------------------------------------------
program = r"""
BPF_PERF_OUTPUT(events);

struct data_t {
    u32 pid;
    u32 uid;
    char comm[16];        // caller's name (the program being replaced)
    char filename[256];   // the binary being executed (execve's 1st arg)
};

// TRACEPOINT_PROBE wires us to syscalls:sys_enter_execve and gives us `args`.
TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    struct data_t data = {};

    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    // The caller's name (e.g. "bash") — same value comm gave us in ch 3.
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    // args->filename is a pointer into USER-SPACE memory, so we copy the
    // string in with the _user_ variant. This is the path being launched.
    bpf_probe_read_user_str(&data.filename, sizeof(data.filename), args->filename);

    // For a tracepoint, the context to submit with is `args`.
    events.perf_submit(args, &data, sizeof(data));
    return 0;
}
"""

# Compile + load. No attach_kprobe() needed — TRACEPOINT_PROBE attaches itself.
b = BPF(text=program)

print(f"{'PID':<8} {'UID':<6} {'COMM':<16} ->  FILENAME")
print("-" * 60)


def print_event(cpu, data, size):
    event = b["events"].event(data)
    comm = event.comm.decode("utf-8", "replace")
    filename = event.filename.decode("utf-8", "replace")
    print(f"{event.pid:<8} {event.uid:<6} {comm:<16} ->  {filename}")


b["events"].open_perf_buffer(print_event)
try:
    while True:
        b.perf_buffer_poll()
except KeyboardInterrupt:
    print("\nDetached. Bye!")
