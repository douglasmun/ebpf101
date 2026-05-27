#!/usr/bin/env python3
"""
eBPF Hello World — Chapter 1
============================

This is the classic first eBPF program (from Liz Rice's "Learning eBPF" /
the Isovalent tutorial). It does ONE thing:

    Every time any process on the machine calls the execve() syscall
    (i.e. runs a new program), our tiny eBPF program prints "Hello World!".

How the pieces fit together:

  1. We write a small C function (the `program` string below). This is NOT
     run by Python — BCC compiles it to eBPF bytecode and the kernel loads
     it into the kernel itself.

  2. We attach that eBPF function to a "kprobe" — a hook that fires whenever
     a specific kernel function is called. We hook the kernel's execve
     implementation, so our code runs on every new process launch.

  3. The eBPF code calls bpf_trace_printk(), which writes a line to the
     kernel's shared trace buffer. Back in user space, Python reads that
     buffer and prints what it finds.

Run it with root (eBPF programs require privilege to load):

    sudo python3 hello.py

Then, in ANOTHER terminal, run any command (ls, echo hi, etc.) and watch
the lines appear here. Press Ctrl-C to stop.
"""

from bcc import BPF

# --- The eBPF program, written in (a restricted subset of) C ---------------
# `ctx` is the context the kernel hands us at the hook point. We ignore it
# here and just emit a message. Every eBPF program returns an int (0 = OK).
program = r"""
int hello(void *ctx) {
    bpf_trace_printk("Hello World!");
    return 0;
}
"""

# Compile the C above into eBPF bytecode and load it into the kernel.
b = BPF(text=program)

# execve has different kernel symbol names across architectures/versions
# (e.g. __x64_sys_execve). BCC figures out the right one for this machine.
syscall = b.get_syscall_fnname("execve")

# Attach our `hello` function as a kprobe on that syscall.
b.attach_kprobe(event=syscall, fn_name="hello")

print(f"Attached to {syscall.decode() if isinstance(syscall, bytes) else syscall}")
print("Run any command in another terminal. Ctrl-C to exit.\n")

# Read the kernel trace buffer and print each line. Blocks until Ctrl-C.
try:
    b.trace_print()
except KeyboardInterrupt:
    print("\nDetached. Bye!")
