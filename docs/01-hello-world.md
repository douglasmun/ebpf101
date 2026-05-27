# Chapter 1 — Hello World

**Code:** [`../01-hello-world/hello.py`](../01-hello-world/hello.py)
**Run:** `sudo python3 01-hello-world/hello.py`

## Concept

Load a tiny program into the kernel, attach it to an event, have it print.
The "hello world" of eBPF: prove you can run your code in kernel space.

## New building blocks

- **kprobe** — a hook that fires whenever a named kernel function is called. We
  hooked the `execve` syscall implementation, so our code runs on every new
  program launch.
- **`bpf_trace_printk()`** — writes a line to the kernel's shared trace buffer.
- **BCC flow** — `BPF(text=...)` compiles the C to bytecode and loads it;
  `get_syscall_fnname("execve")` finds the arch-specific symbol;
  `attach_kprobe(...)` wires it up; `trace_print()` reads the buffer back.

## What the output taught us

- The output appears in the window running the program (it reads the trace
  buffer), **not** the window where you trigger commands.
- An "idle" machine is anything but: `execve` fires constantly from background
  services (cups, snap, dbus). You don't need to do anything to see a flood.
- Process names often showed as `<...>` — the trace subsystem couldn't resolve
  them from its small cache.

## The wall (→ Chapter 2)

`bpf_trace_printk` is debug-only: **one global buffer**, slow, a single format
string, and — crucially — our program captured *no real data*. We printed a
constant; we couldn't tell `ls` from `snap`. We need to store and return real
information. Enter **maps**.
