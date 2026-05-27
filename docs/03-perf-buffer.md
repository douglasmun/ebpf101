# Chapter 3 — Perf Buffer

**Code:** [`../03-perf-buffer/exec_stream.py`](../03-perf-buffer/exec_stream.py)
**Run:** `sudo python3 03-perf-buffer/exec_stream.py`

## Concept

A **perf buffer** is a map purpose-built for *streaming events*: the kernel
fills a struct per event and submits it; user space receives the records as a
live, ordered stream.

```
hash map  : kernel increments a number      -> user polls the total
perf buffer: kernel pushes one record/event -> user reads the stream
```

## New building blocks

- **`BPF_PERF_OUTPUT(events)`** — declares the streaming channel.
- **`struct data_t { ... }`** — *you* define the event shape (pid, uid, comm).
  The kernel fills one per event; Python casts the bytes back with
  `b["events"].event(data)`.
- **`bpf_get_current_pid_tgid() >> 32`** — the high 32 bits are the PID (the one
  `ps` shows).
- **`bpf_get_current_comm()`** — the calling process's name.
- **`open_perf_buffer(cb)` + `perf_buffer_poll()`** — kernel pushes, the Python
  callback fires once per record.

## What the output taught us

This is where the system's behavior became *readable*:

- **We watched ourselves open a terminal**: `gnome-shell` → `gio-launch-desktop`
  → `gnome-terminal` → `bash` → `lesspipe`.
- **One PID, many names** = **fork + exec**. PID 118515 appeared as
  `systemd` → `(snap)` → `snap` → `snap-confine` → `snap-exec`: one process
  re-exec'ing itself through the snap launch chain, keeping its PID each time.
- **A privilege boundary, live**: PID 118486 flipped UID `103 → 0` — D-Bus
  exec'ing a **setuid-root** helper.

## The wall (→ Chapter 4)

`bpf_get_current_comm()` runs at execve *entry*, so it returns the name of the
program *calling* execve (the one being replaced) — `bash`, never `/usr/bin/ls`.
We see "something is about to exec", not *what binary*. To get the launched
path we must read the syscall's `filename` argument — best done via a
**tracepoint**.
