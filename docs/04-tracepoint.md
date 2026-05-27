# Chapter 4 — Tracepoint + filename (mini `execsnoop`)

**Code:** [`../04-tracepoint/execsnoop.py`](../04-tracepoint/execsnoop.py)
**Run:** `sudo python3 04-tracepoint/execsnoop.py`

## Concept

Read the *argument* to `execve` (the binary path) so we log the program being
launched, not just the caller. To do it cleanly, switch from a kprobe to a
**tracepoint**. The result is essentially `execsnoop` — a real security tool
that logs every program executed on the machine, by path.

## New building blocks

- **tracepoint vs kprobe**:
  - *kprobe* hooks a kernel *function* by name — an internal detail that can
    change between kernel versions (fragile).
  - *tracepoint* is a **stable, kernel-defined** hook with a documented argument
    layout the maintainers promise not to break. **Prefer a tracepoint when one
    exists.**
- **`TRACEPOINT_PROBE(syscalls, sys_enter_execve)`** — BCC macro that attaches
  automatically (no `get_syscall_fnname` / `attach_kprobe`). `args` holds the
  tracepoint's fields; `args->filename` is the path.
- **`bpf_probe_read_user_str()`** — `args->filename` points into *user-space*
  memory, so we copy the string across the boundary. Note the `_user_`: there's
  a `_kernel_` twin, and picking the wrong one is a classic eBPF bug.

## What the output taught us

The COMM-vs-FILENAME columns made the fork+exec story complete
(`bash -> /usr/bin/ls`), and we cracked the running mystery and more:

- **The cups heartbeat, solved**: `run-cups-browse -> /usr/bin/sleep` on repeat,
  and the launch chain ended at `/snap/cups/1206/scripts/run-cups-browsed` — CUPS
  is a snap, polling forever via `sleep`. (Also spotted `systemd ->
  /proc/self/fd/9`: snapd launches via a sealed fd, so "filename" is a magic
  `/proc` symlink — `execve` can run an fd.)
- **Caught typing two unknown commands**: `bash -> command-not-found -> snap`
  (Ubuntu's "did you mean…?" handler).
- **Caught a `sudo` escalation**: `bash -> /usr/bin/sudo`, then `sudo -> apt` as
  uid 0 — the whole reason execsnoop exists as a detection tool.
- **The D-Bus chain with its purpose**: `dbus-daemon (103) -> launch-helper`,
  `(0) -> whoopsie-preferences`, `-> systemctl ×3`.
- **`filename` is authoritative; `argv[0]` is not.** `execve`'s `filename`
  argument is the path the *kernel* verifies and loads — it cannot be spoofed
  by user space. `argv[0]` is just a string the caller passes as the program's
  "name"; it can be set to anything:
  ```python
  execve("/bin/bash", ["totally-not-bash"], envp)
  # kernel runs bash; bash sees argv[0] = "totally-not-bash"
  # ps, top, and /proc/<pid>/cmdline show "totally-not-bash"
  ```
  Our FILENAME column shows what actually ran. Anything that reads only
  `argv[0]` (or `/proc/<pid>/cmdline`) can be lied to. This distinction
  matters for intrusion detection — which is exactly why real execsnoop tools
  log `filename`, not `argv[0]`.

## The wall (→ Chapter 5)

We get the path but not the **arguments** — `/usr/bin/ls`, not `ls -la`; we
can't see `apt install <what>`. Reading `args->argv` means walking an array of
user-space string pointers — double indirection, a fixed-size channel, and a
multi-record reassembly problem. That is chapter 5.
