# Chapter 5 — Capturing argv (execsnoop, completed)

**Code:** [`../05-argv/execsnoop_args.py`](../05-argv/execsnoop_args.py)
**Run:** `sudo python3 05-argv/execsnoop_args.py`

## Concept

Read `execve`'s full `argv` so we log the whole command line, not just the
binary path. This completes `execsnoop`: path (Ch 4) **and** arguments.

## New building blocks

- **Double pointer indirection.** `argv` is a user-space pointer to an *array*
  of user-space `char*`. Per argument that's **two** user-space reads:
  - `bpf_probe_read_user()` to copy the i-th pointer out of the array, then
  - `bpf_probe_read_user_str()` to follow it to the string.
  Loop until the `NULL` terminator.
- **Variable-length data over a fixed-size channel.** A perf record is fixed
  size; a command line isn't. The fix (straight from the real execsnoop): send
  **each argument as its own record** (`EVENT_ARG`), then an `EVENT_RET` marker
  meaning "command complete." User space accumulates args per-PID in a dict and
  prints the line on `EVENT_RET`. This reassembly pattern is everywhere in real
  eBPF tooling.
- **`#pragma unroll` + `MAXARGS`** — the verifier bans unbounded loops, so we
  cap the arg count (longer commands are truncated).

## What the output taught us

- **The cups heartbeat, fully resolved**: `run-cups-browse -> sleep 1`. Ch 4
  proved it calls `sleep`; the arg `1` confirms the ~1-second period exactly.
- **Intent, not just action**: the D-Bus → whoopsie chain now reads in full —
  `dbus-daemon-launch-helper com.ubuntu.WhoopsiePreferences`, then
  `systemctl -q is-enabled whoopsie.path` (×2), then `systemctl start
  whoopsie.path`. We can see the exact units and flags, i.e. *what it decided
  to do*.
- **argv shows what actually ran, not what you typed**: typing `ls -al`
  produced `ls --color=auto -al` — bash expanded the `ls` alias before execve.
  Aliases, shell expansion, and wrappers all rewrite the command; a monitor
  sees the post-expansion truth. (Security-relevant: this is also how `argv[0]`
  can be set to lie — see Ch 4's `filename` vs `argv[0]` note.)
- Caught real usage live: `ping 127.0.0.1`, plus the terminal's own startup
  (`tput setaf 1`, `dircolors -b`, lesspipe's `basename`/`dirname` calls).

## The wall (→ next)

We can see process launches in full — but only `execve`. We're blind to file
access, network connections, and everything else a program does after it
starts. And we're still on **BCC**, which compiles the C at runtime on the
target; the production approach is **C + libbpf/CO-RE**, compiled once and
portable across kernels via BTF. The modern streaming channel is also the
**ring buffer**, not the perf buffer. Those are the open directions.
