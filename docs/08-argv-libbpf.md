# Chapter 8 — argv in C (libbpf, full execsnoop)

**Code:** [`../08-argv-libbpf/`](../08-argv-libbpf/)  
**Build:** `cd 08-argv-libbpf && make`  
**Run:** `sudo ./08-argv-libbpf/execsnoop`

## Concept

Port the Chapter 5/6 multi-record argv pattern to C + libbpf, completing the
translation of `execsnoop` from BCC/Python to a portable compiled binary.

## What translated directly

The BPF kernel side is a line-for-line rewrite of ch6:

| BCC (ch 6) | libbpf C (ch 8) |
|------------|-----------------|
| `BPF_RINGBUF_OUTPUT(events, 1<<4)` | BTF `BPF_MAP_TYPE_RINGBUF` struct |
| `events.ringbuf_reserve(sizeof(*e), 0)` | `bpf_ringbuf_reserve(&events, sizeof(*e), 0)` |
| `events.ringbuf_submit(e, 0)` | `bpf_ringbuf_submit(e, 0)` |
| `TRACEPOINT_PROBE(syscalls, sys_enter_execve)` | `SEC("tracepoint/syscalls/sys_enter_execve")` |
| `args->argv` | `(const char *const *)ctx->args[1]` |

The EVENT_ARG / EVENT_RET protocol, `#pragma unroll`, double pointer
indirection, and the `break` on NULL terminator are unchanged.

## What required real thought: the pending table in C

Python's `dict` is essentially free.  C has no built-in hash map, so we
implement a fixed-size table indexed by `pid % TABLE_SIZE` (4096 slots):

```c
struct pending {
    int active; unsigned int pid, uid;
    char comm[16];
    char argv[MAXARGS][ARGSIZE];
    int  argc;
};
static struct pending table[4096];   /* ~10 MB, zero-init'd in BSS */
```

`get_slot(pid)` returns `&table[pid % 4096]`.  On collision (two active PIDs
mapping to the same slot), the older entry is silently overwritten.  For an
execve monitor this is inconsequential — we lose at most one command line —
and avoids the complexity of a proper hash table for a learning tool.

The event handler mirrors the Python `setdefault` / `pop` pattern (pseudocode):

```
if EVENT_ARG:
    if slot empty or wrong pid: reset slot
    strncpy(slot->argv[argc++], e->arg)
else EVENT_RET:
    print slot->argv[0..argc-1] joined by spaces
    slot->active = 0
```

## What the output revealed

Full command lines from a pre-compiled binary — no LLVM startup cost, no BCC
on the target.  Several things stood out:

- **`audit-fix.sh` in full**: an audit/hardening script running in a parallel
  session was completely transparent — every `dpkg`, `apt-get`, `snap list`,
  `ss -tulnH`, `ufw status`, and awk/grep post-processor appeared with its
  exact arguments.  The multi-line awk script was captured verbatim (up to
  `ARGSIZE` bytes).  This is the power of execve monitoring: the full intent
  of every shell script, not just the script name.

- **`cron` → `debian-sa1 1 1`**: the system accounting daemon fired during
  the run.  Full command `command -v debian-sa1 > /dev/null && debian-sa1 1 1`
  visible inside the `/bin/sh -c …` wrapper.

- **snapd's systemctl storm**: snapd batched eight `systemctl show
  --property=Id,ActiveState,…` calls to check the state of cups, chromium,
  mesa, and firmware-updater snaps — twice (the second set is its periodic
  re-check).  Full service unit names visible.

- **PID reuse across fork+exec chains**: PID 24496 (`audit-fix.sh`) appeared
  five times under its own name as it `exec`'d sub-shells; PID 24505 (`dpkg`)
  appeared twice as `dpkg` exec'd `dpkg-query`.  The pending table handled
  these correctly because each exec flushes the slot with a fresh EVENT_RET.

## The wall (→ next)

We have watched execve — program launches — across seven chapters.  But a
running process does far more: opens files, makes network connections, calls
into the kernel constantly.  The next direction is **new hook types**:

- `openat` tracepoint to watch file access
- `kretprobe` / `fexit` to capture return values
- XDP / TC programs for network-level hooks

These use the same libbpf + CO-RE toolchain from ch7/8 — just different
`SEC(…)` annotations and context structs.
