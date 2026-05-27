# Chapter 10 — openat return value (entry/exit correlation)

**Code:** [`../10-openat-ret/`](../10-openat-ret/)  
**Build:** `cd 10-openat-ret && make`  
**Run:** `sudo ./10-openat-ret/opensnoop`

## Concept

Chapter 9 saw the *intent* — what was being opened and with what flags.  This
chapter adds the *outcome* — the fd number on success, or −errno on failure —
by attaching a second BPF program to `sys_exit_openat` and linking the two
events through a shared BPF hash map.

## New building blocks

### Two programs, one object, one stash map

```
sys_enter_openat ──▶ bpf_map_update_elem(&stash, &pid, &entry, BPF_ANY)
                                │
                         stash map (BPF_MAP_TYPE_HASH, keyed by pid)
                                │
sys_exit_openat  ◀── bpf_map_lookup_elem(&stash, &pid) → combine → ring buf
```

Both `trace_enter` and `trace_exit` live in the same `.bpf.c` file.  The
skeleton's `__attach()` pins both tracepoints in one call.  User space
interacts only with the ring buffer; it never touches `stash`.

### BPF_MAP_TYPE_HASH — the general-purpose BPF map

Chapters 2–3 used `BPF_HASH` (BCC macro).  Here is the native libbpf
equivalent:

```c
struct {
    __uint(type,  BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key,   __u32);          /* pid */
    __type(value, struct entry_t); /* filename + flags */
} stash SEC(".maps");
```

The three verifier-required operations:
- `bpf_map_update_elem(&stash, &pid, &e, BPF_ANY)` — insert or overwrite
- `bpf_map_lookup_elem(&stash, &pid)` — returns a **pointer into the map**
  (not a copy), or NULL if absent
- `bpf_map_delete_elem(&stash, &pid)` — remove after consuming

### Reading the return value

`sys_exit_openat` uses `trace_event_raw_sys_exit` (not `sys_enter`):

```c
SEC("tracepoint/syscalls/sys_exit_openat")
int trace_exit(struct trace_event_raw_sys_exit *ctx)
{
    long ret = ctx->ret;   /* fd (≥0) or −errno (<0) */
```

The sign conveys the outcome: `3` means fd 3 opened successfully; `-2` means
ENOENT (no such file); `-13` means EACCES (permission denied).

### Edge cases accepted for a learning tool

| Scenario | What happens | Production fix |
|----------|-------------|----------------|
| Process killed between enter and exit | stash entry leaks | LRU map (`BPF_MAP_TYPE_LRU_HASH`) evicts old entries |
| Multi-threaded process, two threads opening simultaneously | thread race: both threads share the same pid key, one stash entry overwrites the other | Key by `(u64)pid<<32 \| tid` (use the full `bpf_get_current_pid_tgid()` return value) |

## What the output revealed

### Successes

- **systemd-oomd** (UID 129): polling the same 6 cgroup memory-pressure files
  on a ~1-second heartbeat — `memory.pressure`, `memory.current`, `memory.min`,
  `memory.low`, `memory.swap.current`, `memory.stat` — always getting fd 8.
  The fd is constant because the daemon opens, reads, and closes in a tight
  loop; fd 8 is the next free slot each time after the standard fds (0-2) and
  a handful of internal ones.

- **thermald** (UID 0): reading Intel RAPL energy counters
  (`intel-rapl:0/energy_uj`, `intel-rapl:0:2/energy_uj`) and thermal zone
  temperatures (`thermal_zone6/temp`) for CPU thermal management.

- **upowerd** (UID 0): reading 13 battery sysfs files sequentially —
  `manufacturer`, `model_name`, `serial_number`, `voltage_min_design`,
  `cycle_count`, `energy_full`, `energy_full_design`, `technology`,
  `voltage_now`, `power_now`, `energy_now`, `capacity`, `status`.  This is the
  full battery state poll the desktop uses for the battery indicator.

- **FSBroker\*** (UID 1000, PID 5259): Firefox's sandbox IPC broker reading
  `/proc/*/statm` and `/proc/*/smaps` for each renderer process.  fd 133 means
  Firefox holds 130+ file descriptors open — sandboxed processes can't make
  syscalls directly, so a trusted broker does it on their behalf.

### Failures (via `awk '$4 < 0'`)

- **cron** (UID 0), ENOENT on `/var/lib/sss/mc/initgroups`: cron probes the
  SSSD (System Security Services Daemon) user-lookup cache on every job;
  SSSD isn't running on this machine so the cache files don't exist.  Benign,
  but a recurring noise source in opensnoop output.

- **systemd-journal**, ENOENT on `/run/systemd/units/log-extra-fields:cron.service`:
  journald checks for an optional per-service extra-fields file; absent is
  normal.

- **claude** (UID 1000), ENOENT on `/etc/claude-code/managed-settings.json`
  and `/etc/claude-code/managed-settings.d`: Claude Code probes for
  enterprise-managed config on startup.  Not present on this machine — so we
  caught Claude probing for its own config while it was running.  The tool
  observing itself is a nice demonstration that the hook is truly global.

To see only failures (RET is the 4th column):
```bash
sudo ./opensnoop | awk '$4 < 0'
```

(This holds while COMM is a single token. A handful of process names contain
spaces — `HTTP Client`, `Bun Pool 2` — and shift every field after COMM, so on a
busy box prefer matching the text, e.g. `awk '/ -[0-9]/'`.)

## The wall (→ next)

We can now see syscall entry and exit, linked by a PID-keyed stash map.  The
same entry/exit pattern generalizes to any syscall pair — `connect`/`connect`
exit, `read`/`read` exit, `execve`/`execve` exit.

The next natural jump is **network visibility**: hook `sys_enter_connect` to
see every outbound TCP/UDP connection attempt, with the destination address
decoded from the `sockaddr` struct in user space.  This requires reading a
kernel struct (`struct sockaddr_in`) through `bpf_probe_read_user` — a new
kind of data extraction we haven't done yet.

➡️ That is exactly [Chapter 11](11-connect.md).
