# Chapter 2 — Maps

**Code:** [`../02-maps/count_by_uid.py`](../02-maps/count_by_uid.py)
**Run:** `sudo python3 02-maps/count_by_uid.py`

## Concept

A **map** is a key/value store living in the kernel, shared between the eBPF
program (writes on every event) and user space (reads whenever it likes). It is
**the** central mechanism of eBPF — almost every real tool is "kernel fills a
map, user space reads it."

## New building blocks

- **`BPF_HASH(name)`** — declares a hash map (default key/value type `u64`).
- **lookup → modify → update** — read the current value for a key, change it,
  write it back. We used this to increment a per-UID counter.
- **`bpf_get_current_uid_gid() & 0xFFFFFFFF`** — the helper packs gid (high 32
  bits) + uid (low 32); the mask keeps just the uid.
- **`b["counter_table"]`** in Python — the *same* map the kernel writes to,
  iterated every 2 seconds.

## What the output taught us

- **State now lives in the kernel** and persists between our reads — the counts
  are cumulative. Chapter 1 had no memory; this does.
- The map **grows keys on its own**: `root`, then our user, then `messagebus`
  appeared as each UID showed up for the first time.
- You can read behavior from the numbers: `root` climbs forever (background
  daemons); *our* uid only moves when *we* run something; `messagebus` (D-Bus)
  did exactly one exec then sat idle.
- Counts reset to zero on restart — the map is owned by the program and freed
  when it exits.

## Gotcha noted in the code

The read-modify-write isn't atomic — two CPUs can race and lose a count. The
production fix is an atomic increment (e.g. BCC's `.increment()`). We did it the
long way so the map operations are visible.

## The wall (→ Chapter 3)

A counter tells us *how many* per user, but throws away every detail: *which*
command, what PID, in what order. An aggregate can't tell a story. We need to
stream individual, structured events. Enter the **perf buffer**.
