#!/usr/bin/env python3
"""
eBPF Maps — Chapter 2
=====================

In Chapter 1 we printed a string on every execve. Useless flood, and we
couldn't even tell *who* did it. Here we fix both problems with a **map**.

A map is a key/value store that lives in the kernel and is shared between:
  - the eBPF program (runs in the kernel, writes to it on every event), and
  - our Python program (runs in user space, reads from it whenever it likes).

That shared map is THE central idea of eBPF: it's how kernel-side code and
user-space code talk to each other without a flood of prints.

What this program does:
  Every execve, the kernel program looks up the calling user's ID in a hash
  map and increments a counter. Python then prints the whole table every
  couple of seconds — a live "how many programs has each user launched"
  tally. No more spam; just an aggregate that updates in place.

Run it (root required to load eBPF):

    sudo python3 02-maps/count_by_uid.py

Then run commands as your user (and notice root/uid 0 climbing on its own
from all the background services). Ctrl-C to stop.
"""

from bcc import BPF
from time import sleep

# --- The eBPF program -------------------------------------------------------
# BPF_HASH(name) declares a hash map. With no types given, BCC defaults both
# key and value to u64 — fine for "uid -> count".
program = r"""
BPF_HASH(counter_table);

int hello(void *ctx) {
    u64 uid;
    u64 counter = 0;
    u64 *p;

    // bpf_get_current_uid_gid() packs gid in the high 32 bits and uid in the
    // low 32. Mask to keep just the uid.
    uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    // Read the current count for this uid (lookup returns a pointer, or NULL
    // if this uid isn't in the map yet).
    p = counter_table.lookup(&uid);
    if (p != 0) {
        counter = *p;
    }

    counter++;                              // bump it
    counter_table.update(&uid, &counter);   // write it back into the map

    // NOTE: this read-modify-write isn't atomic — two CPUs could race and
    // lose a count. For an exact counter you'd use an atomic add (e.g.
    // counter_table.increment(uid) in BCC). We keep it explicit here so the
    // map lookup/update is obvious. Close enough for learning.
    return 0;
}
"""

# Compile + load into the kernel, then hook execve (as in Chapter 1).
b = BPF(text=program)
syscall = b.get_syscall_fnname("execve")
b.attach_kprobe(event=syscall, fn_name="hello")

print("Counting execve() calls per user ID. Ctrl-C to exit.\n")


def uid_name(uid):
    """Best-effort: turn a numeric uid into a username for nicer output."""
    try:
        import pwd
        return pwd.getpwuid(uid).pw_name
    except (KeyError, ImportError):
        return "?"


# Every 2 seconds, walk the map from user space and print the whole table.
# b["counter_table"] gives us the same map the kernel is writing to.
try:
    while True:
        sleep(2)
        line = "  ".join(
            f"uid {k.value} ({uid_name(k.value)}): {v.value}"
            for k, v in b["counter_table"].items()
        )
        print(line if line else "(no execve calls seen yet)")
except KeyboardInterrupt:
    print("\nDetached. Bye!")
