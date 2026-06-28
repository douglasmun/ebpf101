#!/usr/bin/env python3
"""
Python-BPF — Chapter 24  (the kernel side in Python, a third way)
=================================================================

EXPERIMENTAL / bleeding-edge. Unlike chapters 1–23 (which use BCC or libbpf,
both battle-tested), this chapter uses Python-BPF — a young project that lets
you write the *kernel-side* program in pure Python and compiles it straight to
eBPF. Treat it as a preview of where the ecosystem is heading, not production.

  https://github.com/pythonbpf/Python-BPF   (default branch: master)

Three ways to write the kernel side, all in this repo:

  ch02 (BCC)         the eBPF program is a C *string*; BCC shells out to clang
                     at runtime to compile it. Needs LLVM/clang on the target.
                     ch02 is the closest comparator: it counts execve in a
                     BPF_HASH map (keyed on UID) and reads it from user space.
  ch07 (libbpf/CO-RE) the eBPF program is a real .c file, compiled ahead of time
                     to a portable .o; the target needs no compiler.
  ch24 (Python-BPF)  the eBPF program is *Python* — decorated functions whose
                     AST is lowered to LLVM IR (via llvmlite), then to a BPF .o,
                     then loaded with pylibbpf. No C is ever written.

What it does: hook the sys_enter_execve tracepoint and count launches per PID in
a hash map — the same hash-map-counter idea as ch02 (ch02 keys on UID; we key on
PID), so the *authoring model* is the thing to compare. Note this also moves from
ch02's kprobe to the tracepoint introduced in ch04 — Python-BPF's section string
names the tracepoint directly.

How the pieces fit:

  1. @bpf marks a function as kernel-side eBPF (not ordinary Python — it never
     runs in CPython; its AST is compiled to BPF bytecode).
  2. @bpf + @map (stacked) declares a BPF map; the decorated function returns a
     HashMap. Inside a @section function refer to it by bare name —
     counts.lookup(...) / counts.update(...), NOT counts() — to get .lookup/.update.
  3. @section("tracepoint/...") is Python-BPF's equivalent of libbpf's SEC() —
     it sets the program type and attach point.
  4. A LICENSE function (@bpf + @bpfglobal returning "GPL") is REQUIRED — the
     compiler emits a reference to it unconditionally; omit it and llc fails.
  5. User space: BPF() compiles this module to a .o (reading its own source via
     inspect), then .load() loads it and .attach_all() attaches every section.
     Read a map back by NAME: b["counts"], whose .items() returns a dict.

API note: this was pinned by actually running it (see docs/24-pythonbpf.md) —
the installed package has no load_and_attach()/attach(); it's load()+attach_all().

Dependencies (Linux only — like every chapter here): pythonbpf, pylibbpf,
llvmlite, plus clang + bpftool on PATH and a BTF-capable kernel. Pin versions
(see requirements.txt) — both packages are pre-1.0 and the API still moves.

Run it with root (eBPF programs require privilege to load):

    sudo python3 24-pythonbpf/hello_pythonbpf.py

Then run commands in another terminal. Ctrl-C stops and dumps the counts.

NOTE: the import surface and decorator names below follow Python-BPF's current
README/examples (master branch, 2026-06). Because both packages are pre-1.0,
re-check the upstream API if an import or signature has drifted.
"""

from ctypes import c_int32, c_int64, c_uint64, c_void_p

from pythonbpf import bpf, bpfglobal, map, section, BPF
from pythonbpf.maps import HashMap
from pythonbpf.helper import pid          # note: pythonbpf.helper (singular)


# --- The eBPF program, written in Python (not C, not a C string) -----------
# Each @bpf function is compiled to BPF bytecode. None of this runs in CPython.

# Every eBPF object needs a license; GPL-only helpers refuse to load without it.
# Python-BPF emits a reference to this symbol unconditionally — omitting it makes
# llc fail with "use of undefined value '@LICENSE'".
@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


@bpf
@map
def counts() -> HashMap:
    # key = PID, value = number of execve calls seen for that PID.
    return HashMap(key=c_int32, value=c_uint64, max_entries=4096)


@bpf
@section("tracepoint/syscalls/sys_enter_execve")
def count_exec(ctx: c_void_p) -> c_int64:
    process_id = pid()                       # bpf_get_current_pid_tgid() >> 32
    prev = counts.lookup(process_id)         # like map[key], None if absent
    counts.update(process_id, (prev or 0) + 1)
    return 0


# --- User space: compile, load, attach, then read the map ------------------
# BPF() inspects THIS module's source, compiles every @bpf object to a .o
# (Python AST -> LLVM IR via llvmlite -> llc -march=bpf), and returns a loadable
# object. .load() loads it into the kernel; .attach_all() wires each section to
# its hook. (BPF() must be called from a real .py file — it reads the caller's
# source frame, so it won't work from `python3 -c` or stdin.)
b = BPF()
b.load()
b.attach_all()

# Maps are read back by indexing the loaded object with the map's NAME. The
# handle's .items() returns a plain dict {key: value} (a full snapshot), and
# .keys()/.values() return lists; index access mp[k] also works.
counts_map = b["counts"]

print("Counting execve() per PID. Run commands in another terminal. Ctrl-C to stop.\n")

# Poll the map and reprint the table every 2s — the same live-read loop as ch02
# (count_by_uid). Reading on a timer (rather than only on Ctrl-C) avoids the
# fragile case where the interrupt lands mid-print and truncates the dump.
import time
try:
    while True:
        time.sleep(2)
        snapshot = counts_map.items()          # a dict {pid: count}
        print(f"\n{'PID':<8} EXECVE_COUNT")
        print("-" * 24)
        for k, v in sorted(snapshot.items()):
            print(f"{k:<8} {v}")
except KeyboardInterrupt:
    print("\nDetached. Bye!")
