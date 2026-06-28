# Chapter 24 — Python-BPF (the kernel side in Python)

**Code:** [`../24-pythonbpf/hello_pythonbpf.py`](../24-pythonbpf/hello_pythonbpf.py)
**Run:** `sudo python3 24-pythonbpf/hello_pythonbpf.py`
**Status:** ⚠️ experimental dependency, but **verified to run**. [Python-BPF](https://github.com/pythonbpf/Python-BPF) is a pre-1.0 project its authors call *"not ready for production use,"* so treat it as a preview, not a recommendation. This example was run end-to-end (compile → load → attach → map read, EXIT 0) in a privileged Ubuntu 24.04 container on Docker Desktop's **kernel 6.12 / aarch64** VM (BTF present, tracefs mounted). It has **not** been run on the host (macOS) or on x86; see the run notes at the bottom.

## Concept

Every previous chapter wrote the *kernel-side* program in C — either as a string
BCC compiles at runtime (ch1–6) or as a `.c` file libbpf compiles ahead of time
(ch7+). **Python-BPF removes the C entirely**: you write the eBPF program as
decorated Python functions, and the toolchain lowers their AST to LLVM IR (via
`llvmlite`), compiles that to a BPF object, and loads it with `pylibbpf`.

This chapter reuses a familiar shape — count `execve` in a hash map, the same
idea as [ch02](02-maps.md) — so the *authoring model* is the thing to compare.
It is the "kernel side, three ways" capstone. (Two small differences from ch02:
we key the map on PID rather than UID, and we hook the `sys_enter_execve`
**tracepoint** from [ch04](04-tracepoint.md) instead of ch02's kprobe — the
section string names the tracepoint directly.)

| Way | Kernel code is… | Compiled… | Target needs |
|-----|-----------------|-----------|--------------|
| [ch02](02-maps.md) BCC | a C **string** | at runtime, by clang | LLVM/clang installed |
| [ch07](07-libbpf.md) libbpf/CO-RE | a real **`.c` file** | ahead of time → portable `.o` | nothing (CO-RE) |
| **ch24 Python-BPF** | **Python** | Python AST → LLVM IR → `.o` | clang + bpftool, pre-1.0 libs |

## New building blocks

- **`@bpf`** — marks a function as kernel-side eBPF. It never executes in
  CPython; its AST is the input to the compiler. This is the key mental shift:
  the Python here is *source for a compiler*, not a script.
- **`@bpf` + `@map`** (stacked, over a function returning `HashMap`) — declares
  a BPF map. Referenced inside a `@section` function by the bare name
  (`counts.lookup(...)` / `counts.update(...)`, *not* `counts()`), it is the
  in-kernel map, much like the `BPF_HASH` of [ch02](02-maps.md).
- **`@bpf` + `@bpfglobal` `LICENSE` returning `"GPL"`** — mandatory. The
  compiler emits a reference to this symbol unconditionally; omit it and `llc`
  fails with *"use of undefined value '@LICENSE'"*. (GPL-only helpers also
  refuse to load without a license, exactly as in C.)
- **`@section("tracepoint/syscalls/sys_enter_execve")`** — Python-BPF's
  equivalent of libbpf's `SEC()`: it sets the program type and attach point. The
  string is the same tracepoint path used since [ch04](04-tracepoint.md).
- **Helpers as Python calls** — `pid()` compiles to
  `bpf_get_current_pid_tgid() >> 32`; map methods compile to `bpf_map_*`
  helpers. The Python *names* a helper; it doesn't call it in user space.
- **`b = BPF()` then `b.load()` then `b.attach_all()`** — `BPF()` reads *this
  module's own source* (via `inspect`), compiles every `@bpf` object to a `.o`
  (Python AST → LLVM IR via `llvmlite` → `llc -march=bpf`), and returns a
  loadable object; `.load()` loads it into the kernel, `.attach_all()` wires each
  section. Because it inspects the caller's source frame, `BPF()` only works from
  a real `.py` file — not `python3 -c` or stdin.
- **`b["counts"]`** — read a map back by indexing the loaded object with the
  map's **name** (a string). The handle's `.items()` returns a plain
  `dict {key: value}` snapshot; `.keys()`/`.values()` return lists; `mp[k]`
  works too.

## Why it's a separate, flagged track (not part of the core arc)

The BCC and libbpf chapters lean on tooling that has shipped for years. Python-BPF
(and its `pylibbpf` loader) is young — pre-1.0 and explicitly *not for production*
per upstream. Two practical consequences for this repo:

- **Pin the dependencies** ([`requirements.txt`](../24-pythonbpf/requirements.txt))
  — the decorator/import API still moves, so an unpinned upgrade can break the
  example.
- **The API in this chapter was pinned by running it, not by reading docs.** The
  upstream README and the installed package disagreed on several points; the
  forms used here are the ones that actually compiled, loaded, and ran on the
  tested version. In particular: imports are `from pythonbpf.helper import pid`
  (singular `helper`); the loader is `b.load()` + `b.attach_all()` (there is no
  `load_and_attach`/`attach` on the installed `BpfObject`); maps are read with
  `b["counts"]` (by name), whose `.items()` is a `dict`; the `LICENSE`
  `@bpfglobal` is required or `llc` errors. Re-verify on the version you install,
  since both packages are pre-1.0.

## Where it fits

Conceptually this is a *fourth* way to get bytecode into the kernel, alongside
the trace-buffer/map/perf/ring-buffer bridges of ch1–6 and the compiled-C model
of ch7+. It changes **who writes the kernel program and in what language** —
the hook (`sys_enter_execve` tracepoint, as in ch04+) and the bridge (a hash map
read from user space, as in ch02) are both things the repo has already done in C.
What's new is authoring the kernel side in Python. If the
project matures, "write eBPF in Python, compile to a portable object" could
collapse the BCC-vs-libbpf trade-off (runtime clang vs. ahead-of-time C) into a
single Pythonic workflow. For now: a promising preview, flagged as such.

## Running it (host is macOS — use a Linux container)

This repo's host is Apple Silicon macOS, which has no Linux kernel to load eBPF
into. The other chapters assume a Linux box; for this one a privileged container
on Docker Desktop's LinuxKit VM works, and is how the example was verified. The
VM kernel (6.12) ships BTF; you only need to mount tracefs so libbpf can resolve
the tracepoint id. Sketch:

```dockerfile
FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip python3-dev clang llvm \
    libbpf-dev libelf-dev zlib1g-dev libcap-dev libssl-dev \
    git make gcc g++ cmake ninja-build pybind11-dev pkg-config ca-certificates
# bpftool isn't installable standalone on Ubuntu — build it from source:
RUN git clone --depth 1 --recurse-submodules https://github.com/libbpf/bpftool.git /tmp/bpftool \
 && make -C /tmp/bpftool/src -j"$(nproc)" && make -C /tmp/bpftool/src install
RUN pip3 install --break-system-packages pythonbpf pylibbpf llvmlite
```

```bash
# then, inside a --privileged run with the program mounted at /work:
mount -t tracefs nodev /sys/kernel/tracing
python3 /work/hello_pythonbpf.py     # Ctrl-C to stop
```

Notes from the actual run: `pip install pythonbpf` pulls in `pylibbpf`, which
**builds from source** (cmake/ninja/pybind11 + `python3-dev` — hence those
packages). The container compiles a BPF object for **aarch64**; the x86 path is
untested here. tracefs must be mounted at `/sys/kernel/tracing` specifically —
libbpf looks there first, and a mount only at `/sys/kernel/debug/tracing` gave
`-ENOENT` on the tracepoint.
