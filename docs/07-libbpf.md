# Chapter 7 — libbpf + CO-RE

**Code:** [`../07-libbpf/`](../07-libbpf/)  
**Build:** `cd 07-libbpf && make` (no sudo)  
**Run:** `sudo ./07-libbpf/execsnoop`

## Concept

Abandon BCC's runtime-compilation model.  Write the BPF program as a real C
file, compile it once with `clang -target bpf`, and ship a binary that loads
pre-compiled bytecode.  This is **CO-RE**: Compile Once, Run Everywhere.

## The toolchain shift

| Step | BCC (ch 1–6) | libbpf / CO-RE (ch 7+) |
|------|-------------|------------------------|
| BPF C source | string inside Python | `execsnoop.bpf.c` |
| Compilation | LLVM JIT at `sudo python3 …` | `clang -target bpf` at build time |
| Kernel types | looked up at load time | `vmlinux.h` (generated from BTF, embedded CO-RE annotations) |
| User-space API | `BPF(text=…)` Python object | libbpf C API + **skeleton** |
| Portability | needs LLVM on every target | one binary, any kernel ≥ 5.4 with BTF |

## New building blocks

### vmlinux.h and CO-RE

```bash
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
```

This 3 MB header contains every kernel type (structs, enums, typedefs)
extracted from the kernel's own BTF section.  Including it in the BPF C file
means we reference real kernel types — no manually-maintained shadow structs.

CO-RE works because `clang` embeds *relocation records* in the BPF ELF for
every field access (`->pid`, `->comm`, etc.).  At load time, libbpf patches
those offsets against the *running* kernel's BTF.  The same `.o` handles a
field that moved between kernel versions automatically.

### The skeleton

```bash
bpftool gen skeleton execsnoop.bpf.o > execsnoop.skel.h
```

The skeleton is generated C code that wraps every map and program in the BPF
object as typed C pointers:

```c
struct execsnoop_bpf *skel = execsnoop_bpf__open_and_load();
execsnoop_bpf__attach(skel);
// skel->maps.events  — the ring buffer fd, by name
execsnoop_bpf__destroy(skel);
```

No string lookups, no fd juggling.  The compiler catches typos in map names.

### Build pipeline (four steps, all in `make`)

```
vmlinux.h          ← bpftool btf dump … (no sudo)
    ↓
execsnoop.bpf.o    ← clang -target bpf -c execsnoop.bpf.c
    ↓
execsnoop.skel.h   ← bpftool gen skeleton execsnoop.bpf.o
    ↓
execsnoop          ← gcc execsnoop.c -lbpf -lelf -lz
```

Only `sudo ./execsnoop` needs root; `make` runs as a normal user.

### Ring buffer in C (libbpf API)

```c
// Kernel side: reserve → fill → submit (same logic as ch 6, different API)
struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
bpf_ringbuf_submit(e, 0);

// User side: new → poll → free
struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(skel->maps.events),
                                          handle_event, NULL, NULL);
ring_buffer__poll(rb, 100 /* timeout ms */);
ring_buffer__free(rb);
```

## What the output revealed

Same content as ch4 (the launched binary path), but a different experience:
`make` ran once without `sudo`; `sudo ./execsnoop` loaded in milliseconds with
no LLVM compilation step.

The first run caught the terminal opening itself — the same
`gnome-shell → gio-launch-desktop → gnome-terminal → gnome-terminal.real → bash`
chain seen in ch3/4, now in a pre-compiled binary.  It also caught bash's
startup sequence: `lesspipe → basename → dirname → tput → dircolors`, then the
user's own commands (`ls`, `whoami`, `ping`).  Same data as Python, different
delivery: one binary, no interpreter, no JIT at load time.

## The wall (→ next)

Chapter 7 reads only `execve`'s `filename` argument (`ctx->args[0]` — the
binary path, e.g. `/usr/bin/ls`).  `argv` (`ctx->args[1]`) is the separate
pointer-to-pointer-array that holds the full command line; reading it requires
the multi-record protocol from ch5/6.  Porting that to C + libbpf is
chapter 8.  The C user-space pending-dict equivalent is also more involved
than the Python dict, making it a good standalone chapter.
