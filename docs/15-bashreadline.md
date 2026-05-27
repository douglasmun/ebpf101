# Chapter 15 — Uprobes (`bashreadline`)

**Code:** [`../15-bashreadline/`](../15-bashreadline/)
**Build:** `cd 15-bashreadline && make`
**Run:** `sudo ./15-bashreadline/bashreadline` — then type in another bash

## Concept

Every probe so far ran in the kernel: syscall tracepoints (ch4–11) and a kprobe
on a kernel function (ch12–13). This chapter crosses to the other side with a
**uprobe** — a probe on a function in a *user-space* binary or shared library.

The demo is the classic one: hook the **return** of bash's `readline()`. That
function returns the line a user just finished typing, so a **uretprobe** on it
prints every interactive command on the whole machine.

```
                    kprobe (ch12–13)            uprobe (this chapter)
  attaches to    a kernel function          a function in an ELF file
                 (tcp_set_state)            (/usr/bin/bash : readline)
  identified by  symbol in /proc/kallsyms   binary path + symbol in the ELF
  reads          kernel memory (CORE_READ)  user memory (probe_read_user)
```

Both compile to the same program type (`BPF_PROG_TYPE_KPROBE`); only the *attach*
differs.

## Building blocks

### Attaching to a user-space symbol

The BPF program just declares itself a uretprobe and reads the return value:

```c
SEC("uretprobe")
int BPF_KRETPROBE(bash_readline, const void *ret)   /* ret = readline()'s char* */
```

The *target* is chosen in user space — explicitly, which is the teachable part:

```c
LIBBPF_OPTS(bpf_uprobe_opts, uopts, .func_name = "readline", .retprobe = true);
link = bpf_program__attach_uprobe_opts(skel->progs.bash_readline,
                                       -1, "/usr/bin/bash", 0, &uopts);
```

- **`/usr/bin/bash` + `"readline"`** — libbpf opens the ELF, finds `readline` in
  its symbol table, and converts it to a file offset to probe. On this machine
  the symbol is right there in bash's dynamic table:
  ```
  $ nm -D /usr/bin/bash | grep ' readline'
  00000000000df690 T readline
  ```
  (If a binary is stripped and the symbol isn't exported, you must supply a raw
  `func_offset` instead — see "the wall".)
- **`pid = -1`** — attach to *every* process mapping that binary, present and
  future. Start a new bash after the tracer and it is traced too.

### uretprobe = the return value

`BPF_KRETPROBE`'s argument is the function's return value (`PT_REGS_RC`). For
`readline` that is the `char *` to the typed line — a pointer into the bash
process's heap, so we copy it across with the `_user` reader from ch11:

```c
long n = bpf_probe_read_user_str(&e->line, sizeof(e->line), ret);
```

### reserve / **discard** / submit

A bare Enter makes `readline` return an empty string. Rather than emit a blank
record, we hand the ring-buffer reservation back unused — the counterpart to
`submit` we hadn't needed until now:

```c
struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
...
if (n <= 1) { bpf_ringbuf_discard(e, 0); return 0; }   /* empty / read error */
bpf_ringbuf_submit(e, 0);
```

## What the output reveals

Real capture on this machine — `sudo ./bashreadline`, then typing in a **second**
terminal's bash:

```
Tracing /usr/bin/bash:readline — type commands in another bash. Ctrl-C to stop.
PID      COMM             COMMAND
4957     bash             cls
4957     bash             echo hello
4957     bash             ps -al
```

The first line says everything: **`cls` is not a Linux command** (Windows muscle
memory). It was still captured — because `readline` returns the moment Enter is
pressed, *before* bash decides whether the command even exists. That is the
whole point:

- **It captures the line, not the execution.** You see exactly what was *typed*,
  including commands that are mistyped (`cls`), fail, or are blocked. The shell
  never running it doesn't matter — which is precisely why shell auditing is
  built on uprobes.
- **It is system-wide.** Here every line is PID `4957` (one interactive bash),
  but because `pid = -1` attaches to the *binary*, any other bash — another
  user's, or one in a container sharing the host bash — would appear too, no
  matter when it started.
- **Non-interactive bash is silent.** Script execution (`bash script.sh`) and
  piped input don't call `readline`, so they produce nothing — this traces
  *interactive* typing only.

## The same mechanism, bigger targets

`bashreadline` is the "hello world" of uprobes; the technique generalizes:

| Target | Function | What you see |
|--------|----------|--------------|
| `libssl` / OpenSSL | `SSL_write` / `SSL_read` | **plaintext** before encryption / after decryption (`sslsniff`) |
| `libc` | `getaddrinfo` | every DNS name a process resolves |
| Language runtimes | interpreter entry points | Python/Ruby/Java method calls |
| Your own service | any exported function | arguments + latency without recompiling |

Same `attach_uprobe_opts`, different binary path and symbol.

## The wall (→ next)

Uprobes need a way to *locate* the function: a symbol in the ELF, or a raw file
offset for stripped/static functions (and **USDT** statically-defined tracepoints
for a stable contract). And nothing here required `sudo`-free introspection of
what's *already* loaded. The natural next step is the **`bpftool` workflow** —
listing loaded programs and maps, dumping map contents, and following pinned
objects — the operational side of eBPF we've used in the Makefiles (`btf dump`,
`gen skeleton`) but never explored directly.
