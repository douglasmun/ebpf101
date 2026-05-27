# Chapter 22 — BPF iterators (a pull, not a push)

**Code:** [`../22-iterator/`](../22-iterator/)
**Build:** `cd 22-iterator && make`
**Run:** `sudo ./22-iterator/taskdump`

## Concept

Every program before this was **pushed**: the kernel hit an event — a syscall, a
packet, an exec — and called our code. A **BPF iterator** inverts that. The
kernel walks one of its own data structures and calls our program **once per
element**; user space triggers the walk by *reading* the iterator. It's a
**pull**, producing a consistent snapshot on demand.

`taskdump` iterates every task (thread) in the system and prints its `tgid`,
`pid`, and `comm` — a tiny `ps`, built without `/proc`.

```
              push (ch1–21)                         pull (ch22)
  event → kernel calls your program      user read() → kernel walks tasks →
  (once per event)                        your program runs once per task
```

## Building blocks

### Output goes to a seq_file, not a map/ring buffer

Iterators have their own output channel: a **seq_file**, written with
`bpf_seq_printf` (via the `BPF_SEQ_PRINTF` macro). User space gets the text by
`read()`ing the iterator — no ring buffer, no map.

```c
SEC("iter/task")
int dump_task(struct bpf_iter__task *ctx)
{
    struct seq_file    *seq  = ctx->meta->seq;
    struct task_struct *task = ctx->task;        /* NULL on the final call */
    if (task == NULL) return 0;
    if (ctx->meta->seq_num == 0)                 /* first element → header */
        BPF_SEQ_PRINTF(seq, "%-8s %-8s %s\n", "TGID", "PID", "COMM");
    BPF_SEQ_PRINTF(seq, "%-8d %-8d %s\n", task->tgid, task->pid, task->comm);
    return 0;
}
```

- `ctx->meta->seq_num` is `0` on the first element — handy for a one-time header.
- `ctx->task` is the current `task_struct`, or **NULL** on the final call (a
  chance to print a footer).
- `task->tgid`/`pid`/`comm` are read by **direct (CO-RE) access** — the iterator
  hands us a *trusted* kernel pointer, so the verifier permits dereferencing it
  without `bpf_probe_read`.

### Driving it from user space: attach → create → read

```c
struct bpf_link *link = bpf_program__attach_iter(skel->progs.dump_task, NULL);
int iter_fd = bpf_iter_create(bpf_link__fd(link));   /* a readable fd */
while ((n = read(iter_fd, buf, sizeof(buf))) > 0)    /* each read advances the walk */
    fwrite(buf, 1, n, stdout);
```

Each `read()` advances the kernel's task walk and returns the text the program
printed; loop until EOF for the whole snapshot. (You can also **pin** an
iterator under bpffs and `cat` it like a `/proc` file — same idea as ch16's
pinning, applied to a live view.)

## What the output reveals

Real capture (excerpt — the full run listed ~600 tasks, every thread on the box):

```
$ sudo ./taskdump
TGID     PID      COMM
1        1        systemd
2        2        kthreadd
16       16       ksoftirqd/0          ← kernel threads: TGID == PID, names like kworker/*, migration/*
...
4571     4571     claude               ┐ one process (TGID 4571),
4571     4577     Bun Pool 0           │ many worker THREADS (distinct PIDs):
4571     4579     HTTP Client          │ the agent running this very tool
4571     17822    tokio-rt-worker      ┘
...
7378     7378     firefox              ┐ ~100 threads under one TGID:
7378     7508     Compositor           │ StyleThread#1, IPC I/O Parent,
7378     7477     StyleThread#1        │ WRWorker#0 … — a browser's thread zoo
...
2379     2379     run-cups-browse      ← the CUPS snap from the ch4/5 "mystery"
18613    18613    sudo                 ┐ the tool seeing itself, and its parent
18615    18615    taskdump             ┘
```

- **`TGID` is the process, `PID` is the thread.** Where they match it's a
  thread-group leader; where one `TGID` spans many `PID`s you're seeing that
  process's threads — `firefox` (7378) and `claude` (4571) each fan out into
  dozens, with the kernel's own per-thread names (`Compositor`, `Bun Pool 0`).
  `ps` hides this by default; the kernel's task list makes it plain.
- **Kernel threads vs userspace** are both here: `TGID == PID` with names like
  `kworker/R-*`, `ksoftirqd/0`, `migration/1` are kernel threads; the rest are
  your processes.
- It's a **snapshot**: the walk runs at `read()` time, so you get the task list
  at that instant — the consistency an event stream can't give.
- The tool appears in its own output (`taskdump`, under `sudo`) — the iteration
  is global, and even old friends turn up: `run-cups-browse`, the snap behind the
  `sleep 1` heartbeat traced back in ch4–5.

## The wall (→ extensions, and the end)

`iter/task` is one of a family. The same `attach → create → read` shape, with a
different `SEC("iter/…")`, walks other kernel structures:
- **`iter/tcp` / `iter/udp`** — every socket (build `ss` in BPF).
- **`iter/bpf_map_elem`** — every entry of a given map (dump map state with
  formatting your own program controls).
- **`iter/task_file`** — every open file of every task (build `lsof`).
- **Pin it** under `/sys/fs/bpf` and the iterator reads like a file — a custom,
  always-fresh `/proc` entry backed by your BPF program.

And with that, this repo has walked the whole span the field offers: **observe,
understand, act, compose, govern, and iterate** — from a one-line
`bpf_trace_printk("hello")` to walking the kernel's own task list. The same small
machine throughout; only where you point it changes.

➡️ [Chapter 23](23-ids.md) puts several of these pieces to work in one applied
tool — a rule-based intrusion-detection system: a socket filter taps the wire
and user space runs the C2/anomaly detection logic.
