# Chapter 19 — Tail calls (program-to-program dispatch)

**Code:** [`../19-tailcall/`](../19-tailcall/)
**Build:** `cd 19-tailcall && make`
**Run:** `sudo ./19-tailcall/tailcall` — then run commands in another terminal

## Concept

A **tail call** lets one BPF program hand control to another. The crucial thing:
it is **not a function call** — `bpf_tail_call()` is closer to `goto` or `exec`.
It replaces the running program with the target (reusing the same stack and
context) and **never returns**. Code after a *successful* tail call does not run.

Why it exists:
- **Scaling past the verifier limit.** Each program is verified independently and
  capped at ~1M instructions. Splitting a big pipeline into stages chained by
  tail calls keeps each stage verifiable.
- **Runtime dispatch.** The target is picked at run time from a `PROG_ARRAY`
  jump table — a switch statement whose cases are whole programs.

The demo dispatches each `execve` to a per-privilege handler:

```
execve ─▶ dispatch ─tail_call(jmp_table[idx])─▶ handle_user   (uid != 0)
                                            └──▶ handle_root   (uid == 0)
```

## Building blocks

### The jump table is a PROG_ARRAY

```c
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 2);
    __type(key,   __u32);
    __type(value, __u32);     /* a program fd */
} jmp_table SEC(".maps");
```

Its slots are filled **from user space** — the loader inserts each handler's
program fd at the right index. The skeleton loads the programs but can't know
which one belongs in which slot; that wiring is the loader's job:

```c
key = IDX_USER; fd = bpf_program__fd(skel->progs.handle_user);
bpf_map_update_elem(jmp_table_fd, &key, &fd, BPF_ANY);
key = IDX_ROOT; fd = bpf_program__fd(skel->progs.handle_root);
bpf_map_update_elem(jmp_table_fd, &key, &fd, BPF_ANY);
```

### Jump, and never come back

```c
__u32 idx = (uid == 0) ? IDX_ROOT : IDX_USER;
bpf_tail_call(ctx, &jmp_table, idx);   /* transfer to the handler */
bump(IDX_MISS);                        /* only runs if the tail call FAILED */
return 0;
```

`bump(IDX_MISS)` is reached only when the tail call *can't* happen — an empty
slot, or exceeding the **33-deep** tail-call chain limit. With both slots wired,
the miss counter stays at zero, which is the proof the jump succeeded.

### Attach only the entry point

The handlers are reached *by tail call*, not by their own attachment. So the
loader attaches **only** `dispatch` (with `bpf_program__attach`), and must *not*
call the skeleton's `__attach()` — which would attach all three programs to the
tracepoint and run them independently. (All three share the same program type,
`tracepoint`, which is required: a tail call's target must match the caller's
type.)

## What the output reveals

Real capture: with the tool running, a second terminal ran exactly three things —
`ls`, `echo hi`, `sudo ls /bin`:

```
execve dispatched by tail call:
  user (uid != 0) : 2
  root (uid == 0) : 1
  dispatch miss   : 0   (tail call fell through — should stay 0)
```

The numbers line up with the commands precisely, and that precision teaches more
than a big busy count would:

- **`ls` → `user` +1.** A normal exec by uid 1000.
- **`echo hi` → nothing.** `echo` is a **bash builtin** — no `execve` happens, so
  there is nothing to dispatch. (A great reminder of what `sys_enter_execve`
  does and doesn't see.)
- **`sudo ls /bin` → `user` +1 *and* `root` +1.** The shell execs `sudo` while
  still uid 1000 (so the dispatcher routes it to `handle_user`); then `sudo`,
  now setuid-root, execs `ls` as uid 0 (routed to `handle_root`). You can *see*
  the privilege transition as one user-exec followed by one root-exec.

Totals: `user 2` (ls, sudo), `root 1` (sudo's ls), and **`dispatch miss 0`** —
the load-bearing detail. Miss would only increment if a tail call failed, so a
steady zero proves every dispatch transferred and the code after
`bpf_tail_call` never ran: the "never returns" semantic, visible as a number.
(Leave it running longer and `root` climbs on its own as daemons exec helpers.)

## The wall (→ next)

We can now observe, shape, and *route* — but every program so far has reported on
the system rather than *governing* it. The last step on the advanced track is
**LSM BPF**: attaching to Linux Security Module hooks (`file_open`, `bprm_check`,
`socket_connect`, …) where the program's return value is an allow/deny verdict.
That is eBPF as policy enforcement — the move from watching the kernel to telling
it "no".
