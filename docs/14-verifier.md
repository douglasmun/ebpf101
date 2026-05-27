# Chapter 14 — The verifier & debugging

**Code:** [`../14-verifier/`](../14-verifier/)
**Build:** `cd 14-verifier && make`
**Run:** `sudo ./14-verifier/verifier`

## Concept

Every chapter so far wrote BPF programs that *work*. This one writes programs
that **don't** — on purpose — to meet the part of eBPF that trips up everyone:
the **verifier**.

The verifier is a static analyser inside the kernel. Before it lets your program
run, it proves the program is safe on *every* path: no out-of-bounds memory, no
unchecked pointers, no unbounded loops, bounded stack. If it can't prove safety,
it rejects the load — your program never runs.

The crucial mental model:

```
   clang -target bpf            kernel verifier              attached & running
   (compiles your C,    ──▶   (proves safety at LOAD,  ──▶   (runs on each event)
    no safety checks)          rejects if unsure)
```

clang and the verifier are **different gates**. Code that compiles cleanly can
still be rejected at load. This chapter makes that gate visible.

## How this chapter is different

There is no tool here, no attach, and no event stream — so, unusually, **no
shared `.h` and nothing keyed by pid**. The entire lesson happens at *load
time*. `verifier.bpf.c` holds pairs of programs — a `bad_*` that the verifier
rejects and a `good_*` that fixes it — and `verifier.c` loads them one at a
time, printing the rejection and then the fix.

### Getting the verifier log programmatically

The reusable technique (worth lifting into your own debugging):

```c
LIBBPF_OPTS(bpf_object_open_opts, opts,
    .kernel_log_buf   = logbuf,
    .kernel_log_size  = sizeof(logbuf),
    .kernel_log_level = 1);                 /* 1 = log; 2 = verbose per-insn */

struct verifier_bpf *skel = verifier_bpf__open_opts(&opts);

/* Autoload exactly ONE program, so the captured log is about that program. */
bpf_object__for_each_program(p, skel->obj)
    bpf_program__set_autoload(p, strcmp(bpf_program__name(p), only) == 0);

int err = bpf_object__load(skel->obj);      /* verifier runs here */
/* on failure, the rejection is now in logbuf */
```

`set_autoload(false)` tells libbpf to skip a program at load — that is how we
isolate one specimen at a time instead of failing on the first bad one.

## The three lessons

Each `bad_*` **compiles fine** (clang doesn't run the verifier) but is rejected
when the kernel loads it.

### 1. A map lookup can return NULL

```c
__u64 *val = bpf_map_lookup_elem(&counts, &key);
*val += 1;                  /* BUG: val may be NULL */
```

`bpf_map_lookup_elem` returns the value pointer **or NULL** (key absent). The
verifier types the result `map_value_or_null` and forbids touching it until you
have proven it non-NULL. **Fix:** `if (!val) return 0;` first. This is the most
common beginner rejection.

### 2. Every loop must provably terminate

```c
while (bpf_get_prandom_u32() & 1)   /* BUG: verifier can't bound this */
    cnt++;
```

The verifier walks all paths; a back-edge it cannot bound is a possible infinite
loop. **Fix:** a compile-time constant bound (`for (i = 0; i < 64; i++)`) it can
walk, or the `bpf_loop()` helper for large counts.

### 3. Every memory access must be provably in bounds

```c
char buf[16];
__u32 i = bpf_get_prandom_u32();    /* 0 .. 2^32-1 */
buf[i] = 1;                         /* BUG: index not bounds-checked */
```

A variable index could land anywhere. **Fix:** constrain it with a mask —
`i & 0xf` pins it to `0..15`, which the verifier can verify against `buf[16]`.

> **Sidebar — caught even earlier than the verifier.** The classic "BPF stack is
> only 512 bytes" limit is enforced by *clang's BPF backend at compile time*: a
> `char buf[600]` local fails to build with *"Looks like the BPF stack limit is
> exceeded"*, before the verifier is ever reached. (We hit this writing the
> chapter — it's why lesson 3 uses an unbounded *index* instead, which is a
> genuinely verifier-only rejection.) So there are really three gates: clang's
> frontend, clang's BPF backend, then the kernel verifier.

## What the output reveals

`sudo ./verifier` loads each broken program, prints the kernel's rejection, then
loads the fix. Lesson 1, captured on this machine (kernel 6.8) — note how the log
*is* the verifier replaying your instructions, register by register, until it
hits the one it can't allow:

```
Lesson 1: Unchecked map lookup (possible NULL dereference)
  [bad_null_deref] ❌ REJECTED by the verifier (load err -13). Tail of log:
      | 0: (b7) r1 = 0                        ; R1_w=0
      | ; __u32 key = 0;
      | 1: (63) *(u32 *)(r10 -4) = r1         ; R1_w=0 R10=fp0 fp-8=0000????
      | 2: (bf) r2 = r10                      ; R2_w=fp0 R10=fp0
      | 3: (07) r2 += -4                      ; R2_w=fp-4
      | ; __u64 *val = bpf_map_lookup_elem(&counts, &key);
      | 4: (18) r1 = 0xffff8c3241d27000       ; R1_w=map_ptr(map=counts,ks=4,vs=8)
      | 6: (85) call bpf_map_lookup_elem#1    ; R0_w=map_value_or_null(id=1,map=counts,ks=4,vs=8)
      | ; *val += 1;                 /* BUG: val may be NULL */
      | 7: (79) r1 = *(u64 *)(r0 +0)
      | R0 invalid mem access 'map_value_or_null'
      | processed 7 insns (limit 1000000) ...
  Fix: bpf_map_lookup_elem may return NULL; test it before dereferencing.
  [good_null_deref] ✓ corrected version loads cleanly
```

Read it bottom-up: at instruction 6 the lookup leaves `R0` typed
`map_value_or_null`; at instruction 7 the program dereferences `R0` (`*val`)
**without a NULL check**, so the verifier refuses — `R0 invalid mem access
'map_value_or_null'`. The `good_null_deref` version adds `if (!val) return 0;`
and loads.

**Lesson 3** (out-of-bounds index) rejects the same way — `EACCES` — and names
the problem precisely:

```
Lesson 3: Out-of-bounds access (unbounded array index)
  [bad_oob_index] ❌ REJECTED by the verifier (load err -13). Tail of log:
      | 5: (77) r0 >>= 32   ; R0_w=scalar(smin=0,smax=umax=0xffffffff,var_off=(0x0; 0xffffffff))
      | 7: (07) r1 += -16   ; R1_w=fp-16
      | ; buf[i] = 1;
      | 8: (0f) r1 += r0    ; R1_w=fp(off=-16,smin=0,smax=umax=0xffffffff,...)
      | 10: (73) *(u8 *)(r1 +0) = r2
      | invalid unbounded variable-offset write to stack R1
  Fix: Constrain the index to the buffer size (mask with a constant).
  [good_oob_index] ✓ corrected version loads cleanly
```

`R1` is the stack pointer `fp-16` plus the unbounded index `r0` (`smax=0xffffffff`),
so the write could land anywhere on (or off) the stack — `invalid unbounded
variable-offset write to stack R1`. Masking the index (`& 0xf`) bounds `r0` and it
loads.

**Lesson 2** (unbounded loop) is the interesting one — it fails *differently*:

```
Lesson 2: Unbounded loop (termination not provable)
  [bad_unbounded_loop] ❌ REJECTED by the verifier (load err -28). Tail of log:
      | 5: (55) if r0 != 0x0 goto pc-4   2: R0=1 R6=0x1000289c8 R10=fp0
      | 2: (07) r6 += 1                  ; R6_w=0x1000289c9
      | 3: (85) call bpf_get_prandom_u32#7   ; R0_w=scalar()
      | ...
  Fix: Bound the loop with a compile-time constant (or use bpf_loop()).
  [good_bounded_loop] ✓ corrected version loads cleanly
```

Watch `R6` (our `cnt`) climb — `…c8`, `…c9`, … — on every pass through the
back-edge. Because `cnt` *changes each iteration*, no two loop states are ever
identical, so the verifier's state-pruning never kicks in and it keeps walking
the loop. That explodes the verbose log past our 128 KB buffer, and the load
returns **`-28` (`ENOSPC`)** — "no space" for the log. With a bigger buffer it
would instead hit the 1-million-instruction ceiling (`BPF program is too large`).
Either way the program is rejected; the fixed version with a constant bound walks
in a handful of instructions.

> **The error code tells you which gate said no.** A normal verifier rejection is
> **`-13` (`EACCES`)** — "the verifier denied it" (lessons 1 & 3); not `EINVAL`,
> which is for malformed load *requests*. A pathological program whose log
> overflows the buffer surfaces as **`-28` (`ENOSPC`)** (lesson 2). Seeing either
> from `bpf_object__load` means "read the log", not "bad arguments".

## Reading a verifier log

The log is the program's instructions as the verifier walked them; the **last
few lines** carry the reason. Practical habits:

- **Read bottom-up.** The final line is the verdict; the lines above show the
  register state (`R0`–`R10`) at the failing instruction.
- **Register types matter.** `map_value_or_null`, `scalar`, `pkt`, `inv` — the
  type tells you what check is missing (e.g. a NULL test, a bounds test).
- **Bump the level.** `kernel_log_level = 2` prints per-instruction state — noisy
  but decisive for "why does the verifier think this register is unbounded?".
- From the CLI, `bpftool prog load ... --debug` shows the same log.

## The wall (→ next)

We can now get *past* the verifier and reason about why a load fails. The
complementary skill is inspecting what is *already* loaded and running — listing
programs and maps, dumping map contents, following pinned objects — which is the
**`bpftool` workflow** (a natural next chapter). And every probe so far has been
kernel-side; **uprobes** would add userspace function tracing (libc, OpenSSL,
a shell's `readline`), the other major attach point we haven't touched.
