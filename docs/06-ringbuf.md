# Chapter 6 — Ring Buffer

**Code:** [`../06-ringbuf/execsnoop_ringbuf.py`](../06-ringbuf/execsnoop_ringbuf.py)  
**Run:** `sudo python3 06-ringbuf/execsnoop_ringbuf.py`

## Concept

Replace `BPF_PERF_OUTPUT` (per-CPU rings, copied data) with
`BPF_RINGBUF_OUTPUT` (one shared ring, zero-copy reserve/commit, kernel ≥ 5.8).
Same execsnoop logic as Chapter 5; only the kernel→userspace bridge changes.

## New building blocks

- **Single shared ring buffer.**  `BPF_PERF_OUTPUT` allocates one ring per CPU;
  events arrive per-CPU with no global ordering guarantee.
  `BPF_RINGBUF_OUTPUT` gives all CPUs a window into one shared buffer →
  submission order is the delivery order.

- **Reserve/commit model.**

  | Mechanism | Perf buffer (Ch 5) | Ring buffer (Ch 6) |
  |-----------|--------------------|--------------------|
  | Where struct lives | BPF stack, then copied | directly inside the ring |
  | Kernel work | copy bytes in | flip a "committed" flag |
  | Full-ring signal | silent event drop | `reserve()` returns NULL |

  ```c
  // Ch 5: stack struct → copy into ring
  struct data_t data = {};
  data.pid = ...;
  events.perf_submit(ctx, &data, sizeof(data));

  // Ch 6: pointer INTO ring → fill in-place → commit
  struct data_t *slot = events.ringbuf_reserve(sizeof(*slot));
  if (!slot) return 0;   // explicit drop signal
  slot->pid = ...;
  events.ringbuf_submit(slot, 0);
  ```

- **Python side changes (small).**
  `open_perf_buffer(cb)` → `open_ring_buffer(cb)`,
  `perf_buffer_poll()` → `ring_buffer_poll()`, and the callback signature
  drops the `cpu` argument (replaced by a `ctx` pointer) since there is no
  per-CPU identity on a shared ring.

## What the output revealed

Output is identical to Chapter 5 — same commands, same args, same
alias-expansion catches.  The ring buffer's advantages (ordering, zero copy,
explicit back-pressure) only become visible under high-throughput load where
the perf buffer's per-CPU drops would show up as missing events.

## The wall (→ next)

Both chapters 5 and 6 still use **BCC**, which compiles the embedded C string
at runtime on the target using LLVM:

- LLVM must be present on every target machine.
- Each `sudo python3 ...` invocation pays a ~1-second JIT startup cost.
- The result is not portable — it's compiled fresh from source every run.

The production approach is **libbpf + CO-RE** (Compile Once, Run Everywhere):
- Compile the eBPF C to a `.bpf.o` with `clang -target bpf` at build time.
- Embed BTF type information in the object.
- At load time, libbpf patches memory offsets against the *running* kernel's
  BTF — one binary runs on any kernel ≥ 5.4 with BTF enabled.

This machine has BTF at `/sys/kernel/btf/vmlinux` so it is CO-RE capable, and
clang/llvm/libbpf-dev/libelf-dev were installed at the start of chapter 7.
That is the next chapter.
