# Chapter 16 — The `bpftool` workflow (pinning & inspection)

**Code:** [`../16-bpftool/`](../16-bpftool/)
**Build:** `cd 16-bpftool && make`
**Run:** `sudo ./16-bpftool/opencount` — then inspect with `bpftool` in another terminal

## Concept

Every chapter so far *wrote* eBPF. This one is about *operating* it: once a
program is loaded, how do you see what's there, read a map, or follow an object
that outlives its loader? That is the job of **`bpftool`** — the Swiss-army CLI
we've quietly leaned on in every Makefile (`bpftool btf dump`, `bpftool gen
skeleton`) but never actually explored.

The specimen is intentionally tiny: a tracepoint that counts `openat(2)` calls
per UID into a hash map. Nothing streams to user space — **`bpftool` reads the
map for us**. (As in ch14 there is no shared `name.h`: there's no kernel↔user
struct, because user space never touches the map.)

## New concept: pinning to bpffs

A loaded BPF object normally dies when the last file descriptor to it closes —
i.e. when the loader exits. **Pinning** creates an entry in the BPF filesystem
(`bpffs`, mounted at `/sys/fs/bpf`) that holds a reference and gives the object a
**name and a path**:

```c
mkdir("/sys/fs/bpf/ebpf101", 0700);
bpf_map__pin(skel->maps.open_count,  "/sys/fs/bpf/ebpf101/open_count");
bpf_program__pin(skel->progs.count_open, "/sys/fs/bpf/ebpf101/count_open");
```

Two payoffs:
- **Stable addressing** — `bpftool map dump pinned /sys/fs/bpf/ebpf101/open_count`
  works without knowing the kernel-assigned id.
- **Persistence** — leave the pin in place and the program keeps running after
  the loader exits; the pin is the reference keeping it alive. (Our loader
  unpins on Ctrl-C; comment that out and the counter survives — `rm` the pin to
  finally release it.)

```
$ ls /sys/fs/bpf/ebpf101/
count_open  open_count
```

## The bpftool tour

`opencount` prints these with the live ids filled in. Run them as root while it's
attached.

### List and show — what's loaded

```
# every loaded program system-wide (ours + whatever else is running)
sudo bpftool prog list

# detail on one program (real output, this machine)
sudo bpftool prog show id 139
  139: tracepoint  name count_open  tag f4dd97c9bdd8cfd9  gpl
       loaded_at 2026-05-27T23:59:03+0800  uid 0
       xlated 200B  jited 123B  memlock 4096B  map_ids 31
       btf_id 280
```

`prog show` tells you the **type** (`tracepoint`), the **maps it uses**
(`map_ids 31`), the **translated/JITed sizes**, and that it carries BTF
(`btf_id 280`) — everything you need to identify a program you didn't load
yourself.

> **Programs and maps live in separate id spaces.** Above, the *program* is id
> 139 and *its map* is id 31. `bpftool map dump id 139` fails (`No such file or
> directory` — there is no map 139); `bpftool prog dump id 139` fails too, because
> `prog dump` needs a mode (`xlated`/`jited`). Both are real mistakes worth making
> once: use the right noun's id, and give `prog dump` its keyword.

### Read a map — without writing any code

```
sudo bpftool map show id <MAPID>
  <MAPID>: hash  name open_count  flags 0x0
           key 4B  value 8B  max_entries 1024  memlock ...

sudo bpftool map dump id <MAPID>           # or: dump pinned /sys/fs/bpf/ebpf101/open_count
```

Because the map carries **BTF** (we declared `__type(key, __u32)` and
`__type(value, __u64)`), bpftool knows the field types and **decodes them for
you** — real dump, no hex math required:

```json
[{
        "key": 1000,
        "value": 240
    },{
        "key": 129,
        "value": 48
    },{
        "key": 0,
        "value": 105
    }
]
```

So `key 1000` is uid 1000 with 240 opens, `129` is a service uid, `0` is root.
**Only a map *without* BTF dumps as raw little-endian bytes** —
`key: e8 03 00 00  value: f0 00 ...` — which you'd then decode by hand
(`0x3e8 = 1000`). Providing the `__type(...)` hints in the map definition is what
buys the readable output here (and pass `-jp` for pretty JSON explicitly).

### See the program the verifier actually runs

```
sudo bpftool prog dump xlated id <ID>     # post-verifier bytecode (what ch14 walked)
sudo bpftool prog dump jited  id <ID>     # native machine code, if JITed
```

`xlated` is the same instruction stream the verifier logged in ch14 — useful for
confirming what your C actually compiled to.

### Other everyday subcommands

| Command | Shows |
|---------|-------|
| `bpftool btf dump file /sys/kernel/btf/vmlinux format c` | generates `vmlinux.h` (every chapter's Makefile step 1) |
| `bpftool gen skeleton x.bpf.o` | the `.skel.h` (Makefile step 3) |
| `bpftool prog show pinned <path>` | a program by its bpffs pin |
| `bpftool net show` / `bpftool cgroup tree` | XDP/tc and cgroup attachments |
| `bpftool prog tracelog` | the shared `bpf_trace_printk` buffer (ch1's output, system-wide) |

## What the output reveals

Real capture on this machine. `opencount` printed `prog id=139, map id=31`, then
from another terminal:

```
$ sudo bpftool map dump id 31
[{
        "key": 1000,
        "value": 240
    },{
        "key": 129,
        "value": 48
    },{
        "key": 0,
        "value": 105
    }
]
```

uid 1000 (you) had opened 240 files, uid 129 (a service account) 48, uid 0
(root/daemons) 105. Re-run `map dump` a moment later and the values have grown —
you're watching kernel state mutate live, with no code of your own reading it.
This is the whole pitch of the chapter: the map and program are inspectable,
dumpable, and (via the bpffs pins) addressable by path, entirely from the command
line.

## The wall (→ next)

`bpftool` is read-and-operate: it inspects, dumps, pins, and loads, but the
*interesting* programs it lists do real work. Everything in this repo so far has
been **observability** — watching events. The remaining frontier is eBPF that
**acts on** data in the datapath: **XDP** (drop/redirect packets at the NIC
before the kernel network stack), **tc/BPF** (shaping and filtering), **tail
calls** (chaining programs to scale past the instruction limit), and **LSM BPF**
(security policy decisions). Those move eBPF from *seeing* to *deciding*.

➡️ [Chapter 17](17-xdp.md) takes the first datapath step with XDP.
