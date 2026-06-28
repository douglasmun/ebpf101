# ebpf101

Liz Rice's *Learning eBPF* — via the [Isovalent tutorial](https://isovalent.com/labs/ebpf-tutorial/) —
was our **starting point**, one chapter per directory. The repo has since gone well
**beyond** it. The opening chapters retrace the tutorial's arc (BCC → libbpf/CO-RE →
kprobes/uprobes); from there it keeps going — the verifier as a gate, the `bpftool`
workflow, the XDP and tc datapath, tail calls, LSM BPF (policy enforcement), BPF
iterators, and two applied capstones the tutorial never reaches: an XDP firewall and a
rule-based intrusion-detection system, drawn respectively from a Columbia EECS6891
lecture (Yannis Zarkadas, Spring 2024) and a research paper
([arXiv:2102.09980](https://arxiv.org/abs/2102.09980)). All 23 chapters are built
**and** run live on this machine; every program is written to be read.

📓 **Learning notes:** [`docs/`](docs/README.md) — the *why* behind each chapter and
what our actual runs revealed. The code is the *how*; the notes are the *why*.

## Chapters

| Dir | Topic | Stack | Status |
|-----|-------|-------|--------|
| `01-hello-world/` | kprobe on `execve`, print to trace buffer | BCC / Python | ✅ ready to run |
| `02-maps/` | `BPF_HASH` map: count `execve` per user ID, read from user space | BCC / Python | ✅ ready to run |
| `03-perf-buffer/` | `BPF_PERF_OUTPUT`: stream per-event PID/UID/command to user space | BCC / Python | ✅ ready to run |
| `04-tracepoint/` | `sys_enter_execve` tracepoint: read the launched binary's path (mini `execsnoop`) | BCC / Python | ✅ ready to run |
| `05-argv/` | read `execve`'s `argv` (double pointer indirection, multi-record reassembly): full command lines | BCC / Python | ✅ ready to run |
| `06-ringbuf/` | `BPF_RINGBUF_OUTPUT`: shared ring, zero-copy reserve/commit, explicit back-pressure | BCC / Python | ✅ ready to run |
| `07-libbpf/` | libbpf + CO-RE: real C file, `clang -target bpf`, skeleton, portable binary | C / libbpf | ✅ built |
| `08-argv-libbpf/` | port argv multi-record pattern to C: pending table replaces Python dict | C / libbpf | ✅ built |
| `09-openat/` | `sys_enter_openat`: every file open; flags bitmask decoding; kernel-side filter pattern | C / libbpf | ✅ built |
| `10-openat-ret/` | entry/exit correlation: stash map links `sys_enter` → `sys_exit`; captures fd or −errno | C / libbpf | ✅ built |
| `11-connect/` | `sys_enter/exit_connect`: every outbound TCP/UDP attempt; decode `sockaddr` with `bpf_probe_read_user`; destination IP+port+outcome | C / libbpf | ✅ built |
| `12-tcpstates/` | kprobe on `tcp_set_state`: full TCP lifecycle; read `struct sock` with `BPF_CORE_READ`; per-state durations and SYN→ESTABLISHED latency | C / libbpf | ✅ built |
| `13-tcplife/` | same `tcp_set_state` kprobe, per-connection summary at close: read `struct tcp_sock` byte counters / RTT / retransmits; stash identity at `SYN_SENT` to fix attribution | C / libbpf | ✅ built |
| `14-verifier/` | the verifier as a gate: programs that fail to load (NULL deref, unbounded loop, OOB index) + their fixes; capture verifier logs via `kernel_log_buf` + selective `set_autoload` | C / libbpf | ✅ built |
| `15-bashreadline/` | first **uprobe**: uretprobe on `/usr/bin/bash:readline` to trace every interactive shell command system-wide; manual uprobe attach by path+symbol; `bpf_ringbuf_discard` | C / libbpf | ✅ built |
| `16-bpftool/` | operating eBPF: a per-UID `openat` counter **pinned** to `/sys/fs/bpf`, then inspected/dumped with `bpftool` (prog/map show, dump by id & pinned path, xlated) | C / libbpf | ✅ built |
| `17-xdp/` | first **datapath** program: XDP packet counter per protocol (always `XDP_PASS`, never drops); direct packet access + verifier bounds checks; per-CPU array; attach to a NIC | C / libbpf | ✅ built |
| `18-tc/` | **tc/BPF**: count packets+bytes on **ingress AND egress** (egress is new vs XDP) via the `clsact` qdisc; `struct __sk_buff` + `skb->len`; always `TC_ACT_OK` | C / libbpf | ✅ built |
| `19-tailcall/` | **tail calls**: an `execve` dispatcher jumps via a `PROG_ARRAY` to a user/root handler; `bpf_tail_call` never returns; jump table wired from userspace | C / libbpf | ✅ built |
| `20-lsm/` | **LSM BPF**: hook `bprm_check_security`; the return value is an allow/deny **verdict** (audits + always allows); needs `bpf` in the kernel `lsm=` list | C / libbpf | ✅ built |
| `21-firewall/` | **XDP firewall**: parse to L4 and `XDP_DROP` blocked TCP/UDP ports; rules live in a userspace-filled `blocklist` map (runtime-configurable); safe defaults (`lo` 11111) | C / libbpf | ✅ built |
| `22-iterator/` | **BPF iterator**: a "pull" program — walk every `task_struct` and print it (a mini `ps`) via `bpf_seq_printf`; `attach_iter` → `bpf_iter_create` → `read()` | C / libbpf | ✅ built |
| `23-ids/` | **rule-based IDS**: a `SOCKET_FILTER` taps every packet to a ring buffer; userspace runs C2/anomaly rules (beaconing, port-scan, suspicious-port). No ML — readable rules; `bpf_skb_load_bytes` (socket filters get no direct packet access) | C / libbpf | ✅ built |
| `24-pythonbpf/` | **Python-BPF**: write the *kernel-side* program in pure Python (`@bpf`/`@map`/`@section`), lowered to LLVM IR via `llvmlite` → BPF `.o` → loaded by `pylibbpf`. Same hash-map execve-counter idea as ch02 (keyed on PID here) — "kernel side, three ways" | Python / Python-BPF | ⚠️ pre-1.0 dep, verified in Docker |

Chapters 1–23 are built **and** run live on this machine. Chapter 24
(Python-BPF) depends on a pre-1.0 project ("not ready for production use"), so
it's flagged as a preview — but it **was** run end-to-end (compile → load →
attach → map read, exit 0) in a privileged Ubuntu container on Docker Desktop's
kernel-6.12/aarch64 VM, since macOS has no kernel to load it into. Its API was
pinned by that run, not from docs; see [`docs/24-pythonbpf.md`](docs/24-pythonbpf.md)
for the container recipe and caveats (aarch64-only, x86 untested). Ch23's three rules were verified
on loopback with `23-ids/verify-ids.sh` (suspicious-port, port-scan, and a
0.0%-jitter beacon all fired). Ch20 had needed `bpf` added to the kernel `lsm=`
boot parameter first (`enable-bpf-lsm.sh` + a reboot); done, its exec-audit path
logs `allow` verdicts live. See [`docs/23-ids.md`](docs/23-ids.md) and
[`docs/20-lsm.md`](docs/20-lsm.md).

## Running an example

eBPF programs must be loaded by a privileged process, so examples run under `sudo`:

```bash
sudo python3 01-hello-world/hello.py
```

While it runs, open a **second terminal** and run any command (`ls`, `echo hi`).
Each new process triggers the `execve` hook and prints a line. `Ctrl-C` to stop.

## This machine's eBPF toolchain

- Kernel `6.8` with BTF at `/sys/kernel/btf/vmlinux` → CO-RE capable
- **BCC** (Python) — used for chapters 1–6
- **clang 18, llvm, libbpf-dev, libelf-dev** — installed at ch7; used for chapters 7+
- `bpftrace`, `bpftool`, `gcc`, `make`
