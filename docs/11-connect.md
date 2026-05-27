# Chapter 11 — Network visibility (connect tracing)

**Code:** [`../11-connect/`](../11-connect/)  
**Build:** `cd 11-connect && make`  
**Run:** `sudo ./11-connect/netsnoop`

## Concept

Chapters 7–10 were all about file access.  This chapter jumps to the network:
hook `sys_enter_connect` and `sys_exit_connect` to see every outbound TCP and
UDP connection attempt — destination address, port, and outcome.

The new skill is **reading a kernel struct through a user-space pointer**.
The `sockaddr` argument to `connect(2)` lives in the calling process's virtual
address space.  To read it safely from a BPF tracepoint we use
`bpf_probe_read_user` (the `_user` variant; using `_kernel` on a user pointer
is a classic eBPF mistake that the verifier may not catch).

## Building blocks

### Two programs, one stash (same pattern as ch10)

```
sys_enter_connect ──▶ bpf_map_update_elem(&stash, &pid, &addr_buf, BPF_ANY)
                                  │
                           stash map (BPF_MAP_TYPE_HASH, keyed by pid)
                                  │
sys_exit_connect  ◀── bpf_map_lookup_elem(&stash, &pid) → decode → ring buf
```

Entry saves raw `sockaddr` bytes; exit reads the return value and emits the
decoded record.  The same PID-keyed stash pattern from ch10 generalises to
every syscall that has interesting arguments at entry and a return value at exit.

### Reading a user-space pointer with `bpf_probe_read_user`

```c
struct addr_buf buf = {};
bpf_probe_read_user(&buf, sizeof(buf), uaddr);
```

- `uaddr` is `ctx->args[1]` cast to `const void *` — the `sockaddr *` the
  process passed to `connect`.
- We read into a fixed 128-byte buffer — enough for both `sockaddr_in` (16 B)
  and `sockaddr_in6` (28 B).
- The extra bytes beyond the actual struct size are zero (from the `= {}`
  initialisation).

### sockaddr layout (read as raw bytes)

```
sockaddr_in  (AF_INET, family == 2):
  bytes[0-1]  sa_family   (AF_INET = 2)
  bytes[2-3]  sin_port    (network byte order)
  bytes[4-7]  sin_addr    (network byte order)

sockaddr_in6 (AF_INET6, family == 10):
  bytes[0-1]  sa_family   (AF_INET6 = 10)
  bytes[2-3]  sin6_port   (network byte order)
  bytes[4-7]  sin6_flowinfo
  bytes[8-23] sin6_addr   (16 bytes, network byte order)
```

We peek at the first two bytes to get `sa_family` and skip everything that
isn't IPv4 or IPv6 (Unix sockets, Netlink, …).

### Byte-order conversion in the BPF program

```c
e->port  = bpf_ntohs(nport);   /* network → host */
e->addr4 = bpf_ntohl(naddr);   /* network → host */
```

`bpf_ntohs`/`bpf_ntohl` are the BPF equivalents of the userspace `ntohs`/`ntohl`
macros.  They are available via `<bpf/bpf_endian.h>` and compile to a single
byte-swap instruction on x86.

Doing the conversion in the BPF program means user space receives host-byte-order
values and can print them directly, without any byte-swapping in the event
handler.  (IPv6 addresses are left in network byte order because `inet_ntop`
expects them that way.)

### Return value semantics for connect(2)

| ret    | Meaning |
|--------|---------|
| 0      | Connected (UDP always; TCP loopback) |
| -115   | `-EINPROGRESS` — non-blocking TCP socket, handshake in progress (normal) |
| -111   | `-ECONNREFUSED` — port closed on the remote end |
| -110   | `-ETIMEDOUT` — no reply within the kernel's TCP timeout |
| -101   | `-ENETUNREACH` — no route to host |

Most real TCP connections show `-EINPROGRESS` because applications use
non-blocking I/O.  The connection succeeds later, signalled via `poll`/`epoll`.

### `#ifndef` guards for AF_ constants

`AF_INET` and `AF_INET6` are needed in both the BPF source (which includes only
`vmlinux.h`, not `<sys/socket.h>`) and the userspace source (which already gets
them from `<arpa/inet.h>`).  The shared header defines them behind `#ifndef`
guards so neither compilation unit sees a redefinition:

```c
#ifndef AF_INET
#define AF_INET   2
#endif
```

## What the output reveals

Run `sudo ./netsnoop` on an active machine and you immediately see:

- **Browsers**: dozens of connections per second to CDN edge nodes (port 443)
  and DNS servers (port 53/853), mix of IPv4 and IPv6.
- **System services**: `systemd-resolved` connecting to configured DNS resolvers;
  `packagekitd` polling for updates; `snapd` checking the store.
- **Non-blocking pattern**: virtually every browser connection shows
  `-EINPROGRESS` — the socket was set `O_NONBLOCK` before `connect`.
- **Connection failures**: occasional `-ECONNREFUSED` on localhost ports (a
  service tried to reach a local daemon that isn't running); `-ENETUNREACH` if
  a VPN or route is missing.

Filter to failures only:

```bash
sudo ./netsnoop | awk '$NF ~ /^err/'
```

Filter to a specific port (e.g., HTTPS) — PORT is the 6th column:

```bash
sudo ./netsnoop | awk '$6 == 443'
```

(Column-position `awk` is approximate: a few process names contain spaces —
`HTTP Client`, `Bun Pool 2` — which shift every field after COMM. The failures
filter above keys on `$NF`, the last field, so it is immune; a port filter is
not. For robust filtering, match on the address/port text instead.)

## Edge cases accepted for a learning tool

| Scenario | What happens | Production fix |
|----------|-------------|----------------|
| Non-blocking socket (most real connections) | ret = -EINPROGRESS; we log it | Also hook `connect`'s completion via `epoll_wait`/`io_uring` or kprobe on `tcp_v4_connect` |
| Process killed between enter and exit | stash entry leaks | Use `BPF_MAP_TYPE_LRU_HASH` to evict stale entries |
| Multi-threaded process, two threads connecting simultaneously | same PID-key race as ch10 | Key by full `bpf_get_current_pid_tgid()` (includes TID) |
| UDP "connect" (sets default peer, not a real handshake) | ret = 0, looks like instant success | Filter by `SOCK_DGRAM` type — requires reading socket internals via kprobe |

## The wall (→ next)

We can see *that* a connection was attempted and *where*.  We cannot yet see
*what was sent* — the payload.  Reading send/recv data requires hooking
`sys_enter_write`, `sys_enter_sendto`, or (for TLS) tapping into the encryption
layer before the data is encrypted.  That level of tracing belongs to dedicated
tools like `tcptracer`, `tcpdump`-over-BPF, or Cilium's network policy engine.

A more immediate next step is **TCP state machine tracing**: hook the kernel
function `tcp_set_state` (a kprobe, since there's no stable tracepoint) to track
the full lifecycle of a connection — `SYN_SENT → ESTABLISHED → FIN_WAIT → CLOSED`
— and measure connection latency from SYN to ESTABLISHED.

➡️ That is exactly [Chapter 12](12-tcpstates.md).
