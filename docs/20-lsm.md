# Chapter 20 — LSM BPF (from observing to governing)

**Code:** [`../20-lsm/`](../20-lsm/)
**Build:** `cd 20-lsm && make`
**Run:** `sudo ./20-lsm/execguard`  *(requires BPF to be an active LSM — see below)*
**Verify hands-free:** `sudo bash 20-lsm/verify-execguard.sh`  *(loads it, self-triggers a few execs, detaches)*

## Concept

Every chapter so far *watched*, *shaped*, or *routed*. **LSM BPF** is the one
that **decides**. It attaches to a **Linux Security Module** hook — the same
hooks AppArmor and SELinux use — and the program's **return value is a verdict**:

```
return 0;        →  allow the operation
return -EPERM;   →  deny it
```

The kernel calls LSM hooks at security-relevant moments — `bprm_check_security`
before executing a program, `file_open` before opening a file,
`socket_connect` before connecting — and honours what your BPF program returns.
That is eBPF as policy enforcement, not observation.

This chapter hooks **`bprm_check_security`** (the pre-execution check). For
safety it is an **auditor, not a blocker**: it logs who is executing what and
**always returns 0 (allow)**. The single line that would turn it into a blocker
is marked in the code — and left untaken on purpose:

```c
/* return -EPERM here (with a tight condition!) would BLOCK the exec.
   Doing it carelessly can lock you out of your own system. */
e->verdict = 0;
return 0;
```

## Prerequisite: BPF must be an active LSM

Unlike every other hook in this repo, LSM BPF needs **`bpf` enabled in the
kernel's `lsm=` boot parameter**. `CONFIG_BPF_LSM=y` (compiled in) is not enough —
it must also be *active*. The loader checks this first and, if it's missing, says
exactly how to fix it instead of failing cryptically. On this machine, right now:

```
$ ./execguard
BPF LSM is not active. Current LSMs: lockdown,capability,landlock,yama,apparmor
Enable it (CONFIG_BPF_LSM is already =y, so only a boot param + reboot):
  1. add 'bpf' to the lsm= list in /etc/default/grub, e.g.
     GRUB_CMDLINE_LINUX="... lsm=lockdown,capability,landlock,yama,apparmor,bpf"
  2. sudo update-grub && sudo reboot
Then re-run this program.
```

A helper script does step 1 safely — it reads your *current* LSM list (so it
preserves every active module), appends `bpf`, backs up `/etc/default/grub`, runs
`update-grub`, and is idempotent:

```
sudo bash 20-lsm/enable-bpf-lsm.sh   # then: sudo reboot
```

It writes the parameter to `GRUB_CMDLINE_LINUX_DEFAULT`, so booting **recovery
mode** still comes up without `bpf` — a clean fallback if anything misbehaves.

After running it and rebooting, the list confirms it:

```
$ cat /sys/kernel/security/lsm
lockdown,capability,landlock,yama,apparmor,bpf
```

> **Status note.** Verified live on this machine after the reboot — `bpf` is now
> an active LSM, the program attaches, and the exec-audit path logs verdicts (the
> real output is below). All 22 chapters now run live.

## Building blocks

### The LSM hook and its verdict

```c
SEC("lsm/bprm_check_security")
int BPF_PROG(exec_check, struct linux_binprm *bprm, int ret)
{
    if (ret != 0)
        return ret;                  /* an earlier LSM already denied — respect it */
    ...
    return 0;                        /* our verdict: allow */
}
```

Two LSM-specific details:
- **`BPF_PROG` appends `int ret`** — the verdict accumulated by LSM modules that
  ran before us. The correct citizen returns `ret` if it's already a denial,
  rather than overriding another module's "no".
- **The return value is the contract.** The kernel enforces it. This is the only
  program type in the repo whose output *changes what the kernel does*.

`bprm->filename` (read with `BPF_CORE_READ` + `bpf_probe_read_kernel_str`) is the
path being executed, so each record is `pid / verdict / comm / program`.

## What it shows once BPF LSM is enabled

With `bpf` in `lsm=` after the reboot, the `verify-execguard.sh` helper loaded the
program and triggered `ls` / `id` / `uname`. One line per execution, each with the
verdict the kernel honoured (this is the real run):

```
Auditing exec via LSM bprm_check (always allowing). Ctrl-C to stop.
PID      VERDICT COMM             PROGRAM
4486     allow   bash             /usr/bin/ls
4487     allow   bash             /usr/bin/id
4488     allow   bash             /usr/bin/uname
4489     allow   bash             /usr/bin/sleep
```

The `COMM` is `bash` (the script's shell is what calls `execve`), and the fourth
line is the helper's own `sleep` — the auditor catching itself in the act, just
as ch22's task iterator saw its own process.

Every line reads `allow` because that's what we return. The lesson is that this
column is *causal*: flip the one marked line to `return -EPERM` for a matching
program and the kernel would refuse to run it — `execve` would fail with
"Operation not permitted". That is the whole power, and danger, of LSM BPF.

## End of the line

That closes the arc this repo set out to walk:

- **Observe** — print, maps, perf/ring buffers; tracepoints, kprobes, uprobes
  (ch1–13, 15).
- **Understand the platform** — the verifier and bpftool (ch14, 16).
- **Act on the datapath** — XDP and tc/BPF (ch17–18).
- **Compose and govern** — tail calls and, here, LSM enforcement (ch19–20).

From `bpf_trace_printk("hello")` to returning a verdict the kernel obeys — the
same small machine (a verified program on a hook, sharing maps with user space),
pointed at progressively more of the system.

➡️ [Chapter 21](21-firewall.md) is an applied capstone — putting the datapath
*action* (`XDP_DROP`) and map-driven rules together into a real firewall.
