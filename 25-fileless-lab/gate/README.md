# gate/ — block 19, the eBPF LSM exec gate

`exec_gate.bpf.c.fragment` is byte-identical to block 19 of the document. Regenerate
with `../extract-blocks.py`.

## Why the `.fragment` extension

**It does not compile, by design.** The document presents it as an excerpt of a larger
program, and the author explicitly marks the final `guard_bpf` section as pseudocode.
The extension keeps it out of any `*.bpf.c` glob so a build never picks it up and
appears to succeed.

`tests/gate_compile.sh` measures the gap rather than asserting it. It compiles twice:
once bare (fails instantly — the fragment has no `#include`s at all), then again with
`vmlinux.h` generated from the running kernel's BTF plus `bpf_helpers.h`/`bpf_tracing.h`,
which isolates the document's own omissions:

| Missing symbol | Kind |
|---|---|
| `policy`, `verdict_map` | BPF maps — referenced, never defined |
| `MAX_SIG`, `TAG_XATTR`, `DENY_ANON_EXEC` | policy `#define`s — never given |
| `TMPFS_MAGIC`, `HUGETLBFS_MAGIC` | `linux/magic.h` constants |
| `EPERM`, `PROT_EXEC` | `errno.h` / `mman.h` constants |
| `task_is_verified_agent` | helper — referenced, never written |
| `bpf_get_fsverity_digest`, `bpf_verify_pkcs7_signature` | kfuncs — need extern declarations |

To build on it you supply all of the above; the map definitions and
`task_is_verified_agent` are real design work, not boilerplate.

## What *was* verified

**The CO-RE field accesses are all correct.** Every struct member the fragment
dereferences exists with the expected type in this kernel's BTF:

```
struct file          -> struct inode *f_inode
struct inode         -> struct super_block *i_sb;  const unsigned int i_nlink
struct super_block   -> unsigned long s_magic
struct linux_binprm  -> struct file *file
```

So the fragment's logic is sound against a real kernel layout even though it will not
link as-is.

**Three kfuncs are absent on this kernel** (`bpf_get_fsverity_digest`,
`bpf_verify_pkcs7_signature`, `bpf_inode_storage_get`) while `bpf_get_file_xattr`,
`bpf_lookup_system_key` and `bpf_dynptr_adjust` are present. This is the 6.8+/`CONFIG_FS_VERITY`
requirement the document's own preflight script checks for, and matches the preflight
result recorded in FINDINGS.md.

**The gate was never executed.** FINDINGS.md #3 — `is_anon_exec_inode()` missing pattern
1f when `/tmp` is not tmpfs — comes from measured inode and filesystem data
(`tests/inode.sh`), not from running this program.

```sh
../run-tests.sh gate_compile.sh    # both compile stages + the categorized gap list
```
