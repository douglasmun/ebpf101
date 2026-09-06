# Fileless Execution Lab — Live Test Record

Live-test record for **"Advanced Linux Threat Detection — File Identity vs Fileless
Execution" (TLP:GREEN, v1.1)**. Every code block in the document that can be executed
was extracted verbatim, built, and run under Docker. This file records what was done,
what was observed, and what was found.

**Result: all 8 executable patterns work as documented.** The document's central claims
about `/proc/PID/exe`, `ETXTBSY`, and the `vm.memfd_noexec` mitigation are all
substantiated by measurement. Eight issues were found, none of which invalidate the
document's thesis; the three worth acting on are a data-loss bug in a printed command
line (#1), a gate/filesystem assumption that does not hold on overlayfs (#3), and two
auditd rules that fail to load at all (#8).

- Tested: 2026-09-06
- Document audited: `Adv_Linux_Threat_Detection_-_File_Identity_vs_Fileless_Execution_v1.1.html`,
  and the result of that audit, the same document at v1.2. **Neither is in this
  repository** — both are TLP:GREEN with an author-imposed need-to-know restriction.
  They are superseded by **v1.3, which is TLP:CLEAR and published here** in HTML and
  PDF with the same technical content.

  Everything the document contained that this lab exercises is reproduced here as
  source: `src-v1.1-verbatim/` is the code exactly as v1.1 printed it, and `src/` is
  the code as published in v1.2, re-extracted from that document. So the findings
  below can be reproduced in full without the HTML.
- Test host: Apple Silicon (arm64), Docker 29.7.2

## Method

The document is a React-rendered HTML export; the code lives in 27 `<pre>` blocks with
syntax-highlighting `<span>`s. `extract-blocks.py` de-tags and unescapes them, which
lands the C and shell byte-for-byte as printed. Ten blocks are source files and were
copied out **unmodified** — no fixes were applied before the first run, so build
warnings and runtime failures are the document's, not the harness's. That verbatim v1.1
extraction is preserved as `src-v1.1-verbatim/`.

`src/` now holds the code as published in **v1.2**, re-extracted from that document and
verified identical to it (all 10 files). The diff between the two trees is the evidence
for findings #1, #2 and #7.

```
src/                 the code as published in v1.2 — regenerate with extract-blocks.py
src-v1.1-verbatim/   exactly what v1.1 printed; the before-state for every finding
detection/           blocks 21-24 verbatim from v1.1: auditd rules + 3 Sigma rules
detection-patched/   the same, with the auditd `-F exe=` fix (#8) that v1.2 ships
gate/                block 19 verbatim: the eBPF LSM gate (a fragment; does not compile)
tests/               the harness written for this exercise (not from the document)
logs/                captured transcript of a full run — start at logs/01-summary.txt
```

All findings below were measured against the **unmodified** `src-v1.1-verbatim/`.
`src/` differs in exactly 3 of 10 files and passes the same 8/8; reproduce the original
behaviour with `SRC=src-v1.1-verbatim ./run-tests.sh`.

| Block | File | Doc pattern |
|---|---|---|
| 8, 9 | `hello.c`, `sleeper.c` | payloads |
| 10 | `memfd_exec.c` | 1a — `execve("/proc/self/fd/N")` |
| 11 | `memfd_execveat.c` | 1a — `execveat(fd, "", AT_EMPTY_PATH)` |
| 12 | `memfd_script.c` | 1b — shebang script from a memfd |
| 13 | `interp_oneliner.sh` | 1d — interpreter builds the memfd |
| 14 | `tmpfile_exec.c` | 1f — `O_TMPFILE` |
| 15 | `deleted_exec.c` | 4 — unlink-then-`fexecve` |
| 16 | `Makefile` | build |
| 25 | `fileless-gate-preflight.sh` | preflight |

Blocks 17, 18, 26 are *expected output* and were used as the oracle. Blocks 19–24
(eBPF LSM gate, signing pipeline, auditd rules, Sigma rules) are configuration or
partial source; the openssl pipeline was executed, the rest reviewed against measured
data.

### Environment

Debian trixie, **kernel 7.0.12-linuxkit, aarch64**, gcc 14, glibc 2.41.

Two environment caveats matter when reading the results below:

- `CONFIG_FS_VERITY` is **not set** on this kernel, so the fs-verity *enforcement* path
  could not be exercised — only the userspace tooling.
- `/tmp` and `/work` are **overlayfs**, not tmpfs. This is not a limitation; it is what
  exposed finding #3, and it reflects a realistic container host.

### Reproducing

```sh
./run-tests.sh              # consolidated pass/fail across all patterns
./run-tests.sh --list       # the 11 individual tests
./run-tests.sh mfd.sh       # e.g. the vm.memfd_noexec matrix
```

The driver builds the image, copies `src/` into a writable `/work`, and adds
`--privileged` or `--cap-add=SYS_PTRACE` only for the tests that need them.

## What worked

**Build.** The verbatim Makefile compiled all 7 programs with **zero warnings**, and
still zero under `-Wall -Wextra`. `environ` is used undeclared in five files but glibc's
`unistd.h` exports it under `_GNU_SOURCE`, so this is correct as written.

**Execution.** All 8 patterns produced exactly the output block 17 claims
(`tests/final.sh`): 8 passed, 0 failed.

**Forensic claims (block 18) — confirmed exactly** (`tests/inode.sh`):

| Loader | `/proc/PID/exe` | nlink | fs |
|---|---|---|---|
| `memfd_exec` | `/memfd:payload (deleted)` | 0 | tmpfs |
| `memfd_execveat` | `/memfd:payload (deleted)` | 0 | tmpfs |
| `tmpfile_exec` | `/tmp/#34510835 (deleted)` | 0 | overlayfs |
| `deleted_exec` | `/work/sd (deleted)` | 0 | overlayfs |

**`ETXTBSY`.** The `close(wfd)` comment in `tmpfile_exec.c` ("drop the writable fd, else
ETXTBSY") is correct: deleting that line reproduces `fexecve: Text file busy`
(`tests/edge.sh`).

**Signing pipeline (block 20).** The entire openssl CA → leaf chain runs verbatim,
`openssl verify` returns OK, and the leaf carries `keyUsage=critical,digitalSignature`
plus `extendedKeyUsage=codeSigning` as intended (`tests/signing.sh`).

**Preflight version parser.** Fuzzed across 9 realistic `uname -r` forms
(`6.18.44-fc-v24`, `7.0.12-linuxkit`, `6.8.0`, `6.7.9`, `5.15.0`, `6.12`, `6`,
`6.1.0-rpi`, `4.19.0`) — correct in every case, including the bare-`6` and
major-version-7 edges (`tests/ver_test.sh`).

### The `vm.memfd_noexec` matrix — the strongest result

`tests/mfd.sh` crosses the sysctl against the `MFD_*` flags. This substantiates the
document's M-01 recommendation of `=2` *specifically*:

| sysctl | `flags=0` | `MFD_EXEC` | `MFD_NOEXEC_SEAL` |
|---|---|---|---|
| 0 | runs | runs | denied |
| 1 | denied | **runs** | denied |
| 2 | denied | `memfd_create` denied | denied |

`=1` is bypassed by an attacker passing one flag. Only `=2` refuses `memfd_create`
outright. A document recommending `=1` as a partial measure would be wrong; this one
recommends `=2`, and the measurement backs it.

## Findings

### 1. `deleted_exec` destroys its input — and the document's own command line trips on it

`deleted_exec.c` calls `unlink(argv[1])` on the caller-supplied path. Block 17 prints:

```sh
$ make && for L in memfd_exec memfd_execveat tmpfile_exec deleted_exec; do ./$L ./hello; done
```

After this loop `./hello` is **gone**. The very next line of block 17 is
`./interp_oneliner.sh ./hello`, which then fails — reproduced exactly:

```
FileNotFoundError: [Errno 2] No such file or directory: './hello'
```

The caveat "(copy hello first)" appears in the output column of block 17, not in the
command a reader copies. Suggested fix — make the copy part of the printed command:

```sh
$ for L in memfd_exec memfd_execveat tmpfile_exec; do ./$L ./hello; done
$ cp hello hello.victim && ./deleted_exec ./hello.victim
```

Verified in `tests/edge.sh`. Fixed in `src/` — the patched loader copies the
payload and unlinks the copy, so the block-17 sequence now runs to completion:

```
src          after the loop, ./interp_oneliner.sh ./hello -> FileNotFoundError: './hello'
src (v1.2)   after the loop, ./interp_oneliner.sh ./hello -> hello from a fileless payload
```

Pattern 4 is preserved: the patched process still shows `nlink=0` on a real filesystem
with a `(deleted)` path suffix, so Sigma rule 23 still matches.

### 2. `memfd_execveat.c` drops all error checks, producing a misleading diagnostic

Unlike `memfd_exec.c` (which checks both), `memfd_execveat.c` ignores the return of
`open()` and `memfd_create()`. Given a missing payload it writes nothing and execs an
empty memfd:

```
$ ./memfd_execveat /nonexistent-file
execveat: Exec format error        # not "No such file or directory"
$ ./memfd_exec /nonexistent-file
open payload: No such file or directory
```

`unlink()`'s return is likewise unchecked in `deleted_exec.c`. Since these are teaching
artifacts read as reference implementations, the inconsistency is worth a line of
comment even if the checks stay omitted for brevity. Verified in `tests/exit_test.sh`.
Fixed in `src/`, which now reports `open payload: No such file or directory`
for a missing file and `read payload: Is a directory` for a directory.

### 3. `is_anon_exec_inode()` (block 19) misses pattern 1f on the most common setups

The gate's anonymous-inode test is:

```c
__u64 m = ino->i_sb->s_magic;
return ino->i_nlink == 0 && (m == TMPFS_MAGIC || m == HUGETLBFS_MAGIC);
```

But `tmpfile_exec.c` hardcodes `open("/tmp", O_TMPFILE)`, and **`/tmp` is only tmpfs by
convention**. Measured on this host: `nlink=0` but `fs=overlayfs`, so
`is_anon_exec_inode()` returns false and pattern 1f falls straight through to
`verify_file()`.

The end result is still a denial (the anonymous inode has no signature), but *not by the
path the document describes* — and `verify_file()` reaches
`bpf_get_fsverity_digest()`, which the document's own note F-7 says returns `ENODATA` on
overlay. So on an overlayfs or ext4 `/tmp` the row-1f-to-mechanism mapping in §5 does not
hold as written. Worth either widening the magic check or stating the tmpfs assumption
explicitly. Measured in `tests/inode.sh`.

### 4. The auditd rules (block 21) do not cover patterns 1a and 1b

The `fileless_fdexec` rule comment claims `execveat` catches "memfd / O_TMPFILE /
deleted-file exec". `strace` shows otherwise (`tests/strace_check.sh`):

| Loader | Pattern | Exec syscall actually issued | Caught by |
|---|---|---|---|
| `memfd_exec` | 1a | `execve("/proc/self/fd/4")` | `memfd_create` rule only |
| `memfd_script` | 1b | `execve("/proc/self/fd/3")` | `memfd_create` rule only |
| `interp_oneliner.sh` | 1d | `execve("/proc/self/fd/3")` | `memfd_create` rule only |
| `memfd_execveat` | 1a | `execveat(4, "", AT_EMPTY_PATH)` | both |
| `tmpfile_exec` | 1f | `execveat(3, "", AT_EMPTY_PATH)` | `fileless_fdexec` |
| `deleted_exec` | 4 | `execveat(3, "", AT_EMPTY_PATH)` | `fileless_fdexec` |

Two conclusions. First, glibc's `fexecve` **does** lower to `execveat(AT_EMPTY_PATH)`, so
rows 1f and 4 are genuinely covered — the document is right about those. Second,
`execve()` on a `/proc/self/fd/*` path is the real gap: the three memfd patterns are
caught *only* by the `memfd_create` rule, so an attacker who obtains a memfd without
calling `memfd_create` (inheriting one across a fork, or receiving it over a unix socket
with `SCM_RIGHTS`) evades both rules. The rule set has no `execve` rule beyond the two
interpreter-scoped ones.

The Sigma rules in blocks 22–23 were checked against the measured `Image` strings and
match correctly: rule 22 (`contains 'memfd:'`) matches both memfd loaders; rule 23
(`endswith '(deleted)'`) matches all four (`tests/sigma_check.sh`).

### 5. `fsverity sign` does not require `fsverity enable`

Block 20 presents the per-binary steps as a pipeline (`enable` → `sign` → `setfattr`).
`sign` is in fact **independent** — it computes the Merkle digest entirely in userspace.
On this kernel, where `enable` fails outright:

```
--- fsverity enable /work/foo   (fs=overlayfs)
ERROR: FS_IOC_ENABLE_VERITY failed on '/work/foo': Inappropriate ioctl for device
  exit=1
--- fsverity sign
Signed file '/work/foo' (sha256:3f9eaafd...)
  exit=0                      <-- succeeds anyway
--- setfattr user.org.sig
  exit=0                      <-- and the xattr lands
```

A packaging job that does not check `enable`'s exit status will ship a valid-looking
signature and xattr on a file with **no Merkle tree**. Nothing detects this at build
time; it surfaces only much later at gate time as `ENODATA`, which the gate maps to the
same `-EPERM` as a genuine tampering event. Recommend `set -e` or an explicit
`fsverity measure` assertion after `enable` in the packaging step. Verified in
`tests/verity.sh`.

### 6. Block 20 requires bash but is presented as generic shell

The leaf-certificate command uses process substitution:

```sh
-extfile <(printf "keyUsage=critical,digitalSignature\nextendedKeyUsage=codeSigning")
```

Under `dash`: `Syntax error: "(" unexpected`. Fine interactively on a bash workstation,
breaks in a `/bin/sh` CI runner — which is exactly where a signing pipeline runs. A
heredoc to a temp file is portable.

### 7. Minor: dead variable in the preflight script

`fileless-gate-preflight.sh` sets `pass=0` and never increments it — `ok()` only echoes.
Harmless; `hard_fail` drives the exit status correctly. Dropped in `src/`.

### 8. `-F exe=` in the auditd rules is rejected at parse time

The last two rules of block 21 fail on this kernel:

```
BAD-SYNTAX  -a always,exit -F arch=b64 -S execve -F exe=/usr/bin/python3 -k interp_exec
            -> Field option not supported by kernel: exe
```

This is **not** the container blocking privileged operations. The other five rules fail
differently — `Operation not permitted`, i.e. they parsed correctly and only the netlink
write was refused. `exe=` fails earlier, at field-parse, and `-F path=/usr/bin/python3`
parses fine on the same host. So the two interpreter rules are the only ones with a
portability problem.

The consequence is quiet: `auditctl -R` skips bad rules and continues, so on a host
without `exe=` support the interpreter monitoring (pattern 3) silently loads as nothing
while the file appears to have been accepted. Use `-F path=` unless `exe=` is confirmed
on the target, and check `auditctl -l` after loading. Verified in
`tests/detection_lint.sh`.
## Not tested

The eBPF LSM gate (block 19) was **not executed**. It is extracted to
`gate/exec_gate.bpf.c.fragment` and its gaps are now measured rather than asserted
(`tests/gate_compile.sh`): compiled against a real `vmlinux.h` from kernel BTF, it is
missing two map definitions (`policy`, `verdict_map`), three policy `#define`s
(`MAX_SIG`, `TAG_XATTR`, `DENY_ANON_EXEC`), the `task_is_verified_agent()` helper, and
extern declarations for two kfuncs — plus `guard_bpf` is explicitly pseudocode.

Two things about it *were* verified. Its CO-RE field accesses are all correct against
this kernel's BTF (`f_inode`, `i_sb`, `i_nlink`, `s_magic`, `linux_binprm->file` all
exist with the expected types), so the logic is sound against a real kernel layout. And
`bpf_get_fsverity_digest`, `bpf_verify_pkcs7_signature` and `bpf_inode_storage_get` are
absent on this kernel while `bpf_get_file_xattr`, `bpf_lookup_system_key` and
`bpf_dynptr_adjust` are present — consistent with `CONFIG_FS_VERITY` being unset, and
with what the document's own preflight script reports. See `gate/README.md`.

Finding #3 comes from measured inode and filesystem data, not from running the gate.

Also untested: the `keyctl padd` secondary-keyring enrolment and the `bpftool map update`
epoch bump (block 20), and pattern 5a/5b kernel-module loading.

One process note: I initially read `exit=0` after a denied `execve` as a missing-return
bug in the loaders. That was my own harness piping through `sed` — the loaders return 1
correctly. Retracted; `tests/exit_test.sh` documents the check.

---

## v1.2 verification pass (07 Sep 2026)

v1.2 of the document (not in this repo — see above) was built
from v1.1 by injecting the fixed sources back into the document, then re-running the
whole suite against code **re-extracted from the v1.2 HTML itself** — so what the lab
ran is what a reader copies out of the published file, not a parallel tree that happens
to agree with it.

Result: 8/8 patterns pass, 13/13 test scripts exit 0. No new findings.

Fixed in the v1.2 listings:

| Finding | Was | Now |
|---|---|---|
| #1 | `deleted_exec` unlinked `argv[1]`, destroying the caller's file | execs a private copy; `edge.sh` reports `after: victim EXISTS` |
| #2 | `memfd_execveat` checked no return values | checks `open`/`memfd_create`/`read`, matching `memfd_exec.c` |
| #7 | dead `pass=0` in the preflight script | removed |
| #8 | 2 of 7 auditd rules used `-F exe=`, rejected at parse time | `-F path=`; `detection_lint.sh` now reports 7/7 `PARSES-OK` |

**Correction.** I first reported all four of these as applied to v1.2. #7 was not — the
HTML still read `pass=0; hard_fail=0`. It was caught when the two source trees were
merged and `src/` was checked against the document field by field: seven of ten files
matched, three did not, and the preflight script was one of them. Only #1, #2 and #8 had
actually reached the HTML. #7 is applied now, and `src/` is verified byte-identical to
all ten listings in v1.2. The lesson is that "I edited the file" is not evidence the edit
landed; diffing the artifact against the tree is.

Both `deleted_exec.c` listings were patched — the narrative one in §4A.3 as well as the
Appendix B copy. The narrative version is the one a reader actually runs first, so
leaving it destructive would have kept the bug where it does the most damage. Each keeps
its own header comment.

The corrected auditd rules live in `detection-patched/`; `detection/` still holds
exactly what v1.1 printed.

**Transcript.** `./capture-logs.sh` runs the whole suite and writes `logs/`, so the
results are readable without Docker. Capturing it caught a harness bug that had been
masked all along: `run-tests.sh` hardcoded the `detection/` mount, so `detection_lint.sh`
linted the *verbatim* rules no matter which source tree was under test. The 7/7 I
reported earlier came from a one-off run where I mounted `detection-patched/` by hand;
the committed driver never did. `DET` now tracks `SRC`, and the transcript shows 5/7 for
v1.1 against 7/7 for v1.2.

Note that both trees report `8 passed, 0 failed` on `final.sh`. That is not a bug in the
harness: `final.sh` asks whether each pattern executes, and the buggy loaders do execute.
#1 destroys the caller's file while succeeding and #2 only changes which error is printed
on a missing payload — neither is a pass/fail failure, which is exactly how both survived
into a published document. `edge.sh` and `detection_lint.sh` are where they surface.

**Tree layout since the merge.** `src/` and `src-patched/` were collapsed into a single
`src/` holding the v1.2 code, with the verbatim v1.1 extraction kept as
`src-v1.1-verbatim/`. The lab's before/after evidence is unchanged: `edge.sh` reports
`victim GONE` against the baseline and `victim EXISTS` against `src/`. Full suite after
the merge: 8/8 patterns, 13/13 scripts exit 0.

Documented rather than patched, and now written up in the document's new Appendix G:
#3 (the gate's tmpfs-magic test misses `O_TMPFILE` when `/tmp` is not tmpfs — measured
overlayfs on both `debian:trixie-slim` and `ubuntu:24.04`), #5 (`fsverity sign` succeeds
on a file that was never `fsverity enable`d), #6 (block 20 needs bash), and the fact
that the Appendix C gate is a fragment that does not compile as printed.

Document changes beyond the listings: new Appendix G (harness, results, the seven
defects, and where the gate does not reach) plus its TOC entry; §4 methodology records
the lab pass; the gate's `is_anon_exec_inode` comment points at G.4; the Appendix C
signing pipeline notes that `enable` must precede `sign`.

One correction made during this pass: an ad-hoc auditctl check I wrote to spot-verify
the corrected rules classified all seven as `BAD-SYNTAX`. That was my classifier keying
on "Operation not permitted" — which is the netlink *load* failing for want of an audit
subsystem in the container, not a parse error. `tests/detection_lint.sh` already draws
that distinction correctly and reports 7/7.

---

## v1.3 layout fix (07 Sep 2026)

v1.3 is v1.2 re-marked **TLP:CLEAR** and is the revision published in this repo, in
HTML and PDF. Re-marking it made the HTML a page people actually open in a browser
rather than a file passed around, which surfaced a rendering defect the earlier passes
had no reason to look for.

**Symptom.** On the rendered page, body text, tables and code blocks spilled past the
white A4 sheet onto the grey background, and the document scrolled horizontally.

**Cause.** The document ships a `<doc-page>` web component whose shadow DOM wraps the
page in a table, `.frame`, styled `width: 100%` under the default `table-layout: auto`.
Auto layout treats `width` as a preference that a wide intrinsic child can override: a
figure image with `naturalWidth: 1200` raised the table's min-content width and
stretched the frame to 988px inside a 794px (210mm) sheet. Every slotted block then sat
at the same 257px offset — 406 elements overflowing by an identical amount, which is
what pointed at the wrapper rather than at any individual block.

**Fix.** `table-layout: fixed` on `.frame`, which pins it to the sheet's content box
(794 - 2x86.4 = 621px) and lets the image scale down to fit.

Measured headless (Chrome via puppeteer-core) against the live Pages URL after deploy:

| | Before | After |
|---|---|---|
| `.frame` width | 988px | 621px |
| Overflowing elements | 406 | 0 |
| Document h-scroll | yes | no |

Nothing was lost to the narrower frame: 0 clipped elements, all 28 `<pre>` blocks and
all 10 tables intact at 621px, and the Appendix G column ratios unchanged (G.2 at
34/11/55, G.3 at 7/46.5/46.5). Checked on a mobile-width viewport as well - the fix
caps the frame at the sheet's content box, whatever that shrinks to.

The committed v1.3 PDF was printed before this fix and is unaffected: at print size the
sheet is the paper, and the image is bounded by `img { max-width: 100% }` against the
page box rather than against a table cell, so auto layout never had a wide child to
widen. It was not re-printed.

**Process note.** My first diagnosis was wrong and worth recording, because it repeats
finding #7's lesson. I found `<script src="doc-page.js">` 404ing and concluded the
component had never upgraded. It had - the real definition is in a `src`-less `<script>`
later in the file, and the 404ing tags are documentation examples whose bodies are
escaped. Measuring the live DOM (`upgraded: true`, `sizeAttr: "a4"`) killed that theory
before it reached a fix. The earlier G.2/G.3 column work in this same document failed
the same way: I tested a standalone extract of the two tables, which bypassed the
rendering pipeline that strips `<colgroup>`. Verifying against something other than the
real artifact is the recurring error in this lab.
