# ebpf101 — project instructions

## This repo is PUBLIC

`github.com/douglasmun/ebpf101` is public, and GitHub Pages is enabled
(`https://douglasmun.github.io/ebpf101/`), so anything committed is
world-readable and search-indexable. Check before adding a file.

### TLP boundary — do not cross

The chapter-25 threat-detection note exists in three revisions:

| Rev | Marking | May it live in this repo? |
|-----|---------|---------------------------|
| v1.1 | TLP:GREEN + author need-to-know | **No** — not in the tree, not in history |
| v1.2 | TLP:GREEN + author need-to-know | **No** — not in the tree, not in history |
| v1.3 | **TLP:CLEAR** | **Yes** — the only revision cleared for publication |

v1.1/v1.2 are held outside this repository, in a separate archive directory on
the author's machine. `.gitignore` blocks `*v1.1.html`, `*v1.1.pdf`, `*v1.2.html`, `*v1.2.pdf` anywhere in the tree
(a v1.1 PDF has sat in the repo root before), and deliberately does not match
v1.3. Never commit, push, or paste the restricted documents' prose.

What *is* fine, and already tracked: `25-fileless-lab/src-v1.1-verbatim/` (code
extracted from v1.1) and `25-fileless-lab/logs/*v1.1*`, `*v1.2*` (run
transcripts of that code). Extracted code and its output carry no sharing
restriction — only the documents' prose does. `src-v1.1-verbatim/README.md`
explains the distinction.

## Documentation standards

- **Claims must be verified, not inferred.** Every status badge in the READMEs
  corresponds to an actual run. Do not upgrade a badge, pin a version, or state
  a result from plausibility — pin it from `pip freeze`, a transcript, or emitted
  IR. When a value was never recorded, say so rather than fabricating one (see
  the `llvmlite>=0.45` comment in `24-pythonbpf/requirements.txt`).
- **No defect tallies or self-congratulation** in prose. Describe what the work
  is, not how many problems it found.
- **Status cells describe the chapter**, not work done upstream of it. "Fix PR
  open" belongs in the chapter notes, not the status column.
- Prefer verifying against the real artifact (the live Pages URL, the emitted
  LLVM IR) over a local proxy.

## Layout

- `NN-topic/` — one directory per chapter, code + Makefile
- `docs/NN-topic.md` — the *why* behind each chapter; `docs/README.md` indexes
  them and holds the progression table. Chapter 25's notes are
  `25-fileless-lab/FINDINGS.md` instead.
- Root `README.md` — chapter table with stack + status.

Adding a chapter means updating: its directory, `docs/README.md` (both the
progression table and the numbered index), and the root `README.md` table.

## Upstream Python-BPF (chapter 24)

Chapter 24 depends on the released `pythonbpf==0.1.9`, which has a compiler bug:
a map lookup used in arithmetic (`(prev or 0) + 1`) never dereferences the
pointer. The chapter works around it with an explicit `deref()`.

- Bug: [issue #89](https://github.com/pythonbpf/Python-BPF/issues/89)
- Fix: [PR #100](https://github.com/pythonbpf/Python-BPF/pull/100), on the fork
  `douglasmun/Python-BPF`, branch `fix/bool-op-map-lookup-deref`

**The chapter deliberately does not depend on the fork.** Installing a personal
fork of a pre-1.0 compiler is a worse reader default than a released version plus
one explicit `deref()`. Do not change this without asking.

Note when testing against Python-BPF: its IR and llc test tiers only assert that
compilation *succeeds*, so a wrong-value miscompile passes both. Assert on the
emitted IR.

## Environment

Host is Apple Silicon macOS — no Linux kernel, so nothing here loads locally.
Chapters 1–23 were run on a Linux box (kernel 6.8, BTF, CO-RE capable);
24 and 25 were verified in containers on Docker Desktop's kernel-6.12/aarch64 VM.
