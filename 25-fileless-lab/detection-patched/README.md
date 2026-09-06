# detection-patched/ — corrected auditd rules

Same relationship to `detection/` as `src-patched/` has to `src/`: `detection/` is the
verbatim v1.1 extraction, this is the fixed set. The three Sigma rules are unchanged
(they parse as-is); only `audit-fileless.rules` differs.

FINDINGS.md #8 — the two interpreter rules used `-F exe=`, which the kernel rejects as a
syscall-rule field (`Field option not supported by kernel: exe`), so they failed at parse
time and the set silently loaded five rules instead of seven. Reproduced identically on
`ubuntu:24.04` with auditctl 4.0.2, while `path=`, `dir=`, `euid=` and `key=` all parse —
a kernel-side limitation, not a distro packaging quirk.

Fixed by switching to `-F path=` on the interpreter binary. `tests/detection_lint.sh`
reports 7/7 `PARSES-OK` against this tree, 5/7 against `detection/`.

This is the version that appears in the v1.2 document (Appendix D); `detection/` preserves
what v1.1 printed.
