# src-v1.1-verbatim/ — the code exactly as v1.1 printed it

Byte-identical to the `<pre>` blocks of
`Adv_Linux_Threat_Detection_-_File_Identity_vs_Fileless_Execution_v1.1.html`
(kept at the repo root). Nothing here has been corrected.

This is the before-state. `src/` is the after-state — the code as published in v1.2,
re-extracted from that document. The diff between the two trees is the evidence for
findings #1, #2 and #7 in FINDINGS.md:

    diff src-v1.1-verbatim src

| File | Finding |
|---|---|
| `deleted_exec.c` | #1 — unlinked `argv[1]`, destroying the caller's file |
| `memfd_execveat.c` | #2 — no return-value checks; a missing payload exec'd an empty memfd |
| `fileless-gate-preflight.sh` | #7 — dead `pass=0` counter |

The other seven files are unchanged between the two trees.

Run the suite against this tree to reproduce the original behaviour:

    SRC=src-v1.1-verbatim ./run-tests.sh
