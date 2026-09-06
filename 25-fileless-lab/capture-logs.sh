#!/bin/bash
# Run the whole suite and write a transcript to logs/, so the results are readable
# without Docker and without re-running anything.
#
#   ./capture-logs.sh                     # -> logs/
#   OUT=somewhere ./capture-logs.sh
#
# Runs every test against src/ (the code as published in v1.2), plus the three
# tests that demonstrate a before/after against src-v1.1-verbatim/.
set -eo pipefail
cd "$(dirname "$0")"
OUT="${OUT:-logs}"
mkdir -p "$OUT"

ALL=(final.sh mfd.sh inode.sh edge.sh sigma_check.sh strace_check.sh ver_test.sh
     noexec_test.sh exit_test.sh signing.sh verity.sh detection_lint.sh gate_compile.sh)
BEFORE_AFTER=(final.sh edge.sh detection_lint.sh)

hdr() {
  printf '===============================================================\n'
  printf '  %s\n' "$1"
  printf '  %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  printf '===============================================================\n\n'
}

{
  hdr "environment"
  echo "commit:  $(git rev-parse HEAD 2>/dev/null || echo '(not a git tree)')"
  echo "docker:  $(docker --version)"
  echo "kernel:  $(docker run --rm debian:trixie-slim uname -a 2>/dev/null)"
  echo "host:    $(uname -sm)"
} > "$OUT/00-environment.txt"

fail=0
for t in "${ALL[@]}"; do
  n="${t%.sh}"
  { hdr "src/ (v1.2 code) — tests/$t"
    SRC=src ./run-tests.sh "$t" 2>&1
    rc=$?
    printf '\n[exit=%d]\n' "$rc"
    [ "$rc" -eq 0 ] || fail=1
  } > "$OUT/10-v1.2-$n.txt" 2>&1 || fail=1
  printf '  %-22s -> %s\n' "$t" "$OUT/10-v1.2-$n.txt"
done

for t in "${BEFORE_AFTER[@]}"; do
  n="${t%.sh}"
  { hdr "src-v1.1-verbatim/ (before the fixes) — tests/$t"
    SRC=src-v1.1-verbatim ./run-tests.sh "$t" 2>&1
    printf '\n[exit=%d]\n' "$?"
  } > "$OUT/20-v1.1-$n.txt" 2>&1 || true
  printf '  %-22s -> %s\n' "$t (v1.1)" "$OUT/20-v1.1-$n.txt"
done

{
  hdr "summary"
  echo "v1.2 (src/) — consolidated:"
  grep -E '^\s+(PASS|FAIL)|^TOTAL' "$OUT/10-v1.2-final.txt" || true
  echo
  echo "v1.1 (src-v1.1-verbatim/) — consolidated:"
  grep -E '^\s+(PASS|FAIL)|^TOTAL' "$OUT/20-v1.1-final.txt" || true
  echo
  echo "  Note: v1.1 also reports 8/8. final.sh asks 'does the pattern execute?',"
  echo "  and the buggy loaders do execute — #1 destroys the caller's file while"
  echo "  succeeding, and #2 only changes which error is printed when the payload"
  echo "  is missing. The before/after below is where those two show up."
  echo
  echo "per-test exit codes (v1.2):"
  for f in "$OUT"/10-v1.2-*.txt; do
    printf '  %-28s %s\n' "$(basename "$f")" "$(grep -o '\[exit=[0-9]*\]' "$f" | tail -1)"
  done
  echo
  echo "the data-loss fix (#1), before and after:"
  echo "  v1.1: $(grep -o 'after: victim.*' "$OUT/20-v1.1-edge.txt" || echo n/a)"
  echo "  v1.2: $(grep -o 'after: victim.*' "$OUT/10-v1.2-edge.txt" || echo n/a)"
  echo
  echo "auditd rules that parse (#8):"
  echo "  v1.1: $(grep -c 'PARSES-OK' "$OUT/20-v1.1-detection_lint.txt" || echo 0)/7"
  echo "  v1.2: $(grep -c 'PARSES-OK' "$OUT/10-v1.2-detection_lint.txt" || echo 0)/7"
} > "$OUT/01-summary.txt"

echo
cat "$OUT/01-summary.txt"
exit "$fail"
