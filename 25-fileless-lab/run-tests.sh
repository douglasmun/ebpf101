#!/bin/bash
# Driver: build the image, copy the verbatim doc code into a writable /work,
# and run one test script (default: final.sh).
#
#   ./run-tests.sh                # consolidated pass/fail over all patterns
#   ./run-tests.sh mfd.sh         # vm.memfd_noexec x MFD_* flag matrix
#   ./run-tests.sh --list
#
# By default src/ is tested: the code as published in v1.2, extracted from the HTML,
# together with detection-patched/. The verbatim v1.1 extraction is the before-state
# for every finding, and pairs with the rules as v1.1 printed them:
#   SRC=src-v1.1-verbatim ./run-tests.sh
# Override the detection tree on its own with DET=...
#
# Tests needing extra kernel access get the flags they need, per the table below.
set -eo pipefail   # not -u: empty FLAGS array trips bash 3.2 (macOS)
cd "$(dirname "$0")"

SRC="${SRC:-src}"
# The detection artifacts track the source tree: the v1.1 tree lints the rules as
# v1.1 printed them (5/7 parse), src/ lints the corrected set that v1.2 ships (7/7).
case "$SRC" in
  src-v1.1-verbatim) DET="${DET:-detection}" ;;
  *)                 DET="${DET:-detection-patched}" ;;
esac
t="${1:-final.sh}"
if [ "$t" = "--list" ]; then ls tests/; exit 0; fi
[ -f "tests/$t" ] || { echo "no such test: tests/$t" >&2; exit 2; }
[ -d "$SRC" ]    || { echo "no such source tree: $SRC" >&2; exit 2; }
[ -d "$DET" ]    || { echo "no such detection tree: $DET" >&2; exit 2; }

# noexec/mfd write vm.memfd_noexec; strace needs ptrace; verity needs the ioctls.
case "$t" in
  noexec_test.sh|mfd.sh|exit_test.sh|verity.sh) FLAGS=(--privileged) ;;
  strace_check.sh)                              FLAGS=(--cap-add=SYS_PTRACE) ;;
  detection_lint.sh)                            FLAGS=(--privileged) ;;
  gate_compile.sh)                              FLAGS=(--privileged -v /sys/kernel/btf:/sys/kernel/btf:ro) ;;
  *)                                            FLAGS=() ;;
esac

docker build -q -t fileless-lab . >/dev/null
exec docker run --rm "${FLAGS[@]}" \
  -v "$PWD/$SRC:/src:ro" -v "$PWD/tests:/tests:ro" -v "$PWD/$DET:/d:ro" -v "$PWD/gate:/gate:ro" \
  fileless-lab bash -c '
    if [ "'"$t"'" = gate_compile.sh ]; then
      apt-get update -qq >/dev/null 2>&1
      apt-get install -y -qq clang libbpf-dev bpftool >/dev/null 2>&1
    fi
    if [ "'"$t"'" = detection_lint.sh ]; then
      apt-get update -qq >/dev/null 2>&1
      apt-get install -y -qq python3-yaml auditd >/dev/null 2>&1
    fi
    cp /src/* /work/
    chmod +x /work/*.sh 2>/dev/null || true
    exec bash /tests/'"$t"'
  '
