#!/usr/bin/env bash
#
# verify-execshield.sh — Chapter 28 live-verification helper.
#
# execshield denies execve inside a protected cgroup and leaves everything else
# alone. To prove both halves hands-free, this script:
#
#   - confirms "bpf" is an active LSM (else points you at ch20's enable script)
#   - creates a throwaway cgroup, puts a sleeping shell in it
#   - loads ./execshield scoped to ONLY that cgroup, in the background
#   - from inside the cgroup, tries to exec (should be DENIED)
#   - from outside, execs ls/id (should be ALLOWED — the host stays usable)
#   - detaches cleanly
#
# The throwaway-cgroup scope is the safety rail: even if the policy were wrong,
# only the test shell is affected, never your login shell or the system.
#
# Run:    sudo bash 28-execshield/verify-execshield.sh
#
# Needs root (BPF load, cgroup create, kill). Self-contained: no second terminal.
#
set -euo pipefail

cd "$(dirname "$0")"

# (a) prerequisite: bpf must be an active LSM, or the program cannot attach.
CUR="$(cat /sys/kernel/security/lsm)"
if ! printf '%s' "$CUR" | tr ',' '\n' | grep -qx bpf; then
    echo "bpf is NOT an active LSM. Current: $CUR"
    echo "Enable it first:  sudo bash 20-lsm/enable-bpf-lsm.sh  &&  sudo reboot"
    exit 1
fi
echo "Active LSMs: $CUR   (bpf present — good)"

if [[ ! -x ./execshield ]]; then
    echo "./execshield not built. Run 'make' in 28-execshield/ first."
    exit 1
fi

CG=/sys/fs/cgroup/execshield-test
cleanup() {
    [[ -n "${P:-}" ]] && kill -TERM "$P" 2>/dev/null && wait "$P" 2>/dev/null || true
    [[ -n "${SLEEP_PID:-}" ]] && kill "$SLEEP_PID" 2>/dev/null || true
    [[ -d "$CG" ]] && rmdir "$CG" 2>/dev/null || true
}
trap cleanup EXIT

# (b) throwaway cgroup with one sleeping member, so the scope is contained.
mkdir -p "$CG"
sleep 300 &
SLEEP_PID=$!
echo "$SLEEP_PID" > "$CG/cgroup.procs"
echo "Test cgroup $CG holds pid $SLEEP_PID."

echo "Loading execshield scoped to $CG only ..."
echo
./execshield "$CG" &
P=$!
sleep 1

echo "--- Inside the protected cgroup: exec should be DENIED ---"
# Move a subshell into the cgroup, then try to exec. Expect EPERM.
( echo $BASHPID > "$CG/cgroup.procs"; exec /bin/true ) \
    && echo "UNEXPECTED: exec succeeded inside protected cgroup" \
    || echo "OK: exec denied inside protected cgroup (as designed)"

echo
echo "--- Outside the cgroup: host stays usable ---"
ls / >/dev/null && echo "OK: ls ran"
id    >/dev/null && echo "OK: id ran"

sleep 1
echo
echo "Detaching ..."
