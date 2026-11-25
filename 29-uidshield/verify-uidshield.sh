#!/usr/bin/env bash
#
# verify-uidshield.sh — Chapter 29 live-verification helper.
#
# uidshield denies a setuid transition to root (uid 0) inside a protected cgroup
# and leaves everything else alone. To prove both halves hands-free, this script:
#
#   - confirms "bpf" is an active LSM (else points you at ch20's enable script)
#   - creates a throwaway cgroup, puts a sleeping shell in it
#   - loads ./uidshield scoped to ONLY that cgroup, in the background, capturing
#     its stdout so we can assert on the DENY event it logs
#   - from inside the cgroup, runs ./try-escalate (drop to a non-root uid, then
#     attempt setuid(0)) and asserts it was DENIED with EPERM (exit 10) AND that
#     the shield logged a matching DENY for that pid — a plain setuid failure is
#     not enough, the shield must be shown to be the cause
#   - repeats inside a CHILD of a protected cgroup, to prove the scope is
#     hierarchical (issue #6): a service's workers live in child cgroups
#   - from outside, runs the SAME escalation and asserts it SUCCEEDS (exit 0),
#     so a root transition the shield does not govern still works
#   - detaches, and does not exit until the enforcing program is confirmed gone
#
# The throwaway-cgroup scope is the safety rail: even if the policy were wrong,
# only the test process is affected, never real services or your login shell.
# Because this program ENFORCES, a leaked background process keeps the
# task_fix_setuid hook live, so cleanup here positively confirms the process
# died before removing the cgroup.
#
# Run:    sudo bash 29-uidshield/verify-uidshield.sh
#
# Needs root (BPF load, cgroup create, setuid, kill). Self-contained.
#
set -euo pipefail

cd "$(dirname "$0")"

fail() { echo "FAIL: $*" >&2; exit 1; }

# A non-root uid to drop to before attempting the climb back. 'nobody' is
# universal; fall back to a fixed high uid if it is somehow absent.
DROP_UID="$(id -u nobody 2>/dev/null || echo 65534)"
[[ "$DROP_UID" != "0" ]] || fail "resolved drop-uid is 0; cannot model an escalation."

# (a) prerequisite: bpf must be an active LSM, or the program cannot attach.
CUR="$(cat /sys/kernel/security/lsm)"
if ! printf '%s' "$CUR" | tr ',' '\n' | grep -qx bpf; then
    echo "bpf is NOT an active LSM. Current: $CUR"
    echo "Enable it first:  sudo bash 20-lsm/enable-bpf-lsm.sh  &&  sudo reboot"
    exit 1
fi
echo "Active LSMs: $CUR   (bpf present — good)"

if [[ ! -x ./uidshield ]]; then
    echo "./uidshield not built. Run 'make' in 29-uidshield/ first."
    exit 1
fi
if [[ ! -x ./try-escalate ]]; then
    echo "./try-escalate not built. Run 'make' in 29-uidshield/ first."
    exit 1
fi

CG=/sys/fs/cgroup/uidshield-test
LOG="$(mktemp -t uidshield-verify.XXXXXX)"

# (H1) Guarantee the enforcing program is detached on ANY exit. Same fail-closed
# cleanup as ch28: kill by saved pid, escalate to SIGKILL, CONFIRM the process is
# gone before removing the cgroup, and make a leak visible in the exit status.
cleanup() {
    local rc=$?
    trap - EXIT INT TERM HUP
    if [[ -n "${P:-}" ]] && kill -0 "$P" 2>/dev/null; then
        kill -TERM "$P" 2>/dev/null || true
        if ! timeout 5 bash -c 'while kill -0 '"$P"' 2>/dev/null; do sleep 0.1; done'; then
            echo "note: uidshield did not exit on SIGTERM, sending SIGKILL" >&2
            kill -KILL "$P" 2>/dev/null || true
            sleep 0.3
        fi
    fi
    if [[ -n "${P:-}" ]] && kill -0 "$P" 2>/dev/null; then
        echo "WARNING: could not confirm uidshield (pid $P) is dead — the LSM" >&2
        echo "         hook may still be ENFORCING on $CG. Kill it manually:" >&2
        echo "         sudo kill -9 $P" >&2
        rc=1
    else
        [[ -n "${SLEEP_PID:-}" ]] && kill "$SLEEP_PID" 2>/dev/null || true
        [[ -n "${CHILD_SLEEP_PID:-}" ]] && kill "$CHILD_SLEEP_PID" 2>/dev/null || true
        [[ -d "${NCG_CHILD:-}" ]] && rmdir "$NCG_CHILD" 2>/dev/null || true
        [[ -n "${NCG_PARENT:-}" && -d "$NCG_PARENT" ]] && rmdir "$NCG_PARENT" 2>/dev/null || true
        [[ -d "$CG" ]] && rmdir "$CG" 2>/dev/null || true
    fi
    rm -f "$LOG" 2>/dev/null || true
    exit "$rc"
}
trap cleanup EXIT INT TERM HUP

# (b) throwaway cgroup with one sleeping member, so the scope is contained.
mkdir -p "$CG"
sleep 300 &
SLEEP_PID=$!
echo "$SLEEP_PID" > "$CG/cgroup.procs"
echo "Test cgroup $CG holds pid $SLEEP_PID."

# (b2) A SEPARATE two-level hierarchy for the hierarchical-scope check (cgroup2's
# no-internal-process rule forbids a cgroup holding processes AND having
# children). We protect NCG_PARENT and later escalate in NCG_CHILD, whose own id
# is never handed to the shield.
NCG_PARENT=/sys/fs/cgroup/uidshield-parent
NCG_CHILD="$NCG_PARENT/worker"
NCG_PARENT_ARG=""
if mkdir -p "$NCG_PARENT" 2>/dev/null \
   && { echo "+pids" > "$NCG_PARENT/cgroup.subtree_control" 2>/dev/null || true; } \
   && mkdir "$NCG_CHILD" 2>/dev/null; then
    sleep 300 & CHILD_SLEEP_PID=$!
    echo "$CHILD_SLEEP_PID" > "$NCG_CHILD/cgroup.procs"
    NCG_PARENT_ARG="$NCG_PARENT"
    echo "Nested test: protecting $NCG_PARENT, will escalate in child $NCG_CHILD."
else
    NCG_PARENT=""
    echo "note: could not build a nested cgroup hierarchy; nested check will skip." >&2
fi

echo "Loading uidshield scoped to the test cgroup(s) ..."
echo
# Only the leaf $CG and the parent $NCG_PARENT are handed in — never the child,
# whose deny must come from the ancestry walk. Line-buffer stdout so the DENY row
# is flushed to $LOG before we grep it.
stdbuf -oL ./uidshield "$CG" $NCG_PARENT_ARG > >(tee "$LOG") 2>&1 &
P=$!
sleep 1

# run_escalate <cgroup-dir>: runs ./try-escalate in a child that first joins the
# cgroup, so the governed setuid happens inside the scope under test. Sets two
# globals in THIS shell (no command-substitution subshell, which would discard
# them): RUN_PID = the trigger's pid, RC = its exit code. The trigger prints its
# pid on stdout line 1; we capture that via a temp file so the exit status we
# read is the trigger's, not head's.
RUN_PID=""; RC=""
run_escalate() {
    local cgdir="$1"
    local pidfile; pidfile="$(mktemp)"
    set +e
    bash -c '
        echo $$ > "'"$cgdir"'/cgroup.procs" || exit 70
        echo $$ > "'"$pidfile"'"
        exec ./try-escalate '"$DROP_UID"' >/dev/null 2>&1
    '
    RC=$?
    set -e
    RUN_PID="$(cat "$pidfile" 2>/dev/null)"
    rm -f "$pidfile"
}

echo "--- Inside the protected cgroup: escalation to root should be DENIED ---"
run_escalate "$CG"; E_PID="$RUN_PID"
[[ "$RC" == 10 ]] || fail "escalation inside cgroup exited $RC, expected 10 (EPERM deny). The shield did not veto it."
[[ -n "$E_PID" ]] || fail "could not move the trigger into $CG (cgroup2 rule?); deny test inconclusive."
sleep 0.5
grep -Eq "^[[:space:]]*${E_PID}[[:space:]]+DENY\b" "$LOG" \
    || fail "setuid(0) failed with EPERM but the shield logged no DENY for pid $E_PID — the EPERM came from something other than this shield."
echo "OK: escalation denied inside protected cgroup — EPERM AND shield logged DENY for pid $E_PID."

echo
echo "--- Inside a CHILD of a protected cgroup: escalation should ALSO be DENIED ---"
if [[ -n "${NCG_PARENT:-}" && -d "$NCG_CHILD" ]]; then
    run_escalate "$NCG_CHILD"; C_PID="$RUN_PID"
    [[ "$RC" == 10 ]] || fail "escalation in CHILD cgroup exited $RC, expected 10 — ancestry match failed (issue #6 would be reopened)."
    [[ -n "$C_PID" ]] || fail "could not move the trigger into $NCG_CHILD; nested check inconclusive."
    sleep 0.5
    grep -Eq "^[[:space:]]*${C_PID}[[:space:]]+DENY\b" "$LOG" \
        || fail "child escalation failed with EPERM but no DENY logged for pid $C_PID."
    echo "OK: escalation denied in a CHILD of the protected cgroup — the ancestry walk covers descendants."
else
    echo "note: nested hierarchy unavailable (cgroup delegation); skipping nested check." >&2
fi

echo
echo "--- Outside the cgroup: the SAME escalation must SUCCEED (host stays usable) ---"
# Not placed in any protected cgroup, so the shield must not govern it.
set +e
./try-escalate "$DROP_UID" >/dev/null 2>&1
ORC=$?
set -e
[[ "$ORC" == 0 ]] || fail "escalation OUTSIDE the protected cgroup exited $ORC, expected 0 (success) — the shield is governing scope it should not."
echo "OK: the same escalation succeeded outside the protected cgroup (exit 0)."

sleep 1
echo
echo "Detaching (cleanup confirms the enforcing program is gone before exit) ..."
