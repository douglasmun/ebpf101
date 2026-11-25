#!/usr/bin/env bash
#
# verify-fileshield.sh — Chapter 30 live-verification helper.
#
# fileshield denies opening a guarded file inside a protected cgroup and leaves
# everything else alone. To prove both halves hands-free — and WITHOUT touching
# the real /etc/shadow — this script:
#
#   - confirms "bpf" is an active LSM (else points you at ch20's enable script)
#   - creates a THROWAWAY secret file in a temp dir and guards THAT, not
#     /etc/shadow, so a wrong policy cannot lock the real system out of its own
#     password file (the (dev, ino) match works identically on any file)
#   - creates a throwaway cgroup, puts a sleeping shell in it
#   - loads ./fileshield scoped to ONLY that cgroup, guarding ONLY the temp
#     secret, in the background, capturing its stdout to assert the DENY event
#   - from inside the cgroup, opens the secret and asserts the open FAILED with
#     EPERM AND that the shield logged a matching DENY for that pid
#   - repeats inside a CHILD of a protected cgroup (hierarchical scope, issue #6)
#   - from outside, opens the SAME secret and asserts it SUCCEEDS
#   - opens a DIFFERENT (unguarded) file inside the cgroup and asserts it
#     SUCCEEDS, proving the guard is per-file, not a blanket open deny
#   - detaches, and does not exit until the enforcing program is confirmed gone
#
# The throwaway file + throwaway cgroup are the safety rails: even a wrong policy
# can only affect this one temp file, read only from this one test cgroup.
#
# Run:    sudo bash 30-fileshield/verify-fileshield.sh
#
# Needs root (BPF load, cgroup create, kill). Self-contained.
#
set -euo pipefail

cd "$(dirname "$0")"

fail() { echo "FAIL: $*" >&2; exit 1; }

# (a) prerequisite: bpf must be an active LSM.
CUR="$(cat /sys/kernel/security/lsm)"
if ! printf '%s' "$CUR" | tr ',' '\n' | grep -qx bpf; then
    echo "bpf is NOT an active LSM. Current: $CUR"
    echo "Enable it first:  sudo bash 20-lsm/enable-bpf-lsm.sh  &&  sudo reboot"
    exit 1
fi
echo "Active LSMs: $CUR   (bpf present — good)"

[[ -x ./fileshield ]] || { echo "./fileshield not built. Run 'make' in 30-fileshield/ first."; exit 1; }

CG=/sys/fs/cgroup/fileshield-test
WORK="$(mktemp -d -t fileshield-verify.XXXXXX)"
SECRET="$WORK/secret"        # the guarded stand-in for /etc/shadow
DECOY="$WORK/decoy"          # an unguarded file in the same dir
LOG="$(mktemp -t fileshield-verify-log.XXXXXX)"
printf 'top secret\n' > "$SECRET"
printf 'not secret\n' > "$DECOY"

# (H1) Fail-closed cleanup: confirm the enforcing program is gone before removing
# the cgroup and temp files (same discipline as ch28/29).
cleanup() {
    local rc=$?
    trap - EXIT INT TERM HUP
    if [[ -n "${P:-}" ]] && kill -0 "$P" 2>/dev/null; then
        kill -TERM "$P" 2>/dev/null || true
        if ! timeout 5 bash -c 'while kill -0 '"$P"' 2>/dev/null; do sleep 0.1; done'; then
            echo "note: fileshield did not exit on SIGTERM, sending SIGKILL" >&2
            kill -KILL "$P" 2>/dev/null || true
            sleep 0.3
        fi
    fi
    if [[ -n "${P:-}" ]] && kill -0 "$P" 2>/dev/null; then
        echo "WARNING: could not confirm fileshield (pid $P) is dead — the LSM" >&2
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
    rm -rf "$WORK" 2>/dev/null || true
    rm -f "$LOG" 2>/dev/null || true
    exit "$rc"
}
trap cleanup EXIT INT TERM HUP

# (b) throwaway cgroup with one sleeping member.
mkdir -p "$CG"
sleep 300 &
SLEEP_PID=$!
echo "$SLEEP_PID" > "$CG/cgroup.procs"
echo "Test cgroup $CG holds pid $SLEEP_PID."
echo "Guarded stand-in secret: $SECRET  (NOT /etc/shadow — the match is by (dev,ino), identical on any file)."

# (b2) separate two-level hierarchy for the hierarchical-scope check.
NCG_PARENT=/sys/fs/cgroup/fileshield-parent
NCG_CHILD="$NCG_PARENT/worker"
NCG_PARENT_ARG=()
if mkdir -p "$NCG_PARENT" 2>/dev/null \
   && { echo "+pids" > "$NCG_PARENT/cgroup.subtree_control" 2>/dev/null || true; } \
   && mkdir "$NCG_CHILD" 2>/dev/null; then
    sleep 300 & CHILD_SLEEP_PID=$!
    echo "$CHILD_SLEEP_PID" > "$NCG_CHILD/cgroup.procs"
    NCG_PARENT_ARG=(-c "$NCG_PARENT")
    echo "Nested test: protecting $NCG_PARENT, will open the secret in child $NCG_CHILD."
else
    NCG_PARENT=""
    echo "note: could not build a nested cgroup hierarchy; nested check will skip." >&2
fi

echo "Loading fileshield scoped to the test cgroup(s), guarding only $SECRET ..."
echo
# Only the leaf $CG and the parent $NCG_PARENT are handed in — never the child.
stdbuf -oL ./fileshield -c "$CG" "${NCG_PARENT_ARG[@]}" -f "$SECRET" > >(tee "$LOG") 2>&1 &
P=$!
sleep 1

# open_in <cgroup-dir> <file>: runs `cat` in a child that first joins the cgroup,
# so the governed open happens inside the scope under test. Sets two globals in
# THIS shell (no command-substitution subshell, which would discard them):
# RUN_PID = the opener's pid, RC = 0 on a successful read, nonzero on a failed
# open. The child writes its own pid (which `exec cat` inherits) to a temp file,
# so RUN_PID names the process the shield logs, and RC is cat's status directly.
RUN_PID=""; RC=""
open_in() {
    local cgdir="$1" file="$2"
    local pidfile; pidfile="$(mktemp)"
    set +e
    bash -c '
        echo $$ > "'"$cgdir"'/cgroup.procs" || exit 70
        echo $$ > "'"$pidfile"'"
        exec cat "'"$file"'" >/dev/null 2>&1
    '
    RC=$?
    set -e
    RUN_PID="$(cat "$pidfile" 2>/dev/null)"
    rm -f "$pidfile"
}

echo "--- Inside the protected cgroup: opening the guarded secret should be DENIED ---"
open_in "$CG" "$SECRET"; O_PID="$RUN_PID"
[[ "$RC" != 0 ]] || fail "open of the guarded secret inside the cgroup SUCCEEDED (rc 0) — the shield did not deny it."
[[ -n "$O_PID" ]] || fail "could not move the opener into $CG; deny test inconclusive."
sleep 0.5
grep -Eq "^[[:space:]]*${O_PID}[[:space:]]+DENY\b" "$LOG" \
    || fail "open failed but the shield logged no DENY for pid $O_PID — the failure came from something other than this shield."
echo "OK: open denied inside protected cgroup — open failed AND shield logged DENY for pid $O_PID."

echo
echo "--- Inside the protected cgroup: an UNGUARDED file must still open (per-file, not blanket) ---"
open_in "$CG" "$DECOY"; D_PID="$RUN_PID"
[[ "$RC" == 0 ]] || fail "open of the unguarded decoy inside the cgroup FAILED (rc $RC) — the shield is denying files it should not."
echo "OK: the unguarded decoy opened normally inside the protected cgroup."

echo
echo "--- Inside a CHILD of a protected cgroup: guarded open should ALSO be DENIED ---"
if [[ -n "${NCG_PARENT:-}" && -d "$NCG_CHILD" ]]; then
    open_in "$NCG_CHILD" "$SECRET"; C_PID="$RUN_PID"
    [[ "$RC" != 0 ]] || fail "guarded open in CHILD cgroup SUCCEEDED — ancestry match failed (issue #6 would be reopened)."
    [[ -n "$C_PID" ]] || fail "could not move the opener into $NCG_CHILD; nested check inconclusive."
    sleep 0.5
    grep -Eq "^[[:space:]]*${C_PID}[[:space:]]+DENY\b" "$LOG" \
        || fail "child open failed but no DENY logged for pid $C_PID."
    echo "OK: guarded open denied in a CHILD of the protected cgroup — the ancestry walk covers descendants."
else
    echo "note: nested hierarchy unavailable (cgroup delegation); skipping nested check." >&2
fi

echo
echo "--- Outside the cgroup: the SAME guarded file must OPEN (host stays usable) ---"
if cat "$SECRET" >/dev/null 2>&1; then
    echo "OK: the guarded secret opened normally outside the protected cgroup."
else
    fail "open of the guarded secret OUTSIDE the protected cgroup failed — the shield is governing scope it should not."
fi

sleep 1
echo
echo "Detaching (cleanup confirms the enforcing program is gone before exit) ..."
