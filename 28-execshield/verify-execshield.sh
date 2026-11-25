#!/usr/bin/env bash
#
# verify-execshield.sh — Chapter 28 live-verification helper.
#
# execshield denies execve inside a protected cgroup and leaves everything else
# alone. To prove both halves hands-free, this script:
#
#   - confirms "bpf" is an active LSM (else points you at ch20's enable script)
#   - creates a throwaway cgroup, puts a sleeping shell in it
#   - loads ./execshield scoped to ONLY that cgroup, in the background,
#     capturing its stdout so we can assert on the DENY event it logs
#   - from inside the cgroup, execs and asserts it failed with EPERM AND that
#     the shield logged a matching DENY for that pid — a plain exec failure is
#     not enough, the shield must be shown to be the cause
#   - from outside, execs ls/id and asserts they SUCCEEDED (host stays usable)
#   - detaches, and does not exit until the enforcing program is confirmed gone
#
# The throwaway-cgroup scope is the safety rail: even if the policy were wrong,
# only the test shell is affected, never your login shell or the system. Because
# this program ENFORCES (unlike the observe-only tools in earlier chapters), a
# leaked background process keeps the bprm_check_security hook live, so cleanup
# here must positively confirm the process died before removing the cgroup.
#
# Run:    sudo bash 28-execshield/verify-execshield.sh
#
# Needs root (BPF load, cgroup create, kill). Self-contained: no second terminal.
#
set -euo pipefail

cd "$(dirname "$0")"

fail() { echo "FAIL: $*" >&2; exit 1; }

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
LOG="$(mktemp -t execshield-verify.XXXXXX)"

# (H1) Guarantee the enforcing program is detached on ANY exit — a clean finish,
# an error under set -e, or an interrupt. We kill by saved pid, escalate to
# SIGKILL if SIGTERM is ignored, and CONFIRM the process is gone before removing
# the cgroup. A shield we could not confirm dead is a loud warning, not silence,
# because it would keep enforcing on this cgroup's (recyclable) id.
cleanup() {
    local rc=$?
    trap - EXIT INT TERM HUP        # don't re-enter on signals during cleanup
    if [[ -n "${P:-}" ]] && kill -0 "$P" 2>/dev/null; then
        kill -TERM "$P" 2>/dev/null || true
        # Give it up to 5s to detach on its own, then force it.
        if ! timeout 5 bash -c 'while kill -0 '"$P"' 2>/dev/null; do sleep 0.1; done'; then
            echo "note: execshield did not exit on SIGTERM, sending SIGKILL" >&2
            kill -KILL "$P" 2>/dev/null || true
            sleep 0.3
        fi
    fi
    if [[ -n "${P:-}" ]] && kill -0 "$P" 2>/dev/null; then
        echo "WARNING: could not confirm execshield (pid $P) is dead — the LSM" >&2
        echo "         hook may still be ENFORCING on $CG. Kill it manually:" >&2
        echo "         sudo kill -9 $P" >&2
        rc=1                         # make the leak visible in the exit status
    else
        [[ -n "${SLEEP_PID:-}" ]] && kill "$SLEEP_PID" 2>/dev/null || true
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

echo "Loading execshield scoped to $CG only ..."
echo
# Capture the loader's stdout (tee so the run is still visible) so the deny test
# can assert the shield logged a DENY. Line-buffer it or the DENY row may not be
# flushed to $LOG before we grep it.
stdbuf -oL ./execshield "$CG" > >(tee "$LOG") 2>&1 &
P=$!
sleep 1

echo "--- Inside the protected cgroup: exec should be DENIED by the shield ---"
# (M2) Run the exec attempt in a child whose exit status we can read, and whose
# pid we know, so we can assert BOTH facts that implicate the shield:
#   1. the exec failed with EPERM — the shell reports a permission-denied exec
#      as exit 126 (vmlinux: execve returns -EPERM, which is what the LSM deny
#      produces). A missing binary would be 127; a different error, something else.
#   2. the shield logged a DENY line naming this child's pid.
# Either alone is not proof: an unrelated exec failure gives (1) without (2); a
# stale log line could give (2) without (1). Requiring both means the PASS fails
# closed if the shield silently stopped denying.
DENY_PID=""
set +e
DENY_PID=$(
    bash -c '
        echo $$ > "'"$CG"'/cgroup.procs" || exit 70   # could not enter cgroup
        echo $$                                        # tell parent our pid
        exec /bin/true                                 # expect EPERM from the LSM
    '
)
rc=$?
set -e
# $DENY_PID is the child pid it printed before exec; rc is /bin/true's exec result.
[[ "$rc" == 126 ]] || fail "exec inside cgroup exited $rc, expected 126 (EPERM). The shield did not deny it."
[[ -n "$DENY_PID" ]] || fail "could not move the test child into $CG (cgroup2 rule?); deny test inconclusive."
sleep 0.5    # let the loader flush its DENY row to $LOG
grep -Eq "^[[:space:]]*${DENY_PID}[[:space:]]+DENY\b" "$LOG" \
    || fail "exec failed with EPERM but the shield logged no DENY for pid $DENY_PID — the EPERM came from something other than this shield."
echo "OK: exec denied inside protected cgroup — exit 126 (EPERM) AND shield logged DENY for pid $DENY_PID."

echo
echo "--- Outside the cgroup: host stays usable (exec must SUCCEED) ---"
ls / >/dev/null || fail "ls failed outside the protected cgroup — the shield is denying exec it should not."
echo "OK: ls ran outside the cgroup."
id    >/dev/null || fail "id failed outside the protected cgroup — the shield is denying exec it should not."
echo "OK: id ran outside the cgroup."

sleep 1
echo
echo "Detaching (cleanup confirms the enforcing program is gone before exit) ..."
