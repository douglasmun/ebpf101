#!/usr/bin/env bash
#
# verify-execguard.sh — Chapter 20 live-verification helper.
#
# execguard is an LSM BPF auditor: it attaches to bprm_check_security (the hook
# the kernel runs before every execve) and logs an "allow" verdict for each.
# To see it work you must (a) have "bpf" as an active LSM and (b) actually exec
# some programs while it is attached. This script does both, hands-free:
#
#   - confirms "bpf" is an active LSM (else points you at enable-bpf-lsm.sh)
#   - loads ./execguard in the background and grabs its PID
#   - triggers a few execs (ls, id, uname) so there is guaranteed traffic
#   - sends it SIGTERM so it detaches cleanly and prints "Detached. Bye!"
#
# Run:    sudo bash 20-lsm/verify-execguard.sh
#
# Needs root (loading BPF + the kill). Self-contained: no second terminal.
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

if [[ ! -x ./execguard ]]; then
    echo "./execguard not built. Run 'make' in 20-lsm/ first."
    exit 1
fi

echo "Loading execguard and triggering ls / id / uname ..."
echo

# (b) load it, generate guaranteed exec traffic, then stop it cleanly.
./execguard &
P=$!
sleep 1
ls /    >/dev/null
id      >/dev/null
uname -a >/dev/null
sleep 1
kill -TERM "$P"
wait "$P"
