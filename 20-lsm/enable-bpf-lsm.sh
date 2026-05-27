#!/usr/bin/env bash
#
# enable-bpf-lsm.sh — Chapter 20 helper.
#
# LSM BPF programs (this chapter's lsm/bprm_check_security) can only ATTACH if
# "bpf" is an active Linux Security Module. CONFIG_BPF_LSM=y is not enough — bpf
# must also be listed in the kernel `lsm=` boot parameter. This script enables it
# safely, then you reboot once.
#
# What it does:
#   - reads the CURRENT active LSMs from /sys/kernel/security/lsm (source of truth)
#   - appends ",bpf" and writes it to GRUB_CMDLINE_LINUX_DEFAULT in /etc/default/grub
#     (the _DEFAULT line, so "recovery mode" still boots WITHOUT it — a fallback)
#   - backs up /etc/default/grub first, and is idempotent (no-op if bpf is active)
#   - runs update-grub
#
# Run:     sudo bash 20-lsm/enable-bpf-lsm.sh
# Then:    sudo reboot
# Verify:  cat /sys/kernel/security/lsm        # should now include 'bpf'
# Test:    sudo ./20-lsm/execguard             # run a command in another shell
#
# Revert:  restore the printed /etc/default/grub.bak.* and `sudo update-grub`,
#          or just choose "recovery mode" once in the GRUB menu.
#
# This edits your bootloader configuration and needs root. Read it before running.
#
set -euo pipefail

GRUB=/etc/default/grub
CUR="$(cat /sys/kernel/security/lsm)"          # e.g. lockdown,capability,landlock,yama,apparmor

if printf '%s' "$CUR" | tr ',' '\n' | grep -qx bpf; then
    echo "bpf is already an active LSM — nothing to do."
    exit 0
fi

WANT="lsm=${CUR},bpf"
echo "Current active LSMs  : $CUR"
echo "Will set on next boot: $WANT"
echo

BAK="${GRUB}.bak.$(date +%Y%m%d-%H%M%S)"
cp "$GRUB" "$BAK"
echo "Backed up $GRUB -> $BAK"

# Replace an existing lsm= in the default cmdline, or append one if absent.
if grep -qE '^GRUB_CMDLINE_LINUX_DEFAULT=.*\blsm=' "$GRUB"; then
    sed -i -E "s/\blsm=[^\" ]*/${WANT}/" "$GRUB"
else
    sed -i -E "s/^(GRUB_CMDLINE_LINUX_DEFAULT=\")(.*)(\")\$/\1\2 ${WANT}\3/" "$GRUB"
fi

echo "Updated line:"
grep -n '^GRUB_CMDLINE_LINUX_DEFAULT=' "$GRUB"
echo

update-grub
echo
echo "OK. Now: sudo reboot"
echo "After reboot, confirm:  cat /sys/kernel/security/lsm   (expect '...,bpf')"
echo "Then test ch20:         sudo ./20-lsm/execguard"
echo
echo "Revert:  sudo cp $BAK $GRUB && sudo update-grub   (or boot 'recovery mode' once)"
