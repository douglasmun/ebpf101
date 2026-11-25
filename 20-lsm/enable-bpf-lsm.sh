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
#   - writes a GRUB drop-in /etc/default/grub.d/99-bpf-lsm.cfg that APPENDS
#     "lsm=<current>,bpf" to GRUB_CMDLINE_LINUX_DEFAULT
#   - is idempotent (no-op if bpf is already active; overwrites the drop-in
#     cleanly on a re-run)
#   - runs update-grub
#
# Why a drop-in, not an edit to /etc/default/grub directly:
#   The drop-ins in /etc/default/grub.d/ are sourced AFTER /etc/default/grub, and
#   on cloud images one of them (50-cloudimg-settings.cfg) OVERWRITES
#   GRUB_CMDLINE_LINUX_DEFAULT rather than appending. An lsm= written into the main
#   file is silently clobbered — the kernel boots without bpf and the LSM program
#   cannot attach, with no error to explain why. A 99-ordered drop-in that appends
#   to $GRUB_CMDLINE_LINUX_DEFAULT runs last and survives, on both cloud and plain
#   installs. (Observed on an Ubuntu aarch64 cloud image, kernel 7.0.0-generic.)
#
# Run:     sudo bash 20-lsm/enable-bpf-lsm.sh
# Then:    sudo reboot
# Verify:  cat /sys/kernel/security/lsm        # should now include 'bpf'
# Test:    sudo ./20-lsm/execguard             # run a command in another shell
#
# Revert:  sudo rm /etc/default/grub.d/99-bpf-lsm.cfg && sudo update-grub
#          (or choose "recovery mode" once in the GRUB menu — the drop-in only
#           touches the _DEFAULT cmdline, so recovery still boots without bpf)
#
# This edits your bootloader configuration and needs root. Read it before running.
#
set -euo pipefail

DROPIN=/etc/default/grub.d/99-bpf-lsm.cfg
CUR="$(cat /sys/kernel/security/lsm)"          # e.g. lockdown,capability,landlock,yama,apparmor

if printf '%s' "$CUR" | tr ',' '\n' | grep -qx bpf; then
    echo "bpf is already an active LSM — nothing to do."
    exit 0
fi

WANT="lsm=${CUR},bpf"
echo "Current active LSMs  : $CUR"
echo "Will append on boot  : $WANT"
echo "Drop-in file         : $DROPIN"
echo

# A drop-in that appends to whatever the earlier files set. Ordered 99- so it is
# sourced last and cannot be overwritten by an earlier drop-in (the clobber trap).
mkdir -p "$(dirname "$DROPIN")"
cat > "$DROPIN" <<EOF
# Written by 20-lsm/enable-bpf-lsm.sh — adds bpf to the active LSMs.
# Appends so a cloud-init drop-in that overwrites the var cannot clobber it.
GRUB_CMDLINE_LINUX_DEFAULT="\$GRUB_CMDLINE_LINUX_DEFAULT ${WANT}"
EOF

echo "Wrote $DROPIN:"
sed 's/^/  /' "$DROPIN"
echo

update-grub

echo
echo "Check the generated cmdline carries lsm=...,bpf:"
grep -m1 'lsm=' /boot/grub/grub.cfg 2>/dev/null | sed 's/^/  /' || \
    echo "  (could not read /boot/grub/grub.cfg — verify after reboot instead)"
echo
echo "OK. Now: sudo reboot"
echo "After reboot, confirm:  cat /sys/kernel/security/lsm   (expect '...,bpf')"
echo "Then test ch20:         sudo ./20-lsm/execguard"
echo
echo "Revert:  sudo rm $DROPIN && sudo update-grub"
