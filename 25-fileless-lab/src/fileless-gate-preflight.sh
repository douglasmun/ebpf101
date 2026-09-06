#!/bin/sh
# fileless-gate-preflight.sh — can this host run the signed-exec gate? Reads only.
hard_fail=0
ok(){ echo "  [ OK ]  $1"; }; warn(){ echo "  [WARN]  $1"; }
bad(){ echo "  [FAIL]  $1"; hard_fail=$((hard_fail+1)); }
kver=$(uname -r); echo "Kernel: $kver"
kconf(){ [ -r /proc/config.gz ] && zcat /proc/config.gz ||
         { [ -r "/boot/config-$kver" ] && cat "/boot/config-$kver" ||
           { [ -r /boot/config ] && cat /boot/config; }; }; }
CONF=$(kconf)

echo; echo "Enforcement (M-03) prerequisites:"
maj=${kver%%.*}; rest=${kver#*.}; min=${rest%%.*}
if [ "$maj" -gt 6 ] 2>/dev/null || { [ "$maj" -eq 6 ] && [ "$min" -ge 8 ]; } 2>/dev/null
  then ok "kernel >= 6.8 (xattr/fsverity kfuncs)"; else bad "kernel >= 6.8 required (found $kver)"; fi
printf '%s\n' "$CONF" | grep -q '^CONFIG_BPF_LSM=y'   && ok "CONFIG_BPF_LSM=y"   || bad "CONFIG_BPF_LSM not enabled"
printf '%s\n' "$CONF" | grep -q '^CONFIG_FS_VERITY=y' && ok "CONFIG_FS_VERITY=y" || bad "CONFIG_FS_VERITY not enabled"
if [ -r /sys/kernel/security/lsm ]; then
  grep -q bpf /sys/kernel/security/lsm && ok "bpf active in LSM list" \
    || bad "bpf not in LSM list ($(cat /sys/kernel/security/lsm)); add lsm=...,bpf"
else warn "cannot read /sys/kernel/security/lsm"; fi

echo; echo "Self-protection (M-10) prerequisites:"
if [ -r /sys/kernel/security/lockdown ]; then
  ld=$(cat /sys/kernel/security/lockdown)
  case "$ld" in *'[integrity]'*|*'[confidentiality]'*) ok "lockdown active: $ld";;
    *) warn "lockdown off ($ld) — enforcing gate is removable by root";; esac
else warn "lockdown unavailable — run detect-only"; fi

echo; echo "Cheap standalone control (M-01):"
if [ -r /proc/sys/vm/memfd_noexec ]; then v=$(cat /proc/sys/vm/memfd_noexec)
  [ "$v" = 2 ] && ok "vm.memfd_noexec=2" || warn "vm.memfd_noexec=$v (set 2 after the §7 audit)"
else warn "vm.memfd_noexec absent (needs 6.3+)"; fi

echo
[ "$hard_fail" -eq 0 ] && { echo "RESULT: no hard failures — enforcement feasible."; exit 0; } \
  || { echo "RESULT: $hard_fail hard failure(s) — run detect-only; fix before enforcing."; exit 1; }
