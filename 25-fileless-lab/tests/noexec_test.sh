#!/bin/bash
cd /work; make -s
echo "kernel: $(uname -r)"
echo "vm.memfd_noexec supported? $(test -e /proc/sys/vm/memfd_noexec && echo yes || echo NO)"
for v in 0 1 2; do
  echo "=== setting vm.memfd_noexec=$v ==="
  sysctl -w vm.memfd_noexec=$v 2>&1 | sed 's/^/    /'
  echo "  read back: $(cat /proc/sys/vm/memfd_noexec 2>/dev/null)"
  cp hello h1
  echo "  memfd_exec (MFD_CLOEXEC, no MFD_EXEC/NOEXEC_SEAL):"
  ./memfd_exec ./h1 2>&1 | sed 's/^/      /'; echo "      exit=$?"
  echo "  memfd_script (flags=0):"
  ./memfd_script 2>&1 | sed 's/^/      /'; echo "      exit=$?"
done
