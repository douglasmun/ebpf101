#!/bin/bash
cd /work; make -s
echo "=== strace: which syscall does each loader actually issue? ==="
for L in memfd_exec memfd_execveat tmpfile_exec deleted_exec; do
  cp hello h_$L 2>/dev/null
  echo "--- $L"
  strace -f -e trace=memfd_create,execve,execveat,open,openat ./$L ./h_$L 2>&1 \
    | grep -E 'memfd_create|execveat|execve|O_TMPFILE' | head -8
done
echo
echo "--- memfd_script"
strace -f -e trace=memfd_create,execve,execveat ./memfd_script 2>&1 | grep -E 'memfd_create|execve' | head -8
echo
echo "--- interp_oneliner.sh"
strace -f -e trace=memfd_create,execve,execveat ./interp_oneliner.sh ./hello 2>&1 | grep -E 'memfd_create|execveat|execve.*proc/self' | head -8
