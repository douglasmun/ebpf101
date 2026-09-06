#!/bin/bash
cd /work; make -s
echo "=== SIGMA RULE VALIDATION against observed Image strings ==="
check(){ img="$1"
  case "$img" in *memfd:*) r22=MATCH;; *) r22=no;; esac
  case "$img" in *"(deleted)") r23=MATCH;; *) r23=no;; esac
  printf "  %-40s r22_memfd=%-6s r23_deleted=%s\n" "$img" "$r22" "$r23"
}
for L in memfd_exec memfd_execveat tmpfile_exec; do
  ./$L ./sleeper 2>/dev/null & p=$!; sleep 0.3
  check "$(readlink /proc/$p/exe)"; kill $p 2>/dev/null
done
cp sleeper sc; ./deleted_exec ./sc & p=$!; sleep 0.3
check "$(readlink /proc/$p/exe)"; kill $p 2>/dev/null
echo
echo "=== syscall used by each loader (audit rule coverage, block 21) ==="
for L in memfd_exec memfd_execveat memfd_script tmpfile_exec deleted_exec; do
  printf "  %-16s: " "$L"
  objdump -d "$L" 2>/dev/null >/dev/null
  nm -D "$L" 2>/dev/null | grep -oE 'execveat|execve|memfd_create|fexecve|open' | sort -u | tr '\n' ' '
  echo
done
