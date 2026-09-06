#!/bin/bash
cd /work; make -s
echo "=== is_anon_exec_inode(): nlink==0 && (TMPFS_MAGIC||HUGETLBFS_MAGIC) ==="
echo "Gate logic (block 19) DENIES 1a/1b/1d at bprm_check, and 1f (O_TMPFILE) only if fs is tmpfs."
echo
echo "--- what filesystem is /tmp in this container?"
stat -f -c 'path=%n fstype=%T magic=%i' /tmp
echo "--- and where does the doc's tmpfile_exec open O_TMPFILE? -> hardcoded \"/tmp\""
grep -n 'O_TMPFILE' tmpfile_exec.c
echo
echo "=== run each and report exe-link + nlink of the running inode ==="
for L in memfd_exec memfd_execveat tmpfile_exec; do
  cp hello p_$L; ./$L ./sleeper >/dev/null 2>&1 &
  p=$!; sleep 0.3
  link=$(readlink /proc/$p/exe 2>/dev/null)
  nl=$(stat -L -c '%h' /proc/$p/exe 2>/dev/null)
  fs=$(stat -f -L -c '%T' /proc/$p/exe 2>/dev/null)
  printf "  %-16s exe=%-28s nlink=%-3s fs=%s\n" "$L" "$link" "$nl" "$fs"
  kill $p 2>/dev/null
done
cp sleeper sd; ./deleted_exec ./sd >/dev/null 2>&1 & p=$!; sleep 0.3
printf "  %-16s exe=%-28s nlink=%-3s fs=%s\n" "deleted_exec" "$(readlink /proc/$p/exe)" "$(stat -L -c '%h' /proc/$p/exe)" "$(stat -f -L -c '%T' /proc/$p/exe)"
kill $p 2>/dev/null
