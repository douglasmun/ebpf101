#!/bin/bash
cd /work; make -s 2>&1
pass=0; fail=0
r(){ if [ "$2" = 0 ]; then echo "  PASS  $1"; pass=$((pass+1)); else echo "  FAIL  $1"; fail=$((fail+1)); fi; }
echo "=== FINAL CONSOLIDATED RUN (all doc code, fresh tree each time) ==="
cp hello h1; ./memfd_exec ./h1 >/dev/null 2>&1; r "1a memfd_exec (execve /proc/self/fd/N)" $?
cp hello h2; ./memfd_execveat ./h2 >/dev/null 2>&1; r "1a memfd_execveat (AT_EMPTY_PATH)" $?
./memfd_script >/dev/null 2>&1; r "1b memfd_script (shebang from memfd)" $?
./interp_oneliner.sh ./hello >/dev/null 2>&1; r "1d interp_oneliner.sh (python memfd)" $?
cp hello h3; ./tmpfile_exec ./h3 >/dev/null 2>&1; r "1f tmpfile_exec (O_TMPFILE)" $?
cp hello h4; ./deleted_exec ./h4 >/dev/null 2>&1; r "4  deleted_exec (unlink+fexecve)" $?
printf '#!/bin/sh\necho staged\n' | base64 | base64 -d | sh >/dev/null 2>&1; r "3  staging pipe-to-interpreter" $?
sh ./fileless-gate-preflight.sh >/dev/null 2>&1; [ $? -le 1 ] && r "preflight script runs" 0 || r "preflight script runs" 1
echo
echo "TOTAL: $pass passed, $fail failed"
