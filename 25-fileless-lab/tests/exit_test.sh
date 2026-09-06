#!/bin/bash
cd /work; make -s
sysctl -w vm.memfd_noexec=2 >/dev/null
echo "=== direct exit status (no pipe) ==="
./memfd_exec ./hello; echo "  memfd_exec exit=$?"
./memfd_script; echo "  memfd_script exit=$?"
echo
echo "=== so the earlier exit=0 was the SED PIPELINE, not the program ==="
./memfd_exec ./hello 2>&1 | sed 's/^/x/' ; echo "  piped exit=$? (=sed's status)"
echo
echo "=== check the doc loaders for a real missing-return bug: memfd_execveat ==="
sysctl -w vm.memfd_noexec=0 >/dev/null
echo "--- memfd_execveat with a NONEXISTENT payload (open fails, rc unchecked):"
./memfd_execveat /nonexistent-file; echo "  exit=$?"
echo "--- memfd_exec with nonexistent payload (open IS checked):"
./memfd_exec /nonexistent-file; echo "  exit=$?"
echo
echo "--- memfd_execveat with a DIRECTORY as payload:"
./memfd_execveat /tmp; echo "  exit=$?"
