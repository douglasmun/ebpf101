#!/bin/bash
cd /work; make -s
echo "=== unchecked return values in each loader (grep the doc source) ==="
echo "memfd_execveat: open rc checked? $(grep -c 'if (in < 0)' memfd_execveat.c)  memfd rc checked? $(grep -c 'if (mfd < 0)' memfd_execveat.c)"
echo "deleted_exec:   unlink rc checked? $(grep -c 'unlink.*<' deleted_exec.c)"
echo
echo "=== tmpfile_exec: does removing the close(wfd) really give ETXTBSY? (doc comment claim) ==="
sed 's|close(wfd);.*/\* drop the writable fd.*|/* close(wfd) REMOVED to test claim */|' tmpfile_exec.c > tmpfile_noclose.c
grep -n 'close(wfd)\|REMOVED' tmpfile_noclose.c
gcc -O2 -Wall -o tmpfile_noclose tmpfile_noclose.c && ./tmpfile_noclose ./hello; echo "  exit=$? (expect ETXTBSY=Text file busy)"
echo
echo "=== deleted_exec destroys its input (data-loss bug in doc's for-loop) ==="
cp hello victim; ls -l victim >/dev/null && echo "  before: victim exists"
./deleted_exec ./victim
test -f victim && echo "  after: victim EXISTS" || echo "  after: victim GONE (unlinked by loader)"
echo
echo "=== O_TMPFILE on a non-tmpfs dir? /work is overlayfs ==="
mount | grep -E ' / | /work| /tmp' | head -3
