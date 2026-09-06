#!/bin/sh
# interp_oneliner.sh — the interpreter creates the memfd, reads the ELF, execs it.
# usage: ./interp_oneliner.sh ./hello
exec python3 -c '
import os, sys
fd = os.memfd_create("payload", 0)
os.write(fd, open(sys.argv[1], "rb").read())
os.execve(f"/proc/self/fd/{fd}", ["payload"], os.environ)
' "$1"
