#!/bin/bash
# Attempt to compile the block-19 fragment as a BPF object. It is EXPECTED to fail:
# this records precisely which symbols the document leaves undefined, so the gap is
# measured rather than asserted.
cd /work
cp /gate/exec_gate.bpf.c.fragment ./exec_gate.bpf.c
echo "=== clang version ==="; clang --version | head -1
echo
echo "=== compile attempt: clang -target bpf ==="
clang -target bpf -O2 -g -c exec_gate.bpf.c -o /dev/null 2>&1 | head -40
echo
echo "=== stage 2: same fragment WITH the standard BPF headers prepended ==="
echo "    (isolates the document's own gaps from the missing #includes)"
# Real vmlinux.h from the running kernel's BTF, same as the repo's other chapters
# (see 20-lsm/Makefile). This gives the true struct file / inode / super_block layout.
if [ -r /sys/kernel/btf/vmlinux ] && command -v bpftool >/dev/null; then
  bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h 2>/dev/null \
    && echo "    generated vmlinux.h ($(wc -l < vmlinux.h) lines) from kernel BTF"
fi
cat > hdr.h <<'H'
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
H
if [ -s vmlinux.h ] && [ -f /usr/include/bpf/bpf_helpers.h ]; then
  cat hdr.h exec_gate.bpf.c > exec_gate_hdr.bpf.c
  clang -target bpf -O2 -g -I. -ferror-limit=100 -c exec_gate_hdr.bpf.c -o /dev/null 2>&1 \
    | grep -oE "use of undeclared identifier '[^']+'|call to undeclared function '[^']+'" \
    | sed "s/.*'\(.*\)'/  \1/" | sort -u \
    | while read -r sym; do
        case "$sym" in
          EPERM|PROT_EXEC)                 echo "  $sym   <- errno.h / mman.h constant" ;;
          policy|verdict_map)              echo "  $sym   <- BPF map, never defined in the doc" ;;
          MAX_SIG|TAG_XATTR|DENY_ANON_EXEC) echo "  $sym   <- policy #define, never given" ;;
          TMPFS_MAGIC|HUGETLBFS_MAGIC)     echo "  $sym   <- magic.h constant" ;;
          task_is_verified_agent)          echo "  $sym   <- helper, referenced but never written" ;;
          bpf_*)                           echo "  $sym   <- kfunc, needs an extern declaration" ;;
          *)                               echo "  $sym" ;;
        esac
      done
else
  echo "    no kernel BTF or libbpf headers available; skipping stage 2"
fi
echo
echo "=== distinct undefined/missing symbols reported (stage 1) ==="
clang -target bpf -O2 -g -c exec_gate.bpf.c -o /dev/null 2>&1 \
  | grep -oE "use of undeclared identifier '[^']+'|unknown type name '[^']+'|'[^']+' file not found|call to undeclared function '[^']+'" \
  | sort -u | sed 's/^/  /'
