CLANG  ?= clang
CC     ?= gcc
ARCH   := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH)
CFLAGS     := -g -Wall
LDFLAGS    := -lbpf -lelf -lz

.PHONY: all clean

all: execsnoop

# Step 1 — generate vmlinux.h from the running kernel's BTF.
# This file encodes every kernel type with CO-RE annotations.
# bpftool reads /sys/kernel/btf/vmlinux (world-readable; no sudo needed).
vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

# Step 2 — compile the BPF C to a BPF ELF object.
# -target bpf tells clang to emit BPF bytecode, not x86.
# -g embeds BTF type info in the object (needed for CO-RE and skeleton).
execsnoop.bpf.o: execsnoop.bpf.c execsnoop.h vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c execsnoop.bpf.c -o $@

# Step 3 — generate the C skeleton header from the BPF object.
# The skeleton gives us typed open/load/attach/destroy wrappers and typed
# map/program pointers, eliminating stringly-typed libbpf calls.
execsnoop.skel.h: execsnoop.bpf.o
	bpftool gen skeleton $< > $@

# Step 4 — compile and link the userspace program.
execsnoop: execsnoop.c execsnoop.h execsnoop.skel.h
	$(CC) $(CFLAGS) execsnoop.c $(LDFLAGS) -o $@

clean:
	rm -f execsnoop execsnoop.bpf.o execsnoop.skel.h vmlinux.h
