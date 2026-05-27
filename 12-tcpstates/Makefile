CLANG  ?= clang
CC     ?= gcc
ARCH   := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH)
CFLAGS     := -g -Wall
LDFLAGS    := -lbpf -lelf -lz

.PHONY: all clean

all: tcpstates

# Step 1 — generate vmlinux.h from the running kernel's BTF.
vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

# Step 2 — compile the BPF C to a BPF ELF object.
tcpstates.bpf.o: tcpstates.bpf.c tcpstates.h vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c tcpstates.bpf.c -o $@

# Step 3 — generate the C skeleton header from the BPF object.
tcpstates.skel.h: tcpstates.bpf.o
	bpftool gen skeleton $< > $@

# Step 4 — compile and link the userspace program.
tcpstates: tcpstates.c tcpstates.h tcpstates.skel.h
	$(CC) $(CFLAGS) tcpstates.c $(LDFLAGS) -o $@

clean:
	rm -f tcpstates tcpstates.bpf.o tcpstates.skel.h vmlinux.h
