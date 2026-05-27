CLANG  ?= clang
CC     ?= gcc
ARCH   := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH)
CFLAGS     := -g -Wall
LDFLAGS    := -lbpf -lelf -lz

.PHONY: all clean

all: execguard

# Step 1 — generate vmlinux.h from the running kernel's BTF.
vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

# Step 2 — compile the BPF C to a BPF ELF object.
execguard.bpf.o: execguard.bpf.c execguard.h vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c execguard.bpf.c -o $@

# Step 3 — generate the C skeleton header from the BPF object.
execguard.skel.h: execguard.bpf.o
	bpftool gen skeleton $< > $@

# Step 4 — compile and link the userspace loader.
execguard: execguard.c execguard.h execguard.skel.h
	$(CC) $(CFLAGS) execguard.c $(LDFLAGS) -o $@

clean:
	rm -f execguard execguard.bpf.o execguard.skel.h vmlinux.h
