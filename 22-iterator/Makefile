CLANG  ?= clang
CC     ?= gcc
ARCH   := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH)
CFLAGS     := -g -Wall
LDFLAGS    := -lbpf -lelf -lz

.PHONY: all clean

all: taskdump

# Step 1 — generate vmlinux.h from the running kernel's BTF.
vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

# Step 2 — compile the BPF C to a BPF ELF object.
taskdump.bpf.o: taskdump.bpf.c vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c taskdump.bpf.c -o $@

# Step 3 — generate the C skeleton header from the BPF object.
taskdump.skel.h: taskdump.bpf.o
	bpftool gen skeleton $< > $@

# Step 4 — compile and link the userspace loader.
taskdump: taskdump.c taskdump.skel.h
	$(CC) $(CFLAGS) taskdump.c $(LDFLAGS) -o $@

clean:
	rm -f taskdump taskdump.bpf.o taskdump.skel.h vmlinux.h
