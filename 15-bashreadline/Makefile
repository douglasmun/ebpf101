CLANG  ?= clang
CC     ?= gcc
ARCH   := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH)
CFLAGS     := -g -Wall
LDFLAGS    := -lbpf -lelf -lz

.PHONY: all clean

all: bashreadline

# Step 1 — generate vmlinux.h from the running kernel's BTF.
vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

# Step 2 — compile the BPF C to a BPF ELF object.
bashreadline.bpf.o: bashreadline.bpf.c bashreadline.h vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c bashreadline.bpf.c -o $@

# Step 3 — generate the C skeleton header from the BPF object.
bashreadline.skel.h: bashreadline.bpf.o
	bpftool gen skeleton $< > $@

# Step 4 — compile and link the userspace loader.
bashreadline: bashreadline.c bashreadline.h bashreadline.skel.h
	$(CC) $(CFLAGS) bashreadline.c $(LDFLAGS) -o $@

clean:
	rm -f bashreadline bashreadline.bpf.o bashreadline.skel.h vmlinux.h
