CLANG  ?= clang
CC     ?= gcc
ARCH   := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH)
CFLAGS     := -g -Wall
LDFLAGS    := -lbpf -lelf -lz

.PHONY: all clean

all: xdpcount

# Step 1 — generate vmlinux.h from the running kernel's BTF.
vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

# Step 2 — compile the BPF C to a BPF ELF object.
xdpcount.bpf.o: xdpcount.bpf.c xdpcount.h vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c xdpcount.bpf.c -o $@

# Step 3 — generate the C skeleton header from the BPF object.
xdpcount.skel.h: xdpcount.bpf.o
	bpftool gen skeleton $< > $@

# Step 4 — compile and link the userspace loader.
xdpcount: xdpcount.c xdpcount.h xdpcount.skel.h
	$(CC) $(CFLAGS) xdpcount.c $(LDFLAGS) -o $@

clean:
	rm -f xdpcount xdpcount.bpf.o xdpcount.skel.h vmlinux.h
