CLANG  ?= clang
CC     ?= gcc
ARCH   := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH)
CFLAGS     := -g -Wall
LDFLAGS    := -lbpf -lelf -lz

.PHONY: all clean

all: tailcall

# Step 1 — generate vmlinux.h from the running kernel's BTF.
vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

# Step 2 — compile the BPF C to a BPF ELF object.
tailcall.bpf.o: tailcall.bpf.c tailcall.h vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c tailcall.bpf.c -o $@

# Step 3 — generate the C skeleton header from the BPF object.
tailcall.skel.h: tailcall.bpf.o
	bpftool gen skeleton $< > $@

# Step 4 — compile and link the userspace loader.
tailcall: tailcall.c tailcall.h tailcall.skel.h
	$(CC) $(CFLAGS) tailcall.c $(LDFLAGS) -o $@

clean:
	rm -f tailcall tailcall.bpf.o tailcall.skel.h vmlinux.h
