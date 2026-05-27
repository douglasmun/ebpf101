CLANG  ?= clang
CC     ?= gcc
ARCH   := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH)
CFLAGS     := -g -Wall
LDFLAGS    := -lbpf -lelf -lz -lm          # -lm: sqrt() in the beacon rule

.PHONY: all clean

all: ids

# Step 1 — generate vmlinux.h from the running kernel's BTF.
vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

# Step 2 — compile the BPF C to a BPF ELF object.
ids.bpf.o: ids.bpf.c ids.h vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c ids.bpf.c -o $@

# Step 3 — generate the C skeleton header from the BPF object.
ids.skel.h: ids.bpf.o
	bpftool gen skeleton $< > $@

# Step 4 — compile and link the userspace loader + rule engine.
ids: ids.c ids.h ids.skel.h
	$(CC) $(CFLAGS) ids.c $(LDFLAGS) -o $@

clean:
	rm -f ids ids.bpf.o ids.skel.h vmlinux.h
