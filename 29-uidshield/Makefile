CLANG  ?= clang
CC     ?= gcc
ARCH   := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH)
CFLAGS     := -g -Wall
LDFLAGS    := -lbpf -lelf -lz

.PHONY: all clean

all: uidshield try-escalate

# The verify-script trigger: an ordinary host binary, no BPF.
try-escalate: try-escalate.c
	$(CC) $(CFLAGS) try-escalate.c -o $@

# Step 1 — generate vmlinux.h from the running kernel's BTF.
vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

# Step 2 — compile the BPF C to a BPF ELF object.
uidshield.bpf.o: uidshield.bpf.c uidshield.h vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c uidshield.bpf.c -o $@

# Step 3 — generate the C skeleton header from the BPF object.
uidshield.skel.h: uidshield.bpf.o
	bpftool gen skeleton $< > $@

# Step 4 — compile and link the userspace loader.
uidshield: uidshield.c uidshield.h uidshield.skel.h
	$(CC) $(CFLAGS) uidshield.c $(LDFLAGS) -o $@

clean:
	rm -f uidshield uidshield.bpf.o uidshield.skel.h vmlinux.h
