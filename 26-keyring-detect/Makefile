CLANG  ?= clang
CC     ?= gcc
ARCH   := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH)
CFLAGS     := -g -Wall
LDFLAGS    := -lbpf -lelf -lz

.PHONY: all clean lsm

all: keyring_snoop

# Step 1 — generate vmlinux.h from the running kernel's BTF.
vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

# Step 2 — compile the BPF C to a BPF ELF object.
keyring_snoop.bpf.o: keyring_snoop.bpf.c keyring_snoop.h vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c keyring_snoop.bpf.c -o $@

# Step 3 — generate the C skeleton header from the BPF object.
keyring_snoop.skel.h: keyring_snoop.bpf.o
	bpftool gen skeleton $< > $@

# Step 4 — compile and link the userspace loader.
keyring_snoop: keyring_snoop.c keyring_snoop.h keyring_snoop.skel.h
	$(CC) $(CFLAGS) keyring_snoop.c $(LDFLAGS) -o $@

# The enforcement variant is COMPILE-ONLY: it attaches only on a BPF-LSM host
# (bpf in the kernel `lsm=` param). `make lsm` proves it compiles against BTF.
lsm: keyring_snoop.lsm.bpf.o
keyring_snoop.lsm.bpf.o: keyring_snoop.lsm.bpf.c vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c keyring_snoop.lsm.bpf.c -o $@

clean:
	rm -f keyring_snoop keyring_snoop.bpf.o keyring_snoop.lsm.bpf.o \
	      keyring_snoop.skel.h vmlinux.h
