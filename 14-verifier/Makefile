CLANG  ?= clang
CC     ?= gcc
ARCH   := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH)
CFLAGS     := -g -Wall
LDFLAGS    := -lbpf -lelf -lz

.PHONY: all clean

all: verifier

# Step 1 — generate vmlinux.h from the running kernel's BTF.
vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

# Step 2 — compile the BPF C to a BPF ELF object.
#   Note: the "bad_*" programs compile fine here — clang does not run the
#   verifier. They are only rejected later, by the kernel, at load time.
verifier.bpf.o: verifier.bpf.c vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c verifier.bpf.c -o $@

# Step 3 — generate the C skeleton header from the BPF object.
verifier.skel.h: verifier.bpf.o
	bpftool gen skeleton $< > $@

# Step 4 — compile and link the userspace driver.
verifier: verifier.c verifier.skel.h
	$(CC) $(CFLAGS) verifier.c $(LDFLAGS) -o $@

clean:
	rm -f verifier verifier.bpf.o verifier.skel.h vmlinux.h
