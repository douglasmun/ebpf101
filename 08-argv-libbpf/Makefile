CLANG  ?= clang
CC     ?= gcc
ARCH   := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH)
CFLAGS     := -g -Wall
LDFLAGS    := -lbpf -lelf -lz

.PHONY: all clean

all: execsnoop

# Reuse ch7's vmlinux.h if already generated; otherwise regenerate.
vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

execsnoop.bpf.o: execsnoop.bpf.c execsnoop.h vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c execsnoop.bpf.c -o $@

execsnoop.skel.h: execsnoop.bpf.o
	bpftool gen skeleton $< > $@

execsnoop: execsnoop.c execsnoop.h execsnoop.skel.h
	$(CC) $(CFLAGS) execsnoop.c $(LDFLAGS) -o $@

clean:
	rm -f execsnoop execsnoop.bpf.o execsnoop.skel.h vmlinux.h
