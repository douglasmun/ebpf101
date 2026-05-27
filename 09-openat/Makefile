CLANG  ?= clang
CC     ?= gcc
ARCH   := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH)
CFLAGS     := -g -Wall
LDFLAGS    := -lbpf -lelf -lz

.PHONY: all clean

all: opensnoop

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

opensnoop.bpf.o: opensnoop.bpf.c opensnoop.h vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c opensnoop.bpf.c -o $@

opensnoop.skel.h: opensnoop.bpf.o
	bpftool gen skeleton $< > $@

opensnoop: opensnoop.c opensnoop.h opensnoop.skel.h
	$(CC) $(CFLAGS) opensnoop.c $(LDFLAGS) -o $@

clean:
	rm -f opensnoop opensnoop.bpf.o opensnoop.skel.h vmlinux.h
