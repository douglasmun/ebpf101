CC ?= gcc
CFLAGS ?= -O2 -Wall
LOADERS = memfd_exec memfd_execveat memfd_script tmpfile_exec deleted_exec
PAYLOADS = hello sleeper

all: $(PAYLOADS) $(LOADERS)
hello: hello.c ; $(CC) $(CFLAGS) -static -o $@ $<
sleeper: sleeper.c ; $(CC) $(CFLAGS) -static -o $@ $<
%: %.c ; $(CC) $(CFLAGS) -o $@ $<
clean: ; rm -f $(PAYLOADS) $(LOADERS)
.PHONY: all clean