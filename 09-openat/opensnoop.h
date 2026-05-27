/* Shared between BPF kernel program and userspace loader. */
#pragma once

#define FNAME_LEN 256

struct event {
	unsigned int pid;
	unsigned int uid;
	char         comm[16];
	int          flags;      /* raw O_* flags from the openat call */
	char         filename[FNAME_LEN];
};
