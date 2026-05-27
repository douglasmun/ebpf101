/* Shared between BPF kernel program and userspace loader. */
#pragma once

#define MAXARGS   20
#define ARGSIZE   128

#define EVENT_ARG 0   /* one argument string follows */
#define EVENT_RET 1   /* end-of-command marker       */

struct event {
	unsigned int pid;
	unsigned int uid;
	char         comm[16];
	int          type;
	char         arg[ARGSIZE];
};
