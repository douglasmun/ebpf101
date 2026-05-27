/* Shared between BPF kernel program and userspace loader. */
#ifndef OPENSNOOP_H
#define OPENSNOOP_H

#define FNAME_LEN     256
#define TASK_COMM_LEN 16

/* Stored in the stash map at sys_enter; consumed at sys_exit. */
struct entry_t {
	int  flags;
	char filename[FNAME_LEN];
};

/* Emitted to the ring buffer at sys_exit, with the return value added. */
struct event {
	unsigned int pid;
	unsigned int uid;
	char         comm[TASK_COMM_LEN];
	int          flags;
	long         ret;       /* fd number (≥0 success) or −errno (<0 failure) */
	char         filename[FNAME_LEN];
};

#endif /* OPENSNOOP_H */
