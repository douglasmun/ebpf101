/* execsnoop.h — shared between BPF kernel program and userspace loader.
 *
 * Using plain C types (unsigned int / char) avoids the __u32 vs uint32_t
 * header dance: the types mean the same thing on x86-64, and the struct
 * is only passed through the ring buffer, never across network or disk.
 */
#pragma once

#define FNAME_LEN 256

struct event {
	unsigned int pid;
	unsigned int uid;
	char         comm[16];
	char         filename[FNAME_LEN];
};
