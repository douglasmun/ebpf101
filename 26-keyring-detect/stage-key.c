// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * stage-key.c — the thing keyring_snoop is meant to catch, Chapter 26.
 *
 * Stages <size> bytes in a "user" key on the session keyring, reads it back with
 * keyctl(KEYCTL_READ), then revokes it — the write+read half of keyring-staged
 * fileless execution, without the ELF loader. Emits no exec syscall, no memfd,
 * no file descriptor: invisible to chapter 25's detection set, visible to
 * keyring_snoop's add_key hook.
 *
 *   ./stage-key            # 8192 bytes (default) — flagged
 *   ./stage-key 32         # tiny key — not flagged
 *   ./stage-key 65536      # bigger than the 32767 user-key ceiling — EINVAL
 */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>

#define KEY_SPEC_SESSION_KEYRING (-3)
#define KEYCTL_READ   11
#define KEYCTL_REVOKE  3

int main(int argc, char **argv)
{
    size_t n = argc > 1 ? strtoul(argv[1], NULL, 0) : 8192;
    char *b = malloc(n ? n : 1);
    if (!b) { perror("malloc"); return 1; }
    memset(b, 'A', n);

    long k = syscall(SYS_add_key, "user", "_dntry", b, n, KEY_SPEC_SESSION_KEYRING);
    if (k < 0) { fprintf(stderr, "add_key(%zu): %s\n", n, strerror(errno)); return 1; }
    printf("staged %zu bytes in user key serial=%ld\n", n, k);

    char *out = malloc(n ? n : 1);
    long got = syscall(SYS_keyctl, KEYCTL_READ, k, out, n, 0);
    printf("read back %ld bytes\n", got);

    syscall(SYS_keyctl, KEYCTL_REVOKE, k, 0, 0, 0);
    return 0;
}
