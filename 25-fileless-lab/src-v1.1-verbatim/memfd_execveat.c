/* memfd_execveat.c */
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s <elf>\n", argv[0]); return 2; }
    int in = open(argv[1], O_RDONLY | O_CLOEXEC);
    int mfd = memfd_create("payload", MFD_CLOEXEC);
    char buf[1 << 16]; ssize_t n;
    while ((n = read(in, buf, sizeof buf)) > 0)
        for (ssize_t o = 0, w; o < n; o += w)
            if ((w = write(mfd, buf + o, n - o)) < 0) return 1;
    close(in);
    execveat(mfd, "", (char*[]){ "payload", NULL }, environ, AT_EMPTY_PATH);
    perror("execveat"); return 1;
}