/* memfd_exec.c — memfd_create -> write ELF -> execve /proc/self/fd/N */
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s <elf>\n", argv[0]); return 2; }
    int in = open(argv[1], O_RDONLY | O_CLOEXEC);
    if (in < 0) { perror("open payload"); return 1; }
    int mfd = memfd_create("payload", MFD_CLOEXEC);
    if (mfd < 0) { perror("memfd_create"); return 1; }
    fprintf(stderr, "[loader] memfd_create() -> fd %d\n", mfd);
    char buf[1 << 16]; ssize_t n; long total = 0;
    while ((n = read(in, buf, sizeof buf)) > 0)
        for (ssize_t off = 0; off < n; ) {
            ssize_t w = write(mfd, buf + off, n - off);
            if (w < 0) { perror("write memfd"); return 1; }
            off += w; total += w;
        }
    if (n < 0) { perror("read payload"); return 1; }
    close(in);
    fprintf(stderr, "[loader] wrote %ld ELF bytes into the memfd (nothing on disk)\n", total);
    char path[64]; snprintf(path, sizeof path, "/proc/self/fd/%d", mfd);
    fprintf(stderr, "[loader] execve(\"%s\", ...)\n", path);
    execve(path, (char*[]){ "payload", NULL }, environ);
    perror("execve"); return 1;
}