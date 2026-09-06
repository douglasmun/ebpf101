/* deleted_exec.c — execs a private copy so the caller's file survives. */
#define _GNU_SOURCE
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s <elf>\n", argv[0]); return 2; }
    /* Copy argv[1] to a scratch path and unlink THAT, never the caller's file. */
    char tmp[PATH_MAX];
    snprintf(tmp, sizeof tmp, "%s.deleted_exec.%d", argv[1], (int)getpid());

    int src = open(argv[1], O_RDONLY | O_CLOEXEC);
    if (src < 0) { perror("open"); return 1; }
    int dst = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0700);
    if (dst < 0) { perror("open copy"); return 1; }

    char buf[1 << 16]; ssize_t n;
    while ((n = read(src, buf, sizeof buf)) > 0)
        for (ssize_t o = 0, w; o < n; o += w)
            if ((w = write(dst, buf + o, n - o)) < 0) { perror("write copy"); return 1; }
    if (n < 0) { perror("read"); return 1; }
    close(src); close(dst);

    int fd = open(tmp, O_RDONLY | O_CLOEXEC);      /* re-open r/o: writable fd => ETXTBSY */
    if (fd < 0) { perror("reopen copy"); return 1; }
    if (unlink(tmp) < 0) { perror("unlink"); return 1; }  /* name gone; inode alive via fd */
    fexecve(fd, (char*[]){ "payload", NULL }, environ);
    perror("fexecve"); return 1;
}
