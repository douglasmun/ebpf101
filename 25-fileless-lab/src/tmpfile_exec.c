/* tmpfile_exec.c */
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s <elf>\n", argv[0]); return 2; }
    int src = open(argv[1], O_RDONLY | O_CLOEXEC);
    if (src < 0) { perror("open src"); return 1; }
    int wfd = open("/tmp", O_TMPFILE | O_RDWR | O_EXCL, 0700);  /* unlinked, no name */
    if (wfd < 0) { perror("open O_TMPFILE"); return 1; }
    char buf[1 << 16]; ssize_t n;
    while ((n = read(src, buf, sizeof buf)) > 0)
        for (ssize_t o = 0, w; o < n; o += w)
            if ((w = write(wfd, buf + o, n - o)) < 0) return 1;
    close(src);

    char p[64]; snprintf(p, sizeof p, "/proc/self/fd/%d", wfd);
    int xfd = open(p, O_RDONLY | O_CLOEXEC);       /* reopen the same inode read-only */
    if (xfd < 0) { perror("reopen ro"); return 1; }
    close(wfd);                                    /* drop the writable fd (else ETXTBSY) */
    fexecve(xfd, (char*[]){ "payload", NULL }, environ);
    perror("fexecve"); return 1;
}
