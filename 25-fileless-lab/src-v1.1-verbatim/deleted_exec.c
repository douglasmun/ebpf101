/* deleted_exec.c */
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s <elf>\n", argv[0]); return 2; }
    int fd = open(argv[1], O_RDONLY | O_CLOEXEC);
    if (fd < 0) { perror("open"); return 1; }
    unlink(argv[1]);                               /* name gone; inode alive via fd */
    fexecve(fd, (char*[]){ "payload", NULL }, environ);
    perror("fexecve"); return 1;
}