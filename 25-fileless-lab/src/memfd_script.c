/* memfd_script.c */
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

int main(void) {
    const char *script = "#!/bin/sh\necho 'hello from a memfd shebang script'\n";
    int mfd = memfd_create("script", 0);          /* inheritable: no MFD_CLOEXEC */
    if (mfd < 0) { perror("memfd_create"); return 1; }
    if (write(mfd, script, strlen(script)) < 0) { perror("write"); return 1; }
    char path[64]; snprintf(path, sizeof path, "/proc/self/fd/%d", mfd);
    execve(path, (char*[]){ "script", NULL }, environ);   /* kernel reads #! -> /bin/sh */
    perror("execve"); return 1;
}
