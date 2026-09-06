#!/bin/bash
cd /work
make -s hello || exit 1   # payload must exist; open() below is unchecked
cat > mfdflags.c <<'C'
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>
#ifndef MFD_EXEC
#define MFD_EXEC 0x0010U
#endif
#ifndef MFD_NOEXEC_SEAL
#define MFD_NOEXEC_SEAL 0x0008U
#endif
int main(int argc,char**argv){
    unsigned f = 0;
    if (argc>1 && !__builtin_strcmp(argv[1],"exec")) f=MFD_EXEC;
    if (argc>1 && !__builtin_strcmp(argv[1],"noexec")) f=MFD_NOEXEC_SEAL;
    int m=memfd_create("p",f);
    if(m<0){perror("memfd_create");return 1;}
    printf("  memfd_create(flags=0x%x) ok fd=%d\n",f,m);
    int in=open("./hello",O_RDONLY);
    if(in<0){perror("  open hello");return 1;}
    char b[65536]; ssize_t n;
    while((n=read(in,b,sizeof b))>0) write(m,b,n);
    char p[64]; snprintf(p,sizeof p,"/proc/self/fd/%d",m);
    execve(p,(char*[]){"payload",NULL},environ);
    perror("  execve"); return 1;
}
C
gcc -O2 -o mfdflags mfdflags.c || exit 1
for v in 0 1 2; do
  sysctl -w vm.memfd_noexec=$v >/dev/null 2>&1
  echo "=== vm.memfd_noexec=$(cat /proc/sys/vm/memfd_noexec) ==="
  for flag in none exec noexec; do
    echo "  -- MFD flag: $flag"; ./mfdflags $flag 2>&1 | sed 's/^/    /'
  done
done
