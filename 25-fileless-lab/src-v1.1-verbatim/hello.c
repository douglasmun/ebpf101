/* hello.c — benign native ELF payload */
#include <unistd.h>
int main(void){ write(1, "hello from a fileless payload\n", 30); return 0; }