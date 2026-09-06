/* sleeper.c — stays alive so /proc/<pid> can be inspected */
#include <unistd.h>
int main(void){ pause(); return 0; }
