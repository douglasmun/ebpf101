/*
 * try-escalate.c — Chapter 29 test trigger.
 *
 * Models the move the shield denies: a process running as an unprivileged uid
 * that tries to become root. It must START privileged (only root may set an
 * arbitrary uid), drop to a given non-root uid, then attempt to climb back to
 * uid 0 — the transition the lsm/task_fix_setuid shield governs.
 *
 * Exit codes let the verify script assert precisely:
 *   0  — the setuid(0) SUCCEEDED (shield absent or not in scope)
 *   10 — the setuid(0) was DENIED with EPERM (the shield vetoed it)
 *   11 — the setuid(0) failed with some OTHER errno (not a clean shield deny)
 *   2  — setup failed (could not drop to the requested uid); test inconclusive
 *
 * It prints its own pid on the first line so the caller can match the shield's
 * logged DENY to this exact process.
 *
 * Usage: ./try-escalate <nonroot-uid>
 *        (run as root; the caller places it in the cgroup under test)
 */
#define _GNU_SOURCE          /* setresuid() is a GNU extension */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "usage: %s <nonroot-uid>\n", argv[0]);
        return 2;
    }
    uid_t target = (uid_t)strtoul(argv[1], NULL, 10);
    if (target == 0) {
        fprintf(stderr, "refusing a 0 drop-uid; pass a non-root uid\n");
        return 2;
    }

    printf("%d\n", (int)getpid());
    fflush(stdout);

    /* Drop real+effective+saved to the unprivileged uid. We must still be able
     * to attempt the climb back, so use setresuid: keeping the SAVED uid at 0
     * is what makes a return to root even possible — it mirrors a setuid-root
     * helper that dropped privilege and a bug that tries to regain it. */
    if (setresuid(target, target, 0) != 0) {
        fprintf(stderr, "setup: setresuid(%u,%u,0): %s\n",
                target, target, strerror(errno));
        return 2;
    }

    /* THE GOVERNED MOVE: climb the effective uid back to root. Allowed by the
     * kernel (saved uid is 0) unless an LSM — our shield — vetoes it. */
    errno = 0;
    if (setresuid(-1, 0, -1) == 0) {
        fprintf(stderr, "escalation SUCCEEDED: euid now %u\n", (unsigned)geteuid());
        return 0;
    }
    if (errno == EPERM) {
        fprintf(stderr, "escalation DENIED with EPERM (shield vetoed it)\n");
        return 10;
    }
    fprintf(stderr, "escalation failed with a non-EPERM errno: %s\n", strerror(errno));
    return 11;
}
