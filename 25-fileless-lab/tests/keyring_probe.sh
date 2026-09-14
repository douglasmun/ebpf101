#!/bin/bash
# Feasibility probe for keyring-staged fileless execution (add_key/keyctl).
#
# Measures whether the technique described in
# https://matheuzsecurity.github.io/hacking/linux-kernel-keyring-fileless-exec/
# is reproducible on this kernel, BEFORE any loader is written. Nothing here
# executes a payload: it establishes the staging primitive and its limits.
#
# Five questions, each answered by measurement:
#   Q0  does the container runtime even let add_key through? (seccomp)
#   Q1  is CONFIG_BIG_KEYS available (1 MB payloads) or only "user" keys?
#   Q2  what is the actual per-user quota, and does a static payload fit?
#   Q3  do add_key/keyctl work unprivileged on this arch?
#   Q4  does the payload survive the dropper's exit in the session keyring?
#   Q5  what does /proc/keys show, before and after KEYCTL_REVOKE?
cd /work

echo "=== environment ==="
uname -srm
echo "quota-maxbytes: $(cat /proc/sys/kernel/keys/maxbytes 2>/dev/null || echo UNREADABLE)"
echo "quota-maxkeys:  $(cat /proc/sys/kernel/keys/maxkeys 2>/dev/null || echo UNREADABLE)"
echo "root-maxbytes:  $(cat /proc/sys/kernel/keys/root_maxbytes 2>/dev/null || echo UNREADABLE)"
echo "uid:            $(id -u)"
echo

echo "=== Q1: is the big_key type present? (CONFIG_BIG_KEYS) ==="
if [ -r /proc/config.gz ]; then
    zcat /proc/config.gz | grep -E '^CONFIG_BIG_KEYS' || echo "CONFIG_BIG_KEYS not set"
else
    echo "/proc/config.gz unreadable on this kernel - probing by add_key instead"
fi
echo

cat > kr_probe.c <<'C'
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>

#define KEY_SPEC_SESSION_KEYRING (-3)
#define KEYCTL_READ   11
#define KEYCTL_REVOKE  3

static long add_key_(const char *type, const char *desc,
                     const void *p, size_t plen, int ring) {
    return syscall(SYS_add_key, type, desc, p, plen, ring);
}
static long keyctl_(int op, ...) {
    va_list a; va_start(a, op);
    long b = va_arg(a, long), c = va_arg(a, long);
    long d = va_arg(a, long), e = va_arg(a, long);
    va_end(a);
    return syscall(SYS_keyctl, op, b, c, d, e);
}

/* usage: kr_probe <type> <size>   -- stage <size> zero bytes, read back, revoke */
int main(int argc, char **argv) {
    const char *type = argc > 1 ? argv[1] : "user";
    size_t sz = argc > 2 ? strtoul(argv[2], NULL, 0) : 4096;

    char *buf = calloc(1, sz ? sz : 1);
    if (!buf) { perror("calloc"); return 1; }
    memset(buf, 'A', sz);

    long k = add_key_(type, "_dntry", buf, sz, KEY_SPEC_SESSION_KEYRING);
    if (k < 0) {
        printf("  add_key(type=%s, %zu bytes) FAILED: %s\n", type, sz, strerror(errno));
        return 1;
    }
    printf("  add_key(type=%s, %zu bytes) ok serial=%ld\n", type, sz, k);

    long need = keyctl_(KEYCTL_READ, k, (long)NULL, 0L, 0L);
    if (need < 0) {
        printf("  KEYCTL_READ(probe) FAILED: %s\n", strerror(errno));
        return 1;
    }
    printf("  KEYCTL_READ(probe) reports %ld bytes\n", need);

    char *out = malloc(need ? need : 1);
    long got = keyctl_(KEYCTL_READ, k, (long)out, need, 0L);
    if (got < 0) {
        printf("  KEYCTL_READ(copy) FAILED: %s\n", strerror(errno));
        return 1;
    }
    printf("  KEYCTL_READ(copy)  returned %ld bytes, content %s\n",
           got, (got == (long)sz && out[0] == 'A' && out[got-1] == 'A')
                ? "INTACT" : "MISMATCH");

    if (argc > 3 && !strcmp(argv[3], "keep")) {
        printf("  serial=%ld left in session keyring (no revoke)\n", k);
        return 0;
    }
    if (keyctl_(KEYCTL_REVOKE, k, 0L, 0L, 0L) < 0)
        printf("  KEYCTL_REVOKE FAILED: %s\n", strerror(errno));
    else
        printf("  KEYCTL_REVOKE ok\n");
    return 0;
}
C
sed -i '1a #include <stdarg.h>' kr_probe.c
gcc -O2 -Wall -o kr_probe kr_probe.c || { echo "PROBE BUILD FAILED"; exit 1; }

echo "=== Q0/Q3: does add_key/keyctl work, as root and as a normal uid? ==="
echo "  NOTE: Docker's DEFAULT seccomp profile blocks add_key (EPERM even as uid 0)."
echo "        run-tests.sh passes --security-opt seccomp=unconfined for this probe."
echo "  -- as uid $(id -u)"
./kr_probe user 4096 2>&1 | sed 's/^/    /'
if [ "$(id -u)" = 0 ] && id nobody >/dev/null 2>&1; then
    echo "  -- as uid $(id -u nobody) (nobody): does the technique need privilege?"
    cp kr_probe /tmp/kr_probe_u && chmod 755 /tmp/kr_probe_u
    setpriv --reuid=nobody --regid=nogroup --clear-groups /tmp/kr_probe_u user 4096 2>&1 | sed 's/^/    /'
fi
echo

echo "=== Q2: how large a payload fits? ==="
make -s hello 2>/dev/null
if [ -f hello ]; then
    hsz=$(stat -c '%s' hello)
    echo "  static ./hello is $hsz bytes"
else
    hsz=0
    echo "  ./hello not built - ladder only"
fi
cat > kr_bisect.c <<'C'
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>
static int try_(const char *type, size_t n) {
    char *b = malloc(n ? n : 1);
    if (!b) return -ENOMEM;
    memset(b, 'A', n);
    long k = syscall(SYS_add_key, type, "_b", b, n, -3);
    free(b);
    if (k < 0) return -errno;
    syscall(SYS_keyctl, 3, k, 0, 0, 0);   /* KEYCTL_REVOKE */
    return 0;
}
int main(int argc, char **argv) {
    const char *type = argc > 1 ? argv[1] : "user";
    size_t lo = 1, hi = 2u*1024*1024;
    if (try_(type, lo) != 0) {
        printf("  %s: even %zu byte fails: %s\n", type, lo, strerror(-try_(type, lo)));
        return 1;
    }
    while (lo + 1 < hi) { size_t m = lo + (hi - lo)/2; if (try_(type, m) == 0) lo = m; else hi = m; }
    printf("  %s: max payload = %zu bytes (at %zu: %s)\n",
           type, lo, hi, strerror(-try_(type, hi)));
    return 0;
}
C
gcc -O2 -Wall -o kr_bisect kr_bisect.c || echo "  bisect build failed"
./kr_bisect user
./kr_bisect big_key
if [ "$hsz" != 0 ]; then
    maxu=$(./kr_bisect user | sed -n 's/.*max payload = \([0-9]*\).*/\1/p')
    if [ -n "$maxu" ] && [ "$hsz" -gt "$maxu" ]; then
        echo "  VERDICT-Q2: static hello ($hsz B) EXCEEDS the user-key ceiling ($maxu B)."
        echo "              A keyring loader here needs big_key, a smaller/dynamic payload,"
        echo "              or the payload split across multiple keys."
    else
        echo "  VERDICT-Q2: static hello ($hsz B) fits within the user-key ceiling ($maxu B)."
    fi
fi
echo

echo "=== Q4: does the key survive the dropper's exit? (cross-process staging) ==="
# Stage in a child that exits, then read from a separate process. Both are
# children of this shell, so they share its session keyring.
./kr_probe user 4096 keep | tee kr_stage.out
serial=$(sed -n 's/.*serial=\([0-9]*\) left.*/\1/p' kr_stage.out)
if [ -n "$serial" ]; then
    echo "  dropper exited; reading serial=$serial from a new process"
    cat > kr_read.c <<'C'
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>
#define KEYCTL_READ 11
int main(int argc, char **argv) {
    long k = strtol(argv[1], NULL, 0);
    long need = syscall(SYS_keyctl, KEYCTL_READ, k, NULL, 0, 0);
    if (need < 0) { printf("  post-exit read FAILED: %s\n", strerror(errno)); return 1; }
    printf("  post-exit read ok: %ld bytes still in slab\n", need);
    return 0;
}
C
    gcc -O2 -o kr_read kr_read.c && ./kr_read "$serial"
else
    echo "  could not stage a surviving key - skipping"
fi
echo

echo "=== Q5: /proc/keys visibility, live then revoked ==="
echo "  bytes readable from /proc/keys: $(wc -c < /proc/keys 2>/dev/null || echo UNREADABLE)"
echo "  (an empty /proc/keys is a CONTAINER effect - the rows appear only with"
echo "   --privileged. Under default caps the file reads as 0 bytes even when a"
echo "   live key exists with a valid serial.)"
cat > kr_procview.c <<'C'
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>
static void dump(const char *tag) {
    FILE *f = fopen("/proc/keys", "r");
    if (!f) { printf("    %-8s /proc/keys unreadable\n", tag); return; }
    char l[512]; int seen = 0;
    while (fgets(l, sizeof l, f)) if (strstr(l, "_dntry")) { printf("    %-8s %s", tag, l); seen = 1; }
    if (!seen) printf("    %-8s (no _dntry row)\n", tag);
    fclose(f);
}
int main(void) {
    char b[64]; memset(b, 'A', sizeof b);
    long k = syscall(SYS_add_key, "user", "_dntry", b, sizeof b, -3);
    if (k < 0) { printf("    add_key failed\n"); return 1; }
    printf("    serial=%ld\n", k);
    dump("LIVE");
    syscall(SYS_keyctl, 3, k, 0, 0, 0);   /* KEYCTL_REVOKE */
    dump("REVOKED");
    return 0;
}
C
gcc -O2 -Wall -o kr_procview kr_procview.c && ./kr_procview
echo

echo "=== probe complete - no payload was executed ==="
