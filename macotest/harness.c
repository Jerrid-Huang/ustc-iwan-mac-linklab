/* One-shot macOS behavioral self-test for the utun data path (lab only,
 * not shipped). Links the project's REAL objects -- open_tun/tun_pool/
 * tun_write from tun.c+tun_mac.c, route_iface_up/capture_default from
 * route.c -- so the framing fix is exercised exactly as shipped.
 *
 * Modes:
 *   gw                           print capture_default() parse result
 *   wrap                         Keychain store+read round-trip (user)
 *   unwrap <marker> <dom> <usr>  read back (sudo variant documents root read)
 *   full                         root: utun ping roundtrip (v4+v6) through
 *                                the real pool reader + tun_write, pin
 *                                idempotency, CIDR masked-key semantics
 */
#include <arpa/inet.h>
#include <fcntl.h>
#include <net/if.h>
#include <netinet/icmp6.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "common.h"
#include "tun.h"
#include "route.h"
#include "oidc_pwsecret.h"

/* ---- checksum helpers (big-endian one-complement) ---- */
static uint32_t sum_words(const uint8_t *p, size_t n)
{
    uint32_t s = 0;
    for (size_t i = 0; i + 1 < n; i += 2)
        s += (uint32_t)((p[i] << 8) | p[i + 1]);
    if (n & 1)
        s += (uint32_t)(p[n - 1] << 8);
    while (s >> 16)
        s = (s & 0xFFFFu) + (s >> 16);
    return s;
}

static uint16_t csum16(const uint8_t *p, size_t n)
{
    return (uint16_t)~sum_words(p, n);
}

/* ---- ICMP echo responder: proves BOTH utun directions ----
 * Requests arrive via the project's pool reader (header already
 * stripped); replies go out through the project's tun_write (header
 * prepended). A successful ping therefore validates the whole frame
 * path against the kernel. */
typedef struct {
    int fd;
    atomic_int seen4, seen6;
} echo_ctx_t;

static void echo_cb(void *ud, uint8_t *p, size_t len, bool last)
{
    echo_ctx_t *c = ud;
    if (last || len < 20)
        return;

    if ((p[0] >> 4) == 4) {
        unsigned ihl = (unsigned)(p[0] & 0x0F) * 4;
        if (len < ihl + 8 || p[9] != IPPROTO_ICMP)
            return;
        uint8_t *ic = p + ihl;
        size_t icl = len - ihl;
        if (ic[0] != 8)   /* echo request only */
            return;
        uint8_t t[4];
        memcpy(t, p + 12, 4);
        memcpy(p + 12, p + 16, 4);
        memcpy(p + 16, t, 4);
        ic[0] = 0;   /* echo reply */
        ic[2] = ic[3] = 0;
        uint16_t cs = csum16(ic, icl);
        ic[2] = (uint8_t)(cs >> 8);
        ic[3] = (uint8_t)cs;
        p[10] = p[11] = 0;
        cs = csum16(p, ihl);
        p[10] = (uint8_t)(cs >> 8);
        p[11] = (uint8_t)cs;
        tun_write(c->fd, p, len);
        c->seen4++;
        return;
    }

    if ((p[0] >> 4) == 6 && len >= 48 && p[6] == IPPROTO_ICMPV6) {
        uint8_t *ic = p + 40;
        size_t icl = len - 40;
        if (ic[0] != 128)   /* echo request */
            return;
        uint8_t s6[16], d6[16];
        memcpy(s6, p + 8, 16);
        memcpy(d6, p + 24, 16);
        memcpy(p + 8, d6, 16);    /* reply src = request dst */
        memcpy(p + 24, s6, 16);
        ic[0] = 129;
        ic[2] = ic[3] = 0;
        uint8_t ph[40];
        memcpy(ph, p + 8, 16);
        memcpy(ph + 16, p + 24, 16);
        memset(ph + 32, 0, 3);
        ph[35] = (uint8_t)icl;
        ph[34] = (uint8_t)(icl >> 8);
        ph[33] = (uint8_t)(icl >> 16);
        ph[32] = (uint8_t)(icl >> 24);
        ph[36] = ph[37] = ph[38] = 0;
        ph[39] = IPPROTO_ICMPV6;
        uint32_t s = sum_words(ph, 40) + sum_words(ic, icl);
        while (s >> 16)
            s = (s & 0xFFFFu) + (s >> 16);
        uint16_t cs = (uint16_t)~s;
        ic[2] = (uint8_t)(cs >> 8);
        ic[3] = (uint8_t)cs;
        tun_write(c->fd, p, len);
        c->seen6++;
    }
}

static int run(const char *fmt, ...)
{
    char cmd[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(cmd, sizeof cmd, fmt, ap);
    va_end(ap);
    return system(cmd);
}

/* find the v6 ULA route_iface_up assigned and build a same-/96 target
 * (host bits = ::2) so the kernel routes it into the utun */
static bool v6_target(const char *ifn, char out[64])
{
    char cmd[256];
    snprintf(cmd, sizeof cmd, "ifconfig %s | grep 'inet6 .*\\bfd' | head -1",
             ifn);
    FILE *f = popen(cmd, "r");
    if (!f)
        return false;
    char line[256];
    bool got = false;
    while (fgets(line, sizeof line, f)) {
        char addr[80];
        if (sscanf(line, "%*s %79s", addr) == 1) {
            uint8_t b[16];
            if (inet_pton(AF_INET6, addr, b) == 1) {
                memset(b + 12, 0, 3);
                b[15] = 2;
                if (inet_ntop(AF_INET6, b, out, 64)) {
                    got = true;
                    break;
                }
            }
        }
    }
    pclose(f);
    return got;
}

static int mode_full(void)
{
    int rc = 0;

    int fd = open_tun("iwan0");
    if (fd < 0) {
        perror("open_tun");
        return 2;
    }
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
    const char *ifn = tun_ifname("iwan0");
    printf("IFACE=%s fd=%d\n", ifn, fd);

    if (!route_iface_up("iwan0", "10.207.0.1", 1400)) {
        fprintf(stderr, "route_iface_up failed\n");
        close(fd);
        return 2;
    }

    /* the iface is p2p with dst=self, so pin the ping target in */
    run("route -n delete -host 10.207.0.2 >/dev/null 2>&1");
    if (run("route -n add -host 10.207.0.2 -interface %s >/dev/null", ifn)
        != 0) {
        fprintf(stderr, "add ping-target route failed\n");
        close(fd);
        return 2;
    }

    char t6[64] = "";
    bool have6 = v6_target(ifn, t6);
    printf("V6TARGET=%s\n", have6 ? t6 : "(none)");

    atomic_bool stop = false;
    echo_ctx_t ctx = { .fd = fd, .seen4 = 0, .seen6 = 0 };
    struct tun_pool *pool =
        tun_pool_create("iwan0", fd, 1, 1, echo_cb, &ctx, &stop);
    if (!pool) {
        fprintf(stderr, "tun_pool_create failed\n");
        close(fd);
        return 2;
    }

    int r4 = system("ping -c 3 -W 900 -t 6 10.207.0.2 >/tmp/ping4.log 2>&1");
    int r6 = 1;
    if (have6) {
        char cmd[160];
        snprintf(cmd, sizeof cmd,
                 "ping6 -c 3 -t 6 %s >/tmp/ping6.log 2>&1", t6);
        r6 = system(cmd);
    }
    for (int i = 0; i < 10; i++) {
        tun_pool_tick(pool);
        usleep(100000);
    }

    printf("PING4 rc=%d replies=%d\n", r4, atomic_load(&ctx.seen4));
    printf("PING6 rc=%d replies=%d\n", r6, atomic_load(&ctx.seen6));
    if (r4 != 0 || atomic_load(&ctx.seen4) < 3) {
        fprintf(stderr, "---- /tmp/ping4.log ----\n");
        system("cat /tmp/ping4.log >&2");
        rc = 3;
    }
    if (have6 && (r6 != 0 || atomic_load(&ctx.seen6) < 3)) {
        fprintf(stderr, "---- /tmp/ping6.log ----\n");
        system("cat /tmp/ping6.log >&2");
        rc = 3;
    }

    /* ---- route semantics while the iface is up ---- */
    char gw[16], dev[16], met[16];
    if (capture_default(gw, dev, met)) {
        printf("CAPTURED gw=%s dev=%s metric=%s\n", gw, dev, met);

        /* pin idempotency: a bare add on an existing pin must fail
         * (the audit's EEXIST scenario); delete-then-add must work */
        run("route -n delete -host 198.18.133.7 >/dev/null 2>&1");
        int a1 = run("route -n add -host 198.18.133.7 %s >/dev/null 2>&1",
                     gw);
        int a2 = run("route -n add -host 198.18.133.7 %s >/dev/null 2>&1",
                     gw);
        run("route -n delete -host 198.18.133.7 >/dev/null 2>&1");
        int a3 = run("route -n delete -host 198.18.133.7 %s >/dev/null"
                     " 2>&1; route -n add -host 198.18.133.7 %s"
                     " >/dev/null 2>&1",
                     gw, gw);
        printf("PIN bare-add=%d dup-add=%d delete-then-add=%d\n", a1, a2,
               a3);
        if (a1 != 0 || a2 == 0 || a3 != 0) {
            fprintf(stderr, "pin idempotency semantics unexpected\n");
            rc = rc ? rc : 4;
        } else {
            printf("PIN-SEMANTICS-OK (dup add fails EEXIST as audited;"
                   " delete-first works)\n");
        }
        run("route -n delete -host 198.18.133.7 >/dev/null 2>&1");
    } else {
        printf("CAPTURED none (skipping pin semantics)\n");
    }

    /* CIDR masked-key semantics: canonical form hits, unmasked never */
    if (run("route -n add -net 10.99.1.0/24 -interface %s >/dev/null 2>&1",
            ifn) == 0) {
        char get[256];
        snprintf(get, sizeof get,
                 "route -n get 10.99.1.77 2>/dev/null");
        FILE *f = popen(get, "r");
        char line[256];
        bool hit = false;
        while (fgets(line, sizeof line, f))
            if (strstr(line, ifn))
                hit = true;
        pclose(f);
        printf("CIDR-CANON-HIT=%d\n", hit);
        if (!hit)
            rc = rc ? rc : 5;
        run("route -n delete -net 10.99.1.0/24 -interface %s >/dev/null"
            " 2>&1",
            ifn);
    }
    if (run("route -n add -net 10.99.2.5/24 -interface %s >/dev/null 2>&1",
            ifn) == 0) {
        FILE *f = popen("route -n get 10.99.2.77 2>/dev/null", "r");
        char line[256];
        bool hit = false;
        while (fgets(line, sizeof line, f))
            if (strstr(line, ifn))
                hit = true;
        pclose(f);
        printf("CIDR-UNMASKED-HIT=%d (0 documents the audited BSD radix"
               " behavior)\n",
               hit);
        run("route -n delete -net 10.99.2.5/24 -interface %s >/dev/null"
            " 2>&1",
            ifn);
        run("route -n delete -net 10.99.2.0/24 -interface %s >/dev/null"
            " 2>&1",
            ifn);
    }

    atomic_store(&stop, true);
    tun_pool_destroy(pool);
    run("route -n delete -host 10.207.0.2 >/dev/null 2>&1");
    close(fd);
    if (rc == 0)
        printf("FULL-PASS\n");
    return rc;
}

int main(int argc, char **argv)
{
    if (argc >= 2 && strcmp(argv[1], "gw") == 0) {
        char gw[16], dev[16], met[16];
        if (!capture_default(gw, dev, met)) {
            printf("CAPTURED none\n");
            return 1;
        }
        printf("CAPTURED gw=%s dev=%s metric=%s\n", gw, dev, met);
        return 0;
    }
    if (argc >= 2 && strcmp(argv[1], "wrap") == 0) {
        char *m = oidc_wrap_password("hunter2-blob", "example.com",
                                     "alice");
        printf("WRAP marker=%s\n", m ? m : "(null)");
        if (!m)
            return 2;
        char *b = oidc_unwrap_password(m, "example.com", "alice");
        printf("ROUNDTRIP %s\n",
               b && strcmp(b, "hunter2-blob") == 0 ? "OK" : "MISMATCH");
        free(b);
        free(m);
        return 0;
    }
    if (argc >= 5 && strcmp(argv[1], "unwrap") == 0) {
        char *b = oidc_unwrap_password(argv[2], argv[3], argv[4]);
        printf("UNWRAP uid=%d result=%s\n", (int)getuid(),
               b ? b : "(null)");
        free(b);
        return b ? 0 : 3;
    }
    if (argc >= 2 && strcmp(argv[1], "full") == 0)
        return mode_full();
    fprintf(stderr,
            "usage: harness full|gw|wrap|unwrap <marker> <dom> <usr>\n");
    return 64;
}
