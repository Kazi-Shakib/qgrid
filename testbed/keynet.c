/* Key network: per-link key stores, the two end KMEs, and trusted-node relays.
 *
 * Every QKD link has a leader store (the end that allocates key) and a follower store; the BB84
 * stack of that link appends identical key to both. Topologies (C.topo):
 *   0  KME_A ── link0 ── KME_B                                    (direct)
 *   1  KME_A ── link0 ── T1 ── link1 ── KME_B                     (one trusted node)
 *   2  KME_A ── link0 ── T1 ── link1 ── KME_B  and  KME_A ── link2 ── T2 ── link3 ── KME_B
 * In topology 2, keys requested for slave SAE "G2" take the T2 path and all others the T1 path;
 * C.route2 = 0 sends both through T1 (two-gateway delivery over a single relay).
 *
 * A key K requested at KME_A is drawn from link0's store. Each hop carries a relay message
 * authenticated with a one-time Wegman-Carter tag drawn from that hop's key; on the first hop K is
 * referenced by its offset in the shared store, on later hops it is one-time-pad encrypted with
 * fresh key of that hop (hop-by-hop OTP relay, as in deployed trusted-node networks). A trusted
 * node therefore holds K in the clear while relaying; while compromised it records what it relays. */
#include "qg.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define KSZ (64u << 20)
struct KStore {
    uint8_t *buf; uint64_t produced, next;
    struct { uint64_t end; double t; } *blk; int nblk;
    pthread_mutex_t m; KStore *peer;
};
static KStore *LS[4], *RS[4];          /* leader / follower store of each link */
QLink *LINKS[4]; int NLINKS;
static uint64_t consumed, starved;
uint64_t qkd_consumed(void) { return consumed; }
uint64_t qkd_starved(void) { return starved; }

static KStore *ks_new(void) {
    KStore *s = calloc(1, sizeof *s); s->buf = malloc(KSZ); s->blk = malloc(65536 * sizeof *s->blk);
    pthread_mutex_init(&s->m, NULL); return s;
}
void ks_append(KStore *s, const uint8_t *k, uint32_t n, double t_end) {
    pthread_mutex_lock(&s->m);
    if (s->produced + n <= KSZ) {
        memcpy(s->buf + s->produced, k, n); s->produced += n;
        if (s->nblk < 65536) { s->blk[s->nblk].end = s->produced; s->blk[s->nblk].t = t_end; s->nblk++; }
    }
    pthread_mutex_unlock(&s->m);
}
int ks_pause(KStore *s) { return !C.simclock && s->produced - s->next > C.qkd_reserve; }
static void emu_produce(KStore *s, uint64_t n) {       /* emulator: identical random bytes at both ends */
    if (s->produced + n > KSZ) n = KSZ - s->produced;
    pthread_mutex_lock(&s->peer->m);
    rnd(s->buf + s->produced, n); memcpy(s->peer->buf + s->peer->produced, s->buf + s->produced, n);
    s->produced += n; s->peer->produced += n;
    pthread_mutex_unlock(&s->peer->m);
}
static uint64_t ks_avail(KStore *s) {                  /* caller holds s->m */
    if (C.qkd_mode != 2 || !C.simclock) return s->produced;
    uint64_t a = 0; for (int i = 0; i < s->nblk; i++) if (s->blk[i].t <= C.sim_now) a = s->blk[i].end; return a;
}
static int64_t ks_alloc(KStore *s, uint32_t len) {
    pthread_mutex_lock(&s->m);
    if (C.qkd_mode == 2 && !C.simclock)
        for (int w = 0; w < 120000 && s->next + len > s->produced; w++) { pthread_mutex_unlock(&s->m); usleep(1000); pthread_mutex_lock(&s->m); }
    if (C.qkd_mode != 2 && C.qkd_bps <= 0 && s->next + len > s->produced) emu_produce(s, s->next + len - s->produced + 65536);
    if (s->next + len > ks_avail(s)) { __atomic_add_fetch(&starved, 1, __ATOMIC_RELAXED); pthread_mutex_unlock(&s->m); return -1; }
    int64_t o = (int64_t)s->next; s->next += len; __atomic_add_fetch(&consumed, len, __ATOMIC_RELAXED);
    pthread_mutex_unlock(&s->m); return o;
}
static int ks_read(KStore *s, uint64_t off, uint32_t len, uint8_t *out) {   /* follower end: wait for the key */
    for (int w = 0; w < 120000; w++) {
        pthread_mutex_lock(&s->m);
        if (off + len <= s->produced) { memcpy(out, s->buf + off, len); pthread_mutex_unlock(&s->m); return 0; }
        pthread_mutex_unlock(&s->m); usleep(1000);
    }
    return -1;
}
static void *emu_thread(void *arg) {
    KStore *s = arg; double acc = 0, last = now_ms();
    for (;;) {
        usleep(10000); double t = now_ms();
        pthread_mutex_lock(&s->m);
        acc += C.qkd_bps / 8.0 * (t - last) / 1000.0; last = t;
        uint64_t n = (uint64_t)acc; acc -= n; emu_produce(s, n);
        pthread_mutex_unlock(&s->m);
    }
    return NULL;
}
double keynet_simtime(void) {
    if (C.qkd_mode != 2) return 1e30;
    double t = 1e30; for (int i = 0; i < NLINKS; i++) { double x = qlink_simtime(LINKS[i]); if (x < t) t = x; } return t;
}
uint64_t keynet_min_produced(void) {
    uint64_t m = ~0ULL; for (int i = 0; i < NLINKS; i++) if (LS[i]->produced < m) m = LS[i]->produced; return m;
}

/* ---------------- topology ---------------- */
typedef struct { int nl, link[2], tn; pthread_mutex_t m; int fd; } Path;
static Path PATHS[2]; static int NPATHS;
static int path_for(const char *slave) { return (NPATHS == 2 && C.route2 && !strcmp(slave, "G2")) ? 1 : 0; }

void qkd_start(void) {
    int nl = C.topo == 0 ? 1 : C.topo == 1 ? 2 : 4; NLINKS = nl;
    double L[4] = { C.L1, C.topo ? C.L2 : 0, C.L1, C.L2 };
    for (int i = 0; i < nl; i++) {
        LS[i] = ks_new(); RS[i] = ks_new(); LS[i]->peer = RS[i];
        if (C.qkd_mode == 2) LINKS[i] = qlink_start(i, L[i], C.base_port + 6 + i, LS[i], RS[i]);
        else if (C.qkd_bps > 0) { pthread_t t; pthread_create(&t, NULL, emu_thread, LS[i]); }
    }
    NPATHS = C.topo == 2 ? 2 : 1;
    PATHS[0] = (Path){ .nl = C.topo ? 2 : 1, .link = { 0, 1 }, .tn = C.topo ? 1 : 0 };
    PATHS[1] = (Path){ .nl = 2, .link = { 2, 3 }, .tn = 2 };
    for (int p = 0; p < 2; p++) pthread_mutex_init(&PATHS[p].m, NULL);
}

/* ---------------- trusted nodes ---------------- */
typedef struct { uint8_t kid[KIDLEN]; uint8_t *key; int len; } Leak;
static struct { int comp; Leak log[4096]; int n; pthread_mutex_t m; } TN[3] = {
    [0] = { .m = PTHREAD_MUTEX_INITIALIZER }, [1] = { .m = PTHREAD_MUTEX_INITIALIZER }, [2] = { .m = PTHREAD_MUTEX_INITIALIZER } };
void trusted_compromise(int t, int on) { if (t >= 1 && t <= 2) TN[t].comp = on; }
static void tn_log(int t, const uint8_t *kid, const uint8_t *k, int len) {
    pthread_mutex_lock(&TN[t].m);
    Leak *l = &TN[t].log[TN[t].n++ % 4096]; free(l->key);
    memcpy(l->kid, kid, KIDLEN); l->key = malloc(len); memcpy(l->key, k, len); l->len = len;
    pthread_mutex_unlock(&TN[t].m);
}
int trusted_dump(int t, const uint8_t kid[KIDLEN], uint8_t *key) {
    int r = -1;
    if (t < 1 || t > 2) return -1;
    pthread_mutex_lock(&TN[t].m);
    for (int i = 0; i < TN[t].n && i < 4096; i++) if (!memcmp(TN[t].log[i].kid, kid, KIDLEN)) {
        memcpy(key, TN[t].log[i].key, TN[t].log[i].len); r = TN[t].log[i].len; }
    pthread_mutex_unlock(&TN[t].m); return r;
}
int topo_trusted_node(int g) {         /* trusted node on the path a key for gateway g (or SAE) takes */
    char nm[16]; snprintf(nm, sizeof nm, "G%d", g + 1); return PATHS[path_for(nm)].tn;
}

/* ---------------- relay messages ---------------- */
typedef struct { uint8_t kid[KIDLEN]; uint64_t off, toff; uint32_t len; char slave[16], target[16]; uint8_t first; } Hdr;

/* KME_B key store */
typedef struct { uint8_t kid[KIDLEN]; char slave[16], target[16]; uint8_t *key; int len, valid; } Rec;
static Rec store[1 << 14]; static int nrec;
static pthread_mutex_t SM = PTHREAD_MUTEX_INITIALIZER;

/* send K over the hop that uses link l, leader end; ct = NULL on the first hop */
static int hop_send(int fd, int l, Hdr *h, const uint8_t *K) {
    int64_t off = h->first ? (int64_t)h->off : ks_alloc(LS[l], h->len), toff = off >= 0 ? ks_alloc(LS[l], 16) : -1;
    if (off < 0 || toff < 0) return -1;
    h->off = off; h->toff = toff;
    static __thread uint8_t buf[sizeof(Hdr) + 8 + MAXKEY]; uint8_t tk[16];
    memcpy(buf, h, sizeof *h); int ml = sizeof *h;
    if (!h->first) {
        uint8_t pad[MAXKEY]; ks_read(LS[l], off, h->len, pad);
        for (uint32_t i = 0; i < h->len; i++) buf[ml + i] = K[i] ^ pad[i];
        ml += h->len;
    }
    ks_read(LS[l], toff, 16, tk);
    uint64_t tag = wc_tag(tk, tk + 8, buf, ml); memmove(buf + sizeof *h + 8, buf + sizeof *h, ml - sizeof *h);
    memcpy(buf + sizeof *h, &tag, 8);
    msg_send(fd, buf, ml + 8); __atomic_add_fetch(&kme_link_bytes, ml + 12, __ATOMIC_RELAXED);
    uint8_t ok = 0; if (recv_all(fd, &ok, 1, -1)) return -1;
    return ok ? 0 : -1;
}
typedef struct { int p, j, lfd; } RcvArg;
static void *receiver(void *arg) {
    RcvArg a = *(RcvArg *)arg; free(arg);
    Path *P = &PATHS[a.p]; int l = P->link[a.j], last = (a.j == P->nl - 1);
    int down = last ? -1 : tcp_connect(C.base_port + 60 + a.p * 4 + a.j + 1);
    int fd = tcp_accept(a.lfd);
    static __thread uint8_t buf[sizeof(Hdr) + 8 + MAXKEY];
    for (;;) {
        int n = msg_recv(fd, buf, sizeof buf, -1); if (n < (int)sizeof(Hdr) + 8) break;
        Hdr h; memcpy(&h, buf, sizeof h); uint64_t tag; memcpy(&tag, buf + sizeof h, 8);
        uint8_t ok = 0, tk[16], K[MAXKEY], pad[MAXKEY];
        int ctl = h.first ? 0 : (int)h.len;
        if (h.len <= MAXKEY && n == (int)sizeof h + 8 + ctl && !ks_read(RS[l], h.toff, 16, tk)) {
            memmove(buf + sizeof h, buf + sizeof h + 8, ctl);
            if (wc_tag(tk, tk + 8, buf, sizeof h + ctl) == tag && !ks_read(RS[l], h.off, h.len, pad)) {
                for (uint32_t i = 0; i < h.len; i++) K[i] = h.first ? pad[i] : (uint8_t)(buf[sizeof h + i] ^ pad[i]);
                if (last) {
                    pthread_mutex_lock(&SM);
                    Rec *r = &store[nrec++ % (1 << 14)]; free(r->key);
                    memcpy(r->kid, h.kid, KIDLEN); memcpy(r->slave, h.slave, 16); memcpy(r->target, h.target, 16);
                    r->key = malloc(h.len); memcpy(r->key, K, h.len); r->len = h.len; r->valid = 1;
                    pthread_mutex_unlock(&SM); ok = 1;
                } else {                                     /* trusted node: decrypt, re-encrypt, forward */
                    if (TN[P->tn].comp) tn_log(P->tn, h.kid, K, h.len);
                    Hdr h2 = h; h2.first = 0;
                    ok = hop_send(down, P->link[a.j + 1], &h2, K) == 0;
                }
            }
        }
        send_all(fd, &ok, 1);
    }
    return NULL;
}

/* ---------------- ETSI GS QKD 014 front ends ---------------- */
static void json_str(const char *body, const char *key, char *out, int max) {
    out[0] = 0; char pat[64]; snprintf(pat, sizeof pat, "\"%s\":\"", key);
    const char *p = strstr(body, pat); if (!p) return; p += strlen(pat);
    int i = 0; while (*p && *p != '"' && i < max - 1) out[i++] = *p++; out[i] = 0;
}
static int json_int(const char *body, const char *key) {
    char pat[64]; snprintf(pat, sizeof pat, "\"%s\":", key);
    const char *p = strstr(body, pat); return p ? atoi(p + strlen(pat)) : -1;
}
typedef struct { SSL_CTX *ctx; int fd; } Conn;

static void *kmea_conn(void *arg) {
    Conn c = *(Conn *)arg; free(arg);
    SSL *s = tls_accept(c.ctx, c.fd); if (!s) return NULL;
    char cn[64]; tls_peer_cn(s, cn, sizeof cn);
    char path[256], body[4096];
    while (http_read_req(s, path, sizeof path, body, sizeof body) == 0) {
        char slave[32] = {0}, tgt[32] = {0};
        if (strcmp(cn, "M") || sscanf(path, "/api/v1/keys/%31[^/]/enc_keys", slave) != 1) {
            http_reply(s, 401, "{\"message\":\"unauthorized\"}"); continue;
        }
        int bits = json_int(body, "size"); if (bits <= 0) bits = 256;
        json_str(body, "target", tgt, sizeof tgt);
        uint32_t len = (uint32_t)(bits / 8);
        Path *P = &PATHS[path_for(slave)]; int l0 = P->link[0];
        int64_t off = ks_alloc(LS[l0], len);
        if (off < 0) { http_reply(s, 503, "{\"message\":\"insufficient key\"}"); continue; }
        Hdr h; memset(&h, 0, sizeof h); rnd(h.kid, KIDLEN); h.off = off; h.len = len; h.first = 1;
        snprintf(h.slave, 16, "%s", slave); snprintf(h.target, 16, "%s", tgt);
        uint8_t K[MAXKEY]; ks_read(LS[l0], off, len, K);
        pthread_mutex_lock(&P->m); int r = hop_send(P->fd, l0, &h, K); pthread_mutex_unlock(&P->m);
        if (r) { http_reply(s, 503, "{\"message\":\"relay failed\"}"); continue; }
        char kidh[2*KIDLEN+1], kb[MAXKEY*2], resp[MAXKEY*2+256];
        hexs(h.kid, KIDLEN, kidh); b64e(K, len, kb);
        snprintf(resp, sizeof resp, "{\"keys\":[{\"key_ID\":\"%s\",\"key\":\"%s\"}]}", kidh, kb);
        http_reply(s, 200, resp);
    }
    SSL_free(s); close(c.fd); return NULL;
}
static void *kmeb_conn(void *arg) {
    Conn c = *(Conn *)arg; free(arg);
    SSL *s = tls_accept(c.ctx, c.fd); if (!s) return NULL;
    char cn[64]; tls_peer_cn(s, cn, sizeof cn);
    char path[256], body[4096];
    while (http_read_req(s, path, sizeof path, body, sizeof body) == 0) {
        char kidh[64]; uint8_t kid[KIDLEN]; json_str(body, "key_ID", kidh, sizeof kidh);
        if (unhex(kidh, kid, KIDLEN)) { http_reply(s, 400, "{\"message\":\"bad key ID\"}"); continue; }
        uint8_t K[MAXKEY]; int len = -1, found = 0; char target[16] = "", ftarget[16] = "";
        pthread_mutex_lock(&SM);
        for (int i = 0; i < nrec && i < (1 << 14); i++)
            if (store[i].valid && !memcmp(store[i].kid, kid, KIDLEN)) {
                found = 1; memcpy(ftarget, store[i].target, 16);
                if (!strcmp(store[i].slave, cn)) {               /* ETSI 014: delete on delivery */
                    len = store[i].len; memcpy(K, store[i].key, len); memcpy(target, store[i].target, 16); store[i].valid = 0;
                }
                break;
            }
        pthread_mutex_unlock(&SM);
        if (strlen(cn) == 1)              /* an outstation acting as its own SAE: KME_B audits the release */
            audit_release(2, kid, cn[0], len >= 0 ? target : ftarget, len >= 0 ? REL_OK : found ? REL_REFUSED : REL_UNAVAILABLE);
        if (len < 0) { http_reply(s, 404, "{\"message\":\"key not available to this SAE\"}"); continue; }
        char kb[MAXKEY*2], resp[MAXKEY*2+256];
        b64e(K, len, kb);
        if (C.meta == META_AUTH)
            snprintf(resp, sizeof resp, "{\"keys\":[{\"key_ID\":\"%s\",\"key\":\"%s\",\"key_extension\":{\"target\":\"%s\"}}]}", kidh, kb, target);
        else
            snprintf(resp, sizeof resp, "{\"keys\":[{\"key_ID\":\"%s\",\"key\":\"%s\"}]}", kidh, kb);
        http_reply(s, 200, resp);
    }
    SSL_free(s); close(c.fd); return NULL;
}
typedef struct { int lfd; SSL_CTX *ctx; void *(*fn)(void *); } Srv;
static void *server(void *arg) {
    Srv v = *(Srv *)arg;
    for (;;) {
        int fd = tcp_accept(v.lfd); if (fd < 0) continue;
        Conn *c = malloc(sizeof *c); c->ctx = v.ctx; c->fd = fd;
        pthread_t t; pthread_create(&t, NULL, v.fn, c); pthread_detach(t);
    }
    return NULL;
}
void kme_start(void) {
    static Srv sa, sb; pthread_t t;
    for (int p = 0; p < NPATHS; p++)
        for (int j = 0; j < PATHS[p].nl; j++) {
            RcvArg *a = malloc(sizeof *a); a->p = p; a->j = j; a->lfd = tcp_listen(C.base_port + 60 + p * 4 + j);
            pthread_create(&t, NULL, receiver, a);
        }
    for (int p = 0; p < NPATHS; p++) PATHS[p].fd = tcp_connect(C.base_port + 60 + p * 4);
    sa = (Srv){ tcp_listen(C.base_port + 1), tls_server_ctx("KMEA"), kmea_conn };
    sb = (Srv){ tcp_listen(C.base_port + 3), tls_server_ctx("KMEB"), kmeb_conn };
    pthread_create(&t, NULL, server, &sa); pthread_create(&t, NULL, server, &sb);
}
