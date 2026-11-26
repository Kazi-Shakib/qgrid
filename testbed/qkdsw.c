/* Software implementation of decoy-state BB84 (one-decoy + vacuum, asymmetric bases) with
 * finite-key post-processing after Lim et al., Phys. Rev. A 89, 022307 (2014).
 *
 * Simulated:   the optical channel only (source intensities, fiber loss, detector efficiency,
 *              dark counts, misalignment), producing Alice's and Bob's raw records per pulse
 *              that was detected.  Alice's and Bob's records are handed to separate threads.
 * Implemented: everything after detection, run by an Alice thread and a Bob thread that talk
 *              only through a TCP connection whose every message carries a one-time
 *              Wegman-Carter tag (pre-shared key, replenished from generated key):
 *              sifting, decoy-state parameter estimation with finite-size bounds, Cascade
 *              error correction (4 passes, batched binary searches), verification with two
 *              polynomial hashes, privacy amplification with a random Toeplitz matrix
 *              (number-theoretic-transform multiplication), and key delivery to the KMEs. */
#include "qg.h"
#include <math.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

/* ---------------- parameters ---------------- */
QKDParams QP = {
    .L_km = 10, .f_rep = 100e6, .alpha_db = 0.2, .eta_det = 0.25, .pdc = 1e-6, .e_mis = 0.015,
    .mu = {0.5, 0.1, 2e-4}, .pmu = {0.7, 0.2, 0.1}, .pZ = 0.7, .nZ = 1 << 22,
    .eps_sec = 1e-10, .eps_cor = 1e-15, .max_blocks = 0,
    .eta_det1 = 0.22, .dead_ns = 50, .p_ap = 0.02, .realistic = 1
};

/* ---------------- RNG (simulation and protocol choices) ---------------- */
typedef struct { uint64_t s[4]; } Rng;
static inline uint64_t rotl(uint64_t x, int k) { return (x << k) | (x >> (64 - k)); }
static inline uint64_t rnext(Rng *r) {
    uint64_t *s = r->s, res = rotl(s[1] * 5, 7) * 9, t = s[1] << 17;
    s[2] ^= s[0]; s[3] ^= s[1]; s[1] ^= s[2]; s[0] ^= s[3]; s[2] ^= t; s[3] = rotl(s[3], 45); return res;
}
static void rseed(Rng *r, uint64_t seed) {           /* splitmix64 expansion */
    for (int i = 0; i < 4; i++) { seed += 0x9E3779B97F4A7C15ULL; uint64_t z = seed;
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL; z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL; r->s[i] = z ^ (z >> 31); }
}
static inline double runif(Rng *r) { return (rnext(r) >> 11) * (1.0 / 9007199254740992.0); }
static double rnorm(Rng *r) { double u = runif(r) + 1e-300, v = runif(r); return sqrt(-2 * log(u)) * cos(2 * M_PI * v); }
static uint64_t rpois(Rng *r, double m) {
    if (m > 500) { double x = m + sqrt(m) * rnorm(r) + 0.5; return x < 0 ? 0 : (uint64_t)x; }
    double L = exp(-m), p = 1; uint64_t k = 0; do { k++; p *= runif(r); } while (p > L); return k - 1;
}

/* ---------------- quantum channel (simulated optics) ---------------- */
typedef struct { uint64_t idx; uint8_t bit, basis, k; } ARec;   /* Alice: bit, basis (0=Z,1=X), intensity */
typedef struct { uint64_t idx; uint8_t bit, basis; } BRec;      /* Bob: what his detector recorded */
typedef struct { ARec *a; BRec *b; uint64_t n; double npulses; uint64_t nap; double kappa, eta_d; } RawBlock;

/* Detector model. With QP.realistic: the two detectors' efficiencies differ (eta_det, eta_det1) and
 * the stronger one is attenuated to the weaker (symmetrization, which keeps the security proof's
 * assumption of equal efficiencies); each detector has a non-paralyzable dead time, applied as a
 * count-rate correction; and each click causes an afterpulse with probability p_ap, recorded as an
 * extra detection in a later time slot whose bit is the earlier click's and so uncorrelated with
 * the transmitter's bit. */
static void simulate_block(Rng *r, RawBlock *rb, double L_km) {
    double eta_d = QP.realistic ? fmin(QP.eta_det, QP.eta_det1) : QP.eta_det;
    double eta = eta_d * pow(10, -QP.alpha_db * L_km / 10), D[3], E[3], pz = 0, rate = 0;
    for (int k = 0; k < 3; k++) {
        D[k] = 1 - (1 - QP.pdc) * (1 - QP.pdc) * exp(-eta * QP.mu[k]);
        rate += QP.pmu[k] * D[k];
    }
    double kappa = 1;
    if (QP.realistic) kappa = 1 / (1 + rate * QP.f_rep / 2 * QP.dead_ns * 1e-9);   /* per-detector dead time */
    for (int k = 0; k < 3; k++) {
        double sig = 1 - exp(-eta * QP.mu[k]);
        E[k] = (QP.pdc + QP.e_mis * sig) / D[k];                       /* dark clicks give a random bit */
        D[k] *= kappa;
        pz += QP.pZ * QP.pZ * QP.pmu[k] * D[k];
    }
    double N = QP.nZ / pz; rb->npulses = N;
    uint64_t cnt[3][2][2], tot = 0;
    for (int k = 0; k < 3; k++) for (int a = 0; a < 2; a++) for (int b = 0; b < 2; b++) {
        double pa = a ? 1 - QP.pZ : QP.pZ, pb = b ? 1 - QP.pZ : QP.pZ;
        cnt[k][a][b] = rpois(r, N * QP.pmu[k] * pa * pb * D[k]); tot += cnt[k][a][b];
    }
    uint64_t nap = QP.realistic ? rpois(r, tot * QP.p_ap) : 0;        /* afterpulses */
    rb->a = malloc((tot + nap) * sizeof(ARec)); rb->b = malloc((tot + nap) * sizeof(BRec));
    uint64_t i = 0;
    for (int k = 0; k < 3; k++) for (int a = 0; a < 2; a++) for (int b = 0; b < 2; b++)
        for (uint64_t c = 0; c < cnt[k][a][b]; c++, i++) {
            uint8_t bit = rnext(r) & 1, bb;
            if (a == b) bb = bit ^ (runif(r) < E[k]); else bb = rnext(r) & 1;
            rb->a[i] = (ARec){ 0, bit, (uint8_t)a, (uint8_t)k }; rb->b[i] = (BRec){ 0, bb, (uint8_t)b };
        }
    for (uint64_t j = 0; j < nap; j++, i++) {                             /* afterpulse in some later slot */
        double u = runif(r); int k = u < QP.pmu[0] ? 0 : u < QP.pmu[0] + QP.pmu[1] ? 1 : 2;
        uint8_t a = runif(r) >= QP.pZ, b = runif(r) >= QP.pZ;
        rb->a[i] = (ARec){ 0, (uint8_t)(rnext(r) & 1), a, (uint8_t)k };
        rb->b[i] = (BRec){ 0, rb->b[rnext(r) % (tot ? tot : 1)].bit, b };
    }
    tot += nap; rb->n = tot; rb->nap = nap; rb->kappa = kappa; rb->eta_d = eta_d;
    for (uint64_t j = tot - 1; j > 0; j--) {                           /* detections arrive in random order */
        uint64_t m = rnext(r) % (j + 1); ARec ta = rb->a[j]; rb->a[j] = rb->a[m]; rb->a[m] = ta;
        BRec tb = rb->b[j]; rb->b[j] = rb->b[m]; rb->b[m] = tb;
    }
    double t = 0, gap = N / tot;                                       /* pulse index of each detection */
    for (uint64_t j = 0; j < tot; j++) { t += -log(runif(r) + 1e-300) * gap; rb->a[j].idx = rb->b[j].idx = (uint64_t)t; }
}

/* ---------------- authenticated classical channel ---------------- */
#define AUTHPOOL (1 << 20)
typedef struct { int fd; uint8_t r[8]; uint8_t *pool; uint64_t pos, used; uint64_t bytes, msgs; } Chan;
static int ch_send(Chan *c, uint8_t type, const void *p, uint32_t n) {
    uint8_t h[5]; h[0] = type; memcpy(h + 1, &n, 4);
    uint8_t *buf = malloc(5 + (size_t)n); memcpy(buf, h, 5); if (n) memcpy(buf + 5, p, n);
    uint64_t tag = wc_tag(c->r, c->pool + (c->pos % AUTHPOOL), buf, 5 + (size_t)n); c->pos += 8; c->used += 8;
    int rc = send_all(c->fd, buf, 5 + (size_t)n) || send_all(c->fd, &tag, 8);
    c->bytes += 13 + n; c->msgs++; free(buf); return rc ? -1 : 0;
}
static uint8_t *ch_recv(Chan *c, uint8_t type, uint32_t *n) {
    uint8_t h[5]; if (recv_all(c->fd, h, 5, -1)) return NULL;
    memcpy(n, h + 1, 4); uint8_t *buf = malloc(5 + (size_t)*n + 1); memcpy(buf, h, 5);
    uint64_t tag; if (recv_all(c->fd, buf + 5, *n, -1) || recv_all(c->fd, &tag, 8, -1)) { free(buf); return NULL; }
    uint64_t want = wc_tag(c->r, c->pool + (c->pos % AUTHPOOL), buf, 5 + (size_t)*n); c->pos += 8; c->used += 8;
    c->bytes += 13 + *n; c->msgs++;
    if (tag != want || h[0] != type) { fprintf(stderr, "QKD: authentication failure on message %d\n", type); exit(2); }
    memmove(buf, buf + 5, *n); return buf;
}

/* ---------------- bit helpers ---------------- */
static void pack(const uint8_t *bits, uint64_t n, uint8_t *out) {
    memset(out, 0, (n + 7) / 8); for (uint64_t i = 0; i < n; i++) if (bits[i]) out[i >> 3] |= 1 << (i & 7);
}
static inline int getb(const uint8_t *p, uint64_t i) { return (p[i >> 3] >> (i & 7)) & 1; }
static double h2(double p) { if (p <= 0 || p >= 1) return 0; return -p * log2(p) - (1 - p) * log2(1 - p); }

/* ---------------- decoy-state finite-key bounds (Lim et al. 2014) ---------------- */
static double tau(int n) { double s = 0; for (int k = 0; k < 3; k++) s += QP.pmu[k] * exp(-QP.mu[k]) * pow(QP.mu[k], n) / (n ? 1 : 1); return s; }
static double pm(const double *c, double tot, int k, int sign) {
    double d = sqrt(tot / 2 * log(21 / QP.eps_sec));
    return exp(QP.mu[k]) / QP.pmu[k] * (c[k] + sign * d);
}
static double s0b(const double *c, double tot) {
    double m2 = QP.mu[1], m3 = QP.mu[2];
    double v = tau(0) * (m2 * pm(c, tot, 2, -1) - m3 * pm(c, tot, 1, +1)) / (m2 - m3); return v > 0 ? v : 0;
}
static double s1b(const double *c, double tot) {
    double m1 = QP.mu[0], m2 = QP.mu[1], m3 = QP.mu[2], s0 = s0b(c, tot);
    double num = pm(c, tot, 1, -1) - pm(c, tot, 2, +1) - (m2 * m2 - m3 * m3) / (m1 * m1) * (pm(c, tot, 0, +1) - s0 / tau(0));
    double v = tau(1) * m1 * num / (m1 * (m2 - m3) - m2 * m2 + m3 * m3); return v > 0 ? v : 0;
}
static double key_length(const double *nZk, const double *nXk, const double *mXk, double leak,
                         double *s0Z, double *s1Z, double *phi_out) {
    double nZ = nZk[0] + nZk[1] + nZk[2], nX = nXk[0] + nXk[1] + nXk[2], mX = mXk[0] + mXk[1] + mXk[2];
    *s0Z = s0b(nZk, nZ); *s1Z = s1b(nZk, nZ); double s1X = s1b(nXk, nX);
    if (*s1Z <= 0 || s1X <= 0) { *phi_out = 0.5; return -1; }
    double m2 = QP.mu[1], m3 = QP.mu[2];
    double v1X = tau(1) * (pm(mXk, mX, 1, +1) - pm(mXk, mX, 2, -1)) / (m2 - m3);
    double b = v1X / s1X; if (b < 1e-9) b = 1e-9; if (b > 0.5) b = 0.5;
    double c = *s1Z, d = s1X;
    double gam = sqrt((c + d) * (1 - b) * b / (c * d * log(2)) *
                      log2((c + d) / (c * d * (1 - b) * b) * 441.0 / (QP.eps_sec * QP.eps_sec)));
    double phi = b + gam; if (phi > 0.5) phi = 0.5; *phi_out = phi;
    return *s0Z + *s1Z * (1 - h2(phi)) - leak - 6 * log2(21 / QP.eps_sec) - log2(2 / QP.eps_cor);
}

/* ---------------- Cascade ---------------- */
typedef struct { uint32_t *perm, *inv; uint32_t k; uint32_t nb; uint8_t *apar; } Pass;
static void make_perm(Pass *P, uint32_t n, uint64_t seed, int identity) {
    P->perm = malloc(n * 4); P->inv = malloc(n * 4);
    for (uint32_t i = 0; i < n; i++) P->perm[i] = i;
    if (!identity) { Rng r; rseed(&r, seed); for (uint32_t i = n - 1; i > 0; i--) { uint32_t j = rnext(&r) % (i + 1), t = P->perm[i]; P->perm[i] = P->perm[j]; P->perm[j] = t; } }
    for (uint32_t i = 0; i < n; i++) P->inv[P->perm[i]] = i;
}
static int range_par(const uint8_t *key, const Pass *P, uint32_t s, uint32_t len) {
    int p = 0; for (uint32_t i = s; i < s + len; i++) p ^= key[P->perm[i]]; return p;
}
#define NPASS 4
typedef struct { uint8_t pass; uint32_t start, len; } __attribute__((packed)) Q;
enum { M_SIFT_B = 1, M_SIFT_A, M_XBITS, M_XERR, M_CPASS, M_CPAR, M_CQ, M_CANS, M_CDONE, M_VER, M_VACK, M_PA };

/* Alice answers parity queries until Bob signals completion */
static uint64_t cascade_alice(Chan *c, uint8_t *key, uint32_t n, double qest, int *rounds) {
    uint64_t leak = 0; uint32_t k1 = (uint32_t)fmax(8, ceil(0.73 / fmax(qest, 1e-3)));
    Pass P[NPASS];
    for (int p = 0; p < NPASS; p++) {
        uint64_t seed; rnd(&seed, 8);
        P[p].k = k1 << p; P[p].nb = (n + P[p].k - 1) / P[p].k; make_perm(&P[p], n, seed, p == 0);
        uint8_t *par = malloc(P[p].nb), *pk = malloc(P[p].nb / 8 + 9);
        for (uint32_t b = 0; b < P[p].nb; b++) { uint32_t s = b * P[p].k, l = s + P[p].k > n ? n - s : P[p].k; par[b] = range_par(key, &P[p], s, l); }
        pack(par, P[p].nb, pk + 8); memcpy(pk, &seed, 8);
        ch_send(c, M_CPASS, pk, 8 + (P[p].nb + 7) / 8); leak += P[p].nb; free(par); free(pk);
        for (;;) {                                         /* binary-search rounds for this pass */
            uint32_t ln; uint8_t *m = ch_recv(c, M_CQ, &ln); if (!m) exit(3);
            uint32_t nq = ln / sizeof(Q); if (!nq) { free(m); break; }
            Q *q = (Q *)m; uint8_t *ans = malloc(nq), *pa = malloc(nq / 8 + 1);
            for (uint32_t i = 0; i < nq; i++) ans[i] = range_par(key, &P[q[i].pass], q[i].start, q[i].len);
            pack(ans, nq, pa); ch_send(c, M_CANS, pa, (nq + 7) / 8); leak += nq; (*rounds)++;
            free(m); free(ans); free(pa);
        }
    }
    for (int p = 0; p < NPASS; p++) { free(P[p].perm); free(P[p].inv); }
    return leak;
}
static uint64_t cascade_bob(Chan *c, uint8_t *key, uint32_t n, double qest) {
    uint64_t leak = 0; uint32_t k1 = (uint32_t)fmax(8, ceil(0.73 / fmax(qest, 1e-3)));
    Pass P[NPASS];
    Q *act = malloc(sizeof(Q) * (n / 8 + 1024)); uint32_t nact;
    for (int p = 0; p < NPASS; p++) {
        uint32_t ln; uint8_t *m = ch_recv(c, M_CPASS, &ln); uint64_t seed; memcpy(&seed, m, 8);
        P[p].k = k1 << p; P[p].nb = (n + P[p].k - 1) / P[p].k; make_perm(&P[p], n, seed, p == 0);
        P[p].apar = malloc(P[p].nb); for (uint32_t b = 0; b < P[p].nb; b++) P[p].apar[b] = getb(m + 8, b);
        leak += P[p].nb; free(m);
        for (;;) {
            /* collect mismatched blocks of the lowest pass that has any (passes 0..p) */
            nact = 0; int sel = -1;
            for (int q = 0; q <= p && sel < 0; q++)
                for (uint32_t b = 0; b < P[q].nb; b++) {
                    uint32_t s = b * P[q].k, l = s + P[q].k > n ? n - s : P[q].k;
                    if (range_par(key, &P[q], s, l) != P[q].apar[b]) { act[nact++] = (Q){ (uint8_t)q, s, l }; sel = q; }
                }
            if (!nact) break;
            while (nact) {                                  /* batched binary search on disjoint blocks */
                Q *qs = malloc(sizeof(Q) * nact);
                for (uint32_t i = 0; i < nact; i++) qs[i] = (Q){ act[i].pass, act[i].start, act[i].len / 2 };
                ch_send(c, M_CQ, qs, nact * sizeof(Q));
                uint8_t *ans = ch_recv(c, M_CANS, &ln); leak += nact;
                uint32_t w = 0;
                for (uint32_t i = 0; i < nact; i++) {
                    Q a = act[i]; uint32_t h = a.len / 2;
                    int mine = range_par(key, &P[a.pass], a.start, h);
                    if (mine != getb(ans, i)) a.len = h; else { a.start += h; a.len -= h; }
                    if (a.len == 1) key[P[a.pass].perm[a.start]] ^= 1; else act[w++] = a;
                }
                nact = w; free(qs); free(ans);
            }
        }
        ch_send(c, M_CQ, NULL, 0);                          /* end of this pass */
    }
    for (int p = 0; p < NPASS; p++) { free(P[p].perm); free(P[p].inv); free(P[p].apar); }
    free(act); return leak;
}

/* ---------------- verification hash ---------------- */
static uint64_t poly_hash(const uint8_t *bits, uint32_t n, uint64_t r) {
    uint8_t *pk = malloc(n / 8 + 1); pack(bits, n, pk);
    uint8_t r8[8], z[8] = {0}; memcpy(r8, &r, 8);
    uint64_t t = wc_tag(r8, z, pk, (n + 7) / 8); free(pk); return t;
}

/* ---------------- privacy amplification: Toeplitz product by NTT ---------------- */
#define MODP 998244353u
static uint32_t pw(uint64_t b, uint64_t e) { uint64_t r = 1; b %= MODP; while (e) { if (e & 1) r = r * b % MODP; b = b * b % MODP; e >>= 1; } return (uint32_t)r; }
static void ntt(uint32_t *a, uint32_t n, int inv) {
    for (uint32_t i = 1, j = 0; i < n; i++) { uint32_t bit = n >> 1; for (; j & bit; bit >>= 1) j ^= bit; j ^= bit; if (i < j) { uint32_t t = a[i]; a[i] = a[j]; a[j] = t; } }
    for (uint32_t len = 2; len <= n; len <<= 1) {
        uint64_t w = pw(3, (MODP - 1) / len); if (inv) w = pw(w, MODP - 2);
        uint32_t half = len / 2; uint32_t *ws = malloc(half * 4); ws[0] = 1; for (uint32_t i = 1; i < half; i++) ws[i] = (uint64_t)ws[i - 1] * w % MODP;
        for (uint32_t i = 0; i < n; i += len)
            for (uint32_t j = 0; j < half; j++) {
                uint32_t u = a[i + j], v = (uint64_t)a[i + j + half] * ws[j] % MODP;
                a[i + j] = u + v >= MODP ? u + v - MODP : u + v; a[i + j + half] = u >= v ? u - v : u + MODP - v;
            }
        free(ws);
    }
    if (inv) { uint64_t ni = pw(n, MODP - 2); for (uint32_t i = 0; i < n; i++) a[i] = a[i] * ni % MODP; }
}
/* y_i = sum_j s[i - j + n - 1] x_j  (i < l), s has n + l - 1 bits: a random Toeplitz matrix */
static void toeplitz(const uint8_t *x, uint32_t n, const uint8_t *seedbits, uint32_t l, uint8_t *y) {
    uint32_t N = 1; while (N < n + l - 1) N <<= 1;
    uint32_t *A = calloc(N, 4), *B = calloc(N, 4);
    for (uint32_t t = 0; t < n + l - 1; t++) A[t] = getb(seedbits, t);
    for (uint32_t j = 0; j < n; j++) B[j] = x[j];
    ntt(A, N, 0); ntt(B, N, 0); for (uint32_t i = 0; i < N; i++) A[i] = (uint64_t)A[i] * B[i] % MODP; ntt(A, N, 1);
    for (uint32_t i = 0; i < l; i++) y[i] = A[(i + n - 1) % N] & 1;
    free(A); free(B);
}

/* ---------------- one QKD link: Alice thread, Bob thread, and their hand-off ---------------- */
struct QLink {
    int id, port; double L_km; KStore *L, *R;
    pthread_mutex_t m; pthread_cond_t c;
    BRec *q_b; uint64_t q_n; int q_full;
    uint8_t *judge_zA; uint32_t judge_nz;                         /* test-only: Alice's sifted key */
    uint8_t *pre; double simt; QKDStats st[256]; int nst;
};
#define QM (q->m)
#define QC (q->c)
#define q_b (q->q_b)
#define q_n (q->q_n)
#define q_full (q->q_full)
#define judge_zA (q->judge_zA)
#define judge_nz (q->judge_nz)
#define preshared (q->pre)
#define sim_time_total (q->simt)
#define QS (q->st)
#define nQS (q->nst)
static void stage(double *acc, double *t0) { double t = now_ms(); *acc += t - *t0; *t0 = t; }

static void *alice_thread(void *arg) {
    QLink *q = arg; Rng r; uint64_t sd; rnd(&sd, 8); rseed(&r, sd);
    int lfd = tcp_listen(q->port);
    Chan c = { .fd = tcp_accept(lfd), .pool = malloc(AUTHPOOL) }; memcpy(c.pool, preshared, AUTHPOOL); memcpy(c.r, preshared, 8); c.pos = 8;
    for (int blk = 0; !QP.max_blocks || blk < QP.max_blocks; blk++) {
        while (ks_pause(q->L)) usleep(20000);
        QKDStats st = { .blk = blk }; double t0 = now_ms(), tt = t0;
        RawBlock rb; simulate_block(&r, &rb, q->L_km); stage(&st.t_sim_ms, &tt);
        pthread_mutex_lock(&QM); while (q_full) pthread_cond_wait(&QC, &QM);
        q_b = rb.b; q_n = rb.n; q_full = 1; pthread_cond_broadcast(&QC); pthread_mutex_unlock(&QM);
        uint64_t m0 = c.msgs, b0 = c.bytes, a0 = c.used;
        /* sifting */
        uint32_t ln; uint8_t *m = ch_recv(&c, M_SIFT_B, &ln);
        uint64_t n = rb.n; uint8_t *bb = m + 8 + 4 * n;                 /* Bob's bases */
        uint8_t *ab = malloc(n / 8 + 1), *ak = malloc(n);
        uint8_t *tmp = malloc(n); for (uint64_t i = 0; i < n; i++) { tmp[i] = rb.a[i].basis; ak[i] = rb.a[i].k; }
        pack(tmp, n, ab); free(tmp);
        uint8_t *msg = malloc(n / 8 + 1 + n); memcpy(msg, ab, n / 8 + 1); memcpy(msg + n / 8 + 1, ak, n);
        ch_send(&c, M_SIFT_A, msg, n / 8 + 1 + n); free(msg);
        uint8_t *zA = malloc(n), *xA = malloc(n); uint32_t nz = 0, nx = 0; double nZk[3] = {0}, nXk[3] = {0};
        uint8_t *xk = malloc(n);
        for (uint64_t i = 0; i < n; i++) {
            int bob = getb(bb, i), al = rb.a[i].basis; if (al != bob) continue;
            if (al == 0) { zA[nz++] = rb.a[i].bit; nZk[rb.a[i].k]++; } else { xk[nx] = rb.a[i].k; xA[nx++] = rb.a[i].bit; nXk[rb.a[i].k]++; }
        }
        free(m); free(ab); free(ak); stage(&st.t_sift_ms, &tt);
        /* parameter estimation: disclose X-basis bits, receive error counts */
        uint8_t *px = malloc(nx / 8 + 1); pack(xA, nx, px); ch_send(&c, M_XBITS, px, (nx + 7) / 8); free(px);
        m = ch_recv(&c, M_XERR, &ln); double mXk[3]; for (int k = 0; k < 3; k++) { uint32_t v; memcpy(&v, m + 4 * k, 4); mXk[k] = v; } free(m);
        double qX = (mXk[0] + mXk[1] + mXk[2]) / fmax(1, nx);
        pthread_mutex_lock(&QM); judge_zA = malloc(nz); memcpy(judge_zA, zA, nz); judge_nz = nz; pthread_cond_broadcast(&QC); pthread_mutex_unlock(&QM);
        stage(&st.t_pe_ms, &tt);
        /* error correction */
        int rounds = 0; uint64_t leak = cascade_alice(&c, zA, nz, qX, &rounds); stage(&st.t_ec_ms, &tt);
        /* verification: two independent polynomial hashes */
        uint64_t hv[4]; rnd(&hv[0], 8); rnd(&hv[1], 8); hv[0] &= (1ULL << 61) - 1; hv[1] &= (1ULL << 61) - 1;
        hv[2] = poly_hash(zA, nz, hv[0]); hv[3] = poly_hash(zA, nz, hv[1]);
        ch_send(&c, M_VER, hv, 32); leak += 128;
        m = ch_recv(&c, M_VACK, &ln); int ok = m[0]; free(m); stage(&st.t_ver_ms, &tt);
        double s0Z, s1Z, phi; double lf = key_length(nZk, nXk, mXk, (double)leak, &s0Z, &s1Z, &phi);
        uint32_t l = (ok && lf > 0) ? (uint32_t)lf : 0;
        /* privacy amplification */
        uint8_t *seed = NULL, *fin = NULL;
        if (l) {
            uint32_t sb = nz + l - 1; seed = malloc(sb / 8 + 1); rnd(seed, sb / 8 + 1);
            uint8_t *pm_ = malloc(4 + sb / 8 + 1); memcpy(pm_, &l, 4); memcpy(pm_ + 4, seed, sb / 8 + 1);
            ch_send(&c, M_PA, pm_, 4 + sb / 8 + 1); free(pm_);
            fin = malloc(l); toeplitz(zA, nz, seed, l, fin);
        } else { uint32_t z0 = 0; ch_send(&c, M_PA, &z0, 4); }
        stage(&st.t_pa_ms, &tt);
        /* replenish the authentication pool from the new key, deliver the rest to KME_A */
        uint64_t auth_bits = (c.used - a0) * 8;
        uint32_t lb = l / 8, give = 0;
        uint8_t *kb = NULL; if (lb) { kb = malloc(lb); memset(kb, 0, lb); for (uint32_t i = 0; i < lb * 8; i++) if (fin[i]) kb[i >> 3] |= 1 << (i & 7); }
        uint32_t refill = (uint32_t)(c.used - a0); if (refill > lb) refill = lb;
        for (uint32_t i = 0; i < refill; i++) c.pool[(c.pos - (c.used - a0) + i) % AUTHPOOL] = kb[i];
        if (lb > refill) { give = lb - refill; }
        sim_time_total += rb.npulses / QP.f_rep;
        if (give) ks_append(q->L, kb + refill, give, sim_time_total);
        uint64_t ck = 1469598103934665603ULL; for (uint32_t i = 0; i < lb; i++) ck = (ck ^ kb[i]) * 1099511628211ULL;
        st.ck_a = ck;
        st.pulses = rb.npulses; st.detections = n; st.nz = nz; st.nx = nx; st.qx = qX;
        st.leak_ec = leak; st.l = l; st.net_bits = give * 8ULL; st.auth_bits = auth_bits; st.verified = ok;
        st.s0Z = s0Z; st.s1Z = s1Z; st.phi = phi; st.rounds = rounds; st.sim_s = rb.npulses / QP.f_rep;
        st.afterpulses = rb.nap; st.kappa = rb.kappa; st.eta_d = rb.eta_d; st.link = q->id; st.L_km = q->L_km;
        st.msgs = c.msgs - m0; st.cbytes = c.bytes - b0; st.t_total_ms = now_ms() - t0;
        pthread_mutex_lock(&QM); if (nQS < 256) QS[nQS] = st; nQS++; pthread_cond_broadcast(&QC); pthread_mutex_unlock(&QM);
        free(rb.a); free(zA); free(xA); free(xk); free(seed); free(fin); free(kb);
    }
    return NULL;
}

static void *bob_thread(void *arg) {
    QLink *q = arg;
    Chan c = { .fd = tcp_connect(q->port), .pool = malloc(AUTHPOOL) }; memcpy(c.pool, preshared, AUTHPOOL); memcpy(c.r, preshared, 8); c.pos = 8;
    double simt = 0;
    for (int blk = 0; !QP.max_blocks || blk < QP.max_blocks; blk++) {
        pthread_mutex_lock(&QM); while (!q_full) pthread_cond_wait(&QC, &QM);
        BRec *b = q_b; uint64_t n = q_n; q_full = 0; pthread_cond_broadcast(&QC); pthread_mutex_unlock(&QM);
        uint64_t a0 = c.used;
        /* announce detections (pulse indices) and measurement bases */
        uint8_t *msg = malloc(8 + 4 * n + n / 8 + 1); memcpy(msg, &n, 8);
        uint64_t prev = 0; for (uint64_t i = 0; i < n; i++) { uint32_t d = (uint32_t)(b[i].idx - prev); prev = b[i].idx; memcpy(msg + 8 + 4 * i, &d, 4); }
        uint8_t *tmp = malloc(n); for (uint64_t i = 0; i < n; i++) tmp[i] = b[i].basis; pack(tmp, n, msg + 8 + 4 * n); free(tmp);
        ch_send(&c, M_SIFT_B, msg, 8 + 4 * n + n / 8 + 1); free(msg);
        uint32_t ln; uint8_t *m = ch_recv(&c, M_SIFT_A, &ln); uint8_t *ab = m, *ak = m + n / 8 + 1;
        uint8_t *zB = malloc(n), *xB = malloc(n), *xk = malloc(n); uint32_t nz = 0, nx = 0;
        for (uint64_t i = 0; i < n; i++) {
            int al = getb(ab, i); if (al != b[i].basis) continue;
            if (al == 0) zB[nz++] = b[i].bit; else { xk[nx] = ak[i]; xB[nx++] = b[i].bit; }
        }
        free(m);
        m = ch_recv(&c, M_XBITS, &ln); uint32_t mX[3] = {0};
        for (uint32_t i = 0; i < nx; i++) if (getb(m, i) != xB[i]) mX[xk[i]]++;
        free(m); ch_send(&c, M_XERR, mX, 12);
        double qX = (double)(mX[0] + mX[1] + mX[2]) / (nx ? nx : 1);
        /* test-only ground truth: true QBER of the sifted key before correction */
        pthread_mutex_lock(&QM); while (!judge_zA) pthread_cond_wait(&QC, &QM);
        uint32_t errs = 0; for (uint32_t i = 0; i < nz && i < judge_nz; i++) errs += judge_zA[i] != zB[i];
        double qz = (double)errs / (nz ? nz : 1); pthread_mutex_unlock(&QM);
        cascade_bob(&c, zB, nz, qX);
        m = ch_recv(&c, M_VER, &ln); uint64_t hv[4]; memcpy(hv, m, 32); free(m);
        uint8_t ok = poly_hash(zB, nz, hv[0]) == hv[2] && poly_hash(zB, nz, hv[1]) == hv[3];
        ch_send(&c, M_VACK, &ok, 1);
        m = ch_recv(&c, M_PA, &ln); uint32_t l; memcpy(&l, m, 4);
        uint8_t *fin = NULL; if (l) { fin = malloc(l); toeplitz(zB, nz, m + 4, l, fin); }
        free(m);
        uint32_t lb = l / 8; uint8_t *kb = NULL; if (lb) { kb = calloc(lb, 1); for (uint32_t i = 0; i < lb * 8; i++) if (fin[i]) kb[i >> 3] |= 1 << (i & 7); }
        uint32_t refill = (uint32_t)(c.used - a0); if (refill > lb) refill = lb;
        for (uint32_t i = 0; i < refill; i++) c.pool[(c.pos - (c.used - a0) + i) % AUTHPOOL] = kb[i];
        pthread_mutex_lock(&QM);
        while (nQS <= blk) pthread_cond_wait(&QC, &QM);          /* Alice has published this block's time */
        simt += QS[blk < 256 ? blk : 255].sim_s;
        pthread_mutex_unlock(&QM);
        if (lb > refill) ks_append(q->R, kb + refill, lb - refill, simt);
        /* test-only: did both parties end with the same key? */
        uint64_t ck = 1469598103934665603ULL; for (uint32_t i = 0; i < lb; i++) ck = (ck ^ kb[i]) * 1099511628211ULL;
        pthread_mutex_lock(&QM);
        if (blk < 256) { QS[blk].qz = qz; QS[blk].final_equal = (QS[blk].ck_a == ck); }
        free(kb); free(judge_zA); judge_zA = NULL;
        pthread_mutex_unlock(&QM);
        free(b); free(zB); free(xB); free(xk); free(fin);
    }
    return NULL;
}

QLink *qlink_start(int id, double L_km, int port, KStore *L, KStore *R) {
    QLink *q = calloc(1, sizeof *q); q->id = id; q->L_km = L_km; q->port = port; q->L = L; q->R = R;
    pthread_mutex_init(&q->m, NULL); pthread_cond_init(&q->c, NULL);
    q->pre = malloc(AUTHPOOL); rnd(q->pre, AUTHPOOL);          /* initial authentication key, installed out of band */
    pthread_t t; pthread_create(&t, NULL, alice_thread, q); usleep(20000); pthread_create(&t, NULL, bob_thread, q);
    return q;
}
int qlink_nstats(QLink *q) { return q->nst; }
QKDStats *qlink_stat(QLink *q, int i) { return &q->st[i]; }

double qlink_simtime(QLink *q) { return q->simt; }
