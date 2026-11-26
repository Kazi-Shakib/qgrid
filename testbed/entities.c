/* Gateways, outstations, master, attacker-controlled WAN proxy (with WAN emulation), the feeder
 * model the outstations measure and control, and the ground-truth judge.
 *
 * All master-outstation traffic is IEEE 1815-2012 DNP3: link frames with CRCs, transport
 * segmentation, application headers, and the Secure Authentication v5 objects (group 120):
 *   v11/v12/v13/v15  Update Key Change Request / Reply / Change / Confirmation
 *   v4/v5/v6         Session Key Status Request / Status / Change
 *   v1/v2            Authentication Challenge / Reply (critical requests and responses)
 *   v7               Error
 * The one change for QKD is the payload of g120v13: instead of the update key encrypted under a
 * pre-shared or asymmetric key, it carries the ETSI 014 key ID(s) under which the outstation (or
 * its gateways) can fetch the QKD key (key change method 0x80, vendor specific). */
#include "qg.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <poll.h>
#include <math.h>

Cfg C; Atk ATK; Sess J;
pthread_mutex_t JM = PTHREAD_MUTEX_INITIALIZER;

#define ADDR_M 1
#define ADDR_O(i) (10 + (i))
#define ADDR_G(g) (100 + (g))
#define P_PROXY (C.base_port + 10)
#define P_OWAN(i) (C.base_port + 1000 + (i))
#define P_GWAN(g) (C.base_port + 40 + (g))
#define P_GDBG(g) (C.base_port + 50 + (g))
#define P_GLOC(g, i) (C.base_port + 2000 + (g) * 500 + (i))
#define ASDU 2048
#define KCM_QKD 0x80          /* key change method: vendor specific (QKD key reference) */
#define MACL 16               /* HMAC-SHA256 truncated to 16 bytes (MAL 4) */
#define V5H 43                /* g120v5 fields before the MAC */

static const char ONAMES[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~!*()+,;=:@$&";
static char oname(int i) { return ONAMES[i]; }

/* ======================= feeder model (IEEE 33-bus, pandapower) ======================= */
/* outstation i controls the breaker of lateral i%3 and reports the voltage at its far end */
static void headp_load(const char *dir);
static float VTEL[1440][3]; static float SHED[97][3]; static int grid_ok;
void grid_load(const char *dir) {
    char p[256]; snprintf(p, sizeof p, "%s/telemetry.csv", dir); FILE *f = fopen(p, "r"); if (!f) return;
    char line[256]; int m; float a, b, c; if (!fgets(line, sizeof line, f)) { fclose(f); return; }
    while (fgets(line, sizeof line, f)) if (sscanf(line, "%d,%f,%f,%f", &m, &a, &b, &c) == 4 && m >= 0 && m < 1440) {
        VTEL[m][0] = a; VTEL[m][1] = b; VTEL[m][2] = c; }
    fclose(f);
    snprintf(p, sizeof p, "%s/impact.csv", dir); f = fopen(p, "r"); if (!f) return;
    if (!fgets(line, sizeof line, f)) { fclose(f); return; }
    char o; float kw, vm;
    while (fgets(line, sizeof line, f)) if (sscanf(line, "%d,%c,%f,%f", &m, &o, &kw, &vm) == 4 && o >= 'A' && o <= 'C')
        SHED[(m / 15) % 97][o - 'A'] = kw;
    fclose(f); grid_ok = 1; headp_load(dir);
}
static int brkr[MAXO];                                   /* 1 = breaker closed */
int grid_breaker(int i) { return brkr[i]; }
static float v_now(int i) { return brkr[i] ? (grid_ok ? VTEL[C.minute % 1440][i % 3] : 12.0f) : 0.0f; }

/* ======================= judge ======================= */
static uint8_t known[64][MAXKEY]; static int knownl[64], nknown;
static struct { uint8_t st; float v; } tel_sent[256]; static int ntel_sent;
static uint8_t cmd_sent[256][11]; static int ncmd_sent;
void judge_reset(void) {
    pthread_mutex_lock(&JM);
    memset(&J, 0, sizeof J); nknown = 0; ntel_sent = 0; ncmd_sent = 0;
    for (int i = 0; i < MAXO; i++) brkr[i] = 1;         /* every trial starts with the feeder intact */
    pthread_mutex_unlock(&JM);
}
void judge_attacker_learns(const uint8_t *k, int len) {
    pthread_mutex_lock(&JM);
    if (nknown < 64) { memcpy(known[nknown], k, len); knownl[nknown++] = len; }
    pthread_mutex_unlock(&JM);
}
int judge_attacker_knows(const uint8_t *k, int len) {
    int r = 0; pthread_mutex_lock(&JM);
    for (int i = 0; i < nknown; i++) if (knownl[i] == len && !memcmp(known[i], k, len)) r = 1;
    pthread_mutex_unlock(&JM); return r;
}
static void judge_master_key(const uint8_t *k, int len) {
    pthread_mutex_lock(&JM); memcpy(J.K_master, k, len); J.klen = len; pthread_mutex_unlock(&JM);
}
static void judge_out_accept(int idx, const uint8_t *k, int len) {
    int att = judge_attacker_knows(k, len);
    pthread_mutex_lock(&JM);
    int same = (J.klen == len && !memcmp(J.K_master, k, len));
    if (idx == ATK.victim) { if (same) J.o_accept = 1; if (att) J.a_accepted_attacker_key = 1; }
    else if (same) J.o_accept_other = 1;
    pthread_mutex_unlock(&JM);
}
static void judge_tel_sent(int idx, uint8_t st, float v) {
    pthread_mutex_lock(&JM);
    if (idx == ATK.victim && ntel_sent < 256) { tel_sent[ntel_sent].st = st; tel_sent[ntel_sent++].v = v; }
    pthread_mutex_unlock(&JM);
}
static void judge_tel_accept(int idx, uint8_t st, float v) {
    pthread_mutex_lock(&JM);
    if (idx == ATK.victim) {
        int ok = 0; for (int i = 0; i < ntel_sent; i++) if (tel_sent[i].st == st && tel_sent[i].v == v) ok = 1;
        if (ok) J.tel_ok = 1; else J.tel_forged = 1;
        J.tel_st = st + 1;
    }
    pthread_mutex_unlock(&JM);
}
static void judge_cmd_sent(const uint8_t *crob) { pthread_mutex_lock(&JM); if (ncmd_sent < 256) memcpy(cmd_sent[ncmd_sent++], crob, 11); pthread_mutex_unlock(&JM); }
static void judge_cmd_exec(int idx, const uint8_t *crob) {   /* outstation operates its breaker */
    pthread_mutex_lock(&JM);
    int genuine = 0; for (int i = 0; i < ncmd_sent; i++) if (!memcmp(cmd_sent[i], crob, 11)) genuine = 1;
    int code = crob[0];
    if (code == 0x81 && brkr[idx]) { brkr[idx] = 0; if (!genuine) J.shed_kw += grid_ok ? SHED[(C.minute / 15) % 97][idx % 3] : 0; }
    if (code == 0x41) brkr[idx] = 1;
    if (idx == ATK.victim) { if (genuine) J.cmd_ok = 1; else J.cmd_forged = 1; }
    pthread_mutex_unlock(&JM);
}


/* ======================= Secure Authentication helpers ======================= */
typedef struct {               /* per-association key state */
    uint8_t K[MAXKEY]; int klen;
    uint8_t sk_ctrl[32], sk_mon[32]; int have_sk;
    int tel_i, cmd_i;
} Keys;
static int key_len(void) { return C.its ? 24 + 8 * C.msgs_per_epoch : 32; }
static int p16(uint8_t *p, uint16_t v) { memcpy(p, &v, 2); return 2; }
static int p32(uint8_t *p, uint32_t v) { memcpy(p, &v, 4); return 4; }
static uint32_t g32(const uint8_t *p) { uint32_t v; memcpy(&v, p, 4); return v; }
static uint16_t g16(const uint8_t *p) { uint16_t v; memcpy(&v, p, 2); return v; }
static uint8_t *G120(uint8_t *a, int n, int v, int *len) { return (uint8_t *)find_obj(a, n, 120, v, len); }
static int is(uint8_t *a, int n, int fc, int g, int v) { return n >= 2 && a[1] == fc && find_obj(a, n, g, v, NULL); }

/* update-key confirmation input (SAv5 g120v15): user, both challenges, KSQ (+ outstation name) */
static void conf_input(uint8_t *m, int *ml, const char *label, const uint8_t *c1, const uint8_t *c2, uint32_t ksq, uint16_t user, char name) {
    int n = 0; memcpy(m + n, label, strlen(label)); n += (int)strlen(label);
    memcpy(m + n, c1, CHAL); n += CHAL; memcpy(m + n, c2, CHAL); n += CHAL;
    memcpy(m + n, &ksq, 4); n += 4; memcpy(m + n, &user, 2); n += 2;
    if (C.oid) m[n++] = (uint8_t)name;
    *ml = n;
}
static int conf_mac(const Keys *k, int who, const uint8_t *m, int ml, uint8_t *out) {
    if (!C.its) { hmac256(k->K, 32, m, ml, out); return 32; }
    uint64_t t = wc_tag(k->K, k->K + 8 + 8 * who, m, ml); memcpy(out, &t, 8); return 8;
}
/* MAC of a challenge-reply: HMAC under the session key, or a one-time WC tag from the update key */
static int msg_mac(Keys *k, int cmd, const uint8_t *m, int ml, uint8_t *out, int slot) {
    if (!C.its) { uint8_t f[32]; hmac256(cmd ? k->sk_ctrl : k->sk_mon, 32, m, ml, f); memcpy(out, f, MACL); return MACL; }
    int half = C.msgs_per_epoch / 2, s = cmd ? half + slot : slot;
    if (slot >= half) return -1;
    uint64_t t = wc_tag(k->K, k->K + 24 + 8 * s, m, ml); memcpy(out, &t, 8); return 8;
}
static int chal_input(uint8_t *m, const uint8_t *v1, int v1l, const uint8_t *asdu, int al) {
    memcpy(m, v1, v1l); memcpy(m + v1l, asdu, al); return v1l + al;
}
/* ASDU builders */
static int b_v1(uint8_t *a, int fc, uint32_t csq, uint8_t reason, uint8_t *chal, uint8_t *v1out) {
    uint8_t d[64]; int n = 0; n += p32(d, csq); n += p16(d + n, 1); d[n++] = 4; d[n++] = reason;
    rnd(chal, CHAL); memcpy(d + n, chal, CHAL); n += CHAL; if (v1out) memcpy(v1out, d, n);
    int l = fc == FC_AUTH_REQ ? app_req(a, fc) : app_rsp(a, fc, 0); return l + obj_g120(a + l, 1, d, n);
}
static int b_v2(uint8_t *a, int fc, uint32_t csq, const uint8_t *mac, int ml) {
    uint8_t d[64]; int n = p32(d, csq); n += p16(d + n, 1); memcpy(d + n, mac, ml); n += ml;
    int l = fc == FC_AUTH_REQ ? app_req(a, fc) : app_rsp(a, fc, 0); return l + obj_g120(a + l, 2, d, n);
}
static int b_tel(uint8_t *a, int st, float v) {
    int l = app_rsp(a, FC_RESPONSE, 0); l += obj_binary(a + l, 0, st); l += obj_analog_f(a + l, 0, v); return l;
}
static void tel_parse(uint8_t *a, int n, uint8_t *st, float *v) {
    const uint8_t *b = find_obj(a, n, 1, 2, NULL), *f = find_obj(a, n, 30, 5, NULL);
    *st = b ? (b[0] >> 7) & 1 : 0; *v = 0; if (f) memcpy(v, f + 1, 4);
}
static int b_do(uint8_t *a, uint8_t code, uint32_t nonce) {
    int l = app_req(a, FC_DIRECT_OPERATE); int c = l; l += obj_crob(a + l, 0, code, 0);
    memcpy(a + c + 7, &nonce, 4); return l;       /* on-time field carries a per-command value */
}
/* key status (g120v5) header: KSQ, USR, KWA=2 (AES-256 key wrap), KST, MAL=4, challenge */
static int v5_head(uint8_t *d, uint32_t ksq, uint8_t kst, uint8_t *chal) {
    int n = p32(d, ksq); n += p16(d + n, 1); d[n++] = 2; d[n++] = kst; d[n++] = 4; n += p16(d + n, CHAL);
    memcpy(d + n, chal, CHAL); return n + CHAL;
}

/* ======================= gateways ======================= */
typedef struct { uint8_t kid[KIDLEN]; uint8_t key[MAXKEY]; int len; char target[16]; int used; } GEnt;
typedef struct {
    int g; SSL *kme; pthread_mutex_t m; GEnt e[512]; int ne;
    struct { uint8_t kid[KIDLEN]; char target[16]; } ann[512]; int nann;
    int compromised;
} GW;
static GW GWS[2];
static int gw_comp_seen[2];

static int b64key_from_json(const char *resp, uint8_t *key, char *target) {
    char kb[MAXKEY * 2]; const char *p = strstr(resp, "\"key\":\""); if (!p) return -1;
    p += 7; int i = 0; while (*p && *p != '"') kb[i++] = *p++; kb[i] = 0;
    target[0] = 0; const char *t = strstr(resp, "\"target\":\"");
    if (t) { t += 10; int j = 0; while (*t && *t != '"' && j < 15) target[j++] = *t++; target[j] = 0; }
    return b64d(kb, key);
}
static GEnt *gw_fetch(GW *w, const uint8_t kid[KIDLEN]) {     /* caller holds w->m */
    for (int i = 0; i < w->ne; i++) if (w->e[i].used && !memcmp(w->e[i].kid, kid, KIDLEN)) return &w->e[i];
    char kh[2*KIDLEN+1], body[128], resp[MAXKEY*2+512]; hexs(kid, KIDLEN, kh);
    snprintf(body, sizeof body, "{\"key_IDs\":[{\"key_ID\":\"%s\"}]}", kh);
    if (http_post(w->kme, "/api/v1/keys/M/dec_keys", body, resp, sizeof resp) != 200) return NULL;
    GEnt *e = NULL; for (int i = 0; i < 512; i++) if (!w->e[i].used) { e = &w->e[i]; if (i >= w->ne) w->ne = i + 1; break; }
    if (!e) return NULL;
    memcpy(e->kid, kid, KIDLEN); e->len = b64key_from_json(resp, e->key, e->target); e->used = 1;
    return e;
}
static const char *gw_target(GW *w, GEnt *e) {
    if (C.meta == META_AUTH) return e->target;
    if (C.meta == META_INBAND)
        for (int i = w->nann - 1; i >= 0; i--) if (!memcmp(w->ann[i].kid, e->kid, KIDLEN)) return w->ann[i].target;
    return "";
}
typedef struct { GW *w; int i; int lfd; } GLoc;
static void *gw_local(void *arg) {           /* one wired port per outstation */
    GLoc L = *(GLoc *)arg; free(arg);
    int fd = tcp_accept(L.lfd); GW *w = L.w; char me[2] = { oname(L.i), 0 };
    uint8_t req[64], out[MAXKEY + 8];
    for (;;) {
        int n = msg_recv(fd, req, sizeof req, -1); if (n != 1 + KIDLEN) break;
        __atomic_add_fetch(&local_bytes, n + 4, __ATOMIC_RELAXED);
        int len = 0; uint8_t st = 0; char tgt[16] = ""; int status = REL_UNAVAILABLE;
        pthread_mutex_lock(&w->m);
        GEnt *e = gw_fetch(w, req + 1);
        if (e) {
            const char *t = gw_target(w, e); snprintf(tgt, sizeof tgt, "%s", t);
            status = REL_REFUSED;
            if (!C.bind || !strcmp(t, me)) {
                st = 1; len = e->len; memcpy(out + 5, e->key, len); status = REL_OK;
                if (C.erase) memset(e, 0, sizeof *e);
            }
        }
        pthread_mutex_unlock(&w->m);
        audit_release(w->g, req + 1, me[0], tgt, status);
        out[0] = st; memcpy(out + 1, &len, 4);
        msg_send(fd, out, 5 + len); __atomic_add_fetch(&local_bytes, 9 + len, __ATOMIC_RELAXED);
    }
    return NULL;
}
/* in-band recipient announcement: FC 0x21 with a vendor g120 object (key ID, target name) */
static void *gw_wan(void *arg) {
    GW *w = arg; int lfd = tcp_listen(P_GWAN(w->g)), fd = tcp_accept(lfd);
    uint8_t a[ASDU]; uint16_t d, s;
    for (;;) {
        int n = dnp3_recv(fd, &d, &s, a, sizeof a, -1); if (n < 0) break;
        int dl; uint8_t *p = G120(a, n, 99, &dl);
        if (a[1] == FC_AUTH_REQ_NOACK && p && dl >= KIDLEN + 1) {
            pthread_mutex_lock(&w->m);
            int k = w->nann++ % 512; memcpy(w->ann[k].kid, p, KIDLEN);
            w->ann[k].target[0] = (char)p[KIDLEN]; w->ann[k].target[1] = 0;
            pthread_mutex_unlock(&w->m);
        }
    }
    return NULL;
}
static void *gw_debug(void *arg) {           /* what an attacker controlling the gateway can do */
    GW *w = arg; int lfd = tcp_listen(P_GDBG(w->g));
    for (;;) {
        int fd = tcp_accept(lfd); uint8_t req[64]; static uint8_t out[512 * (KIDLEN + 4 + MAXKEY)];
        for (;;) {
            int n = msg_recv(fd, req, sizeof req, -1); if (n < 1) break;
            pthread_mutex_lock(&w->m);
            int ol = 0, extra = 0;
            if (!w->compromised) { out[0] = 0; ol = 1; }
            else if (req[0] == 1) {
                int cnt = 0; ol = 2;
                for (int i = 0; i < w->ne; i++) if (w->e[i].used) {
                    memcpy(out + ol, w->e[i].kid, KIDLEN); memcpy(out + ol + KIDLEN, &w->e[i].len, 4);
                    memcpy(out + ol + KIDLEN + 4, w->e[i].key, w->e[i].len); ol += KIDLEN + 4 + w->e[i].len; cnt++;
                }
                out[0] = 1; out[1] = (uint8_t)(cnt & 0xFF); out[ol] = (uint8_t)(cnt >> 8); extra = 1;
            } else if (req[0] == 2) { out[0] = gw_fetch(w, req + 1) ? 1 : 0; ol = 1; }
            pthread_mutex_unlock(&w->m);
            msg_send(fd, out, ol + extra);
        }
        close(fd);
    }
    return NULL;
}
void gateways_start(void) {
    if (C.sae) return;
    for (int g = 0; g < C.npath; g++) {
        GW *w = &GWS[g]; memset(w, 0, sizeof *w); w->g = g; pthread_mutex_init(&w->m, NULL);
        char nm[8]; snprintf(nm, sizeof nm, "G%d", g + 1);
        w->kme = tls_connect(tls_client_ctx(nm), tcp_connect(C.base_port + 3));
        pthread_t t;
        for (int i = 0; i < C.nout; i++) {
            GLoc *L = malloc(sizeof *L); L->w = w; L->i = i; L->lfd = tcp_listen(P_GLOC(g, i));
            pthread_create(&t, NULL, gw_local, L);
        }
        pthread_create(&t, NULL, gw_wan, w); pthread_create(&t, NULL, gw_debug, w);
    }
}
int gw_compromise(int g, int on) { pthread_mutex_lock(&GWS[g].m); GWS[g].compromised = on; pthread_mutex_unlock(&GWS[g].m); if (on) gw_comp_seen[g] = 1; return 0; }
static int dbg_fd[2] = { -1, -1 };
static int dbg(int g) { if (dbg_fd[g] < 0) dbg_fd[g] = tcp_connect(P_GDBG(g)); return dbg_fd[g]; }
int gw_prefetch(int g, const uint8_t kid[KIDLEN]) {
    uint8_t r[1 + KIDLEN]; r[0] = 2; memcpy(r + 1, kid, KIDLEN); msg_send(dbg(g), r, sizeof r);
    uint8_t o[4]; return msg_recv(dbg(g), o, sizeof o, 2000) >= 1 && o[0] == 1;
}
int gw_dump(int g, uint8_t kids[][KIDLEN], uint8_t keys[][MAXKEY], int *lens, int max) {
    uint8_t r = 1; msg_send(dbg(g), &r, 1);
    static uint8_t o[512 * (KIDLEN + 4 + MAXKEY)];
    int n = msg_recv(dbg(g), o, sizeof o, 2000); if (n < 3 || o[0] != 1) return 0;
    int cnt = o[1] | o[n - 1] << 8, p = 2, k = 0;
    for (int i = 0; i < cnt && k < max; i++, k++) {
        memcpy(kids[k], o + p, KIDLEN); memcpy(&lens[k], o + p + KIDLEN, 4);
        memcpy(keys[k], o + p + KIDLEN + 4, lens[k]); p += KIDLEN + 4 + lens[k];
    }
    return k;
}

/* ======================= operator-side monitoring ======================= */
/* D1 release audit and D2 delivery receipts are reported by gateways (and by KME_B for outstation
 * SAEs) over an audit channel the WAN attacker does not control. A gateway under attacker control
 * reports nothing (D1) and forges receipts consistent with honest delivery (D2). D3 compares the
 * substation feeder-head meter with the power implied by the outstation states the master accepted. */
typedef struct { uint8_t kid[KIDLEN]; int idx, src, receipted; } Intent;
static Intent INT[256]; static int nint;
static float HP[1440][8]; static int hp_ok;
double METER_SD = 0.005;
unsigned meter_seed = 99;
static int oidx(char c) { const char *p = strchr(ONAMES, c); return p ? (int)(p - ONAMES) : -1; }
void mon_trial_reset(void) { pthread_mutex_lock(&JM); nint = 0; gw_comp_seen[0] = gw_comp_seen[1] = 0; pthread_mutex_unlock(&JM); }
static void mon_intend(const uint8_t *kid, int idx, int src) {
    pthread_mutex_lock(&JM);
    if (nint < 256) { memcpy(INT[nint].kid, kid, KIDLEN); INT[nint].idx = idx; INT[nint].src = src; INT[nint].receipted = 0; nint++; }
    pthread_mutex_unlock(&JM);
}
static void alarm_(int det) {      /* caller holds JM */
    double t = now_ms() - J.t0;
    if (det == 1) { if (!J.d1) J.d1_ms = t; J.d1++; } else { if (!J.d2) J.d2_ms = t; J.d2++; }
}
void audit_release(int src, const uint8_t kid[KIDLEN], char who, const char *target, int status) {
    if (src < 2 && GWS[src].compromised) return;          /* a compromised gateway reports nothing */
    pthread_mutex_lock(&JM);
    int port = oidx(who);
    /* D1: refused request, a key the legitimate requester can no longer obtain, or release to a port
     * other than the recipient the gateway knows */
    if (status != REL_OK || (target[0] && target[0] != who)) alarm_(1);
    /* D2: receipt (kid, source, port) compared with the association the master intended */
    if (status == REL_OK)
        for (int i = 0; i < nint; i++) if (!memcmp(INT[i].kid, kid, KIDLEN)) {
            if (INT[i].idx != port) alarm_(2); else INT[i].receipted = 1;
        }
    pthread_mutex_unlock(&JM);
}
static double gauss_m(void) {
    double u = (rand_r(&meter_seed) + 1.0) / (RAND_MAX + 2.0), v = (rand_r(&meter_seed) + 1.0) / (RAND_MAX + 2.0);
    return sqrt(-2 * log(u)) * cos(2 * M_PI * v);
}
void mon_end(int idx) {
    pthread_mutex_lock(&JM);
    /* D2 completeness: an accepted update key whose shares have no receipt for the intended outstation */
    if (J.m_accept)
        for (int i = 0; i < nint; i++)
            if (INT[i].idx == idx && !INT[i].receipted && !(INT[i].src < 2 && gw_comp_seen[INT[i].src])) { alarm_(2); break; }
    /* D3: head-meter change from minute m to m+1 versus the change implied by the accepted states */
    if (hp_ok && idx >= 0 && idx < 3) {
        int m = C.minute % 1440, m1 = (m + 1) % 1440, lat = idx % 3;
        int open_true = !brkr[idx], open_rep = J.tel_st == 1;
        double meas0 = HP[m][0] * (1 + METER_SD * gauss_m());
        double meas1 = HP[m1][open_true ? 1 + lat : 0] * (1 + METER_SD * gauss_m());
        double exp0 = HP[m][4], exp1 = HP[m1][open_rep ? 5 + lat : 4];
        J.d3_resid = (meas1 - meas0) - (exp1 - exp0);
        J.d3_true_change = open_true;
    }
    pthread_mutex_unlock(&JM);
}
static void headp_load(const char *dir) {
    char p[256]; snprintf(p, sizeof p, "%s/headp.csv", dir); FILE *f = fopen(p, "r"); if (!f) return;
    char line[256]; int m; float x[8];
    if (!fgets(line, sizeof line, f)) { fclose(f); return; }
    while (fgets(line, sizeof line, f))
        if (sscanf(line, "%d,%f,%f,%f,%f,%f,%f,%f,%f", &m, x, x+1, x+2, x+3, x+4, x+5, x+6, x+7) == 9 && m >= 0 && m < 1440)
            memcpy(HP[m], x, sizeof x);
    fclose(f); hp_ok = 1;
}

/* ======================= outstations ======================= */
typedef struct { int i; int loc[2]; SSL *kme; int wan; int compromised; Keys k; } Out;
static Out OS[MAXO];
static int fetch_share(Out *o, int g, const uint8_t kid[KIDLEN], uint8_t *key) {
    if (C.sae) {
        char kh[2*KIDLEN+1], body[128], resp[MAXKEY*2+512], tg[16]; hexs(kid, KIDLEN, kh);
        snprintf(body, sizeof body, "{\"key_IDs\":[{\"key_ID\":\"%s\"}]}", kh);
        if (http_post(o->kme, "/api/v1/keys/M/dec_keys", body, resp, sizeof resp) != 200) return -1;
        return b64key_from_json(resp, key, tg);
    }
    uint8_t req[1 + KIDLEN], out[MAXKEY + 8]; req[0] = 1; memcpy(req + 1, kid, KIDLEN);
    msg_send(o->loc[g], req, sizeof req); __atomic_add_fetch(&local_bytes, sizeof req + 4, __ATOMIC_RELAXED);
    int n = msg_recv(o->loc[g], out, sizeof out, 2000); if (n < 5 || out[0] != 1) return -1;
    int len; memcpy(&len, out + 1, 4); memcpy(key, out + 5, len); return len;
}
static void *out_thread(void *arg) {
    Out *o = arg; int lfd = tcp_listen(P_OWAN(o->i));
    if (!C.sae) for (int g = 0; g < C.npath; g++) o->loc[g] = tcp_connect(P_GLOC(g, o->i));
    else { char nm[2] = { oname(o->i), 0 }; o->kme = tls_connect(tls_client_ctx(nm), tcp_connect(C.base_port + 3)); }
    if (o->compromised) return NULL;                  /* sockets are handed to the attacker */
    o->wan = tcp_accept(lfd);
    static __thread uint8_t a[ASDU], r[ASDU], m[ASDU], last_rsp[ASDU], pend[ASDU], v5d[64];
    uint16_t d, s; int last_rl = 0, pendl = 0;
    uint8_t cda[CHAL], cdb[CHAL], chal[CHAL], v1d[64]; uint32_t ksq = 0, csq = 0; uint16_t user = 1; int have = 0;
    const uint16_t me = ADDR_O(o->i);
    for (;;) {
        int n = dnp3_recv(o->wan, &d, &s, a, ASDU, -1); if (n < 0) break;
        int fc = a[1], dl, rl, ml; uint8_t *p;
        if (fc == FC_AUTH_REQ && (p = G120(a, n, 11, &dl)) && dl >= 5 + CHAL && p[0] == KCM_QKD) {
            int ul = g16(p + 1); if (dl < 5 + ul + CHAL) continue;      /* user name -> user number 1 */
            memcpy(cda, p + 5 + ul, CHAL); rnd(cdb, CHAL); ksq++; have = 0; o->k.have_sk = 0;
            uint8_t v[64]; int vn = p32(v, ksq); vn += p16(v + vn, user); vn += p16(v + vn, CHAL); memcpy(v + vn, cdb, CHAL); vn += CHAL;
            rl = app_rsp(r, FC_AUTH_RESPONSE, 0); rl += obj_g120(r + rl, 12, v, vn);
            dnp3_send(o->wan, ADDR_M, me, r, rl);
        } else if (fc == FC_AUTH_REQ && (p = G120(a, n, 13, &dl)) && dl >= 8 + 1 + 2 * KIDLEN) {
            if (g32(p) != ksq) continue;
            const uint8_t *ref = p + 8; int np = ref[0];
            int cl; uint8_t *cm = G120(a, n, 15, &cl); if (!cm) continue;
            uint8_t share[MAXKEY]; int len = -1; memset(o->k.K, 0, MAXKEY);
            for (int g = 0; g < np && g < 2; g++) {
                len = fetch_share(o, g, ref + 1 + g * KIDLEN, share); if (len < 0) break;
                for (int b = 0; b < len; b++) o->k.K[b] ^= share[b];
            }
            if (len < 0) continue;                                     /* key unavailable: no reply */
            o->k.klen = len;
            conf_input(m, &ml, "MASTER", cda, cdb, ksq, user, oname(o->i));
            uint8_t mac[32]; int L = conf_mac(&o->k, 0, m, ml, mac);
            if (L != cl || memcmp(mac, cm, L)) continue;
            judge_out_accept(o->i, o->k.K, o->k.klen); have = 1; o->k.tel_i = o->k.cmd_i = 0;
            conf_input(m, &ml, "OUTSTATION", cdb, cda, ksq, user, oname(o->i));
            L = conf_mac(&o->k, 1, m, ml, mac);
            rl = app_rsp(r, FC_AUTH_RESPONSE, 0); rl += obj_g120(r + rl, 15, mac, L);
            dnp3_send(o->wan, ADDR_M, me, r, rl);
        } else if (fc == FC_AUTH_REQ && G120(a, n, 4, &dl) && have && !C.its) {   /* session key status request */
            uint8_t c5[CHAL]; rnd(c5, CHAL); int hn = v5_head(v5d, ksq, o->k.have_sk ? 1 : 2, c5);
            uint8_t v[80]; memcpy(v, v5d, hn); int vn = hn + p16(v + hn, 0);
            rl = app_rsp(r, FC_AUTH_RESPONSE, 0); rl += obj_g120(r + rl, 5, v, vn);
            dnp3_send(o->wan, ADDR_M, me, r, rl);
        } else if (fc == FC_AUTH_REQ && (p = G120(a, n, 6, &dl)) && have && !C.its && dl > 8) {   /* session key change */
            int wl = g16(p + 6); uint8_t pt[160];
            int pl = aes_unwrap(o->k.K, p + 8, wl, pt);
            if (pl < 2 + 64 + V5H || g16(pt) != 32 || memcmp(pt + 66, v5d, V5H)) continue;   /* must echo our key status */
            memcpy(o->k.sk_ctrl, pt + 2, 32); memcpy(o->k.sk_mon, pt + 34, 32); o->k.have_sk = 1;
            uint8_t c5[CHAL], v[80], mac[32]; rnd(c5, CHAL); int hn = v5_head(v5d, ksq, 1, c5);
            hmac256(o->k.sk_mon, 32, p, dl, mac);
            memcpy(v, v5d, hn); int vn = hn + p16(v + hn, MACL); memcpy(v + vn, mac, MACL); vn += MACL;
            rl = app_rsp(r, FC_AUTH_RESPONSE, 0); rl += obj_g120(r + rl, 5, v, vn);
            dnp3_send(o->wan, ADDR_M, me, r, rl);
        } else if (fc == FC_READ && find_obj(a, n, 60, 1, NULL) && have) {   /* class 0 poll */
            pthread_mutex_lock(&JM); int st = brkr[o->i]; float v = v_now(o->i); pthread_mutex_unlock(&JM);
            judge_tel_sent(o->i, (uint8_t)st, v);
            last_rl = b_tel(last_rsp, st, v);
            dnp3_send(o->wan, ADDR_M, me, last_rsp, last_rl);
        } else if (fc == FC_AUTH_REQ && (p = G120(a, n, 1, &dl)) && have && last_rl) {   /* master challenges our response */
            ml = chal_input(m, p, dl, last_rsp, last_rl); uint8_t mac[32];
            int L = msg_mac(&o->k, 0, m, ml, mac, o->k.tel_i++); if (L < 0) continue;
            rl = b_v2(r, FC_AUTH_RESPONSE, g32(p), mac, L);
            dnp3_send(o->wan, ADDR_M, me, r, rl); last_rl = 0;
        } else if (fc == FC_DIRECT_OPERATE && find_obj(a, n, 12, 1, NULL) && have) {   /* critical: challenge it */
            memcpy(pend, a, n); pendl = n;
            rl = b_v1(r, FC_AUTH_RESPONSE, ++csq, 1, chal, v1d);
            dnp3_send(o->wan, ADDR_M, me, r, rl);
        } else if (fc == FC_AUTH_REQ && (p = G120(a, n, 2, &dl)) && have && pendl) {     /* challenge reply */
            ml = chal_input(m, v1d, 8 + CHAL, pend, pendl); uint8_t mac[32];
            int L = msg_mac(&o->k, 1, m, ml, mac, o->k.cmd_i++);
            int ok = L > 0 && g32(p) == csq && dl == 6 + L && !memcmp(p + 6, mac, L);
            const uint8_t *crob = find_obj(pend, pendl, 12, 1, NULL);
            if (ok) {
                judge_cmd_exec(o->i, crob + 1);
                rl = app_rsp(r, FC_RESPONSE, 0); int c = rl; memcpy(r + rl, pend + 2, pendl - 2); rl += pendl - 2; r[c + 15] = 0;
            } else {
                uint8_t e[8]; int en = p32(e, csq); en += p16(e + en, user); e[en++] = 1;   /* error: authentication failed */
                rl = app_rsp(r, FC_AUTH_RESPONSE, 0); rl += obj_g120(r + rl, 7, e, en);
            }
            dnp3_send(o->wan, ADDR_M, me, r, rl); pendl = 0;
        }
    }
    return NULL;
}
void outstation_set_compromised(int i) { OS[i].compromised = 1; }
void outstations_start(void) {
    for (int i = 0; i < C.nout; i++) { OS[i].i = i; pthread_t t; pthread_create(&t, NULL, out_thread, &OS[i]); }
    usleep(50000);
}

/* ======================= master ======================= */
static int mwan; static SSL *mkme;
int master_connect(void) {
    mkme = tls_connect(tls_client_ctx("M"), tcp_connect(C.base_port + 1));
    mwan = tcp_connect(P_PROXY); return mkme && mwan >= 0 ? 0 : -1;
}
/* wait for an ASDU from outstation `from` with function fc carrying object (g,v), or a g120v7 error */
static int mrecv(int from, int fc, int g, int v, uint8_t *a) {
    double t0 = now_ms(); uint16_t d, s;
    for (;;) {
        int left = C.timeout_ms - (int)(now_ms() - t0); if (left <= 0) return -1;
        int n = dnp3_recv(mwan, &d, &s, a, ASDU, left); if (n < 0) return -1;
        if (s != ADDR_O(from)) continue;
        if (is(a, n, fc, g, v)) return n;
        if (is(a, n, FC_AUTH_RESPONSE, 120, 7)) return -7;
    }
}
static Keys MK[MAXO];
int master_session(int idx) {
    static uint8_t a[ASDU], r[ASDU], m[ASDU];
    int al, ml, n, dl; uint16_t user = 1; uint8_t *p; const uint16_t dst = ADDR_O(idx);
    uint8_t cda[CHAL]; rnd(cda, CHAL); double t0 = now_ms();
    pthread_mutex_lock(&JM); J.t0 = t0; pthread_mutex_unlock(&JM);
    /* g120v11: update key change request */
    uint8_t v[256]; int vn = 0; v[vn++] = KCM_QKD; vn += p16(v + vn, 3); vn += p16(v + vn, CHAL);
    memcpy(v + vn, "OP1", 3); vn += 3; memcpy(v + vn, cda, CHAL); vn += CHAL;
    al = app_req(a, FC_AUTH_REQ); al += obj_g120(a + al, 11, v, vn);
    dnp3_send(mwan, dst, ADDR_M, a, al);
    if ((n = mrecv(idx, FC_AUTH_RESPONSE, 120, 12, r)) < 0) return -1;
    p = G120(r, n, 12, &dl); uint32_t ksq = g32(p); uint8_t cdb[CHAL]; memcpy(cdb, p + 8, CHAL);
    /* one QKD key per delivery path, target named in an ETSI 014 request extension */
    Keys *k = &MK[idx]; memset(k->K, 0, MAXKEY); k->klen = key_len(); k->have_sk = 0;
    uint8_t kids[2][KIDLEN]; int np = C.sae ? 1 : C.npath;
    for (int g = 0; g < np; g++) {
        char path[64], body[160], resp[MAXKEY*2+512], kh[64]; uint8_t share[MAXKEY];
        if (C.sae) snprintf(path, sizeof path, "/api/v1/keys/%c/enc_keys", oname(idx));
        else snprintf(path, sizeof path, "/api/v1/keys/G%d/enc_keys", g + 1);
        snprintf(body, sizeof body, "{\"number\":1,\"size\":%d,\"extension_mandatory\":[{\"target\":\"%c\"}]}", k->klen * 8, oname(idx));
        if (http_post(mkme, path, body, resp, sizeof resp) != 200) return -2;     /* no key available */
        const char *q = strstr(resp, "\"key_ID\":\""); memcpy(kh, q + 10, 2 * KIDLEN); kh[2*KIDLEN] = 0;
        unhex(kh, kids[g], KIDLEN); char tg[16]; b64key_from_json(resp, share, tg);
        mon_intend(kids[g], idx, C.sae ? 2 : g);
        for (int b = 0; b < k->klen; b++) k->K[b] ^= share[b];
        if (C.meta == META_INBAND && !C.sae) {           /* tell the gateway who the key is for */
            uint8_t an[64], x[KIDLEN + 1]; memcpy(x, kids[g], KIDLEN); x[KIDLEN] = (uint8_t)oname(idx);
            int nl = app_req(an, FC_AUTH_REQ_NOACK); nl += obj_g120(an + nl, 99, x, KIDLEN + 1);
            dnp3_send(mwan, ADDR_G(g), ADDR_M, an, nl);
        }
    }
    judge_master_key(k->K, k->klen);
    /* g120v13 (key reference container) + g120v15 (master confirmation) in one ASDU */
    vn = p32(v, ksq); vn += p16(v + vn, user); vn += p16(v + vn, 1 + 2 * KIDLEN);
    v[vn++] = (uint8_t)np; memset(v + vn, 0, 2 * KIDLEN); for (int g = 0; g < np; g++) memcpy(v + vn + g * KIDLEN, kids[g], KIDLEN);
    vn += 2 * KIDLEN;
    al = app_req(a, FC_AUTH_REQ); al += obj_g120(a + al, 13, v, vn);
    conf_input(m, &ml, "MASTER", cda, cdb, ksq, user, oname(idx));
    uint8_t mac[32]; int L = conf_mac(k, 0, m, ml, mac); al += obj_g120(a + al, 15, mac, L);
    dnp3_send(mwan, dst, ADDR_M, a, al);
    if ((n = mrecv(idx, FC_AUTH_RESPONSE, 120, 15, r)) < 0) return -3;
    conf_input(m, &ml, "OUTSTATION", cdb, cda, ksq, user, oname(idx));
    L = conf_mac(k, 1, m, ml, mac); p = G120(r, n, 15, &dl);
    if (dl != L || memcmp(p, mac, L)) return -4;
    double t1 = now_ms();
    pthread_mutex_lock(&JM); J.m_accept = 1; J.t_ukc_ms = t1 - t0; pthread_mutex_unlock(&JM);
    k->tel_i = k->cmd_i = 0;
    if (!C.its) {                                        /* session keys: v4 -> v5 -> v6 -> v5 */
        al = app_req(a, FC_AUTH_REQ); p16(v, user); al += obj_g120(a + al, 4, v, 2);
        dnp3_send(mwan, dst, ADDR_M, a, al);
        if ((n = mrecv(idx, FC_AUTH_RESPONSE, 120, 5, r)) < 0) return -5;
        p = G120(r, n, 5, &dl); if (dl < V5H) return -5;
        uint8_t pt[160], w[176]; int pl = 0; pl += p16(pt, 32); rnd(k->sk_ctrl, 32); rnd(k->sk_mon, 32);
        memcpy(pt + pl, k->sk_ctrl, 32); memcpy(pt + pl + 32, k->sk_mon, 32); pl += 64;
        memcpy(pt + pl, p, V5H); pl += V5H; while (pl % 8) pt[pl++] = 0;
        int wl = aes_wrap(k->K, pt, pl, w);
        vn = p32(v, g32(p)); vn += p16(v + vn, user); vn += p16(v + vn, (uint16_t)wl); memcpy(v + vn, w, wl); vn += wl;
        al = app_req(a, FC_AUTH_REQ); al += obj_g120(a + al, 6, v, vn);
        dnp3_send(mwan, dst, ADDR_M, a, al);
        uint8_t v6[256]; memcpy(v6, v, vn); int v6n = vn;
        if ((n = mrecv(idx, FC_AUTH_RESPONSE, 120, 5, r)) < 0) return -5;
        p = G120(r, n, 5, &dl); hmac256(k->sk_mon, 32, v6, v6n, mac);
        if (dl != V5H + 2 + MACL || p[7] != 1 || memcmp(p + V5H + 2, mac, MACL)) return -6;
        k->have_sk = 1;
    }
    double t2 = now_ms(); pthread_mutex_lock(&JM); J.t_sk_ms = t2 - t1; pthread_mutex_unlock(&JM);
    /* class 0 poll; the master challenges the response before using it */
    al = app_req(a, FC_READ); al += obj_class0(a + al);
    dnp3_send(mwan, dst, ADDR_M, a, al);
    if ((n = mrecv(idx, FC_RESPONSE, 30, 5, r)) > 0) {
        uint8_t rsp[ASDU], v1[64], ch[CHAL]; int rn = n; memcpy(rsp, r, n);
        static uint32_t mcsq; al = b_v1(a, FC_AUTH_REQ, ++mcsq, 1, ch, v1);
        dnp3_send(mwan, dst, ADDR_M, a, al);
        if ((n = mrecv(idx, FC_AUTH_RESPONSE, 120, 2, r)) > 0) {
            p = G120(r, n, 2, &dl); ml = chal_input(m, v1, 8 + CHAL, rsp, rn);
            L = msg_mac(k, 0, m, ml, mac, k->tel_i++);
            if (L > 0 && g32(p) == mcsq && dl == 6 + L && !memcmp(p + 6, mac, L)) {
                uint8_t st; float vv; tel_parse(rsp, rn, &st, &vv); judge_tel_accept(idx, st, vv);
                pthread_mutex_lock(&JM); J.t_tel_ms = now_ms() - t2; pthread_mutex_unlock(&JM);
            }
        }
    }
    /* control: CROB latch-close on the lateral breaker (a no-op on a closed breaker), challenged by the outstation */
    double t3 = now_ms(); uint32_t nonce; rnd(&nonce, 4);
    uint8_t cmd[ASDU]; int cn = b_do(cmd, 0x41, nonce); judge_cmd_sent(find_obj(cmd, cn, 12, 1, NULL) + 1);
    dnp3_send(mwan, dst, ADDR_M, cmd, cn);
    if ((n = mrecv(idx, FC_AUTH_RESPONSE, 120, 1, r)) > 0) {
        p = G120(r, n, 1, &dl); ml = chal_input(m, p, dl, cmd, cn);
        L = msg_mac(k, 1, m, ml, mac, k->cmd_i++);
        if (L > 0) {
            al = b_v2(a, FC_AUTH_REQ, g32(p), mac, L); dnp3_send(mwan, dst, ADDR_M, a, al);
            if ((n = mrecv(idx, FC_RESPONSE, 12, 1, r)) > 0) {
                pthread_mutex_lock(&JM); J.t_cmd_ms = now_ms() - t3; if (!J.cmd_ok && idx == ATK.victim) J.cmd_acked_unexecuted = 1;
                pthread_mutex_unlock(&JM);
            }
        }
    }
    return 0;
}

/* ======================= WAN emulation (in the proxy) ======================= */
/* Each direction is a FIFO delay line: one-way delay + Gaussian jitter, and segment loss modelled
 * as TCP retransmission after the 200 ms minimum RTO (DNP3 over TCP does not lose data, it is
 * delayed). Release times are kept monotonic per direction, as TCP delivers in order. */
typedef struct DItem { struct DItem *next; int fd, n; double t; uint8_t b[]; } DItem;
typedef struct { DItem *h, *t; pthread_mutex_t m; pthread_cond_t c; double last; unsigned seed; } DLine;
static DLine DL[2];
static double gauss(unsigned *s) { double u = (rand_r(s) + 1.0) / (RAND_MAX + 2.0), w = (rand_r(s) + 1.0) / (RAND_MAX + 2.0); return sqrt(-2 * log(u)) * cos(2 * M_PI * w); }
static void *dline(void *arg) {
    DLine *d = arg;
    for (;;) {
        pthread_mutex_lock(&d->m); while (!d->h) pthread_cond_wait(&d->c, &d->m);
        DItem *it = d->h; pthread_mutex_unlock(&d->m);
        double w = it->t - now_ms(); if (w > 0) usleep((useconds_t)(w * 1000));
        send_all(it->fd, it->b, it->n);
        pthread_mutex_lock(&d->m); d->h = it->next; if (!d->h) d->t = NULL; pthread_mutex_unlock(&d->m); free(it);
    }
    return NULL;
}
static int wan_on(void) { return C.wan_ms > 0 || C.wan_jit > 0 || C.wan_loss > 0; }
static void wan_push(int dir, int fd, const uint8_t *b, int n) {
    if (!wan_on()) { send_all(fd, b, n); return; }
    DLine *d = &DL[dir]; DItem *it = malloc(sizeof *it + n); it->next = NULL; it->fd = fd; it->n = n; memcpy(it->b, b, n);
    pthread_mutex_lock(&d->m);
    double dl = C.wan_ms + C.wan_jit * gauss(&d->seed); if (dl < 0) dl = 0;
    int segs = 0; for (int i = 0; i < n; ) { segs++; i += 10 + (b[i + 2] - 5) + 2 * ((b[i + 2] - 5 + 15) / 16); }
    for (int s = 0; s < segs; s++) while ((double)rand_r(&d->seed) / RAND_MAX < C.wan_loss) dl += 200;
    double t = now_ms() + dl; if (t < d->last) t = d->last; d->last = t; it->t = t;
    if (d->t) d->t->next = it; else d->h = it; d->t = it;
    pthread_cond_signal(&d->c); pthread_mutex_unlock(&d->m);
}

/* ======================= attacker: WAN proxy + compromised outstation ======================= */
typedef struct {
    uint8_t cda[CHAL], cdb[CHAL]; uint32_t ksq; uint16_t user;
    uint8_t kids[2][KIDLEN]; int np;
    Keys k; int have_key;
    int imp;                  /* 1 answers for the victim, 2 drives the victim (T3), 3 inside the victim's session */
    int drive, cmd;           /* sub-states of the forged session and of the forged command */
    uint8_t v5d[64], v1m[64]; int v1ml; uint32_t csq;
    uint8_t fake[ASDU]; int fakel; uint8_t fcmd[ASDU]; int fcmdl; uint8_t fv1[64]; uint8_t scmd[ASDU]; int scmdl;
    uint8_t okids[2][KIDLEN]; uint8_t oK[MAXKEY]; int have_other;
} AState;
static AState AS;
static int pfd_m, pfd_o[MAXO], pfd_g[2];
static int route(uint16_t dst) {
    if (dst == ADDR_M) return pfd_m;
    if (dst >= 10 && dst < 10 + MAXO) return pfd_o[dst - 10];
    if (dst >= 100 && dst < 102) return pfd_g[dst - 100];
    return -1;
}
static void fwd(uint16_t dst, uint16_t src, const uint8_t *a, int al) {
    int fd = route(dst); if (fd < 0) return;
    static uint8_t f[4096]; int n = dnp3_frames(f, dst, src, a, al); wan_push(dst == ADDR_M ? 0 : 1, fd, f, n);
}
static int steal_via_accomplice(int g, const uint8_t kid[KIDLEN], uint8_t *share) {
    if (ATK.accomplice < 0 || !OS[ATK.accomplice].compromised) return -1;
    return fetch_share(&OS[ATK.accomplice], g, kid, share);
}
static int dump_for(int g, const uint8_t kid[KIDLEN], uint8_t *share) {
    static uint8_t kids[512][KIDLEN], keys[512][MAXKEY]; static int lens[512];
    int n = gw_dump(g, kids, keys, lens, 512);
    for (int i = 0; i < n; i++) if (!memcmp(kids[i], kid, KIDLEN)) { memcpy(share, keys[i], lens[i]); return lens[i]; }
    return -1;
}
static uint8_t post_share[2][MAXKEY]; static int post_got[2], post_len;
static void combine_if_complete(void) {
    int all = 1; for (int g = 0; g < AS.np; g++) all &= post_got[g];
    if (!all || !post_len || AS.have_key) return;
    memset(AS.k.K, 0, MAXKEY);
    for (int g = 0; g < AS.np; g++) for (int b = 0; b < post_len; b++) AS.k.K[b] ^= post_share[g][b];
    AS.k.klen = post_len; AS.have_key = 1; judge_attacker_learns(AS.k.K, post_len);
}
static void attacker_try_key(void) {        /* before the victim fetches its shares */
    /* B asks for A's share only when the attacker has no gateway or relay to take it from: a
     * refused request is visible in the gateway's audit, so a careful attacker avoids it */
    int other_route = ATK.mode == ATK_GWDUMP && (ATK.g1_window || ATK.g2_window || ATK.tn);
    for (int g = 0; g < AS.np; g++) {
        int l = other_route ? -1 : steal_via_accomplice(g, AS.kids[g], post_share[g]);
        if (l > 0) { post_got[g] = 1; post_len = l; }
        int t = topo_trusted_node(g);                    /* trusted-node relay on this key's path */
        if (!post_got[g] && t && (ATK.tn >> (t - 1) & 1) && (l = trusted_dump(t, AS.kids[g], post_share[g])) > 0) {
            post_got[g] = 1; post_len = l; }
    }
    int win[2] = { ATK.g1_window, ATK.g2_window };
    for (int g = 0; g < AS.np && g < 2; g++) {
        if (C.sae || post_got[g] || !(win[g] == 1 || win[g] == 2)) continue;
        gw_compromise(g, 1); gw_prefetch(g, AS.kids[g]);  /* uses the gateway's own SAE credentials */
        int l = dump_for(g, AS.kids[g], post_share[g]); if (l > 0) { post_got[g] = 1; post_len = l; }
        if (win[g] == 2) gw_compromise(g, 0);
    }
    combine_if_complete();
}
static void attacker_post_delivery(void) {
    if (AS.have_key) return;
    for (int g = 0; g < AS.np; g++) {
        if (C.sae || post_got[g]) continue;
        int w = g == 0 ? ATK.g1_window : ATK.g2_window;
        if (w == 1 || w == 3) { gw_compromise(g, 1); int l = dump_for(g, AS.kids[g], post_share[g]); if (l > 0) { post_got[g] = 1; post_len = l; } }
    }
    combine_if_complete();
}
static void to_master(const uint8_t *a, int n) { fwd(ADDR_M, ADDR_O(ATK.victim), a, n); }
static void to_victim(const uint8_t *a, int n) { fwd(ADDR_O(ATK.victim), ADDR_M, a, n); }
/* masked telemetry: breaker closed, the lateral's normal voltage for this minute */
static int fake_tel(uint8_t *a) { return b_tel(a, 1, grid_ok ? VTEL[C.minute % 1440][ATK.victim % 3] : 12.0f); }
static void inject_trip(void) {       /* forged critical request to the victim */
    uint32_t nonce; rnd(&nonce, 4); AS.fcmdl = b_do(AS.fcmd, 0x81, nonce); AS.cmd = 1; to_victim(AS.fcmd, AS.fcmdl);
}
static void imp_answer_v15(void) {
    uint8_t m[256], mac[32], r[64]; int ml;
    conf_input(m, &ml, "OUTSTATION", AS.cdb, AS.cda, AS.ksq, AS.user, oname(ATK.victim));
    int L = conf_mac(&AS.k, 1, m, ml, mac), rl = app_rsp(r, FC_AUTH_RESPONSE, 0); rl += obj_g120(r + rl, 15, mac, L);
    to_master(r, rl);
}
/* attacker plays the victim towards the master (imp 1) */
static void imp1_master(uint8_t *a, int n) {
    static uint8_t r[ASDU], m[ASDU]; int rl, dl; uint8_t *p, mac[32];
    if (a[1] == FC_AUTH_REQ && G120(a, n, 4, &dl)) {
        uint8_t c5[CHAL], v[80]; rnd(c5, CHAL); int hn = v5_head(AS.v5d, AS.ksq, 2, c5); memcpy(v, AS.v5d, hn);
        rl = app_rsp(r, FC_AUTH_RESPONSE, 0); rl += obj_g120(r + rl, 5, v, hn + p16(v + hn, 0)); to_master(r, rl);
    } else if (a[1] == FC_AUTH_REQ && (p = G120(a, n, 6, &dl))) {
        uint8_t pt[160]; if (aes_unwrap(AS.k.K, p + 8, g16(p + 6), pt) < 66) return;
        memcpy(AS.k.sk_ctrl, pt + 2, 32); memcpy(AS.k.sk_mon, pt + 34, 32);
        uint8_t c5[CHAL], v[80]; rnd(c5, CHAL); int hn = v5_head(v, AS.ksq, 1, c5); hmac256(AS.k.sk_mon, 32, p, dl, mac);
        int vn = hn + p16(v + hn, MACL); memcpy(v + vn, mac, MACL); vn += MACL;
        rl = app_rsp(r, FC_AUTH_RESPONSE, 0); rl += obj_g120(r + rl, 5, v, vn); to_master(r, rl);
    } else if (a[1] == FC_READ) {
        AS.fakel = fake_tel(AS.fake); to_master(AS.fake, AS.fakel);
    } else if (a[1] == FC_AUTH_REQ && (p = G120(a, n, 1, &dl)) && AS.fakel) {
        int ml = chal_input(m, p, dl, AS.fake, AS.fakel), L = msg_mac(&AS.k, 0, m, ml, mac, AS.k.tel_i++);
        if (L > 0) { rl = b_v2(r, FC_AUTH_RESPONSE, g32(p), mac, L); to_master(r, rl); }
    } else if (a[1] == FC_DIRECT_OPERATE) {          /* challenge the master's command ourselves, then ack it */
        memcpy(AS.scmd, a, n); AS.scmdl = n; uint8_t ch[CHAL]; rl = b_v1(r, FC_AUTH_RESPONSE, ++AS.csq, 1, ch, AS.fv1); to_master(r, rl);
    } else if (a[1] == FC_AUTH_REQ && G120(a, n, 2, &dl) && AS.scmdl) {
        rl = app_rsp(r, FC_RESPONSE, 0); memcpy(r + rl, AS.scmd + 2, AS.scmdl - 2); rl += AS.scmdl - 2; to_master(r, rl); AS.scmdl = 0;
    }
}
static void on_master_frame(uint16_t dst, uint16_t src, uint8_t *a, int n) {
    int V = ATK.victim, B = ATK.accomplice, dl; uint8_t *p;
    int toV = (dst == ADDR_O(V));
    if (ATK.mode == ATK_REDIRECT && toV) { fwd(ADDR_O(B), src, a, n); return; }
    if (a[1] == FC_AUTH_REQ_NOACK && (p = G120(a, n, 99, &dl)) && ATK.forge_announce) {
        p[KIDLEN] = (uint8_t)oname(B); fwd(dst, src, a, n); return;     /* rebind announced key IDs */
    }
    if (ATK.mode == ATK_SUBST && dst == ADDR_O(B) && (p = G120(a, n, 13, &dl))) {
        memcpy(AS.okids, p + 9, 2 * KIDLEN);           /* T3: harvest B's key IDs, suppress delivery */
        pthread_mutex_lock(&JM); memcpy(AS.oK, J.K_master, J.klen); pthread_mutex_unlock(&JM);
        AS.have_other = 1; return;
    }
    if (!toV) { fwd(dst, src, a, n); return; }
    if ((p = G120(a, n, 11, &dl))) { AS.user = 1; memcpy(AS.cda, p + 5 + g16(p + 1), CHAL); }
    if ((p = G120(a, n, 13, &dl))) {
        AS.np = p[8]; memcpy(AS.kids, p + 9, 2 * KIDLEN);
        int cl; uint8_t *cm = G120(a, n, 15, &cl);
        if (ATK.mode == ATK_SUBST && AS.have_other && cm) {
            memcpy(p + 9, AS.okids, 2 * KIDLEN);       /* substitute, re-MAC under the key we know */
            memcpy(AS.k.K, AS.oK, MAXKEY); AS.k.klen = key_len(); AS.have_key = 1; judge_attacker_learns(AS.k.K, AS.k.klen);
            uint8_t m[256]; int ml; conf_input(m, &ml, "MASTER", AS.cda, AS.cdb, AS.ksq, AS.user, oname(V));
            conf_mac(&AS.k, 0, m, ml, cm); fwd(dst, src, a, n); AS.imp = 2; return;
        }
        attacker_try_key();
        if (AS.have_key && !ATK.passive) { AS.imp = 1; imp_answer_v15(); return; }
        fwd(dst, src, a, n); return;
    }
    if (AS.imp == 1) { imp1_master(a, n); return; }    /* the victim never sees its session */
    if (AS.imp == 3 && (p = G120(a, n, 6, &dl)) && !C.its) {       /* learn the victim's session keys */
        uint8_t pt[160]; if (aes_unwrap(AS.k.K, p + 8, g16(p + 6), pt) >= 66) {
            memcpy(AS.k.sk_ctrl, pt + 2, 32); memcpy(AS.k.sk_mon, pt + 34, 32); AS.k.have_sk = 1; }
        fwd(dst, src, a, n); if (AS.k.have_sk && !AS.cmd) inject_trip(); return;
    }
    if (AS.imp == 3 && a[1] == FC_AUTH_REQ && (p = G120(a, n, 1, &dl))) { memcpy(AS.v1m, p, dl); AS.v1ml = dl; }
    /* keep the operator's own commands away from the victim, acknowledging them under the stolen key */
    if (AS.imp == 3 && (a[1] == FC_DIRECT_OPERATE || (a[1] == FC_AUTH_REQ && G120(a, n, 2, &dl) && AS.scmdl))) { imp1_master(a, n); return; }
    fwd(dst, src, a, n);
}
static void on_out_frame(int from, uint16_t dst, uint16_t src, uint8_t *a, int n) {
    int V = ATK.victim, B = ATK.accomplice, dl; uint8_t *p; static uint8_t r[ASDU], m[ASDU]; uint8_t mac[32];
    if (ATK.mode == ATK_REDIRECT && from == B) { fwd(dst, ADDR_O(V), a, n); return; }
    if (from != V) { fwd(dst, src, a, n); return; }
    if ((p = G120(a, n, 12, &dl))) { AS.ksq = g32(p); memcpy(AS.cdb, p + 8, CHAL); }
    /* forged command in flight: answer the victim's challenge, swallow its response */
    if (AS.cmd == 1 && (p = G120(a, n, 1, &dl))) {
        int ml = chal_input(m, p, dl, AS.fcmd, AS.fcmdl), L = msg_mac(&AS.k, 1, m, ml, mac, AS.k.cmd_i++);
        if (L > 0) { int rl = b_v2(r, FC_AUTH_REQ, g32(p), mac, L); to_victim(r, rl); }
        AS.cmd = 2; return;
    }
    if (AS.cmd == 2 && a[1] == FC_RESPONSE && find_obj(a, n, 12, 1, NULL)) { AS.cmd = 3; return; }
    if (AS.imp == 2) {                                 /* T3: run a session with the victim ourselves */
        if (G120(a, n, 15, &dl)) {                     /* drop the genuine confirmation */
            if (C.its) inject_trip();
            else { int rl = app_req(r, FC_AUTH_REQ); uint8_t u[2]; p16(u, 1); rl += obj_g120(r + rl, 4, u, 2); to_victim(r, rl); AS.drive = 1; }
            return;
        }
        if (AS.drive == 1 && (p = G120(a, n, 5, &dl)) && dl >= V5H) {
            uint8_t pt[160], w[176], v[256]; int pl = p16(pt, 32); rnd(AS.k.sk_ctrl, 32); rnd(AS.k.sk_mon, 32);
            memcpy(pt + pl, AS.k.sk_ctrl, 32); memcpy(pt + pl + 32, AS.k.sk_mon, 32); pl += 64;
            memcpy(pt + pl, p, V5H); pl += V5H; while (pl % 8) pt[pl++] = 0;
            int wl = aes_wrap(AS.k.K, pt, pl, w), vn = p32(v, g32(p)); vn += p16(v + vn, 1); vn += p16(v + vn, (uint16_t)wl);
            memcpy(v + vn, w, wl); vn += wl;
            int rl = app_req(r, FC_AUTH_REQ); rl += obj_g120(r + rl, 6, v, vn); to_victim(r, rl); AS.drive = 2; return;
        }
        if (AS.drive == 2 && G120(a, n, 5, &dl)) { AS.drive = 3; inject_trip(); return; }
        return;
    }
    if (G120(a, n, 15, &dl)) {                         /* victim confirmed the update key */
        fwd(dst, src, a, n); attacker_post_delivery();
        if (AS.have_key && !ATK.passive) { AS.imp = 3; if (C.its) inject_trip(); }
        return;
    }
    if (AS.imp == 3 && a[1] == FC_RESPONSE && find_obj(a, n, 30, 5, NULL)) {   /* mask the telemetry */
        AS.fakel = fake_tel(AS.fake); to_master(AS.fake, AS.fakel); return;
    }
    if (AS.imp == 3 && (p = G120(a, n, 2, &dl)) && AS.fakel && AS.v1ml) {     /* re-MAC the challenged response */
        int ml = chal_input(m, AS.v1m, AS.v1ml, AS.fake, AS.fakel), L = msg_mac(&AS.k, 0, m, ml, mac, AS.k.tel_i++);
        if (L > 0) { int rl = b_v2(r, FC_AUTH_RESPONSE, g32(p), mac, L); to_master(r, rl); }
        return;
    }
    fwd(dst, src, a, n);
}
static void *proxy_thread(void *arg) {
    (void)arg; int lfd = tcp_listen(P_PROXY);
    for (int i = 0; i < C.nout; i++) pfd_o[i] = OS[i].compromised ? -1 : tcp_connect(P_OWAN(i));
    for (int g = 0; g < 2; g++) pfd_g[g] = (!C.sae && g < C.npath) ? tcp_connect(P_GWAN(g)) : -1;
    pfd_m = tcp_accept(lfd);
    struct pollfd pf[MAXO + 1]; static uint8_t a[ASDU];
    for (;;) {
        int n = 0; pf[n++] = (struct pollfd){ pfd_m, POLLIN, 0 };
        int map[MAXO + 1]; map[0] = -1;
        for (int i = 0; i < C.nout; i++) if (pfd_o[i] >= 0) { map[n] = i; pf[n++] = (struct pollfd){ pfd_o[i], POLLIN, 0 }; }
        if (poll(pf, n, -1) <= 0) continue;
        for (int j = 0; j < n; j++) if (pf[j].revents & POLLIN) {
            uint16_t d, s; int al = dnp3_recv(pf[j].fd, &d, &s, a, ASDU, 1000);
            if (al < 2) continue;
            if (j == 0) on_master_frame(d, s, a, al); else on_out_frame(map[j], d, s, a, al);
        }
    }
    return NULL;
}
void proxy_start(void) {
    pthread_t t;
    for (int i = 0; i < 2; i++) { pthread_mutex_init(&DL[i].m, NULL); pthread_cond_init(&DL[i].c, NULL); DL[i].seed = 12345 + i; pthread_create(&t, NULL, dline, &DL[i]); }
    pthread_create(&t, NULL, proxy_thread, NULL); usleep(50000);
}
void attacker_reset(int keep_other) {
    static uint8_t ok[2][KIDLEN], oK[MAXKEY]; int ho = AS.have_other;
    memcpy(ok, AS.okids, sizeof ok); memcpy(oK, AS.oK, MAXKEY);
    memset(&AS, 0, sizeof AS);
    if (keep_other) { memcpy(AS.okids, ok, sizeof ok); memcpy(AS.oK, oK, MAXKEY); AS.have_other = ho; }
    memset(post_got, 0, sizeof post_got); post_len = 0;
    for (int g = 0; g < 2; g++) if (!C.sae && g < C.npath) gw_compromise(g, 0);
}
