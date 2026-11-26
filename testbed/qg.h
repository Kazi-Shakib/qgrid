/* qgrid: experimental testbed for QKD key delivery into DNP3 Secure Authentication.
 * Entities run as threads and talk only over real TCP sockets (ETSI-014-style HTTPS with mutual
 * TLS, DNP3 link framing with CRCs, local gateway links, an ITS-authenticated inter-KME link).
 * The only emulated component is the QKD link itself: a source that delivers identical random
 * bytes to both KMEs at a configured rate. */
#ifndef QG_H
#define QG_H
#include <stdint.h>
#include <stddef.h>
#include <pthread.h>
#include <openssl/ssl.h>

#define MAXO 78            /* outstations (one printable name byte each) */
#define KIDLEN 16
#define MAXKEY 8192         /* bytes of one update key / share */
#define CHAL 32

/* ---------- configuration ---------- */
enum { META_NONE = 0, META_AUTH = 1, META_INBAND = 2 };
typedef struct {
    int npath;          /* 1 or 2 delivery paths (gateways) */
    int bind;           /* gateway releases a key only to its target outstation */
    int erase;          /* gateway deletes a share after delivering it (else retains) */
    int meta;           /* where the gateway learns the target */
    int oid;            /* outstation identity included in confirmation MACs */
    int sae;            /* outstations are their own SAEs (no gateway) */
    int its;            /* 0: HMAC-SHA256 + AES key wrap (SAv5); 1: Wegman-Carter tags + OTP */
    int msgs_per_epoch; /* ITS mode: number of one-time message tags carried in the update key */
    double qkd_bps;     /* QKD link emulator rate, bits/s (0 = unlimited) */
    int base_port;
    int nout;           /* number of outstations */
    int timeout_ms;
    int qkd_mode;       /* 0: key-output emulator, 2: software decoy-state BB84 stack */
    int simclock;       /* key availability follows the QKD stack's simulated clock */
    double sim_now;     /* current simulated time (s) when simclock is on */
    uint64_t qkd_reserve; /* fast mode: pause the QKD stack when this much key is buffered */
    int topo;           /* 0 direct link, 1 one trusted node, 2 two disjoint trusted-node paths */
    int route2;         /* topology 2: send G2's keys over the second path (else both over T1) */
    double L1, L2;      /* fibre length of the KME_A-side and KME_B-side links (km) */
    double wan_ms, wan_jit, wan_loss; /* WAN one-way delay, jitter (s.d.), segment loss probability */
    int minute;         /* grid time of day (minute) used by the outstations */
} Cfg;
extern Cfg C;

/* ---------- crypto.c ---------- */
void rnd(void *p, size_t n);
void hmac256(const uint8_t *k, size_t kl, const uint8_t *m, size_t ml, uint8_t out[32]);
uint64_t wc_tag(const uint8_t r[8], const uint8_t s[8], const uint8_t *m, size_t ml);
int aes_wrap(const uint8_t *kek, const uint8_t *in, int inl, uint8_t *out);
int aes_unwrap(const uint8_t *kek, const uint8_t *in, int inl, uint8_t *out);
uint16_t crc_dnp(const uint8_t *p, size_t n);
void hexs(const uint8_t *b, size_t n, char *out);
int unhex(const char *s, uint8_t *b, size_t n);
int b64e(const uint8_t *in, int n, char *out);
int b64d(const char *in, uint8_t *out);
double now_ms(void);

/* ---------- net.c ---------- */
int tcp_listen(int port);
int tcp_accept(int lfd);
int tcp_connect(int port);
int send_all(int fd, const void *p, size_t n);
int recv_all(int fd, void *p, size_t n, int tmo_ms);
int msg_send(int fd, const void *p, uint32_t n);            /* length-prefixed */
int msg_recv(int fd, void *p, uint32_t max, int tmo_ms);    /* returns length or -1 */
/* DNP3 link layer (0x0564 header, CRC per block); single-fragment transport */
int dnp_build(uint8_t *out, uint16_t dst, uint16_t src, const uint8_t *app, int appl);
int dnp_send(int fd, uint16_t dst, uint16_t src, const uint8_t *app, int appl);
int dnp_recv(int fd, uint16_t *dst, uint16_t *src, uint8_t *app, int max, int tmo_ms, uint8_t *raw, int *rawl);
int dnp_parse(const uint8_t *raw, int rawl, uint16_t *dst, uint16_t *src, uint8_t *app, int max);
int dnp_build_raw(uint8_t *out, uint16_t dst, uint16_t src, const uint8_t *ud, int udl);
int dnp_recv_raw(int fd, uint16_t *dst, uint16_t *src, uint8_t *ud, int max, int tmo);
/* ---------- dnp3.c: transport + application (IEEE 1815) ---------- */
enum { FC_READ = 0x01, FC_DIRECT_OPERATE = 0x05, FC_AUTH_REQ = 0x20, FC_AUTH_REQ_NOACK = 0x21,
       FC_RESPONSE = 0x81, FC_UNSOLICITED = 0x82, FC_AUTH_RESPONSE = 0x83 };
int dnp3_frames(uint8_t *out, uint16_t dst, uint16_t src, const uint8_t *asdu, int n);
int dnp3_send(int fd, uint16_t dst, uint16_t src, const uint8_t *asdu, int n);
int dnp3_recv(int fd, uint16_t *dst, uint16_t *src, uint8_t *asdu, int max, int tmo);
int app_req(uint8_t *a, uint8_t fc);
int app_rsp(uint8_t *a, uint8_t fc, uint16_t iin);
int app_hlen(const uint8_t *a);
int obj_g120(uint8_t *p, int var, const void *data, int len);
int obj_class0(uint8_t *p);
int obj_crob(uint8_t *p, uint8_t index, uint8_t code, uint8_t status);
int obj_binary(uint8_t *p, uint8_t index, int state);
int obj_analog_f(uint8_t *p, uint8_t index, float v);
const uint8_t *find_obj(const uint8_t *a, int n, int g, int v, int *len);
/* TLS (mutual) */
SSL_CTX *tls_server_ctx(const char *name);
SSL_CTX *tls_client_ctx(const char *name);
SSL *tls_accept(SSL_CTX *ctx, int fd);
SSL *tls_connect(SSL_CTX *ctx, int fd);
const char *tls_peer_cn(SSL *s, char *buf, int n);
int http_post(SSL *s, const char *path, const char *body, char *resp, int max);
int http_read_req(SSL *s, char *path, int pmax, char *body, int bmax);
int http_reply(SSL *s, int code, const char *body);
extern uint64_t wan_bytes, local_bytes, api_bytes, kme_link_bytes;

/* ---------- keynet.c (continued) ---------- */
void qkd_start(void);
int topo_trusted_node(int g);
uint64_t qkd_consumed(void);       /* bytes of QKD key consumed (keys + relay tags) */
uint64_t qkd_starved(void);        /* key requests refused for lack of key */
void kme_start(void);              /* KME_A (control centre) and KME_B (substation) */

/* ---------- qkdsw.c: software decoy-state BB84 ---------- */
typedef struct { double L_km, f_rep, alpha_db, eta_det, pdc, e_mis, mu[3], pmu[3], pZ; uint32_t nZ;
                 double eps_sec, eps_cor; int max_blocks;
                 double eta_det1, dead_ns, p_ap; int realistic; } QKDParams;
typedef struct { int blk; double pulses, sim_s; uint64_t detections; uint32_t nz, nx; double qx, qz;
                 uint64_t leak_ec; uint32_t l; uint64_t net_bits, auth_bits; int verified, final_equal;
                 double s0Z, s1Z, phi; int rounds; uint64_t msgs, cbytes; uint64_t ck_a;
                 double t_sim_ms, t_sift_ms, t_pe_ms, t_ec_ms, t_ver_ms, t_pa_ms, t_total_ms;
                 uint64_t afterpulses; double kappa, eta_d; int link; double L_km; } QKDStats;
extern QKDParams QP;
typedef struct KStore KStore;
typedef struct QLink QLink;
QLink *qlink_start(int id, double L_km, int port, KStore *L, KStore *R);
int qlink_nstats(QLink *q); QKDStats *qlink_stat(QLink *q, int i); double qlink_simtime(QLink *q);
/* ---------- keynet.c: key stores, KMEs, trusted nodes ---------- */
void ks_append(KStore *s, const uint8_t *k, uint32_t n, double t_end);
int  ks_pause(KStore *s);
double keynet_simtime(void);          /* slowest link's simulated time */
uint64_t keynet_min_produced(void);   /* least key buffered at any link's leader end */
void trusted_compromise(int t, int on);
int  trusted_dump(int t, const uint8_t kid[KIDLEN], uint8_t *key);
extern QLink *LINKS[4]; extern int NLINKS;

/* ---------- entities.c ---------- */
void gateways_start(void);
void outstations_start(void);
void outstation_set_compromised(int idx);
void proxy_start(void);
int  master_connect(void);
/* one Update Key Change + session + telemetry + command for outstation idx */
int  master_session(int idx);
void attacker_reset(int keep_other);

/* gateway compromise (attacker side) */
int gw_compromise(int g, int on);
int gw_dump(int g, uint8_t kids[][KIDLEN], uint8_t keys[][MAXKEY], int *lens, int max);
int gw_prefetch(int g, const uint8_t kid[KIDLEN]);

/* ---------- attacker modes ---------- */
enum { ATK_NONE, ATK_REDIRECT, ATK_THEFT, ATK_SUBST, ATK_GWDUMP };
typedef struct {
    int mode;
    int victim, accomplice;       /* outstation indices: A and compromised B */
    int g1_window;                /* 0 none, 1 compromised throughout, 2 before delivery then restored */
    int g2_window;                /* 0 none, 1 throughout, 2 before delivery (after G1 restored), 3 after delivery */
    int forge_announce;           /* forge recipient announcements (in-band metadata) */
    int tn;                       /* bitmask of compromised trusted nodes (1 = T1, 2 = T2) */
    int passive;                  /* 1: having learned a key, copy it but never use it */
} Atk;
extern Atk ATK;

/* ---------- judge (ground truth, never read by protocol entities) ---------- */
typedef struct {
    int m_accept, o_accept, o_accept_other;
    int key_known;            /* attacker holds the key the master accepted / intended for the victim */
    int a_accepted_attacker_key; /* victim accepted a key the attacker knows */
    int tel_ok, tel_forged, cmd_ok, cmd_forged;
    double t_ukc_ms, t_sk_ms, t_tel_ms, t_cmd_ms;
    int cmd_acked_unexecuted;     /* master got a command response although the victim never ran it */
    int tel_st;                   /* breaker state in the telemetry the master accepted (+1; 0 none) */
    double shed_kw;               /* load disconnected by commands the master never sent */
    uint8_t K_master[MAXKEY]; int klen;
    /* operator-side monitoring (alarms arrive over a trusted audit channel, not the WAN) */
    double t0;                    /* session start (ms) */
    int d1, d2;                   /* release-audit and delivery-receipt alarms */
    double d1_ms, d2_ms;          /* time of the first alarm after session start */
    double d3_resid;              /* feeder-head residual (kW) */
    int d3_true_change;           /* a breaker actually changed state in this trial */
} Sess;
enum { REL_OK, REL_REFUSED, REL_UNAVAILABLE };
void audit_release(int src, const uint8_t kid[KIDLEN], char who, const char *target, int status);
void mon_end(int idx);
void mon_trial_reset(void);
extern double METER_SD;
void grid_load(const char *dir);
int grid_breaker(int i);
extern Sess J;
extern pthread_mutex_t JM;
void judge_reset(void);
void judge_attacker_learns(const uint8_t *k, int len);
int  judge_attacker_knows(const uint8_t *k, int len);
#endif
