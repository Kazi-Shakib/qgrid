/* qgrid driver.  Usage: ./qgrid key=value ...   (see README)
 * run=security : N sessions against the victim under one attacker scenario, prints one JSON line
 * run=supply   : honest associations re-keyed every epoch against a rate-limited QKD link
 * run=bench    : microbenchmarks of the MAC and key-wrap primitives */
#include "qg.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/resource.h>
#include <math.h>

static void pr_stats(const char *label, QKDStats *q);

static int cmpd(const void *a, const void *b) { double x = *(double *)a, y = *(double *)b; return x < y ? -1 : x > y; }
static double pct(double *v, int n, double p) { if (!n) return -1; qsort(v, n, sizeof *v, cmpd); return v[(int)(p * (n - 1))]; }

static void bench(void) {
    uint8_t k[32], m[96], out[32], r[8], s[8], w[80], sk[64]; rnd(k, 32); rnd(m, 96); rnd(r, 8); rnd(s, 8); rnd(sk, 64);
    int N = 200000; volatile uint64_t acc = 0; double t0;
    for (int i = 0; i < N; i++) { m[0] = i; hmac256(k, 32, m, 76, out); acc += out[0]; acc += wc_tag(r, s, m, 76); }  /* warm-up */
    t0 = now_ms(); for (int i = 0; i < N; i++) { m[0] = i; hmac256(k, 32, m, 15, out); acc += out[0]; }
    double h15 = (now_ms() - t0) * 1e3 / N;
    t0 = now_ms(); for (int i = 0; i < N; i++) { m[0] = i; acc += wc_tag(r, s, m, 15); }
    double w15 = (now_ms() - t0) * 1e3 / N;
    t0 = now_ms(); for (int i = 0; i < N; i++) { m[0] = i; hmac256(k, 32, m, 76, out); acc += out[0]; }
    double h76 = (now_ms() - t0) * 1e3 / N;
    t0 = now_ms(); for (int i = 0; i < N; i++) { m[0] = i; acc += wc_tag(r, s, m, 76); }
    double w76 = (now_ms() - t0) * 1e3 / N;
    t0 = now_ms(); for (int i = 0; i < N / 10; i++) { sk[0] = i; acc += aes_wrap(k, sk, 64, w); }
    double aw = (now_ms() - t0) * 1e3 / (N / 10);
    printf("{\"run\":\"bench\",\"hmac_15B_us\":%.3f,\"wc_15B_us\":%.3f,\"hmac_76B_us\":%.3f,\"wc_76B_us\":%.3f,\"aeswrap_64B_us\":%.3f}\n",
           h15, w15, h76, w76, aw);
}

int main(int argc, char **argv) {
    char run[64] = "security", label[64] = "x", residf[256] = ""; int n = 100, epoch_s = 20, epochs = 4, warm = 0;
    C = (Cfg){ .npath = 1, .bind = 0, .erase = 1, .meta = META_NONE, .oid = 0, .sae = 0, .its = 0,
               .msgs_per_epoch = 20, .qkd_bps = 0, .base_port = 20000, .nout = 3, .timeout_ms = 300, .route2 = 1 };
    ATK = (Atk){ .mode = ATK_NONE, .victim = 0, .accomplice = 1 };
    for (int i = 1; i < argc; i++) {
        char k[32]; char v[64]; if (sscanf(argv[i], "%31[^=]=%63s", k, v) != 2) continue;
        if (!strcmp(k, "run")) snprintf(run, sizeof run, "%s", v);
        else if (!strcmp(k, "label")) snprintf(label, sizeof label, "%s", v);
        else if (!strcmp(k, "n")) n = atoi(v);
        else if (!strcmp(k, "npath")) C.npath = atoi(v);
        else if (!strcmp(k, "bind")) C.bind = atoi(v);
        else if (!strcmp(k, "erase")) C.erase = atoi(v);
        else if (!strcmp(k, "meta")) C.meta = atoi(v);
        else if (!strcmp(k, "oid")) C.oid = atoi(v);
        else if (!strcmp(k, "sae")) C.sae = atoi(v);
        else if (!strcmp(k, "its")) C.its = atoi(v);
        else if (!strcmp(k, "mpe")) C.msgs_per_epoch = atoi(v);
        else if (!strcmp(k, "qkd")) C.qkd_bps = atof(v);
        else if (!strcmp(k, "port")) C.base_port = atoi(v);
        else if (!strcmp(k, "nout")) C.nout = atoi(v);
        else if (!strcmp(k, "tmo")) C.timeout_ms = atoi(v);
        else if (!strcmp(k, "mode")) ATK.mode = atoi(v);
        else if (!strcmp(k, "g1")) ATK.g1_window = atoi(v);
        else if (!strcmp(k, "g2")) ATK.g2_window = atoi(v);
        else if (!strcmp(k, "fa")) ATK.forge_announce = atoi(v);
        else if (!strcmp(k, "epoch")) epoch_s = atoi(v);
        else if (!strcmp(k, "epochs")) epochs = atoi(v);
        else if (!strcmp(k, "qm")) C.qkd_mode = atoi(v);
        else if (!strcmp(k, "dist")) QP.L_km = atof(v);
        else if (!strcmp(k, "nz")) QP.nZ = (uint32_t)atof(v);
        else if (!strcmp(k, "blocks")) QP.max_blocks = atoi(v);
        else if (!strcmp(k, "emis")) QP.e_mis = atof(v);
        else if (!strcmp(k, "simclock")) C.simclock = atoi(v);
        else if (!strcmp(k, "reserve")) C.qkd_reserve = (uint64_t)atof(v);
        else if (!strcmp(k, "topo")) C.topo = atoi(v);
        else if (!strcmp(k, "route2")) C.route2 = atoi(v);
        else if (!strcmp(k, "L1")) C.L1 = atof(v);
        else if (!strcmp(k, "L2")) C.L2 = atof(v);
        else if (!strcmp(k, "wan")) C.wan_ms = atof(v);
        else if (!strcmp(k, "jit")) C.wan_jit = atof(v);
        else if (!strcmp(k, "loss")) C.wan_loss = atof(v);
        else if (!strcmp(k, "tn")) ATK.tn = atoi(v);
        else if (!strcmp(k, "det")) QP.realistic = atoi(v);
        else if (!strcmp(k, "ap")) QP.p_ap = atof(v);
        else if (!strcmp(k, "dead")) QP.dead_ns = atof(v);
        else if (!strcmp(k, "eta1")) QP.eta_det1 = atof(v);
        else if (!strcmp(k, "warm")) warm = atoi(v);
        else if (!strcmp(k, "victim")) ATK.victim = atoi(v);
        else if (!strcmp(k, "passive")) ATK.passive = atoi(v);
        else if (!strcmp(k, "meter")) METER_SD = atof(v);
        else if (!strcmp(k, "mseed")) { extern unsigned meter_seed; meter_seed = (unsigned)atoi(v); }
        else if (!strcmp(k, "resid")) snprintf(residf, sizeof residf, "%s", v);
        else if (!strcmp(k, "acc")) ATK.accomplice = atoi(v);
    }
    if (!C.L1) C.L1 = QP.L_km;
    if (!C.L2) C.L2 = C.L1;
    if (!strcmp(run, "bench")) { bench(); return 0; }
    if (!C.qkd_reserve) C.qkd_reserve = 1 << 18;
    if (!strcmp(run, "qkd")) {                       /* QKD stack alone: run a number of blocks, report each */
        C.qkd_mode = 2; C.qkd_reserve = ~0ULL; if (!QP.max_blocks) QP.max_blocks = 5;
        qkd_start();
        for (;;) { int done = 1; for (int i = 0; i < NLINKS; i++) done &= qlink_nstats(LINKS[i]) >= QP.max_blocks; if (done) break; usleep(100000); }
        usleep(300000);
        for (int l = 0; l < NLINKS; l++) for (int i = 0; i < qlink_nstats(LINKS[l]) && i < 256; i++) pr_stats(label, qlink_stat(LINKS[l], i));
        fflush(stdout); _exit(0);
    }
    struct rlimit rl; getrlimit(RLIMIT_NOFILE, &rl); rl.rlim_cur = rl.rlim_max; setrlimit(RLIMIT_NOFILE, &rl);
    if (access("certs/ca.crt", R_OK)) { if (system("sh mkcerts.sh >/dev/null 2>&1")) return 1; }
    int comp_b = (ATK.mode == ATK_THEFT || ATK.mode == ATK_GWDUMP || ATK.forge_announce);
    if (comp_b) outstation_set_compromised(ATK.accomplice);
    if (strcmp(run, "security")) ATK.victim = -1;          /* supply runs: no victim, no attacker */

    grid_load("grid");
    for (int t = 1; t <= 2; t++) if (ATK.tn >> (t - 1) & 1) trusted_compromise(t, 1);
    qkd_start(); kme_start(); gateways_start(); outstations_start(); proxy_start();
    if (master_connect()) { fprintf(stderr, "master connect failed\n"); return 1; }
    if (C.qkd_mode == 2 && !C.simclock) {          /* let the BB84 stack fill the key store, then it pauses */
        while (keynet_min_produced() < C.qkd_reserve) usleep(50000);
        usleep(200000);
    }

    if (!strcmp(run, "supply")) {
        /* every epoch, every association runs an Update Key Change carrying its tag pool, then one
         * authenticated poll and command; count associations that obtained key in each epoch */
        int served = 0, tried = 0; double t_start = now_ms();
        for (int e = 0; e < epochs; e++) {
            if (C.qkd_mode == 2 && C.simclock) {           /* advance simulated time to the end of the epoch */
                C.sim_now = (e + 1) * (double)epoch_s;
                while (keynet_simtime() < C.sim_now) usleep(20000);
            } else {
                double te = t_start + (e + 1) * epoch_s * 1000.0;
                while (now_ms() < te) usleep(20000);       /* key accumulates for one epoch */
            }
            int ok = 0;
            for (int i = 0; i < C.nout; i++) { judge_reset(); int r = master_session(i); ok += (r == 0); if (e >= warm) { tried++; served += (r == 0); } }
            fprintf(stderr, "epoch %d served %d/%d\n", e, ok, C.nout);
        }
        printf("{\"run\":\"supply\",\"label\":\"%s\",\"npath\":%d,\"nout\":%d,\"qkd_bps\":%.0f,\"epoch_s\":%d,\"mpe\":%d,"
               "\"served\":%d,\"tried\":%d,\"frac\":%.4f,\"qkd_bytes\":%llu,\"starved\":%llu,\"qm\":%d,\"topo\":%d,\"L1\":%.0f,\"L2\":%.0f,\"det\":%d,\"sim_s\":%.1f}\n",
               label, C.npath, C.nout, C.qkd_bps, epoch_s, C.msgs_per_epoch, served, tried, (double)served / tried,
               (unsigned long long)qkd_consumed(), (unsigned long long)qkd_starved(), C.qkd_mode, C.topo, C.L1, C.topo ? C.L2 : 0, QP.realistic, keynet_simtime());
        fflush(stdout); _exit(0);
    }

    /* security / performance: n sessions with the victim */
    int c[16] = {0}; double *tu = malloc(sizeof(double) * n), *ts = malloc(sizeof(double) * n), *tt = malloc(sizeof(double) * n),
        *tc = malloc(sizeof(double) * n), shed = 0; int ntu = 0, nts = 0, ntt = 0, ntc = 0;
    double *d1t = malloc(sizeof(double) * n), *d2t = malloc(sizeof(double) * n); int nd1 = 0, nd2 = 0;
    FILE *rf = residf[0] ? fopen(residf, "a") : NULL;
    uint64_t w0 = wan_bytes, l0 = local_bytes, a0 = api_bytes, k0 = kme_link_bytes, q0 = qkd_consumed();
    for (int s = 0; s < n; s++) {
        C.minute = (s * 15) % 1440; judge_reset(); attacker_reset(0); mon_trial_reset();
        if (ATK.mode == ATK_SUBST) { master_session(ATK.accomplice); judge_reset(); attacker_reset(1); }
        master_session(ATK.victim);
        usleep(ATK.mode == ATK_NONE ? 0 : 60000);         /* let injected traffic settle */
        mon_end(ATK.victim);
        pthread_mutex_lock(&JM); Sess S = J; pthread_mutex_unlock(&JM);
        c[13] += S.d1 > 0; c[14] += S.d2 > 0; c[15] += S.d3_true_change;
        if (S.d1) d1t[nd1++] = S.d1_ms;
        if (S.d2) d2t[nd2++] = S.d2_ms;
        if (rf) fprintf(rf, "{\"label\":\"%s\",\"mode\":%d,\"bind\":%d,\"npath\":%d,\"erase\":%d,\"passive\":%d,\"victim\":%d,\"s\":%d,\"minute\":%d,"
                            "\"resid\":%.2f,\"open\":%d,\"rep\":%d,\"d1\":%d,\"d2\":%d,\"known\":%d}\n",
                        label, ATK.mode, C.bind, C.npath, C.erase, ATK.passive, ATK.victim, s, C.minute, S.d3_resid, S.d3_true_change, S.tel_st,
                        S.d1 > 0, S.d2 > 0, S.klen && judge_attacker_knows(S.K_master, S.klen));
        int known = S.klen && judge_attacker_knows(S.K_master, S.klen);
        c[0] += S.m_accept; c[1] += S.o_accept; c[2] += S.o_accept_other;
        c[3] += known; c[4] += S.a_accepted_attacker_key;
        c[5] += S.tel_ok; c[6] += S.tel_forged; c[7] += S.cmd_ok; c[8] += S.cmd_forged;
        c[9] += (S.m_accept && !S.o_accept);              /* master accepted a key the victim does not hold */
        int victim_open = ATK.victim >= 0 && !grid_breaker(ATK.victim);
        c[10] += S.cmd_acked_unexecuted; c[11] += (S.tel_st == 2 && victim_open); c[12] += victim_open; shed += S.shed_kw;
        if (S.m_accept && S.o_accept) { tu[ntu++] = S.t_ukc_ms; if (!C.its) ts[nts++] = S.t_sk_ms; }
        if (S.t_tel_ms > 0) tt[ntt++] = S.t_tel_ms;
        if (S.t_cmd_ms > 0) tc[ntc++] = S.t_cmd_ms;
    }
    double med = pct(tu, ntu, 0.5), p95 = pct(tu, ntu, 0.95);
    double skm = pct(ts, nts, 0.5), tlm = pct(tt, ntt, 0.5), tl95 = pct(tt, ntt, 0.95), cmm = pct(tc, ntc, 0.5), cm95 = pct(tc, ntc, 0.95);
    printf("{\"run\":\"security\",\"label\":\"%s\",\"n\":%d,\"npath\":%d,\"bind\":%d,\"erase\":%d,\"meta\":%d,\"oid\":%d,\"sae\":%d,\"its\":%d,"
           "\"mode\":%d,\"g1\":%d,\"g2\":%d,\"fa\":%d,\"tn\":%d,\"victim\":%d,\"topo\":%d,\"route2\":%d,\"wan_ms\":%.1f,\"jit\":%.1f,\"loss\":%.3f,"
           "\"m_accept\":%d,\"victim_accept\":%d,\"other_accepts_victim_key\":%d,\"master_accepts_unheld_key\":%d,"
           "\"attacker_knows_key\":%d,\"victim_accepts_attacker_key\":%d,"
           "\"tel_ok\":%d,\"tel_forged\":%d,\"cmd_ok\":%d,\"cmd_forged\":%d,"
           "\"cmd_ack_unexecuted\":%d,\"tel_masked\":%d,\"breaker_open\":%d,\"shed_kw_total\":%.1f,"
           "\"ukc_ms_median\":%.3f,\"ukc_ms_p95\":%.3f,\"sk_ms_median\":%.3f,\"tel_ms_median\":%.3f,\"tel_ms_p95\":%.3f,\"cmd_ms_median\":%.3f,\"cmd_ms_p95\":%.3f,\"wan_B\":%.1f,\"local_B\":%.1f,\"api_B\":%.1f,\"kmelink_B\":%.1f,\"qkd_B\":%.1f,\"passive\":%d,\"d1_sessions\":%d,\"d2_sessions\":%d,\"d1_ms_median\":%.3f,\"d2_ms_median\":%.3f,\"trips\":%d}\n",
           label, n, C.npath, C.bind, C.erase, C.meta, C.oid, C.sae, C.its, ATK.mode, ATK.g1_window, ATK.g2_window, ATK.forge_announce,
           ATK.tn, ATK.victim, C.topo, C.route2, C.wan_ms, C.wan_jit, C.wan_loss,
           c[0], c[1], c[2], c[9], c[3], c[4], c[5], c[6], c[7], c[8], c[10], c[11], c[12], shed, med, p95, skm, tlm, tl95, cmm, cm95,
           (double)(wan_bytes - w0) / n, (double)(local_bytes - l0) / n, (double)(api_bytes - a0) / n,
           (double)(kme_link_bytes - k0) / n, (double)(qkd_consumed() - q0) / n,
           ATK.passive, c[13], c[14], pct(d1t, nd1, 0.5), pct(d2t, nd2, 0.5), c[15]);
    if (rf) fclose(rf);
    fflush(stdout); _exit(0);
}

static void pr_stats(const char *label, QKDStats *q) {
    printf("{\"run\":\"qkd\",\"label\":\"%s\",\"link\":%d,\"L_km\":%.0f,\"det\":%d,\"blk\":%d,\"pulses\":%.4g,\"sim_s\":%.4f,\"detections\":%llu,"
           "\"afterpulses\":%llu,\"kappa\":%.5f,\"eta_d\":%.3f,"
           "\"nz\":%u,\"nx\":%u,\"qx\":%.5f,\"qz\":%.5f,\"leak_ec\":%llu,\"f_ec\":%.4f,\"rounds\":%d,\"s0Z\":%.1f,\"s1Z\":%.1f,\"phi\":%.5f,"
           "\"l\":%u,\"net_bits\":%llu,\"auth_bits\":%llu,\"verified\":%d,\"equal\":%d,\"msgs\":%llu,\"cbytes\":%llu,"
           "\"t_sim\":%.1f,\"t_sift\":%.1f,\"t_pe\":%.1f,\"t_ec\":%.1f,\"t_ver\":%.1f,\"t_pa\":%.1f,\"t_total\":%.1f}\n",
           label, q->link, q->L_km, QP.realistic, q->blk, q->pulses, q->sim_s, (unsigned long long)q->detections,
           (unsigned long long)q->afterpulses, q->kappa, q->eta_d, q->nz, q->nx, q->qx, q->qz,
           (unsigned long long)q->leak_ec, q->qz > 0 ? (double)q->leak_ec / (q->nz * (-q->qz*log2(q->qz)-(1-q->qz)*log2(1-q->qz))) : 0,
           q->rounds, q->s0Z, q->s1Z, q->phi, q->l, (unsigned long long)q->net_bits, (unsigned long long)q->auth_bits,
           q->verified, q->final_equal, (unsigned long long)q->msgs, (unsigned long long)q->cbytes,
           q->t_sim_ms, q->t_sift_ms, q->t_pe_ms, q->t_ec_ms, q->t_ver_ms, q->t_pa_ms, q->t_total_ms);
}
