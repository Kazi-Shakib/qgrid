/* DNP3 (IEEE 1815-2012) transport and application layers used by the testbed.
 * Link layer frames (0x0564, CRC per 16-byte block) are in net.c. This file adds transport
 * segmentation/reassembly (FIR/FIN/sequence), application headers (AC, FC, IIN), and object
 * encoding/parsing for the objects the testbed uses:
 *   g1v2  binary input with flags        (qualifier 0x00, 1 byte)
 *   g12v1 control relay output block     (qualifier 0x17, 11 bytes)
 *   g30v5 analog input, 32-bit float     (qualifier 0x00, 5 bytes)
 *   g60v1 class 0 data                   (qualifier 0x06)
 *   g120  Secure Authentication objects  (qualifier 0x5B, free format)                   */
#include "qg.h"
#include <string.h>
#include <stdio.h>

/* ---------------- transport ---------------- */
/* link frames for one ASDU, segmented into transport segments of at most 249 bytes of user data */
int dnp3_frames(uint8_t *out, uint16_t dst, uint16_t src, const uint8_t *asdu, int n) {
    static uint8_t seq; uint8_t seg[256];
    int off = 0, first = 1, tot = 0;
    do {
        int chunk = n - off > 249 ? 249 : n - off;
        uint8_t th = (uint8_t)(__atomic_fetch_add(&seq, 1, __ATOMIC_RELAXED) & 0x3F);
        if (first) th |= 0x40;
        if (off + chunk == n) th |= 0x80;
        seg[0] = th; memcpy(seg + 1, asdu + off, chunk);
        tot += dnp_build_raw(out + tot, dst, src, seg, chunk + 1);
        off += chunk; first = 0;
    } while (off < n);
    return tot;
}
int dnp3_send(int fd, uint16_t dst, uint16_t src, const uint8_t *asdu, int n) {
    uint8_t f[4096]; int fl = dnp3_frames(f, dst, src, asdu, n);
    __atomic_add_fetch(&wan_bytes, fl, __ATOMIC_RELAXED);
    return send_all(fd, f, fl);
}
int dnp3_recv(int fd, uint16_t *dst, uint16_t *src, uint8_t *asdu, int max, int tmo) {
    uint8_t seg[260]; int n = 0, started = 0;
    for (;;) {
        int sl = dnp_recv_raw(fd, dst, src, seg, sizeof seg, tmo); if (sl < 1) return -1;
        uint8_t th = seg[0];
        if (th & 0x40) { n = 0; started = 1; }
        if (!started) continue;
        if (n + sl - 1 > max) return -1;
        memcpy(asdu + n, seg + 1, sl - 1); n += sl - 1;
        if (th & 0x80) return n;
    }
}

/* ---------------- application layer ---------------- */
static uint8_t app_seq;
int app_req(uint8_t *a, uint8_t fc) { a[0] = 0xC0 | (app_seq++ & 0x0F); a[1] = fc; return 2; }
int app_rsp(uint8_t *a, uint8_t fc, uint16_t iin) { a[0] = 0xC0 | (app_seq++ & 0x0F); a[1] = fc; a[2] = iin & 0xFF; a[3] = iin >> 8; return 4; }
int app_hlen(const uint8_t *a) { return (a[1] == FC_RESPONSE || a[1] == FC_UNSOLICITED || a[1] == FC_AUTH_RESPONSE) ? 4 : 2; }

int obj_g120(uint8_t *p, int var, const void *data, int len) {
    p[0] = 120; p[1] = (uint8_t)var; p[2] = 0x5B; p[3] = 1; p[4] = len & 0xFF; p[5] = len >> 8;
    memcpy(p + 6, data, len); return 6 + len;
}
int obj_class0(uint8_t *p) { p[0] = 60; p[1] = 1; p[2] = 0x06; return 3; }
int obj_crob(uint8_t *p, uint8_t index, uint8_t code, uint8_t status) {
    p[0] = 12; p[1] = 1; p[2] = 0x17; p[3] = 1; p[4] = index;
    p[5] = code; p[6] = 1; uint32_t on = 1000, off = 0; memcpy(p + 7, &on, 4); memcpy(p + 11, &off, 4); p[15] = status;
    return 16;
}
int obj_binary(uint8_t *p, uint8_t index, int state) {
    p[0] = 1; p[1] = 2; p[2] = 0x00; p[3] = index; p[4] = index; p[5] = 0x01 | (state ? 0x80 : 0); return 6;
}
int obj_analog_f(uint8_t *p, uint8_t index, float v) {
    p[0] = 30; p[1] = 5; p[2] = 0x00; p[3] = index; p[4] = index; p[5] = 0x01; memcpy(p + 6, &v, 4); return 10;
}
static int obj_size(int g, int v) {
    if (g == 1 && v == 2) return 1;
    if (g == 12 && v == 1) return 11;
    if (g == 30 && v == 5) return 5;
    return -1;
}
/* walk the objects of an ASDU; returns pointer to the data of the first object (g,v) and its length */
const uint8_t *find_obj(const uint8_t *a, int n, int g, int v, int *len) {
    int p = app_hlen(a);
    while (p + 3 <= n) {
        int og = a[p], ov = a[p + 1], q = a[p + 2]; p += 3;
        const uint8_t *data; int dl;
        if (q == 0x5B) { if (p + 3 > n) return NULL; dl = a[p + 1] | a[p + 2] << 8; data = a + p + 3; p += 3 + dl; }
        else if (q == 0x06) { data = a + p; dl = 0; }
        else if (q == 0x00) { int cnt = a[p + 1] - a[p] + 1, s = obj_size(og, ov); if (s < 0) return NULL; data = a + p + 2; dl = cnt * s; p += 2 + dl; }
        else if (q == 0x17) { int cnt = a[p], s = obj_size(og, ov); if (s < 0) return NULL; data = a + p + 1; dl = cnt * (s + 1); p += 1 + dl; }
        else return NULL;
        if (p > n) return NULL;
        if (og == g && ov == v) { if (len) *len = dl; return data; }
    }
    return NULL;
}
