#include "qg.h"
#include <string.h>
#include <time.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>

void rnd(void *p, size_t n) { RAND_bytes(p, (int)n); }

double now_ms(void) {
    struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1e3 + t.tv_nsec / 1e6;
}

void hmac256(const uint8_t *k, size_t kl, const uint8_t *m, size_t ml, uint8_t out[32]) {
    unsigned int ol = 32;
    HMAC(EVP_sha256(), k, (int)kl, m, ml, out, &ol);
}

/* Wegman-Carter one-time tag: polynomial hash mod p = 2^61-1 keyed by r, then one-time pad s
 * (addition mod 2^64). Forgery probability <= (#56-bit chunks + 1) / p per tag. */
#define P61 ((1ULL << 61) - 1)
static uint64_t mulmod(uint64_t a, uint64_t b) {
    unsigned __int128 z = (unsigned __int128)a * b;
    uint64_t lo = (uint64_t)(z & P61), hi = (uint64_t)(z >> 61);
    uint64_t s = lo + hi; if (s >= P61) s -= P61; return s;
}
uint64_t wc_tag(const uint8_t r8[8], const uint8_t s8[8], const uint8_t *m, size_t ml) {
    uint64_t r, s; memcpy(&r, r8, 8); memcpy(&s, s8, 8);
    r &= P61; if (r >= P61) r -= P61;
    uint64_t h = 0;
    for (size_t i = 0; i < ml; i += 7) {
        uint64_t c = 0; size_t n = ml - i < 7 ? ml - i : 7;
        memcpy(&c, m + i, n);
        h = mulmod(h + c, r);
    }
    h = mulmod(h + (uint64_t)ml, r);
    return h + s;
}

int aes_wrap(const uint8_t *kek, const uint8_t *in, int inl, uint8_t *out) {
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new(); int l = 0, t = 0;
    EVP_CIPHER_CTX_set_flags(c, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
    EVP_EncryptInit_ex(c, EVP_aes_256_wrap(), NULL, kek, NULL);
    EVP_EncryptUpdate(c, out, &l, in, inl); EVP_EncryptFinal_ex(c, out + l, &t);
    EVP_CIPHER_CTX_free(c); return l + t;
}
int aes_unwrap(const uint8_t *kek, const uint8_t *in, int inl, uint8_t *out) {
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new(); int l = 0, t = 0, ok;
    EVP_CIPHER_CTX_set_flags(c, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
    EVP_DecryptInit_ex(c, EVP_aes_256_wrap(), NULL, kek, NULL);
    ok = EVP_DecryptUpdate(c, out, &l, in, inl) && EVP_DecryptFinal_ex(c, out + l, &t);
    EVP_CIPHER_CTX_free(c); return ok ? l + t : -1;
}

/* DNP3 CRC-16 (poly 0x3D65, reflected), complemented, little-endian on the wire */
uint16_t crc_dnp(const uint8_t *p, size_t n) {
    uint16_t c = 0;
    for (size_t i = 0; i < n; i++) {
        c ^= p[i];
        for (int b = 0; b < 8; b++) c = (c & 1) ? (c >> 1) ^ 0xA6BC : c >> 1;
    }
    return ~c;
}

void hexs(const uint8_t *b, size_t n, char *out) {
    static const char *h = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) { out[2*i] = h[b[i] >> 4]; out[2*i+1] = h[b[i] & 15]; }
    out[2*n] = 0;
}
int unhex(const char *s, uint8_t *b, size_t n) {
    for (size_t i = 0; i < n; i++) {
        unsigned v; if (sscanf(s + 2*i, "%2x", &v) != 1) return -1; b[i] = (uint8_t)v;
    }
    return 0;
}
int b64e(const uint8_t *in, int n, char *out) { return EVP_EncodeBlock((unsigned char *)out, in, n); }
int b64d(const char *in, uint8_t *out) {
    int L = (int)strlen(in), n = EVP_DecodeBlock(out, (const unsigned char *)in, L);
    if (n < 0) return -1;
    while (L > 0 && in[L-1] == '=') { n--; L--; }
    return n;
}
