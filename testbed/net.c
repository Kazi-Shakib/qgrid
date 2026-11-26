#include "qg.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <poll.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <openssl/err.h>
#include <openssl/x509.h>

uint64_t wan_bytes, local_bytes, api_bytes, kme_link_bytes;

int tcp_listen(int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0), one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons(port),
                             .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
    if (bind(fd, (void *)&a, sizeof a) || listen(fd, 256)) { perror("listen"); exit(1); }
    return fd;
}
int tcp_accept(int lfd) {
    int fd = accept(lfd, NULL, NULL), one = 1;
    if (fd >= 0) setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
    return fd;
}
int tcp_connect(int port) {
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons(port),
                             .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
    for (int tries = 0; tries < 200; tries++) {
        int fd = socket(AF_INET, SOCK_STREAM, 0), one = 1;
        if (connect(fd, (void *)&a, sizeof a) == 0) {
            setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one); return fd;
        }
        close(fd); usleep(10000);
    }
    fprintf(stderr, "connect %d failed\n", port); exit(1);
}
int send_all(int fd, const void *p, size_t n) {
    const uint8_t *b = p;
    while (n) { ssize_t k = send(fd, b, n, MSG_NOSIGNAL); if (k <= 0) return -1; b += k; n -= k; }
    return 0;
}
int recv_all(int fd, void *p, size_t n, int tmo) {
    uint8_t *b = p;
    while (n) {
        if (tmo >= 0) {
            struct pollfd pf = { fd, POLLIN, 0 };
            int r = poll(&pf, 1, tmo); if (r <= 0) return -1;
        }
        ssize_t k = recv(fd, b, n, 0); if (k <= 0) return -1; b += k; n -= k;
    }
    return 0;
}
int msg_send(int fd, const void *p, uint32_t n) {
    uint8_t h[4]; memcpy(h, &n, 4);
    if (send_all(fd, h, 4)) return -1;
    return send_all(fd, p, n);
}
int msg_recv(int fd, void *p, uint32_t max, int tmo) {
    uint32_t n; if (recv_all(fd, &n, 4, tmo)) return -1;
    if (n > max) return -1;
    if (recv_all(fd, p, n, tmo)) return -1;
    return (int)n;
}

/* ---------- DNP3 link layer ---------- */
int dnp_build_raw(uint8_t *out, uint16_t dst, uint16_t src, const uint8_t *ud, int udl) {
    if (udl > 250) return -1;
    uint8_t *o = out;
    o[0] = 0x05; o[1] = 0x64; o[2] = (uint8_t)(5 + udl); o[3] = 0xC4;
    o[4] = dst & 0xFF; o[5] = dst >> 8; o[6] = src & 0xFF; o[7] = src >> 8;
    uint16_t c = crc_dnp(o, 8); o[8] = c & 0xFF; o[9] = c >> 8;
    int n = 10;
    for (int i = 0; i < udl; i += 16) {
        int bl = udl - i < 16 ? udl - i : 16;
        memcpy(out + n, ud + i, bl); c = crc_dnp(ud + i, bl);
        out[n + bl] = c & 0xFF; out[n + bl + 1] = c >> 8; n += bl + 2;
    }
    return n;
}
static int frame_len2(int udl) { return 10 + udl + 2 * ((udl + 15) / 16); }
int dnp_recv_raw(int fd, uint16_t *dst, uint16_t *src, uint8_t *ud, int max, int tmo) {
    uint8_t r[400];
    if (recv_all(fd, r, 10, tmo)) return -1;
    if (r[0] != 0x05 || r[1] != 0x64) return -1;
    uint16_t c = crc_dnp(r, 8); if ((r[8] | r[9] << 8) != c) return -1;
    int udl = r[2] - 5, fl = frame_len2(udl);
    if (recv_all(fd, r + 10, fl - 10, tmo)) return -1;
    int n = 10, k = 0;
    for (int i = 0; i < udl; i += 16) {
        int bl = udl - i < 16 ? udl - i : 16;
        c = crc_dnp(r + n, bl); if ((r[n+bl] | r[n+bl+1] << 8) != c) return -1;
        if (k + bl > max) return -1;
        memcpy(ud + k, r + n, bl); k += bl; n += bl + 2;
    }
    *dst = r[4] | r[5] << 8; *src = r[6] | r[7] << 8;
    return k;
}
int dnp_build(uint8_t *out, uint16_t dst, uint16_t src, const uint8_t *app, int appl) {
    static uint8_t tseq; uint8_t ud[256];
    if (appl > 249) return -1;
    ud[0] = 0xC0 | (tseq++ & 0x3F);                       /* transport: FIR|FIN */
    memcpy(ud + 1, app, appl); int udl = appl + 1;
    uint8_t *o = out;
    o[0] = 0x05; o[1] = 0x64; o[2] = (uint8_t)(5 + udl); o[3] = 0xC4; /* DIR|PRM, unconfirmed user data */
    o[4] = dst & 0xFF; o[5] = dst >> 8; o[6] = src & 0xFF; o[7] = src >> 8;
    uint16_t c = crc_dnp(o, 8); o[8] = c & 0xFF; o[9] = c >> 8;
    int n = 10;
    for (int i = 0; i < udl; i += 16) {
        int bl = udl - i < 16 ? udl - i : 16;
        memcpy(out + n, ud + i, bl); c = crc_dnp(ud + i, bl);
        out[n + bl] = c & 0xFF; out[n + bl + 1] = c >> 8; n += bl + 2;
    }
    return n;
}
int dnp_send(int fd, uint16_t dst, uint16_t src, const uint8_t *app, int appl) {
    uint8_t f[400]; int n = dnp_build(f, dst, src, app, appl);
    __atomic_add_fetch(&wan_bytes, n, __ATOMIC_RELAXED);
    return send_all(fd, f, n);
}
int dnp_parse(const uint8_t *raw, int rawl, uint16_t *dst, uint16_t *src, uint8_t *app, int max) {
    if (rawl < 10 || raw[0] != 0x05 || raw[1] != 0x64) return -1;
    uint16_t c = crc_dnp(raw, 8); if ((raw[8] | raw[9] << 8) != c) return -1;
    int udl = raw[2] - 5, n = 10, k = 0; uint8_t ud[256];
    for (int i = 0; i < udl; i += 16) {
        int bl = udl - i < 16 ? udl - i : 16;
        if (n + bl + 2 > rawl) return -1;
        c = crc_dnp(raw + n, bl); if ((raw[n+bl] | raw[n+bl+1] << 8) != c) return -1;
        memcpy(ud + k, raw + n, bl); k += bl; n += bl + 2;
    }
    *dst = raw[4] | raw[5] << 8; *src = raw[6] | raw[7] << 8;
    if (udl - 1 > max) return -1;
    memcpy(app, ud + 1, udl - 1); return udl - 1;
}
static int frame_len(int udl) { return 10 + udl + 2 * ((udl + 15) / 16); }
int dnp_recv(int fd, uint16_t *dst, uint16_t *src, uint8_t *app, int max, int tmo, uint8_t *raw, int *rawl) {
    uint8_t buf[400]; uint8_t *r = raw ? raw : buf;
    if (recv_all(fd, r, 10, tmo)) return -1;
    int fl = frame_len(r[2] - 5);
    if (recv_all(fd, r + 10, fl - 10, tmo)) return -1;
    if (rawl) *rawl = fl;
    return dnp_parse(r, fl, dst, src, app, max);
}

/* ---------- TLS with client certificates ---------- */
static void load(SSL_CTX *c, const char *name) {
    char p[256];
    snprintf(p, sizeof p, "certs/%s.crt", name);
    if (SSL_CTX_use_certificate_file(c, p, SSL_FILETYPE_PEM) != 1) { ERR_print_errors_fp(stderr); exit(1); }
    snprintf(p, sizeof p, "certs/%s.key", name);
    if (SSL_CTX_use_PrivateKey_file(c, p, SSL_FILETYPE_PEM) != 1) { ERR_print_errors_fp(stderr); exit(1); }
    SSL_CTX_load_verify_locations(c, "certs/ca.crt", NULL);
    SSL_CTX_set_verify(c, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    SSL_CTX_set_min_proto_version(c, TLS1_3_VERSION);
}
SSL_CTX *tls_server_ctx(const char *n) { SSL_CTX *c = SSL_CTX_new(TLS_server_method()); load(c, n); return c; }
SSL_CTX *tls_client_ctx(const char *n) { SSL_CTX *c = SSL_CTX_new(TLS_client_method()); load(c, n); return c; }
SSL *tls_accept(SSL_CTX *ctx, int fd) {
    SSL *s = SSL_new(ctx); SSL_set_fd(s, fd);
    if (SSL_accept(s) != 1) { SSL_free(s); return NULL; } return s;
}
SSL *tls_connect(SSL_CTX *ctx, int fd) {
    SSL *s = SSL_new(ctx); SSL_set_fd(s, fd);
    if (SSL_connect(s) != 1) { ERR_print_errors_fp(stderr); SSL_free(s); return NULL; } return s;
}
const char *tls_peer_cn(SSL *s, char *buf, int n) {
    X509 *x = SSL_get1_peer_certificate(s); buf[0] = 0;
    if (x) { X509_NAME_get_text_by_NID(X509_get_subject_name(x), NID_commonName, buf, n); X509_free(x); }
    return buf;
}
static int ssl_read_all(SSL *s, char *p, int n) {
    while (n > 0) { int k = SSL_read(s, p, n); if (k <= 0) return -1; p += k; n -= k; } return 0;
}
static int read_http(SSL *s, char *hdr, int hmax, char *body, int bmax) {
    int n = 0;
    while (n < hmax - 1) {
        if (SSL_read(s, hdr + n, 1) != 1) return -1;
        n++; hdr[n] = 0;
        if (n >= 4 && !memcmp(hdr + n - 4, "\r\n\r\n", 4)) break;
    }
    char *cl = strstr(hdr, "Content-Length:"); int L = cl ? atoi(cl + 15) : 0;
    if (L >= bmax) return -1;
    if (ssl_read_all(s, body, L)) return -1;
    body[L] = 0;
    __atomic_add_fetch(&api_bytes, n + L, __ATOMIC_RELAXED);
    return L;
}
int http_post(SSL *s, const char *path, const char *body, char *resp, int max) {
    char req[16384]; int bl = (int)strlen(body);
    int n = snprintf(req, sizeof req, "POST %s HTTP/1.1\r\nHost: kme\r\nContent-Type: application/json\r\n"
                     "Content-Length: %d\r\n\r\n%s", path, bl, body);
    __atomic_add_fetch(&api_bytes, n, __ATOMIC_RELAXED);
    if (SSL_write(s, req, n) != n) return -1;
    char hdr[2048]; if (read_http(s, hdr, sizeof hdr, resp, max) < 0) return -1;
    return atoi(hdr + 9);              /* HTTP status code */
}
int http_read_req(SSL *s, char *path, int pmax, char *body, int bmax) {
    char hdr[2048]; if (read_http(s, hdr, sizeof hdr, body, bmax) < 0) return -1;
    if (sscanf(hdr, "POST %255s", path) != 1) return -1;
    (void)pmax;
    return 0;
}
int http_reply(SSL *s, int code, const char *body) {
    char r[16384]; int bl = (int)strlen(body);
    int n = snprintf(r, sizeof r, "HTTP/1.1 %d %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s",
                     code, code == 200 ? "OK" : "Error", bl, body);
    __atomic_add_fetch(&api_bytes, n, __ATOMIC_RELAXED);
    return SSL_write(s, r, n) == n ? 0 : -1;
}
