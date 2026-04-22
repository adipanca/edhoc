/*
 * Minimal RFC 2865 RADIUS PAP client used by the AAA-mode benchmark to
 * measure the round-trip cost of a single RADIUS Access-Request /
 * Access-Accept exchange between the EAP authenticator (NAS) and the
 * FreeRADIUS server.
 *
 * The implementation is intentionally small: it only supports PAP, only
 * sends a single request, and validates the response only loosely (we
 * trust the local benchmark loopback transport and only verify the Code
 * field). The packet format follows RFC 2865 §3 and the User-Password
 * encoding follows RFC 2865 §5.2 using MD5 from mbedTLS.
 */

#include "aaa_radius.h"
#include "benchmark.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <mbedtls/md5.h>
#include <mbedtls/md.h>

#define RADIUS_CODE_ACCESS_REQUEST   1
#define RADIUS_CODE_ACCESS_ACCEPT    2
#define RADIUS_CODE_ACCESS_REJECT    3

#define RADIUS_ATTR_USER_NAME        1
#define RADIUS_ATTR_USER_PASSWORD    2
#define RADIUS_ATTR_NAS_IP_ADDRESS   4
#define RADIUS_ATTR_NAS_PORT         5
#define RADIUS_ATTR_MESSAGE_AUTH    80

#define RADIUS_HEADER_LEN           20
#define RADIUS_AUTH_LEN             16
#define RADIUS_MAX_PACKET           4096
#define RADIUS_MAX_PASSWORD         128 /* RFC 2865 limit */

static int append_attr(uint8_t *buf, size_t cap, size_t *off,
                       uint8_t type, const uint8_t *val, size_t vlen)
{
    if (vlen > 253) return -1;
    if (*off + 2 + vlen > cap) return -1;
    buf[(*off)++] = type;
    buf[(*off)++] = (uint8_t)(2 + vlen);
    memcpy(buf + *off, val, vlen);
    *off += vlen;
    return 0;
}

static void random_bytes(uint8_t *out, size_t n)
{
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) {
        ssize_t r = read(fd, out, n);
        close(fd);
        if (r == (ssize_t)n) return;
    }
    /* fallback */
    for (size_t i = 0; i < n; i++) out[i] = (uint8_t)(rand() & 0xff);
}

static void md5_concat(const uint8_t *a, size_t alen,
                       const uint8_t *b, size_t blen,
                       uint8_t out[16])
{
    mbedtls_md5_context ctx;
    mbedtls_md5_init(&ctx);
    mbedtls_md5_starts(&ctx);
    mbedtls_md5_update(&ctx, a, alen);
    mbedtls_md5_update(&ctx, b, blen);
    mbedtls_md5_finish(&ctx, out);
    mbedtls_md5_free(&ctx);
}

static int encode_pap_password(const char *secret, const uint8_t auth[16],
                               const char *password,
                               uint8_t *enc, size_t *enc_len)
{
    size_t plen = strlen(password);
    if (plen == 0 || plen > RADIUS_MAX_PASSWORD) return -1;

    /* Pad to multiple of 16 with zero bytes. */
    size_t padded = ((plen + 15) / 16) * 16;
    uint8_t pad[RADIUS_MAX_PASSWORD] = {0};
    memcpy(pad, password, plen);

    size_t slen = strlen(secret);
    uint8_t b[16];
    const uint8_t *prev = auth;

    for (size_t i = 0; i < padded; i += 16) {
        md5_concat((const uint8_t *)secret, slen, prev, 16, b);
        for (size_t j = 0; j < 16; j++) {
            enc[i + j] = pad[i + j] ^ b[j];
        }
        prev = enc + i;
    }
    *enc_len = padded;
    return 0;
}

int aaa_radius_pap_auth(const char *server_ip,
                        uint16_t server_port,
                        const char *shared_secret,
                        const char *username,
                        const char *password,
                        double *rtt_us,
                        size_t *req_bytes,
                        size_t *resp_bytes)
{
    if (!server_ip || !shared_secret || !username || !password) return -1;

    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) return -2;

    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port = htons(server_port);
    if (inet_pton(AF_INET, server_ip, &dst.sin_addr) != 1) {
        close(sockfd);
        return -3;
    }

    struct timeval rcv_to = {2, 0};
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &rcv_to, sizeof(rcv_to));

    uint8_t pkt[RADIUS_MAX_PACKET];
    memset(pkt, 0, sizeof(pkt));

    uint8_t identifier;
    random_bytes(&identifier, 1);
    uint8_t authenticator[16];
    random_bytes(authenticator, 16);

    pkt[0] = RADIUS_CODE_ACCESS_REQUEST;
    pkt[1] = identifier;
    /* length placeholder at [2..3] */
    memcpy(pkt + 4, authenticator, 16);

    size_t off = RADIUS_HEADER_LEN;

    /* User-Name */
    size_t ulen = strlen(username);
    if (ulen == 0 || ulen > 253) { close(sockfd); return -4; }
    if (append_attr(pkt, sizeof(pkt), &off, RADIUS_ATTR_USER_NAME,
                    (const uint8_t *)username, ulen) != 0) {
        close(sockfd); return -5;
    }

    /* User-Password (PAP encoded) */
    uint8_t enc_pw[RADIUS_MAX_PASSWORD];
    size_t enc_pw_len = 0;
    if (encode_pap_password(shared_secret, authenticator, password,
                            enc_pw, &enc_pw_len) != 0) {
        close(sockfd); return -6;
    }
    if (append_attr(pkt, sizeof(pkt), &off, RADIUS_ATTR_USER_PASSWORD,
                    enc_pw, enc_pw_len) != 0) {
        close(sockfd); return -7;
    }

    /* NAS-IP-Address = 127.0.0.1 */
    uint8_t nas_ip[4] = {127, 0, 0, 1};
    if (append_attr(pkt, sizeof(pkt), &off, RADIUS_ATTR_NAS_IP_ADDRESS,
                    nas_ip, 4) != 0) {
        close(sockfd); return -8;
    }

    /* Message-Authenticator (RFC 3579 §3.2): required by modern
     * FreeRADIUS to mitigate the BlastRADIUS attack. Append the
     * attribute with a zeroed 16-byte placeholder, finalize the
     * packet length, then overwrite the placeholder with
     * HMAC-MD5(secret, full_packet). */
    size_t ma_off = off + 2; /* offset of the value bytes */
    uint8_t ma_zero[16] = {0};
    if (append_attr(pkt, sizeof(pkt), &off, RADIUS_ATTR_MESSAGE_AUTH,
                    ma_zero, 16) != 0) {
        close(sockfd); return -12;
    }

    /* finalize length */
    pkt[2] = (uint8_t)((off >> 8) & 0xff);
    pkt[3] = (uint8_t)(off & 0xff);

    /* Compute HMAC-MD5 over the full packet (with MA = zeros). */
    {
        const mbedtls_md_info_t *mi = mbedtls_md_info_from_type(MBEDTLS_MD_MD5);
        uint8_t mac[16];
        if (!mi || mbedtls_md_hmac(mi,
                                   (const uint8_t *)shared_secret,
                                   strlen(shared_secret),
                                   pkt, off, mac) != 0) {
            close(sockfd); return -13;
        }
        memcpy(pkt + ma_off, mac, 16);
    }

    double t0 = now_us();
    ssize_t sent = sendto(sockfd, pkt, off, 0,
                          (struct sockaddr *)&dst, sizeof(dst));
    if (sent != (ssize_t)off) {
        close(sockfd);
        return -9;
    }

    uint8_t resp[RADIUS_MAX_PACKET];
    ssize_t rlen = recv(sockfd, resp, sizeof(resp), 0);
    double t1 = now_us();
    close(sockfd);

    if (rlen < RADIUS_HEADER_LEN) {
        return -10;
    }
    if (resp[1] != identifier) {
        return -11;
    }

    if (rtt_us) *rtt_us = t1 - t0;
    if (req_bytes) *req_bytes = off;
    if (resp_bytes) *resp_bytes = (size_t)rlen;

    return resp[0]; /* 2 = Accept, 3 = Reject */
}
