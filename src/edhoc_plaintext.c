#include "edhoc_plaintext.h"

#include <string.h>

static void put_u16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)((v >> 8) & 0xFF);
    p[1] = (uint8_t)(v & 0xFF);
}

static uint16_t get_u16(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

int encode_plaintext2(uint8_t *out, size_t cap, size_t *out_len,
                      uint8_t c_r,
                      const uint8_t id_cred_r[EDHOC_ID_CRED_LEN],
                      const uint8_t th2[32],
                      const uint8_t mac2[EDHOC_MAC_LEN],
                      const uint8_t *ead, size_t ead_len)
{
    size_t need = 1 + EDHOC_ID_CRED_LEN + 32 + EDHOC_MAC_LEN + 2 + ead_len;
    if (cap < need || ead_len > 0xFFFF) return -1;

    size_t off = 0;
    out[off++] = c_r;
    memcpy(out + off, id_cred_r, EDHOC_ID_CRED_LEN);
    off += EDHOC_ID_CRED_LEN;
    memcpy(out + off, th2, 32);
    off += 32;
    memcpy(out + off, mac2, EDHOC_MAC_LEN);
    off += EDHOC_MAC_LEN;
    put_u16(out + off, (uint16_t)ead_len);
    off += 2;
    if (ead_len > 0) {
        memcpy(out + off, ead, ead_len);
        off += ead_len;
    }

    *out_len = off;
    return 0;
}

int decode_plaintext2(const uint8_t *in, size_t in_len,
                      uint8_t *c_r,
                      uint8_t id_cred_r[EDHOC_ID_CRED_LEN],
                      uint8_t th2[32],
                      uint8_t mac2[EDHOC_MAC_LEN],
                      const uint8_t **ead, size_t *ead_len)
{
    if (in_len < 1 + EDHOC_ID_CRED_LEN + 32 + EDHOC_MAC_LEN + 2) return -1;

    size_t off = 0;
    *c_r = in[off++];
    memcpy(id_cred_r, in + off, EDHOC_ID_CRED_LEN);
    off += EDHOC_ID_CRED_LEN;
    memcpy(th2, in + off, 32);
    off += 32;
    memcpy(mac2, in + off, EDHOC_MAC_LEN);
    off += EDHOC_MAC_LEN;

    uint16_t n = get_u16(in + off);
    off += 2;
    if (in_len < off + n) return -1;

    *ead = in + off;
    *ead_len = n;
    return 0;
}

int encode_plaintext2a(uint8_t *out, size_t cap, size_t *out_len,
                       const uint8_t *pt2, size_t pt2_len,
                       const uint8_t *sig2, size_t sig2_len)
{
    size_t need = pt2_len + 2 + sig2_len;
    if (cap < need || sig2_len > 0xFFFF) return -1;

    size_t off = 0;
    memcpy(out + off, pt2, pt2_len);
    off += pt2_len;
    if (sig2_len > 0) {
        memcpy(out + off, sig2, sig2_len);
        off += sig2_len;
    }
    put_u16(out + off, (uint16_t)sig2_len);
    off += 2;

    *out_len = off;
    return 0;
}

int decode_plaintext2a(const uint8_t *in, size_t in_len,
                       const uint8_t **pt2, size_t *pt2_len,
                       const uint8_t **sig2, size_t *sig2_len)
{
    if (in_len < 2) return -1;

    uint16_t n = get_u16(in + in_len - 2);
    if (in_len < 2U + (size_t)n) return -1;

    *pt2_len = in_len - 2 - n;
    *pt2 = in;
    *sig2 = in + *pt2_len;
    *sig2_len = n;
    return 0;
}

int encode_plaintext3(uint8_t *out, size_t cap, size_t *out_len,
                      const uint8_t id_cred_i[EDHOC_ID_CRED_LEN],
                      const uint8_t *sig3, size_t sig3_len,
                      const uint8_t *ead, size_t ead_len)
{
    size_t need = EDHOC_ID_CRED_LEN + 2 + sig3_len + 2 + ead_len;
    if (cap < need || sig3_len > 0xFFFF || ead_len > 0xFFFF) return -1;

    size_t off = 0;
    memcpy(out + off, id_cred_i, EDHOC_ID_CRED_LEN);
    off += EDHOC_ID_CRED_LEN;
    put_u16(out + off, (uint16_t)sig3_len);
    off += 2;
    if (sig3_len > 0) {
        memcpy(out + off, sig3, sig3_len);
        off += sig3_len;
    }
    put_u16(out + off, (uint16_t)ead_len);
    off += 2;
    if (ead_len > 0) {
        memcpy(out + off, ead, ead_len);
        off += ead_len;
    }

    *out_len = off;
    return 0;
}

int decode_plaintext3(const uint8_t *in, size_t in_len,
                      uint8_t id_cred_i[EDHOC_ID_CRED_LEN],
                      const uint8_t **sig3, size_t *sig3_len,
                      const uint8_t **ead, size_t *ead_len)
{
    if (in_len < EDHOC_ID_CRED_LEN + 2 + 2) return -1;

    size_t off = 0;
    memcpy(id_cred_i, in + off, EDHOC_ID_CRED_LEN);
    off += EDHOC_ID_CRED_LEN;

    uint16_t s = get_u16(in + off);
    off += 2;
    if (in_len < off + s + 2) return -1;

    *sig3 = in + off;
    *sig3_len = s;
    off += s;

    uint16_t e = get_u16(in + off);
    off += 2;
    if (in_len < off + e) return -1;

    *ead = in + off;
    *ead_len = e;
    return 0;
}

int encode_plaintext4(uint8_t *out, size_t cap, size_t *out_len,
                      uint8_t has_mac2,
                      const uint8_t mac2[EDHOC_MAC_LEN],
                      const uint8_t *ead, size_t ead_len)
{
    size_t need = 1 + EDHOC_MAC_LEN + 2 + ead_len;
    if (cap < need || ead_len > 0xFFFF) return -1;

    size_t off = 0;
    out[off++] = has_mac2 ? 1 : 0;
    memcpy(out + off, mac2, EDHOC_MAC_LEN);
    off += EDHOC_MAC_LEN;
    put_u16(out + off, (uint16_t)ead_len);
    off += 2;
    if (ead_len > 0) {
        memcpy(out + off, ead, ead_len);
        off += ead_len;
    }

    *out_len = off;
    return 0;
}

int decode_plaintext4(const uint8_t *in, size_t in_len,
                      uint8_t *has_mac2,
                      uint8_t mac2[EDHOC_MAC_LEN],
                      const uint8_t **ead, size_t *ead_len)
{
    if (in_len < 1 + EDHOC_MAC_LEN + 2) return -1;

    size_t off = 0;
    *has_mac2 = in[off++];
    memcpy(mac2, in + off, EDHOC_MAC_LEN);
    off += EDHOC_MAC_LEN;

    uint16_t n = get_u16(in + off);
    off += 2;
    if (in_len < off + n) return -1;

    *ead = in + off;
    *ead_len = n;
    return 0;
}
