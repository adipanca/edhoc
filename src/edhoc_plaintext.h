#ifndef EDHOC_PLAINTEXT_H
#define EDHOC_PLAINTEXT_H

#include <stddef.h>
#include <stdint.h>

#define EDHOC_ID_CRED_LEN 32
#define EDHOC_MAC_LEN 32

int encode_plaintext2(uint8_t *out, size_t cap, size_t *out_len,
                      uint8_t c_r,
                      const uint8_t id_cred_r[EDHOC_ID_CRED_LEN],
                      const uint8_t th2[32],
                      const uint8_t mac2[EDHOC_MAC_LEN],
                      const uint8_t *ead, size_t ead_len);

int decode_plaintext2(const uint8_t *in, size_t in_len,
                      uint8_t *c_r,
                      uint8_t id_cred_r[EDHOC_ID_CRED_LEN],
                      uint8_t th2[32],
                      uint8_t mac2[EDHOC_MAC_LEN],
                      const uint8_t **ead, size_t *ead_len);

int encode_plaintext2a(uint8_t *out, size_t cap, size_t *out_len,
                       const uint8_t *pt2, size_t pt2_len,
                       const uint8_t *sig2, size_t sig2_len);

int decode_plaintext2a(const uint8_t *in, size_t in_len,
                       const uint8_t **pt2, size_t *pt2_len,
                       const uint8_t **sig2, size_t *sig2_len);

int encode_plaintext3(uint8_t *out, size_t cap, size_t *out_len,
                      const uint8_t id_cred_i[EDHOC_ID_CRED_LEN],
                      const uint8_t *sig3, size_t sig3_len,
                      const uint8_t *ead, size_t ead_len);

int decode_plaintext3(const uint8_t *in, size_t in_len,
                      uint8_t id_cred_i[EDHOC_ID_CRED_LEN],
                      const uint8_t **sig3, size_t *sig3_len,
                      const uint8_t **ead, size_t *ead_len);

int encode_plaintext4(uint8_t *out, size_t cap, size_t *out_len,
                      uint8_t has_mac2,
                      const uint8_t mac2[EDHOC_MAC_LEN],
                      const uint8_t *ead, size_t ead_len);

int decode_plaintext4(const uint8_t *in, size_t in_len,
                      uint8_t *has_mac2,
                      uint8_t mac2[EDHOC_MAC_LEN],
                      const uint8_t **ead, size_t *ead_len);

#endif
