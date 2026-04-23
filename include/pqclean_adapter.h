#ifndef PQCLEAN_ADAPTER_H
#define PQCLEAN_ADAPTER_H

#include <stddef.h>
#include <stdint.h>

#include <sodium.h>

#define MLKEM768_PK_LEN 1184
#define MLKEM768_SK_LEN 2400
#define MLKEM768_CT_LEN 1088
#define MLKEM768_SS_LEN 32

#define MLDSA65_PK_LEN 1952
#define MLDSA65_SK_LEN 4032
#define MLDSA65_SIG_MAX_LEN 3309

int pq_mlkem768_keygen(uint8_t *pk, uint8_t *sk);
int pq_mlkem768_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int pq_mlkem768_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

int pq_mldsa65_keygen(uint8_t *pk, uint8_t *sk);
int pq_mldsa65_sign(uint8_t *sig, size_t *sig_len,
                    const uint8_t *msg, size_t msg_len,
                    const uint8_t *sk);
int pq_mldsa65_verify(const uint8_t *sig, size_t sig_len,
                      const uint8_t *msg, size_t msg_len,
                      const uint8_t *pk);

void hkdf_extract_sha256(const uint8_t *salt, size_t salt_len,
                         const uint8_t *ikm, size_t ikm_len,
                         uint8_t out32[32]);

void hkdf_expand_sha256_oneblock(const uint8_t prk[32],
                                 const uint8_t *info, size_t info_len,
                                 uint8_t out32[32]);

void hkdf_expand_sha256(const uint8_t prk[32],
                        const uint8_t *info, size_t info_len,
                        uint8_t *out, size_t out_len);

#endif
