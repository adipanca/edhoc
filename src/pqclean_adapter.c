#include "pqclean_adapter.h"

#include <string.h>

#include "crypto_kem/ml-kem-768/clean/api.h"
#include "crypto_sign/ml-dsa-65/clean/api.h"

int pq_mlkem768_keygen(uint8_t *pk, uint8_t *sk)
{
    return PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair(pk, sk);
}

int pq_mlkem768_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk)
{
    return PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc(ct, ss, pk);
}

int pq_mlkem768_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk)
{
    return PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec(ss, ct, sk);
}

int pq_mldsa65_keygen(uint8_t *pk, uint8_t *sk)
{
    return PQCLEAN_MLDSA65_CLEAN_crypto_sign_keypair(pk, sk);
}

int pq_mldsa65_sign(uint8_t *sig, size_t *sig_len,
                    const uint8_t *msg, size_t msg_len,
                    const uint8_t *sk)
{
    return PQCLEAN_MLDSA65_CLEAN_crypto_sign_signature(sig, sig_len, msg, msg_len, sk);
}

int pq_mldsa65_verify(const uint8_t *sig, size_t sig_len,
                      const uint8_t *msg, size_t msg_len,
                      const uint8_t *pk)
{
    return PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify(sig, sig_len, msg, msg_len, pk);
}

void hkdf_extract_sha256(const uint8_t *salt, size_t salt_len,
                         const uint8_t *ikm, size_t ikm_len,
                         uint8_t out32[32])
{
    uint8_t zero_salt[32];
    if (salt == NULL || salt_len == 0) {
        memset(zero_salt, 0, sizeof(zero_salt));
        salt = zero_salt;
        salt_len = sizeof(zero_salt);
    }
    crypto_auth_hmacsha256_state st;
    crypto_auth_hmacsha256_init(&st, salt, salt_len);
    crypto_auth_hmacsha256_update(&st, ikm, ikm_len);
    crypto_auth_hmacsha256_final(&st, out32);
}

void hkdf_expand_sha256(const uint8_t prk[32],
                        const uint8_t *info, size_t info_len,
                        uint8_t *out, size_t out_len)
{
    crypto_auth_hmacsha256_state st;
    uint8_t t[32];
    uint8_t counter = 1;
    size_t produced = 0;
    size_t t_len = 0;

    while (produced < out_len) {
        crypto_auth_hmacsha256_init(&st, prk, 32);
        if (t_len > 0) {
            crypto_auth_hmacsha256_update(&st, t, t_len);
        }
        if (info_len > 0) {
            crypto_auth_hmacsha256_update(&st, info, info_len);
        }
        crypto_auth_hmacsha256_update(&st, &counter, 1);
        crypto_auth_hmacsha256_final(&st, t);

        t_len = sizeof(t);
        size_t remain = out_len - produced;
        size_t take = (remain < sizeof(t)) ? remain : sizeof(t);
        memcpy(out + produced, t, take);
        produced += take;
        counter++;
    }
}

void hkdf_expand_sha256_oneblock(const uint8_t prk[32],
                                 const uint8_t *info, size_t info_len,
                                 uint8_t out32[32])
{
    hkdf_expand_sha256(prk, info, info_len, out32, 32);
}
