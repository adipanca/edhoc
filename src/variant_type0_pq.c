#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 199309L
#endif
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
/*
 * =============================================================================
 * EDHOC Type 0 PQ — sig-sig with ML-DSA-65 + ML-KEM-768
 *
 * Protocol flow (3 messages, analogous to Type 0 Classic):
 *   Pre-exchange: I ↔ R exchange ML-DSA-65 public keys (certificates)
 *   MSG1: METHOD || SUITES || pk_eph(ML-KEM) || C_I       (I → R)
 *   MSG2: ct_eph || CIPHERTEXT_2(C_R, ID_CRED_R, Sig_2)  (R → I)
 *   MSG3: AEAD(ID_CRED_I, Sig_3)                          (I → R)
 *   DONE:                                                   (R → I)
 *
 * Key exchange: ML-KEM-768 (ephemeral)
 * Authentication: ML-DSA-65 signature over MAC (sig-sig)
 * Key schedule:
 *   PRK_2e   = HKDF-Extract(0, ss_eph)
 *   PRK_3e2m = PRK_2e       (sig-sig: no static KEM)
 *   PRK_4e3m = PRK_3e2m
 * =============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/resource.h>
#include <arpa/inet.h>
#include <time.h>
#include <errno.h>

#include <sodium.h>
#include <psa/crypto.h>
#include "edhoc_benchmark_p2p.h"
#include "edhoc_pq_kem.h"
#include "mbedtls/gcm.h"

/* =============================================================================
 * INITIATOR — Type 0 PQ (sig-sig, ML-DSA-65 + ML-KEM-768)
 * =============================================================================
 */
int handshake_type0_pq_initiator(int sockfd, int variant)
{
	int N = P2P_BENCH_HANDSHAKE_ITERATIONS;

	/* Generate long-term ML-DSA-65 key pair (certificate/credential) */
	uint8_t sig_pk_i[PQ_SIG_PK_LEN], sig_sk_i[PQ_SIG_SK_LEN];
	pq_sig_keygen(sig_pk_i, sig_sk_i);

	/* Exchange ML-DSA-65 public keys (certificates) with responder */
	if (p2p_send_msg(sockfd, P2P_MSG_TYPE_HANDSHAKE_START, sig_pk_i, PQ_SIG_PK_LEN) != 0) return -1;
	uint8_t type, sig_pk_r[PQ_SIG_PK_LEN]; uint32_t len;
	if (p2p_recv_msg(sockfd, &type, sig_pk_r, &len, PQ_SIG_PK_LEN) != 0) return -1;

	double total_wall_us = 0, total_txrx_us = 0, total_precomp_us = 0;
	struct rusage ru_start, ru_end;
	long mem_before = get_memory_usage_bytes();
	long mem_peak = mem_before;
	getrusage(RUSAGE_SELF, &ru_start);
	uint64_t wall_all_start = bench_get_ns();

	for (int iter = 0; iter < N; iter++) {
		uint64_t iter_start = bench_get_ns();
		uint64_t txrx_ns = 0;

		/* ── (1) Ephemeral ML-KEM-768 key generation ── */
		uint8_t eph_pk[PQ_KEM_PK_LEN], eph_sk[PQ_KEM_SK_LEN];
		{
			HS_TIME_START();
			pq_kem_keygen(eph_pk, eph_sk);
			HS_TIME_END(variant, OP_KEYGEN);
		}
		uint64_t precomp_end = bench_get_ns();

		/* ── Send MSG1: METHOD(1) || SUITES(1) || pk_eph || C_I(1) ── */
		uint8_t msg1[PQ_KEM_PK_LEN + 3];
		msg1[0] = 0x00;  /* METHOD = 0 (sig-sig) */
		msg1[1] = 0x00;  /* SUITES_I */
		memcpy(msg1 + 2, eph_pk, PQ_KEM_PK_LEN);
		msg1[2 + PQ_KEM_PK_LEN] = 0x00;  /* C_I */
		uint32_t msg1_len = PQ_KEM_PK_LEN + 3;

		{
			uint64_t tx_start = bench_get_ns();
			p2p_send_msg(sockfd, P2P_MSG_TYPE_MSG1, msg1, msg1_len);
			txrx_ns += (bench_get_ns() - tx_start);
		}

		/* ── Receive MSG2: ct_eph || CIPHERTEXT_2 ── */
		uint8_t msg2[P2P_MSG_BUF_SIZE]; uint32_t msg2_len;
		{
			uint64_t rx_start = bench_get_ns();
			p2p_recv_msg(sockfd, &type, msg2, &msg2_len, sizeof(msg2));
			txrx_ns += (bench_get_ns() - rx_start);
		}

		/* Parse MSG2 */
		uint8_t ct_eph[PQ_KEM_CT_LEN];
		memcpy(ct_eph, msg2, PQ_KEM_CT_LEN);
		uint8_t *ciphertext_2 = msg2 + PQ_KEM_CT_LEN;
		uint32_t ciphertext_2_len = msg2_len - PQ_KEM_CT_LEN;

		/* ── Decapsulate: ss_eph = kemDecaps(ct_eph, sk_eph) ── */
		uint8_t ss_eph[PQ_KEM_SS_LEN];
		{
			HS_TIME_START();
			pq_kem_decaps(ss_eph, ct_eph, eph_sk);
			HS_TIME_END(variant, OP_DECAPS);
		}

		/* TH_2 = H(H(Message_1), ct_eph) */
		uint8_t th2[PQ_HASH_LEN];
		{
			HS_TIME_START();
			uint8_t h_msg1[PQ_HASH_LEN];
			pq_hash_sha256(msg1, msg1_len, h_msg1);
			uint8_t th2_input[PQ_HASH_LEN + PQ_KEM_CT_LEN];
			memcpy(th2_input, h_msg1, PQ_HASH_LEN);
			memcpy(th2_input + PQ_HASH_LEN, ct_eph, PQ_KEM_CT_LEN);
			pq_hash_sha256(th2_input, PQ_HASH_LEN + PQ_KEM_CT_LEN, th2);
			HS_TIME_END(variant, OP_HASH);
		}

		/* PRK_2e = HKDF-Extract(salt=0, IKM=ss_eph) */
		uint8_t prk_2e[PQ_PRK_LEN];
		{
			HS_TIME_START();
			pq_hkdf_extract(NULL, 0, ss_eph, PQ_KEM_SS_LEN, prk_2e);
			HS_TIME_END(variant, OP_HKDF_EXTRACT);
		}

		/* Decrypt CIPHERTEXT_2: KEYSTREAM_2 = Expand(PRK_2e, TH_2, ...) */
		uint8_t plaintext_2[PQ_SIG_MAX_LEN + 16];
		{
			HS_TIME_START();
			uint8_t keystream_2[PQ_SIG_MAX_LEN + 16];
			pq_hkdf_expand(prk_2e, th2, PQ_HASH_LEN, keystream_2, ciphertext_2_len);
			for (uint32_t i = 0; i < ciphertext_2_len; i++)
				plaintext_2[i] = ciphertext_2[i] ^ keystream_2[i];
			HS_TIME_END(variant, OP_HKDF_EXPAND);
		}
		/* plaintext_2 = (C_R, ID_CRED_R, Sig_2) */

		/* Extract Sig_2 from plaintext_2 */
		uint8_t sig2[PQ_SIG_MAX_LEN];
		uint32_t sig2_len = ciphertext_2_len - 2;
		memcpy(sig2, plaintext_2 + 2, sig2_len);

		/* PRK_3e2m = PRK_2e (sig-sig: no static key contribution) */
		uint8_t prk_3e2m[PQ_PRK_LEN];
		memcpy(prk_3e2m, prk_2e, PQ_PRK_LEN);

		/* MAC_2 = KDF(PRK_3e2m, context_2 with CRED_R) */
		uint8_t mac2[32];
		{
			HS_TIME_START();
			uint8_t context_2[PQ_SIG_PK_LEN + PQ_HASH_LEN + 16];
			size_t ctx2_len = 0;
			context_2[ctx2_len++] = plaintext_2[0]; /* C_R */
			context_2[ctx2_len++] = plaintext_2[1]; /* ID_CRED_R */
			memcpy(context_2 + ctx2_len, th2, PQ_HASH_LEN); ctx2_len += PQ_HASH_LEN;
			memcpy(context_2 + ctx2_len, sig_pk_r, PQ_SIG_PK_LEN); ctx2_len += PQ_SIG_PK_LEN; /* CRED_R = pk_R */
			pq_hkdf_expand(prk_3e2m, context_2, ctx2_len, mac2, 32);
			HS_TIME_END(variant, OP_HKDF_EXPAND);
		}

		/* Verify Sig_2 using ML-DSA-65 (responder's certificate) */
		{
			HS_TIME_START();
			pq_sig_verify(mac2, 32, sig2, sig2_len, sig_pk_r);
			HS_TIME_END(variant, OP_VERIFY);
		}

		/* TH_3 = H(TH_2, PLAINTEXT_2, CRED_R) */
		uint8_t th3[PQ_HASH_LEN];
		{
			HS_TIME_START();
			uint8_t th3_input[P2P_MSG_BUF_SIZE];
			size_t th3_in_len = 0;
			memcpy(th3_input, th2, PQ_HASH_LEN); th3_in_len += PQ_HASH_LEN;
			memcpy(th3_input + th3_in_len, plaintext_2, ciphertext_2_len); th3_in_len += ciphertext_2_len;
			memcpy(th3_input + th3_in_len, sig_pk_r, PQ_SIG_PK_LEN); th3_in_len += PQ_SIG_PK_LEN;
			pq_hash_sha256(th3_input, th3_in_len, th3);
			HS_TIME_END(variant, OP_HASH);
		}

		/* PRK_4e3m = PRK_3e2m (sig-sig) */
		uint8_t prk_4e3m[PQ_PRK_LEN];
		memcpy(prk_4e3m, prk_3e2m, PQ_PRK_LEN);

		/* MAC_3 = KDF(PRK_4e3m, context_3 with CRED_I) */
		uint8_t mac3[32];
		{
			HS_TIME_START();
			uint8_t context_3[PQ_SIG_PK_LEN + PQ_HASH_LEN + 16];
			size_t ctx3_len = 0;
			context_3[ctx3_len++] = 0x02; /* ID_CRED_I */
			memcpy(context_3 + ctx3_len, th3, PQ_HASH_LEN); ctx3_len += PQ_HASH_LEN;
			memcpy(context_3 + ctx3_len, sig_pk_i, PQ_SIG_PK_LEN); ctx3_len += PQ_SIG_PK_LEN; /* CRED_I = pk_I */
			pq_hkdf_expand(prk_4e3m, context_3, ctx3_len, mac3, 32);
			HS_TIME_END(variant, OP_HKDF_EXPAND);
		}

		/* Sign MAC_3 with ML-DSA-65 (initiator's credential) */
		uint8_t sig3[PQ_SIG_MAX_LEN];
		size_t sig3_len = 0;
		{
			HS_TIME_START();
			pq_sig_sign(mac3, 32, sig_sk_i, sig3, &sig3_len);
			HS_TIME_END(variant, OP_SIGNATURE);
		}

		/* PLAINTEXT_3 = ID_CRED_I || Sig_3 */
		uint8_t plaintext_3[1 + PQ_SIG_MAX_LEN];
		plaintext_3[0] = 0x02; /* ID_CRED_I */
		memcpy(plaintext_3 + 1, sig3, sig3_len);
		uint32_t pt3_len = 1 + (uint32_t)sig3_len;

		/* Derive K_3, IV_3 */
		uint8_t k3[PQ_AEAD_KEY_LEN], iv3[PQ_AEAD_NONCE_LEN];
		{
			HS_TIME_START();
			derive_key_iv(prk_3e2m, INFO_K3, INFO_K3_LEN, k3, iv3);
			HS_TIME_END(variant, OP_HKDF_EXPAND);
		}

		/* AEAD Encrypt: MSG3 = AEAD(K_3, IV_3, TH_3, PLAINTEXT_3) */
		uint8_t msg3_buf[PQ_SIG_MAX_LEN + 64];
		uint32_t msg3_len;
		{
			HS_TIME_START();
			mbedtls_gcm_context gcm;
			mbedtls_gcm_init(&gcm);
			mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, k3, 128);
			uint8_t tag[16];
			mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, pt3_len,
			                          iv3, PQ_AEAD_NONCE_LEN, th3, PQ_HASH_LEN,
			                          plaintext_3, msg3_buf, 16, tag);
			memcpy(msg3_buf + pt3_len, tag, 16);
			msg3_len = pt3_len + 16;
			mbedtls_gcm_free(&gcm);
			HS_TIME_END(variant, OP_AEAD_ENCRYPT);
		}

		/* Send MSG3 */
		{
			uint64_t tx_start = bench_get_ns();
			p2p_send_msg(sockfd, P2P_MSG_TYPE_MSG3, msg3_buf, msg3_len);
			txrx_ns += (bench_get_ns() - tx_start);
		}

		/* Receive DONE */
		uint8_t done_buf[16]; uint32_t done_len;
		{
			uint64_t rx_start = bench_get_ns();
			p2p_recv_msg(sockfd, &type, done_buf, &done_len, sizeof(done_buf));
			txrx_ns += (bench_get_ns() - rx_start);
		}

		/* TH_4 = H(TH_3, PLAINTEXT_3, CRED_I) */
		uint8_t th4[PQ_HASH_LEN];
		{
			HS_TIME_START();
			uint8_t th4_input[P2P_MSG_BUF_SIZE];
			size_t th4_in_len = 0;
			memcpy(th4_input, th3, PQ_HASH_LEN); th4_in_len += PQ_HASH_LEN;
			memcpy(th4_input + th4_in_len, plaintext_3, pt3_len); th4_in_len += pt3_len;
			memcpy(th4_input + th4_in_len, sig_pk_i, PQ_SIG_PK_LEN); th4_in_len += PQ_SIG_PK_LEN;
			pq_hash_sha256(th4_input, th4_in_len, th4);
			HS_TIME_END(variant, OP_HASH);
		}

		/* PRK_out = KDF(PRK_4e3m, TH_4) */
		{
			HS_TIME_START();
			uint8_t prk_out[PQ_PRK_LEN];
			pq_hkdf_expand(prk_4e3m, th4, PQ_HASH_LEN, prk_out, PQ_PRK_LEN);
			HS_TIME_END(variant, OP_HKDF_EXPAND);
		}

		if (iter == 0) { long m = get_memory_usage_bytes(); if (m > mem_peak) mem_peak = m; }
		uint64_t iter_end = bench_get_ns();
		total_wall_us += ns_to_us(iter_end - iter_start);
		total_txrx_us += ns_to_us(txrx_ns);
		total_precomp_us += ns_to_us(precomp_end - iter_start);
	}

	uint64_t wall_all_end = bench_get_ns();
	getrusage(RUSAGE_SELF, &ru_end);
	finalize_variant_stats(variant, N, total_wall_us, total_txrx_us, total_precomp_us,
	                       wall_all_start, wall_all_end, &ru_start, &ru_end, mem_before, mem_peak);

	return 0;
}

/* =============================================================================
 * RESPONDER — Type 0 PQ (sig-sig, ML-DSA-65 + ML-KEM-768)
 * =============================================================================
 */
int handshake_type0_pq_responder(int sockfd, int variant)
{
	int N = P2P_BENCH_HANDSHAKE_ITERATIONS;

	/* Generate long-term ML-DSA-65 key pair (certificate/credential) */
	uint8_t sig_pk_r[PQ_SIG_PK_LEN], sig_sk_r[PQ_SIG_SK_LEN];
	pq_sig_keygen(sig_pk_r, sig_sk_r);

	/* Receive initiator's ML-DSA-65 pk, send own */
	uint8_t type, sig_pk_i[PQ_SIG_PK_LEN]; uint32_t len;
	if (p2p_recv_msg(sockfd, &type, sig_pk_i, &len, PQ_SIG_PK_LEN) != 0) return -1;
	if (p2p_send_msg(sockfd, P2P_MSG_TYPE_HANDSHAKE_START, sig_pk_r, PQ_SIG_PK_LEN) != 0) return -1;

	double total_wall_us = 0, total_txrx_us = 0, total_precomp_us = 0;
	struct rusage ru_start, ru_end;
	long mem_before = get_memory_usage_bytes();
	long mem_peak = mem_before;
	getrusage(RUSAGE_SELF, &ru_start);
	uint64_t wall_all_start = bench_get_ns();

	for (int iter = 0; iter < N; iter++) {
		uint64_t iter_start = bench_get_ns();
		uint64_t txrx_ns = 0;
		uint64_t precomp_end = iter_start; /* Responder has no precomputation */

		/* ── Receive MSG1: METHOD || SUITES || pk_eph || C_I ── */
		uint8_t msg1[P2P_MSG_BUF_SIZE]; uint32_t msg1_len;
		{
			uint64_t rx_start = bench_get_ns();
			p2p_recv_msg(sockfd, &type, msg1, &msg1_len, sizeof(msg1));
			txrx_ns += (bench_get_ns() - rx_start);
		}

		/* Parse MSG1 — extract ephemeral ML-KEM public key */
		uint8_t pk_eph[PQ_KEM_PK_LEN];
		memcpy(pk_eph, msg1 + 2, PQ_KEM_PK_LEN); /* skip METHOD + SUITES */

		/* ── Encapsulate: ct_eph, ss_eph = kemEncaps(pk_eph) ── */
		uint8_t ct_eph[PQ_KEM_CT_LEN], ss_eph[PQ_KEM_SS_LEN];
		{
			HS_TIME_START();
			pq_kem_encaps(ct_eph, ss_eph, pk_eph);
			HS_TIME_END(variant, OP_ENCAPS);
		}

		/* TH_2 = H(H(Message_1), ct_eph) */
		uint8_t th2[PQ_HASH_LEN];
		{
			HS_TIME_START();
			uint8_t h_msg1[PQ_HASH_LEN];
			pq_hash_sha256(msg1, msg1_len, h_msg1);
			uint8_t th2_input[PQ_HASH_LEN + PQ_KEM_CT_LEN];
			memcpy(th2_input, h_msg1, PQ_HASH_LEN);
			memcpy(th2_input + PQ_HASH_LEN, ct_eph, PQ_KEM_CT_LEN);
			pq_hash_sha256(th2_input, PQ_HASH_LEN + PQ_KEM_CT_LEN, th2);
			HS_TIME_END(variant, OP_HASH);
		}

		/* PRK_2e = HKDF-Extract(salt=0, IKM=ss_eph) */
		uint8_t prk_2e[PQ_PRK_LEN];
		{
			HS_TIME_START();
			pq_hkdf_extract(NULL, 0, ss_eph, PQ_KEM_SS_LEN, prk_2e);
			HS_TIME_END(variant, OP_HKDF_EXTRACT);
		}

		/* PRK_3e2m = PRK_2e (sig-sig) */
		uint8_t prk_3e2m[PQ_PRK_LEN];
		memcpy(prk_3e2m, prk_2e, PQ_PRK_LEN);

		/* MAC_2 = KDF(PRK_3e2m, context_2 with CRED_R) */
		uint8_t c_r = 0x37, id_cred_r = 0x01;
		uint8_t mac2[32];
		{
			HS_TIME_START();
			uint8_t context_2[PQ_SIG_PK_LEN + PQ_HASH_LEN + 16];
			size_t ctx2_len = 0;
			context_2[ctx2_len++] = c_r;
			context_2[ctx2_len++] = id_cred_r;
			memcpy(context_2 + ctx2_len, th2, PQ_HASH_LEN); ctx2_len += PQ_HASH_LEN;
			memcpy(context_2 + ctx2_len, sig_pk_r, PQ_SIG_PK_LEN); ctx2_len += PQ_SIG_PK_LEN; /* CRED_R */
			pq_hkdf_expand(prk_3e2m, context_2, ctx2_len, mac2, 32);
			HS_TIME_END(variant, OP_HKDF_EXPAND);
		}

		/* Sign MAC_2 with ML-DSA-65 (responder's credential) */
		uint8_t sig2[PQ_SIG_MAX_LEN];
		size_t sig2_len = 0;
		{
			HS_TIME_START();
			pq_sig_sign(mac2, 32, sig_sk_r, sig2, &sig2_len);
			HS_TIME_END(variant, OP_SIGNATURE);
		}

		/* PLAINTEXT_2 = C_R || ID_CRED_R || Sig_2 */
		uint8_t plaintext_2[2 + PQ_SIG_MAX_LEN];
		plaintext_2[0] = c_r;
		plaintext_2[1] = id_cred_r;
		memcpy(plaintext_2 + 2, sig2, sig2_len);
		uint32_t pt2_len = 2 + (uint32_t)sig2_len;

		/* Encrypt PLAINTEXT_2: CIPHERTEXT_2 = XOR(PLAINTEXT_2, KEYSTREAM_2) */
		uint8_t ciphertext_2[2 + PQ_SIG_MAX_LEN];
		{
			HS_TIME_START();
			uint8_t keystream_2[2 + PQ_SIG_MAX_LEN];
			pq_hkdf_expand(prk_2e, th2, PQ_HASH_LEN, keystream_2, pt2_len);
			for (uint32_t i = 0; i < pt2_len; i++)
				ciphertext_2[i] = plaintext_2[i] ^ keystream_2[i];
			HS_TIME_END(variant, OP_HKDF_EXPAND);
		}

		/* ── Send MSG2: ct_eph || CIPHERTEXT_2 ── */
		uint8_t msg2[P2P_MSG_BUF_SIZE];
		uint32_t msg2_len = 0;
		memcpy(msg2, ct_eph, PQ_KEM_CT_LEN); msg2_len += PQ_KEM_CT_LEN;
		memcpy(msg2 + msg2_len, ciphertext_2, pt2_len); msg2_len += pt2_len;

		{
			uint64_t tx_start = bench_get_ns();
			p2p_send_msg(sockfd, P2P_MSG_TYPE_MSG2, msg2, msg2_len);
			txrx_ns += (bench_get_ns() - tx_start);
		}

		/* ── Receive MSG3: AEAD(ID_CRED_I, Sig_3) ── */
		uint8_t msg3[P2P_MSG_BUF_SIZE]; uint32_t msg3_len;
		{
			uint64_t rx_start = bench_get_ns();
			p2p_recv_msg(sockfd, &type, msg3, &msg3_len, sizeof(msg3));
			txrx_ns += (bench_get_ns() - rx_start);
		}

		/* TH_3 = H(TH_2, PLAINTEXT_2, CRED_R) */
		uint8_t th3[PQ_HASH_LEN];
		{
			HS_TIME_START();
			uint8_t th3_input[P2P_MSG_BUF_SIZE];
			size_t th3_in_len = 0;
			memcpy(th3_input, th2, PQ_HASH_LEN); th3_in_len += PQ_HASH_LEN;
			memcpy(th3_input + th3_in_len, plaintext_2, pt2_len); th3_in_len += pt2_len;
			memcpy(th3_input + th3_in_len, sig_pk_r, PQ_SIG_PK_LEN); th3_in_len += PQ_SIG_PK_LEN;
			pq_hash_sha256(th3_input, th3_in_len, th3);
			HS_TIME_END(variant, OP_HASH);
		}

		/* Derive K_3, IV_3 */
		uint8_t k3[PQ_AEAD_KEY_LEN], iv3[PQ_AEAD_NONCE_LEN];
		{
			HS_TIME_START();
			derive_key_iv(prk_3e2m, INFO_K3, INFO_K3_LEN, k3, iv3);
			HS_TIME_END(variant, OP_HKDF_EXPAND);
		}

		/* AEAD Decrypt MSG3 → PLAINTEXT_3 */
		uint8_t plaintext_3[PQ_SIG_MAX_LEN + 16];
		uint32_t pt3_len;
		{
			HS_TIME_START();
			mbedtls_gcm_context gcm;
			mbedtls_gcm_init(&gcm);
			mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, k3, 128);
			pt3_len = msg3_len - 16;
			if (msg3_len > 16) {
				mbedtls_gcm_auth_decrypt(&gcm, pt3_len,
				                         iv3, PQ_AEAD_NONCE_LEN,
				                         th3, PQ_HASH_LEN,
				                         msg3 + pt3_len, 16,
				                         msg3, plaintext_3);
			}
			mbedtls_gcm_free(&gcm);
			HS_TIME_END(variant, OP_AEAD_DECRYPT);
		}

		/* Parse PLAINTEXT_3: ID_CRED_I(1) || Sig_3 */
		uint8_t sig3[PQ_SIG_MAX_LEN];
		uint32_t sig3_len = pt3_len - 1;
		memcpy(sig3, plaintext_3 + 1, sig3_len);

		/* PRK_4e3m = PRK_3e2m (sig-sig) */
		uint8_t prk_4e3m[PQ_PRK_LEN];
		memcpy(prk_4e3m, prk_3e2m, PQ_PRK_LEN);

		/* MAC_3 = KDF(PRK_4e3m, context_3 with CRED_I) */
		uint8_t mac3[32];
		{
			HS_TIME_START();
			uint8_t context_3[PQ_SIG_PK_LEN + PQ_HASH_LEN + 16];
			size_t ctx3_len = 0;
			context_3[ctx3_len++] = 0x02; /* ID_CRED_I */
			memcpy(context_3 + ctx3_len, th3, PQ_HASH_LEN); ctx3_len += PQ_HASH_LEN;
			memcpy(context_3 + ctx3_len, sig_pk_i, PQ_SIG_PK_LEN); ctx3_len += PQ_SIG_PK_LEN; /* CRED_I */
			pq_hkdf_expand(prk_4e3m, context_3, ctx3_len, mac3, 32);
			HS_TIME_END(variant, OP_HKDF_EXPAND);
		}

		/* Verify Sig_3 using ML-DSA-65 (initiator's certificate) */
		{
			HS_TIME_START();
			pq_sig_verify(mac3, 32, sig3, sig3_len, sig_pk_i);
			HS_TIME_END(variant, OP_VERIFY);
		}

		/* Send DONE */
		{
			uint64_t tx_start = bench_get_ns();
			p2p_send_msg(sockfd, P2P_MSG_TYPE_DONE, NULL, 0);
			txrx_ns += (bench_get_ns() - tx_start);
		}

		/* TH_4 = H(TH_3, PLAINTEXT_3, CRED_I) */
		uint8_t th4[PQ_HASH_LEN];
		{
			HS_TIME_START();
			uint8_t th4_input[P2P_MSG_BUF_SIZE];
			size_t th4_in_len = 0;
			memcpy(th4_input, th3, PQ_HASH_LEN); th4_in_len += PQ_HASH_LEN;
			memcpy(th4_input + th4_in_len, plaintext_3, pt3_len); th4_in_len += pt3_len;
			memcpy(th4_input + th4_in_len, sig_pk_i, PQ_SIG_PK_LEN); th4_in_len += PQ_SIG_PK_LEN;
			pq_hash_sha256(th4_input, th4_in_len, th4);
			HS_TIME_END(variant, OP_HASH);
		}

		/* PRK_out = KDF(PRK_4e3m, TH_4) */
		{
			HS_TIME_START();
			uint8_t prk_out[PQ_PRK_LEN];
			pq_hkdf_expand(prk_4e3m, th4, PQ_HASH_LEN, prk_out, PQ_PRK_LEN);
			HS_TIME_END(variant, OP_HKDF_EXPAND);
		}

		if (iter == 0) { long m = get_memory_usage_bytes(); if (m > mem_peak) mem_peak = m; }
		uint64_t iter_end = bench_get_ns();
		total_wall_us += ns_to_us(iter_end - iter_start);
		total_txrx_us += ns_to_us(txrx_ns);
		total_precomp_us += ns_to_us(precomp_end - iter_start);
	}

	uint64_t wall_all_end = bench_get_ns();
	getrusage(RUSAGE_SELF, &ru_end);
	finalize_variant_stats(variant, N, total_wall_us, total_txrx_us, total_precomp_us,
	                       wall_all_start, wall_all_end, &ru_start, &ru_end, mem_before, mem_peak);

	return 0;
}
