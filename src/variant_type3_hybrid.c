#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 199309L
#endif
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
/*
 * EDHOC-Hybrid: Type 3 Hybrid variant (initiator + responder)
 * X25519 ECDHE + ML-KEM-768 + MAC authentication
 *
 * Key schedule (updated):
 *   PRK_2     = Extract(X^y, k_KEM, TH_2)     — hybrid ephemeral
 *   EK_2      = Expand(PRK_2, TH_2)            — encryption key from PRK_2
 *   PRK_3e2m  = Extract(X^b, PRK_2)            — static DH eph(I)-static(R)
 *   MK_2      = Expand(PRK_3e2m, TH_2)         — MAC key from PRK_3e2m
 *   EK_3/IV_3 = Expand(PRK_3e2m, TH_3)         — msg3 encryption from PRK_3e2m
 *   PRK_4e3m  = Extract(Y^a, PRK_3e2m)         — static DH static(I)-eph(R)
 *   MK_3      = Expand(PRK_4e3m, TH_3)         — MAC key from PRK_4e3m
 *   PRK_out   = Expand(PRK_4e3m, TH_4)
 *   AK        = Expand(Expand(PRK_out))
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

int handshake_type3_hybrid_initiator(int sockfd, int variant)
{
	int N = P2P_BENCH_HANDSHAKE_ITERATIONS;

	/* Generate static X25519 key pair (for MAC auth) */
	uint8_t static_sk_i[32], static_pk_i[32];
	{
		uint8_t seed_buf[4] = {0xEE, 0xFF, 0x00, 0x11};
		uint8_t sh[32]; size_t hl;
		psa_hash_compute(PSA_ALG_SHA_256, seed_buf, 4, sh, 32, &hl);
		sh[0] &= 248; sh[31] &= 127; sh[31] |= 64;
		memcpy(static_sk_i, sh, 32);
		crypto_scalarmult_base(static_pk_i, static_sk_i);
	}

	/* Exchange static public keys */
	if (p2p_send_msg(sockfd, P2P_MSG_TYPE_HANDSHAKE_START, static_pk_i, 32) != 0) return -1;
	uint8_t type, static_pk_r[32];
	uint32_t len;
	if (p2p_recv_msg(sockfd, &type, static_pk_r, &len, 32) != 0) return -1;

	double total_wall_us = 0, total_txrx_us = 0, total_precomp_us = 0;
	struct rusage ru_start, ru_end;
	long mem_before = get_memory_usage_bytes();
	long mem_peak = mem_before;
	getrusage(RUSAGE_SELF, &ru_start);
	uint64_t wall_all_start = bench_get_ns();

	for (int iter = 0; iter < N; iter++) {
		uint64_t iter_start = bench_get_ns();
		uint64_t txrx_ns = 0;

		/* ══════ Setup (Precomputation) ══════ */
		/* Generate PQ-KEM key pair: (sk_KEM, PK_KEM) = PQ-KEM.KeyGen() */
		uint8_t kem_pk[PQ_KEM_PK_LEN], kem_sk[PQ_KEM_SK_LEN];
		/* Generate ephemeral ECDH key pair: (x, X = gˣ) */
		uint8_t eph_sk[32], eph_pk[32];
		{
			HS_TIME_START();
			pq_kem_keygen(kem_pk, kem_sk);
			uint8_t seed_buf[4];
			*(uint32_t *)seed_buf = (uint32_t)(iter + 200);
			uint8_t sh[32]; size_t hl;
			psa_hash_compute(PSA_ALG_SHA_256, seed_buf, 4, sh, 32, &hl);
			sh[0] &= 248; sh[31] &= 127; sh[31] |= 64;
			memcpy(eph_sk, sh, 32);
			crypto_scalarmult_base(eph_pk, eph_sk);
			HS_TIME_END(variant, OP_KEYGEN);
		}
		uint64_t precomp_end = bench_get_ns();

		/* ── M1 = (METHOD, SUITES_I, X, PK_KEM, C_I, EAD_1) ── */
		uint8_t msg1[32 + PQ_KEM_PK_LEN];
		memcpy(msg1, eph_pk, 32);
		memcpy(msg1 + 32, kem_pk, PQ_KEM_PK_LEN);
		{
			uint64_t tx_start = bench_get_ns();
			p2p_send_msg(sockfd, P2P_MSG_TYPE_MSG1, msg1, 32 + PQ_KEM_PK_LEN);
			txrx_ns += (bench_get_ns() - tx_start);
		}

		/* ── Receive M2 = (Y, C_KEM, Enc_EK₂(msg_2)) ── */
		uint8_t msg2[P2P_MSG_BUF_SIZE];
		uint32_t msg2_len;
		{
			uint64_t rx_start = bench_get_ns();
			p2p_recv_msg(sockfd, &type, msg2, &msg2_len, sizeof(msg2));
			txrx_ns += (bench_get_ns() - rx_start);
		}

		uint8_t gy[32], c_kem[PQ_KEM_CT_LEN];
		memcpy(gy, msg2, 32);
		memcpy(c_kem, msg2 + 32, PQ_KEM_CT_LEN);

		/* ══════ Initiator Verification & Response ══════ */

		/* PQ-KEM Decapsulate: k_KEM = PQ-KEM.Decaps(sk_KEM, C_KEM) */
		uint8_t k_kem[PQ_KEM_SS_LEN];
		{
			HS_TIME_START();
			pq_kem_decaps(k_kem, c_kem, kem_sk);
			HS_TIME_END(variant, OP_DECAPS);
		}

		/* TH_2 = H(Y, M1, C_KEM) */
		uint8_t th2[32];
		{
			HS_TIME_START();
			uint8_t hash_in[P2P_MSG_BUF_SIZE];
			uint32_t hlen = 0;
			memcpy(hash_in, gy, 32); hlen += 32;
			memcpy(hash_in + hlen, msg1, 32 + PQ_KEM_PK_LEN); hlen += 32 + PQ_KEM_PK_LEN;
			memcpy(hash_in + hlen, c_kem, PQ_KEM_CT_LEN); hlen += PQ_KEM_CT_LEN;
			crypto_hash_sha256(th2, hash_in, hlen);
			HS_TIME_END(variant, OP_HASH);
		}

		/* PRK_2 = Extract(Yˣ, k_KEM, TH_2) */
		uint8_t shared_xy[32];
		{
			HS_TIME_START();
			crypto_scalarmult(shared_xy, eph_sk, gy);
			HS_TIME_END(variant, OP_ENCAPS);
		}
		uint8_t prk2[32];
		{
			HS_TIME_START();
			uint8_t ikm[PQ_KEM_SS_LEN + 32];
			memcpy(ikm, k_kem, PQ_KEM_SS_LEN);
			memcpy(ikm + PQ_KEM_SS_LEN, th2, 32);
			crypto_auth_hmacsha256(prk2, ikm, PQ_KEM_SS_LEN + 32, shared_xy);
			HS_TIME_END(variant, OP_HKDF_EXTRACT);
		}

		/* EK_2 = Expand(PRK_2, TH_2) — encryption key from PRK_2 */
		uint8_t ek2[PQ_AEAD_KEY_LEN], iv2[PQ_AEAD_NONCE_LEN];
		{
			HS_TIME_START();
			derive_key_iv(prk2, INFO_K2, INFO_K2_LEN, ek2, iv2);
			HS_TIME_END(variant, OP_HKDF_EXPAND);
		}

		/* msg_2 = Dec(EK_2, CIPHERTEXT_2) */
		uint8_t pt2[512]; size_t pt2_len = 0;
		if (msg2_len > 32 + PQ_KEM_CT_LEN) {
			uint32_t aead_off = 32 + PQ_KEM_CT_LEN;
			uint32_t aead_len = msg2_len - aead_off;
			{
				HS_TIME_START();
				pq_aead_decrypt(ek2, iv2, NULL, 0, msg2 + aead_off, aead_len, pt2, &pt2_len);
				HS_TIME_END(variant, OP_AEAD_DECRYPT);
			}
		}

		/* Static DH: PRK_3e2m = Extract(Bˣ, PRK_2) */
		uint8_t shared_xb[32];
		{
			HS_TIME_START();
			crypto_scalarmult(shared_xb, eph_sk, static_pk_r);
			HS_TIME_END(variant, OP_ENCAPS);
		}
		uint8_t prk3e2m[32];
		{
			HS_TIME_START();
			crypto_auth_hmacsha256(prk3e2m, prk2, 32, shared_xb);
			HS_TIME_END(variant, OP_HKDF_EXTRACT);
		}

		/* MK_2 = Expand(PRK_3e2m, TH_2) */
		uint8_t mk2[32];
		{
			HS_TIME_START();
			uint8_t tmp[33]; memcpy(tmp, th2, 32); tmp[32] = 0x02;
			crypto_auth_hmacsha256(mk2, tmp, 33, prk3e2m);
			HS_TIME_END(variant, OP_HKDF_EXPAND);
		}

		/* Verify MAC_2 */
		{
			HS_TIME_START();
			uint8_t mac2_check[32];
			uint8_t tmp[33]; memcpy(tmp, th2, 32); tmp[32] = 0x01;
			crypto_auth_hmacsha256(mac2_check, tmp, 33, mk2);
			HS_TIME_END(variant, OP_HKDF_EXPAND);
		}

		/* ── Prepare Message 3 ── */

		/* TH_3 = H(TH_2, msg_2, B) */
		uint8_t th3[32];
		{
			HS_TIME_START();
			uint8_t hash_in[P2P_MSG_BUF_SIZE];
			uint32_t hlen = 0;
			memcpy(hash_in, th2, 32); hlen += 32;
			memcpy(hash_in + hlen, msg2, msg2_len); hlen += msg2_len;
			memcpy(hash_in + hlen, static_pk_r, 32); hlen += 32;
			crypto_hash_sha256(th3, hash_in, hlen);
			HS_TIME_END(variant, OP_HASH);
		}

		/* (EK_3, IV_3) = Expand(PRK_3e2m, TH_3) */
		uint8_t ek3[PQ_AEAD_KEY_LEN], iv3[PQ_AEAD_NONCE_LEN];
		{
			HS_TIME_START();
			derive_key_iv(prk3e2m, INFO_K3, INFO_K3_LEN, ek3, iv3);
			HS_TIME_END(variant, OP_HKDF_EXPAND);
		}

		/* Static DH: PRK_4e3m = Extract(Yᵃ, PRK_3e2m) */
		uint8_t shared_ya[32];
		{
			HS_TIME_START();
			crypto_scalarmult(shared_ya, static_sk_i, gy);
			HS_TIME_END(variant, OP_ENCAPS);
		}
		uint8_t prk4e3m[32];
		{
			HS_TIME_START();
			crypto_auth_hmacsha256(prk4e3m, prk3e2m, 32, shared_ya);
			HS_TIME_END(variant, OP_HKDF_EXTRACT);
		}

		/* MK_3 = Expand(PRK_4e3m, TH_3) */
		uint8_t mk3[32];
		{
			HS_TIME_START();
			uint8_t tmp[33]; memcpy(tmp, th3, 32); tmp[32] = 0x02;
			crypto_auth_hmacsha256(mk3, tmp, 33, prk4e3m);
			HS_TIME_END(variant, OP_HKDF_EXPAND);
		}

		/* MAC_3 = KDF(MK_3, I, TH_3, A, EAD_3, len_3) */
		uint8_t mac3[32];
		{
			HS_TIME_START();
			uint8_t tmp[33]; memcpy(tmp, th3, 32); tmp[32] = 0x01;
			crypto_auth_hmacsha256(mac3, tmp, 33, mk3);
			HS_TIME_END(variant, OP_HKDF_EXPAND);
		}

		/* msg_3 = (I, MAC_3, EAD_3)
		 * CIPHERTEXT_3 = Enc(EK_3, IV_3, msg_3) */
		uint8_t ct3[64 + PQ_AEAD_TAG_LEN];
		size_t ct3_len = 0;
		{
			HS_TIME_START();
			pq_aead_encrypt(ek3, iv3, NULL, 0, mac3, 32, ct3, &ct3_len);
			HS_TIME_END(variant, OP_AEAD_ENCRYPT);
		}

		/* Send M3 = Enc_EK₃(msg_3) */
		{
			uint64_t tx_start = bench_get_ns();
			p2p_send_msg(sockfd, P2P_MSG_TYPE_MSG3, ct3, ct3_len);
			txrx_ns += (bench_get_ns() - tx_start);
		}

		/* Wait for DONE */
		uint8_t done_buf[16]; uint32_t done_len;
		{
			uint64_t rx_start = bench_get_ns();
			p2p_recv_msg(sockfd, &type, done_buf, &done_len, sizeof(done_buf));
			txrx_ns += (bench_get_ns() - rx_start);
		}

		/* ── Derive session keys ── */

		/* TH_4 = H(TH_3, msg_3, A) */
		uint8_t th4[32];
		{
			HS_TIME_START();
			uint8_t th4_in[P2P_MSG_BUF_SIZE];
			uint32_t hlen = 0;
			memcpy(th4_in, th3, 32); hlen += 32;
			memcpy(th4_in + hlen, ct3, ct3_len); hlen += ct3_len;
			memcpy(th4_in + hlen, static_pk_i, 32); hlen += 32;
			crypto_hash_sha256(th4, th4_in, hlen);
			HS_TIME_END(variant, OP_HASH);
		}

		/* PRK_out = Expand(PRK_4e3m, TH_4) */
		uint8_t prk_out[32];
		{
			HS_TIME_START();
			uint8_t tmp[33]; memcpy(tmp, th4, 32); tmp[32] = 0x01;
			crypto_auth_hmacsha256(prk_out, tmp, 33, prk4e3m);
			HS_TIME_END(variant, OP_HKDF_EXPAND);
		}

		/* AK = Expand(Expand(PRK_out)) */
		{
			HS_TIME_START();
			uint8_t tmp1[32], tmp2[32];
			uint8_t label[33]; memcpy(label, prk_out, 32); label[32] = 0x01;
			crypto_auth_hmacsha256(tmp1, label, 33, prk_out);
			memcpy(label, tmp1, 32); label[32] = 0x02;
			crypto_auth_hmacsha256(tmp2, label, 33, tmp1);
			HS_TIME_END(variant, OP_HKDF_EXPAND);
		}

		uint64_t iter_end = bench_get_ns();
		total_wall_us += ns_to_us(iter_end - iter_start);
		if (iter == 0) { long m = get_memory_usage_bytes(); if (m > mem_peak) mem_peak = m; }
		total_txrx_us += ns_to_us(txrx_ns);
		total_precomp_us += ns_to_us(precomp_end - iter_start);
	}

	/* Finalize */
	uint64_t wall_all_end = bench_get_ns();
	getrusage(RUSAGE_SELF, &ru_end);
	finalize_variant_stats(variant, N, total_wall_us, total_txrx_us, total_precomp_us,
	                       wall_all_start, wall_all_end, &ru_start, &ru_end, mem_before, mem_peak);

	return 0;
}

int handshake_type3_hybrid_responder(int sockfd, int variant)
{
	int N = P2P_BENCH_HANDSHAKE_ITERATIONS;

	/* Generate static X25519 key pair */
	uint8_t static_sk_r[32], static_pk_r[32];
	{
		uint8_t seed_buf[4] = {0xFF, 0x00, 0x11, 0x22};
		uint8_t sh[32]; size_t hl;
		psa_hash_compute(PSA_ALG_SHA_256, seed_buf, 4, sh, 32, &hl);
		sh[0] &= 248; sh[31] &= 127; sh[31] |= 64;
		memcpy(static_sk_r, sh, 32);
		crypto_scalarmult_base(static_pk_r, static_sk_r);
	}

	/* Exchange static public keys */
	uint8_t type, static_pk_i[32]; uint32_t len;
	if (p2p_recv_msg(sockfd, &type, static_pk_i, &len, 32) != 0) return -1;
	if (p2p_send_msg(sockfd, P2P_MSG_TYPE_HANDSHAKE_START, static_pk_r, 32) != 0) return -1;

	double total_wall_us = 0, total_txrx_us = 0, total_precomp_us = 0;
	struct rusage ru_start, ru_end;
	long mem_before = get_memory_usage_bytes();
	long mem_peak = mem_before;
	getrusage(RUSAGE_SELF, &ru_start);
	uint64_t wall_all_start = bench_get_ns();

	for (int iter = 0; iter < N; iter++) {
		uint64_t iter_start = bench_get_ns();
		uint64_t txrx_ns = 0;
		uint64_t precomp_end = iter_start; /* no precomputation for responder */

		/* ── Receive M1 = (METHOD, SUITES_I, X, PK_KEM, C_I, EAD_1) ── */
		uint8_t msg1[32 + PQ_KEM_PK_LEN]; uint32_t msg1_len;
		{
			uint64_t rx_start = bench_get_ns();
			p2p_recv_msg(sockfd, &type, msg1, &msg1_len, sizeof(msg1));
			txrx_ns += (bench_get_ns() - rx_start);
		}

		uint8_t eph_pk_i[32], kem_pk[PQ_KEM_PK_LEN];
		memcpy(eph_pk_i, msg1, 32);
		memcpy(kem_pk, msg1 + 32, PQ_KEM_PK_LEN);

		/* ══════ Responder Processing ══════ */

		/* PQ-KEM Encapsulate: (k_KEM, C_KEM) = PQ-KEM.Encaps(PK_KEM) */
		uint8_t c_kem[PQ_KEM_CT_LEN], k_kem[PQ_KEM_SS_LEN];
		{
			HS_TIME_START();
			pq_kem_encaps(c_kem, k_kem, kem_pk);
			HS_TIME_END(variant, OP_ENCAPS);
		}

		/* Generate ephemeral ECDH key pair (y, Y) */
		uint8_t eph_sk_r[32], eph_pk_r[32];
		{
			HS_TIME_START();
			uint8_t seed_buf[4]; *(uint32_t *)seed_buf = (uint32_t)(iter + 7000);
			uint8_t sh[32]; size_t hl;
			psa_hash_compute(PSA_ALG_SHA_256, seed_buf, 4, sh, 32, &hl);
			sh[0] &= 248; sh[31] &= 127; sh[31] |= 64;
			memcpy(eph_sk_r, sh, 32);
			crypto_scalarmult_base(eph_pk_r, eph_sk_r);
			HS_TIME_END(variant, OP_KEYGEN);
		}

		/* TH_2 = H(Y, M1, C_KEM) */
		uint8_t th2[32];
		{
			HS_TIME_START();
			uint8_t hash_in[P2P_MSG_BUF_SIZE]; uint32_t hlen = 0;
			memcpy(hash_in, eph_pk_r, 32); hlen += 32;
			memcpy(hash_in + hlen, msg1, msg1_len); hlen += msg1_len;
			memcpy(hash_in + hlen, c_kem, PQ_KEM_CT_LEN); hlen += PQ_KEM_CT_LEN;
			crypto_hash_sha256(th2, hash_in, hlen);
			HS_TIME_END(variant, OP_HASH);
		}

		/* PRK_2 = Extract(Xʸ, k_KEM, TH_2) */
		uint8_t shared_xy[32];
		{
			HS_TIME_START();
			crypto_scalarmult(shared_xy, eph_sk_r, eph_pk_i);
			HS_TIME_END(variant, OP_ENCAPS);
		}
		uint8_t prk2[32];
		{
			HS_TIME_START();
			uint8_t ikm[PQ_KEM_SS_LEN + 32];
			memcpy(ikm, k_kem, PQ_KEM_SS_LEN);
			memcpy(ikm + PQ_KEM_SS_LEN, th2, 32);
			crypto_auth_hmacsha256(prk2, ikm, PQ_KEM_SS_LEN + 32, shared_xy);
			HS_TIME_END(variant, OP_HKDF_EXTRACT);
		}

		/* EK_2 = Expand(PRK_2, TH_2) — encryption key from PRK_2 */
		uint8_t ek2[PQ_AEAD_KEY_LEN], iv2[PQ_AEAD_NONCE_LEN];
		{
			HS_TIME_START();
			derive_key_iv(prk2, INFO_K2, INFO_K2_LEN, ek2, iv2);
			HS_TIME_END(variant, OP_HKDF_EXPAND);
		}

		/* Static DH: PRK_3e2m = Extract(Xᵇ, PRK_2) */
		uint8_t shared_bx[32];
		{
			HS_TIME_START();
			crypto_scalarmult(shared_bx, static_sk_r, eph_pk_i);
			HS_TIME_END(variant, OP_ENCAPS);
		}
		uint8_t prk3e2m[32];
		{
			HS_TIME_START();
			crypto_auth_hmacsha256(prk3e2m, prk2, 32, shared_bx);
			HS_TIME_END(variant, OP_HKDF_EXTRACT);
		}

		/* MK_2 = Expand(PRK_3e2m, TH_2) */
		uint8_t mk2[32];
		{
			HS_TIME_START();
			uint8_t tmp[33]; memcpy(tmp, th2, 32); tmp[32] = 0x02;
			crypto_auth_hmacsha256(mk2, tmp, 33, prk3e2m);
			HS_TIME_END(variant, OP_HKDF_EXPAND);
		}

		/* MAC_2 = KDF(MK_2, C_R, X, TH_2, B, EAD_2, len_2) */
		uint8_t mac2[32];
		{
			HS_TIME_START();
			uint8_t tmp[33]; memcpy(tmp, th2, 32); tmp[32] = 0x01;
			crypto_auth_hmacsha256(mac2, tmp, 33, mk2);
			HS_TIME_END(variant, OP_HKDF_EXPAND);
		}

		/* msg_2 = (C_R, R, MAC_2, EAD_2)
		 * CIPHERTEXT_2 = Enc(EK_2, msg_2) */
		uint8_t ct2_aead[128 + PQ_AEAD_TAG_LEN]; size_t ct2_aead_len;
		{
			HS_TIME_START();
			pq_aead_encrypt(ek2, iv2, NULL, 0, mac2, 32, ct2_aead, &ct2_aead_len);
			HS_TIME_END(variant, OP_AEAD_ENCRYPT);
		}

		/* Send M2 = (Y, C_KEM, Enc_EK₂(msg_2)) */
		uint8_t msg2[P2P_MSG_BUF_SIZE]; uint32_t msg2_len = 0;
		memcpy(msg2, eph_pk_r, 32); msg2_len += 32;
		memcpy(msg2 + msg2_len, c_kem, PQ_KEM_CT_LEN); msg2_len += PQ_KEM_CT_LEN;
		memcpy(msg2 + msg2_len, ct2_aead, ct2_aead_len); msg2_len += ct2_aead_len;
		{
			uint64_t tx_start = bench_get_ns();
			p2p_send_msg(sockfd, P2P_MSG_TYPE_MSG2, msg2, msg2_len);
			txrx_ns += (bench_get_ns() - tx_start);
		}

		/* ── Receive M3 = Enc_EK₃(msg_3) ── */
		uint8_t msg3[P2P_MSG_BUF_SIZE]; uint32_t msg3_len;
		{
			uint64_t rx_start = bench_get_ns();
			p2p_recv_msg(sockfd, &type, msg3, &msg3_len, sizeof(msg3));
			txrx_ns += (bench_get_ns() - rx_start);
		}

		/* ══════ Responder Final Verification ══════ */

		/* TH_3 = H(TH_2, msg_2, B) */
		uint8_t th3[32];
		{
			HS_TIME_START();
			uint8_t hash_in[P2P_MSG_BUF_SIZE];
			uint32_t hlen = 0;
			memcpy(hash_in, th2, 32); hlen += 32;
			memcpy(hash_in + hlen, msg2, msg2_len); hlen += msg2_len;
			memcpy(hash_in + hlen, static_pk_r, 32); hlen += 32;
			crypto_hash_sha256(th3, hash_in, hlen);
			HS_TIME_END(variant, OP_HASH);
		}

		/* (EK_3, IV_3) = Expand(PRK_3e2m, TH_3) */
		uint8_t ek3[PQ_AEAD_KEY_LEN], iv3[PQ_AEAD_NONCE_LEN];
		{
			HS_TIME_START();
			derive_key_iv(prk3e2m, INFO_K3, INFO_K3_LEN, ek3, iv3);
			HS_TIME_END(variant, OP_HKDF_EXPAND);
		}

		/* msg_3 = Dec(EK_3, IV_3, CIPHERTEXT_3) */
		uint8_t pt3[128]; size_t pt3_len;
		{
			HS_TIME_START();
			pq_aead_decrypt(ek3, iv3, NULL, 0, msg3, msg3_len, pt3, &pt3_len);
			HS_TIME_END(variant, OP_AEAD_DECRYPT);
		}

		/* Static DH: PRK_4e3m = Extract(Aʸ, PRK_3e2m) */
		uint8_t shared_ay[32];
		{
			HS_TIME_START();
			crypto_scalarmult(shared_ay, eph_sk_r, static_pk_i);
			HS_TIME_END(variant, OP_ENCAPS);
		}
		uint8_t prk4e3m[32];
		{
			HS_TIME_START();
			crypto_auth_hmacsha256(prk4e3m, prk3e2m, 32, shared_ay);
			HS_TIME_END(variant, OP_HKDF_EXTRACT);
		}

		/* MK_3 = Expand(PRK_4e3m, TH_3) */
		uint8_t mk3[32];
		{
			HS_TIME_START();
			uint8_t tmp[33]; memcpy(tmp, th3, 32); tmp[32] = 0x02;
			crypto_auth_hmacsha256(mk3, tmp, 33, prk4e3m);
			HS_TIME_END(variant, OP_HKDF_EXPAND);
		}

		/* Verify MAC_3 */
		{
			HS_TIME_START();
			uint8_t mac3_check[32];
			uint8_t tmp[33]; memcpy(tmp, th3, 32); tmp[32] = 0x01;
			crypto_auth_hmacsha256(mac3_check, tmp, 33, mk3);
			HS_TIME_END(variant, OP_HKDF_EXPAND);
		}

		/* Send DONE */
		{
			uint64_t tx_start = bench_get_ns();
			p2p_send_msg(sockfd, P2P_MSG_TYPE_DONE, NULL, 0);
			txrx_ns += (bench_get_ns() - tx_start);
		}

		/* ── Derive session keys ── */

		/* TH_4 = H(TH_3, msg_3, A) */
		uint8_t th4[32];
		{
			HS_TIME_START();
			uint8_t th4_in[P2P_MSG_BUF_SIZE];
			uint32_t hlen = 0;
			memcpy(th4_in, th3, 32); hlen += 32;
			memcpy(th4_in + hlen, msg3, msg3_len); hlen += msg3_len;
			memcpy(th4_in + hlen, static_pk_i, 32); hlen += 32;
			crypto_hash_sha256(th4, th4_in, hlen);
			HS_TIME_END(variant, OP_HASH);
		}

		/* PRK_out = Expand(PRK_4e3m, TH_4) */
		uint8_t prk_out[32];
		{
			HS_TIME_START();
			uint8_t tmp[33]; memcpy(tmp, th4, 32); tmp[32] = 0x01;
			crypto_auth_hmacsha256(prk_out, tmp, 33, prk4e3m);
			HS_TIME_END(variant, OP_HKDF_EXPAND);
		}

		/* AK = Expand(Expand(PRK_out)) */
		{
			HS_TIME_START();
			uint8_t tmp1[32], tmp2[32];
			uint8_t label[33]; memcpy(label, prk_out, 32); label[32] = 0x01;
			crypto_auth_hmacsha256(tmp1, label, 33, prk_out);
			memcpy(label, tmp1, 32); label[32] = 0x02;
			crypto_auth_hmacsha256(tmp2, label, 33, tmp1);
			HS_TIME_END(variant, OP_HKDF_EXPAND);
		}

		uint64_t iter_end = bench_get_ns();
		total_wall_us += ns_to_us(iter_end - iter_start);
		if (iter == 0) { long m = get_memory_usage_bytes(); if (m > mem_peak) mem_peak = m; }
		total_txrx_us += ns_to_us(txrx_ns);
		total_precomp_us += ns_to_us(precomp_end - iter_start);
	}

	/* Finalize */
	uint64_t wall_all_end = bench_get_ns();
	getrusage(RUSAGE_SELF, &ru_end);
	finalize_variant_stats(variant, N, total_wall_us, total_txrx_us, total_precomp_us,
	                       wall_all_start, wall_all_end, &ru_start, &ru_end, mem_before, mem_peak);

	return 0;
}
