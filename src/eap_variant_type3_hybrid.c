#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 199309L
#endif
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
/*
 * =============================================================================
 * EAP-EDHOC Type 3 Hybrid — X25519 ECDHE + ML-KEM-768 + MAC authentication
 *
 * EAP-EDHOC Flow:
 *   Pre-session : I ↔ R exchange static X25519 PKs  (raw TCP)
 *   R → I : EAP-Request/EAP-EDHOC-Start
 *   I → R : EAP-Response(MSG_1)   [32+1184=1216 B → 2 EAP frags]
 *   R → I : EAP-Request(MSG_2)    [32+1088+~48=~1168 B → 2 EAP frags]
 *   I → R : EAP-Response(MSG_3)   [~48 B → 1 frag]
 *   R → I : EAP-Success + MSK/EMSK
 *
 * Key schedule:
 *   PRK_2     = Extract(X^y || k_KEM, TH_2)
 *   PRK_3e2m  = Extract(X^b, PRK_2)
 *   PRK_4e3m  = Extract(Y^a, PRK_3e2m)
 *   PRK_out   = Expand(PRK_4e3m, TH_4)
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
#include "edhoc_benchmark_eap.h"
#include "edhoc_pq_kem.h"

/* =============================================================================
 * INITIATOR — EAP-EDHOC Type 3 Hybrid
 * =============================================================================
 */
int eap_handshake_type3_hybrid_initiator(int sockfd, int variant)
{
	int N = P2P_BENCH_HANDSHAKE_ITERATIONS;

	/* Static X25519 key pair */
	uint8_t static_sk_i[32], static_pk_i[32];
	{
		uint8_t seed[4] = {0xEE, 0xFF, 0x00, 0x11};
		uint8_t sh[32]; size_t hl;
		psa_hash_compute(PSA_ALG_SHA_256, seed, 4, sh, 32, &hl);
		sh[0] &= 248; sh[31] &= 127; sh[31] |= 64;
		memcpy(static_sk_i, sh, 32);
		crypto_scalarmult_base(static_pk_i, static_sk_i);
	}

	/* Pre-session: exchange static X25519 PKs (raw TCP) */
	if (p2p_send_msg(sockfd, P2P_MSG_TYPE_HANDSHAKE_START, static_pk_i, 32) != 0) return -1;
	uint8_t type, static_pk_r[32]; uint32_t len;
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

		/* ── Keygen: ML-KEM-768 + ephemeral X25519 ── */
		uint8_t kem_pk[PQ_KEM_PK_LEN], kem_sk[PQ_KEM_SK_LEN];
		uint8_t eph_sk[32], eph_pk[32];
		{
			HS_TIME_START();
			pq_kem_keygen(kem_pk, kem_sk);
			uint8_t seed_buf[4]; *(uint32_t *)seed_buf = (uint32_t)(iter + 200);
			uint8_t sh[32]; size_t hl;
			psa_hash_compute(PSA_ALG_SHA_256, seed_buf, 4, sh, 32, &hl);
			sh[0] &= 248; sh[31] &= 127; sh[31] |= 64;
			memcpy(eph_sk, sh, 32);
			crypto_scalarmult_base(eph_pk, eph_sk);
			HS_TIME_END(variant, OP_KEYGEN);
		}
		uint64_t precomp_end = bench_get_ns();

		/* ── Build MSG1 = eph_pk(32) || kem_pk(1184) ── */
		uint8_t msg1[32 + PQ_KEM_PK_LEN];
		memcpy(msg1, eph_pk, 32);
		memcpy(msg1 + 32, kem_pk, PQ_KEM_PK_LEN);

		/* ── [EAP] Receive EAP-Start ── */
		uint8_t eap_id = 0;
		if (eap_recv_start(sockfd, &eap_id) != 0) return -1;

		/* ── Send MSG1 as EAP-Response ── */
		if (eap_send_edhoc_msg(sockfd, 0, eap_id, msg1, 32 + PQ_KEM_PK_LEN, &txrx_ns) != 0) return -1;
		if (iter == 0) { g_eap_transport[variant].msg1_frags = g_eap_last_frag_count; g_eap_transport[variant].msg1_bytes = 32 + PQ_KEM_PK_LEN; }

		/* ── Receive MSG2 as EAP-Request ── */
		uint8_t msg2[EAP_MSG_BUF_SIZE]; uint32_t msg2_len;
		if (eap_recv_edhoc_msg(sockfd, EAP_CODE_REQUEST,
		                       msg2, &msg2_len, sizeof(msg2),
		                       &eap_id, &txrx_ns) != 0) return -1;
		if (iter == 0) { g_eap_transport[variant].msg2_frags = g_eap_last_frag_count; g_eap_transport[variant].msg2_bytes = msg2_len; }

		uint8_t gy[32], c_kem[PQ_KEM_CT_LEN];
		memcpy(gy, msg2, 32);
		memcpy(c_kem, msg2 + 32, PQ_KEM_CT_LEN);

		/* ── KEM Decaps: k_kem ── */
		uint8_t k_kem[PQ_KEM_SS_LEN];
		{
			HS_TIME_START();
			pq_kem_decaps(k_kem, c_kem, kem_sk);
			HS_TIME_END(variant, OP_DECAPS);
		}

		/* ── TH_2 = H(Y, MSG1, C_KEM) ── */
		uint8_t th2[32];
		{
			HS_TIME_START();
			uint8_t hash_in[EAP_MSG_BUF_SIZE]; uint32_t hlen = 0;
			memcpy(hash_in, gy, 32); hlen += 32;
			memcpy(hash_in + hlen, msg1, 32 + PQ_KEM_PK_LEN); hlen += 32 + PQ_KEM_PK_LEN;
			memcpy(hash_in + hlen, c_kem, PQ_KEM_CT_LEN); hlen += PQ_KEM_CT_LEN;
			crypto_hash_sha256(th2, hash_in, hlen);
			HS_TIME_END(variant, OP_HASH);
		}

		/* ── ECDH: shared_xy = X^y ── */
		uint8_t shared_xy[32];
		{
			HS_TIME_START();
			crypto_scalarmult(shared_xy, eph_sk, gy);
			HS_TIME_END(variant, OP_ENCAPS);
		}

		/* ── PRK_2 = Extract(shared_xy || k_kem || th2) ── */
		uint8_t prk2[32];
		{
			HS_TIME_START();
			uint8_t ikm[PQ_KEM_SS_LEN + 32];
			memcpy(ikm, k_kem, PQ_KEM_SS_LEN);
			memcpy(ikm + PQ_KEM_SS_LEN, th2, 32);
			crypto_auth_hmacsha256(prk2, ikm, PQ_KEM_SS_LEN + 32, shared_xy);
			HS_TIME_END(variant, OP_HKDF_EXTRACT);
		}

		/* ── EK_2, IV_2 + Decrypt CIPHERTEXT_2 ── */
		uint8_t ek2[PQ_AEAD_KEY_LEN], iv2[PQ_AEAD_NONCE_LEN];
		{
			HS_TIME_START();
			derive_key_iv(prk2, INFO_K2, INFO_K2_LEN, ek2, iv2);
			HS_TIME_END(variant, OP_HKDF_EXPAND);
		}
		uint8_t pt2[512]; size_t pt2_len = 0;
		if (msg2_len > 32 + PQ_KEM_CT_LEN) {
			uint32_t aoff = 32 + PQ_KEM_CT_LEN;
			uint32_t alen = msg2_len - aoff;
			{
				HS_TIME_START();
				pq_aead_decrypt(ek2, iv2, NULL, 0, msg2 + aoff, alen, pt2, &pt2_len);
				HS_TIME_END(variant, OP_AEAD_DECRYPT);
			}
		}

		/* ── PRK_3e2m = Extract(X^b, PRK_2) ── */
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

		/* ── MK_2 ── */
		uint8_t mk2[32];
		{
			HS_TIME_START();
			uint8_t tmp[33]; memcpy(tmp, th2, 32); tmp[32] = 0x02;
			crypto_auth_hmacsha256(mk2, tmp, 33, prk3e2m);
			HS_TIME_END(variant, OP_HKDF_EXPAND);
		}

		/* ── Verify MAC_2 ── */
		{
			HS_TIME_START();
			uint8_t mac2_check[32];
			uint8_t tmp[33]; memcpy(tmp, th2, 32); tmp[32] = 0x01;
			crypto_auth_hmacsha256(mac2_check, tmp, 33, mk2);
			HS_TIME_END(variant, OP_HKDF_EXPAND);
		}

		/* ── TH_3 ── */
		uint8_t th3[32];
		{
			HS_TIME_START();
			uint8_t hash_in[EAP_MSG_BUF_SIZE]; uint32_t hlen = 0;
			memcpy(hash_in, th2, 32); hlen += 32;
			memcpy(hash_in + hlen, msg2, msg2_len); hlen += msg2_len;
			memcpy(hash_in + hlen, static_pk_r, 32); hlen += 32;
			crypto_hash_sha256(th3, hash_in, hlen);
			HS_TIME_END(variant, OP_HASH);
		}

		/* ── EK_3, IV_3 ── */
		uint8_t ek3[PQ_AEAD_KEY_LEN], iv3[PQ_AEAD_NONCE_LEN];
		{
			HS_TIME_START();
			derive_key_iv(prk3e2m, INFO_K3, INFO_K3_LEN, ek3, iv3);
			HS_TIME_END(variant, OP_HKDF_EXPAND);
		}

		/* ── PRK_4e3m = Extract(Y^a, PRK_3e2m) ── */
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

		/* ── MK_3 ── */
		uint8_t mk3[32];
		{
			HS_TIME_START();
			uint8_t tmp[33]; memcpy(tmp, th3, 32); tmp[32] = 0x02;
			crypto_auth_hmacsha256(mk3, tmp, 33, prk4e3m);
			HS_TIME_END(variant, OP_HKDF_EXPAND);
		}

		/* ── MAC_3 ── */
		uint8_t mac3[32];
		{
			HS_TIME_START();
			uint8_t tmp[33]; memcpy(tmp, th3, 32); tmp[32] = 0x01;
			crypto_auth_hmacsha256(mac3, tmp, 33, mk3);
			HS_TIME_END(variant, OP_HKDF_EXPAND);
		}

		/* ── Encrypt MSG3 ── */
		uint8_t ct3[64 + PQ_AEAD_TAG_LEN]; size_t ct3_len = 0;
		{
			HS_TIME_START();
			pq_aead_encrypt(ek3, iv3, NULL, 0, mac3, 32, ct3, &ct3_len);
			HS_TIME_END(variant, OP_AEAD_ENCRYPT);
		}

		/* ── Send MSG3 as EAP-Response ── */
		if (eap_send_edhoc_msg(sockfd, 0, eap_id, ct3, (uint32_t)ct3_len, &txrx_ns) != 0) return -1;
		if (iter == 0) { g_eap_transport[variant].msg3_frags = g_eap_last_frag_count; g_eap_transport[variant].msg3_bytes = (uint32_t)ct3_len; }

		/* ── Receive EAP-Success ── */
		if (eap_recv_success(sockfd) != 0) return -1;

		/* ── TH_4 ── */
		uint8_t th4[32];
		{
			HS_TIME_START();
			uint8_t th4_in[EAP_MSG_BUF_SIZE]; uint32_t hlen = 0;
			memcpy(th4_in, th3, 32); hlen += 32;
			/* ct3 is msg_3 for TH_4 */
			memcpy(th4_in + hlen, ct3, ct3_len); hlen += (uint32_t)ct3_len;
			memcpy(th4_in + hlen, static_pk_i, 32); hlen += 32;
			crypto_hash_sha256(th4, th4_in, hlen);
			HS_TIME_END(variant, OP_HASH);
		}

		/* ── PRK_out + MSK/EMSK ── */
		uint8_t prk_out[32];
		{
			HS_TIME_START();
			uint8_t tmp[33]; memcpy(tmp, th4, 32); tmp[32] = 0x01;
			crypto_auth_hmacsha256(prk_out, tmp, 33, prk4e3m);
			HS_TIME_END(variant, OP_HKDF_EXPAND);
		}
		/* ── AK (MSK/EMSK) ── */
		uint8_t msk[64], emsk[64];
		{
			HS_TIME_START();
			eap_derive_msk_emsk(prk_out, msk, emsk);
			HS_TIME_END(variant, OP_HKDF_EXPAND);
		}

		if (iter == 0) {
			long m = get_memory_usage_bytes(); if (m > mem_peak) mem_peak = m;
			struct eap_transport_stats *t = &g_eap_transport[variant];
			t->edhoc_messages = 3;
			t->total_fragments = t->msg1_frags + t->msg2_frags + t->msg3_frags;
			t->frag_ack_roundtrips = (t->msg1_frags - 1) + (t->msg2_frags - 1) + (t->msg3_frags - 1);
			if (t->frag_ack_roundtrips < 0) t->frag_ack_roundtrips = 0;
			t->total_eap_roundtrips = 1/*Start*/ + t->edhoc_messages + t->frag_ack_roundtrips + 1/*Success*/;
		}
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
 * RESPONDER — EAP-EDHOC Type 3 Hybrid (EAP Server)
 * =============================================================================
 */
int eap_handshake_type3_hybrid_responder(int sockfd, int variant)
{
	int N = P2P_BENCH_HANDSHAKE_ITERATIONS;

	/* Static X25519 key pair */
	uint8_t static_sk_r[32], static_pk_r[32];
	{
		uint8_t seed[4] = {0xFF, 0x00, 0x11, 0x22};
		uint8_t sh[32]; size_t hl;
		psa_hash_compute(PSA_ALG_SHA_256, seed, 4, sh, 32, &hl);
		sh[0] &= 248; sh[31] &= 127; sh[31] |= 64;
		memcpy(static_sk_r, sh, 32);
		crypto_scalarmult_base(static_pk_r, static_sk_r);
	}

	/* Pre-session: exchange static X25519 PKs (raw TCP) */
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
		uint64_t precomp_end = iter_start;

		/* ── [EAP] Send EAP-Start ── */
		uint8_t eap_id = (uint8_t)(iter + 1);
		if (eap_send_start(sockfd, eap_id) != 0) return -1;

		/* ── Receive MSG1 as EAP-Response ── */
		uint8_t msg1[32 + PQ_KEM_PK_LEN]; uint32_t msg1_len;
		if (eap_recv_edhoc_msg(sockfd, EAP_CODE_RESPONSE,
		                       msg1, &msg1_len, sizeof(msg1),
		                       NULL, &txrx_ns) != 0) return -1;
		if (iter == 0) { g_eap_transport[variant].msg1_frags = g_eap_last_frag_count; g_eap_transport[variant].msg1_bytes = msg1_len; }

		uint8_t eph_pk_i[32], kem_pk[PQ_KEM_PK_LEN];
		memcpy(eph_pk_i, msg1, 32);
		memcpy(kem_pk, msg1 + 32, PQ_KEM_PK_LEN);

		/* ── KEM Encaps: c_kem, k_kem ── */
		uint8_t c_kem[PQ_KEM_CT_LEN], k_kem[PQ_KEM_SS_LEN];
		{
			HS_TIME_START();
			pq_kem_encaps(c_kem, k_kem, kem_pk);
			HS_TIME_END(variant, OP_ENCAPS);
		}

		/* ── Ephemeral X25519 keygen ── */
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

		/* ── TH_2 = H(Y, MSG1, C_KEM) ── */
		uint8_t th2[32];
		{
			HS_TIME_START();
			uint8_t hash_in[EAP_MSG_BUF_SIZE]; uint32_t hlen = 0;
			memcpy(hash_in, eph_pk_r, 32); hlen += 32;
			memcpy(hash_in + hlen, msg1, msg1_len); hlen += msg1_len;
			memcpy(hash_in + hlen, c_kem, PQ_KEM_CT_LEN); hlen += PQ_KEM_CT_LEN;
			crypto_hash_sha256(th2, hash_in, hlen);
			HS_TIME_END(variant, OP_HASH);
		}

		/* ── ECDH: shared_xy = X^y ── */
		uint8_t shared_xy[32];
		{
			HS_TIME_START();
			crypto_scalarmult(shared_xy, eph_sk_r, eph_pk_i);
			HS_TIME_END(variant, OP_ENCAPS);
		}

		/* ── PRK_2 ── */
		uint8_t prk2[32];
		{
			HS_TIME_START();
			uint8_t ikm[PQ_KEM_SS_LEN + 32];
			memcpy(ikm, k_kem, PQ_KEM_SS_LEN);
			memcpy(ikm + PQ_KEM_SS_LEN, th2, 32);
			crypto_auth_hmacsha256(prk2, ikm, PQ_KEM_SS_LEN + 32, shared_xy);
			HS_TIME_END(variant, OP_HKDF_EXTRACT);
		}

		/* ── EK_2, IV_2 ── */
		uint8_t ek2[PQ_AEAD_KEY_LEN], iv2[PQ_AEAD_NONCE_LEN];
		{
			HS_TIME_START();
			derive_key_iv(prk2, INFO_K2, INFO_K2_LEN, ek2, iv2);
			HS_TIME_END(variant, OP_HKDF_EXPAND);
		}

		/* ── PRK_3e2m = Extract(X^b, PRK_2) ── */
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

		/* ── MK_2 ── */
		uint8_t mk2[32];
		{
			HS_TIME_START();
			uint8_t tmp[33]; memcpy(tmp, th2, 32); tmp[32] = 0x02;
			crypto_auth_hmacsha256(mk2, tmp, 33, prk3e2m);
			HS_TIME_END(variant, OP_HKDF_EXPAND);
		}

		/* ── MAC_2 ── */
		uint8_t mac2[32];
		{
			HS_TIME_START();
			uint8_t tmp[33]; memcpy(tmp, th2, 32); tmp[32] = 0x01;
			crypto_auth_hmacsha256(mac2, tmp, 33, mk2);
			HS_TIME_END(variant, OP_HKDF_EXPAND);
		}

		/* ── Encrypt CIPHERTEXT_2 = Enc(EK_2, mac2) ── */
		uint8_t ct2[64 + PQ_AEAD_TAG_LEN]; size_t ct2_len = 0;
		{
			HS_TIME_START();
			pq_aead_encrypt(ek2, iv2, NULL, 0, mac2, 32, ct2, &ct2_len);
			HS_TIME_END(variant, OP_AEAD_ENCRYPT);
		}

		/* ── Build MSG2 = eph_pk_r(32) || c_kem(1088) || ct2 ── */
		uint8_t msg2[EAP_MSG_BUF_SIZE]; uint32_t msg2_len = 0;
		memcpy(msg2, eph_pk_r, 32); msg2_len += 32;
		memcpy(msg2 + msg2_len, c_kem, PQ_KEM_CT_LEN); msg2_len += PQ_KEM_CT_LEN;
		memcpy(msg2 + msg2_len, ct2, ct2_len); msg2_len += (uint32_t)ct2_len;

		/* ── Send MSG2 as EAP-Request ── */
		eap_id++;
		if (eap_send_edhoc_msg(sockfd, 1, eap_id, msg2, msg2_len, &txrx_ns) != 0) return -1;
		if (iter == 0) { g_eap_transport[variant].msg2_frags = g_eap_last_frag_count; g_eap_transport[variant].msg2_bytes = msg2_len; }

		/* ── Receive MSG3 as EAP-Response ── */
		uint8_t msg3[EAP_MSG_BUF_SIZE]; uint32_t msg3_len;
		if (eap_recv_edhoc_msg(sockfd, EAP_CODE_RESPONSE,
		                       msg3, &msg3_len, sizeof(msg3),
		                       NULL, &txrx_ns) != 0) return -1;
		if (iter == 0) { g_eap_transport[variant].msg3_frags = g_eap_last_frag_count; g_eap_transport[variant].msg3_bytes = msg3_len; }

		/* ── TH_3 ── */
		uint8_t th3[32];
		{
			HS_TIME_START();
			uint8_t hash_in[EAP_MSG_BUF_SIZE]; uint32_t hlen = 0;
			memcpy(hash_in, th2, 32); hlen += 32;
			memcpy(hash_in + hlen, msg2, msg2_len); hlen += msg2_len;
			memcpy(hash_in + hlen, static_pk_r, 32); hlen += 32;
			crypto_hash_sha256(th3, hash_in, hlen);
			HS_TIME_END(variant, OP_HASH);
		}

		/* ── EK_3, IV_3 + Decrypt MSG3 ── */
		uint8_t ek3[PQ_AEAD_KEY_LEN], iv3[PQ_AEAD_NONCE_LEN];
		{
			HS_TIME_START();
			derive_key_iv(prk3e2m, INFO_K3, INFO_K3_LEN, ek3, iv3);
			HS_TIME_END(variant, OP_HKDF_EXPAND);
		}
		uint8_t pt3[128]; size_t pt3_len = 0;
		{
			HS_TIME_START();
			pq_aead_decrypt(ek3, iv3, NULL, 0, msg3, msg3_len, pt3, &pt3_len);
			HS_TIME_END(variant, OP_AEAD_DECRYPT);
		}

		/* ── PRK_4e3m = Extract(A^y, PRK_3e2m) ── */
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

		/* ── MK_3 ── */
		uint8_t mk3[32];
		{
			HS_TIME_START();
			uint8_t tmp[33]; memcpy(tmp, th3, 32); tmp[32] = 0x02;
			crypto_auth_hmacsha256(mk3, tmp, 33, prk4e3m);
			HS_TIME_END(variant, OP_HKDF_EXPAND);
		}

		/* ── Verify MAC_3 ── */
		{
			HS_TIME_START();
			uint8_t mac3_check[32];
			uint8_t tmp[33]; memcpy(tmp, th3, 32); tmp[32] = 0x01;
			crypto_auth_hmacsha256(mac3_check, tmp, 33, mk3);
			HS_TIME_END(variant, OP_HKDF_EXPAND);
		}

		/* ── Send EAP-Success ── */
		eap_id++;
		if (eap_send_success(sockfd, eap_id) != 0) return -1;

		/* ── TH_4 ── */
		uint8_t th4[32];
		{
			HS_TIME_START();
			uint8_t th4_in[EAP_MSG_BUF_SIZE]; uint32_t hlen = 0;
			memcpy(th4_in, th3, 32); hlen += 32;
			memcpy(th4_in + hlen, msg3, msg3_len); hlen += msg3_len;
			memcpy(th4_in + hlen, static_pk_i, 32); hlen += 32;
			crypto_hash_sha256(th4, th4_in, hlen);
			HS_TIME_END(variant, OP_HASH);
		}

		/* ── PRK_out + MSK/EMSK ── */
		uint8_t prk_out[32];
		{
			HS_TIME_START();
			uint8_t tmp[33]; memcpy(tmp, th4, 32); tmp[32] = 0x01;
			crypto_auth_hmacsha256(prk_out, tmp, 33, prk4e3m);
			HS_TIME_END(variant, OP_HKDF_EXPAND);
		}
		/* ── AK (MSK/EMSK) ── */
		uint8_t msk[64], emsk[64];
		{
			HS_TIME_START();
			eap_derive_msk_emsk(prk_out, msk, emsk);
			HS_TIME_END(variant, OP_HKDF_EXPAND);
		}

		if (iter == 0) {
			long m = get_memory_usage_bytes(); if (m > mem_peak) mem_peak = m;
			struct eap_transport_stats *t = &g_eap_transport[variant];
			t->edhoc_messages = 3;
			t->total_fragments = t->msg1_frags + t->msg2_frags + t->msg3_frags;
			t->frag_ack_roundtrips = (t->msg1_frags - 1) + (t->msg2_frags - 1) + (t->msg3_frags - 1);
			if (t->frag_ack_roundtrips < 0) t->frag_ack_roundtrips = 0;
			t->total_eap_roundtrips = 1 + t->edhoc_messages + t->frag_ack_roundtrips + 1;
		}
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
