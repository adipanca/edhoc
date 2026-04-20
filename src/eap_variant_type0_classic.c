#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 199309L
#endif
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
/*
 * =============================================================================
 * EAP-EDHOC Type 0 Classic — sig-sig with Ed25519 + X25519
 *
 * EAP-EDHOC Flow (per draft-ietf-emu-eap-edhoc):
 *   Pre-session : I ↔ R exchange Ed25519 PKs  (raw TCP, outside EAP)
 *   [EAP-EDHOC session per iteration:]
 *   R → I : EAP-Request/EAP-EDHOC-Start (S-flag)
 *   I → R : EAP-Response/EAP-EDHOC(MSG_1)    [eph X25519 pk]
 *   R → I : EAP-Request/EAP-EDHOC(MSG_2)     [gy || ct2 (id,sig)]
 *   I → R : EAP-Response/EAP-EDHOC(MSG_3)    [AEAD(sig3)]
 *   R → I : EAP-Success  + MSK/EMSK derived
 *
 * MSK/EMSK: 64B each, derived from PRK_out via HKDF-Expand
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
#include "mbedtls/gcm.h"

/* =============================================================================
 * INITIATOR — EAP-EDHOC Type 0 Classic
 * =============================================================================
 */
int eap_handshake_type0_classic_initiator(int sockfd, int variant)
{
	int N = P2P_BENCH_HANDSHAKE_ITERATIONS;

	/* Long-term Ed25519 credential */
	uint8_t ed_pk_i[32], ed_sk_i[64];
	crypto_sign_keypair(ed_pk_i, ed_sk_i);

	/* Pre-session: exchange static Ed25519 public keys (raw TCP) */
	if (p2p_send_msg(sockfd, P2P_MSG_TYPE_HANDSHAKE_START, ed_pk_i, 32) != 0) return -1;
	uint8_t type, ed_pk_r[32]; uint32_t len;
	if (p2p_recv_msg(sockfd, &type, ed_pk_r, &len, 32) != 0) return -1;

	double total_wall_us = 0, total_txrx_us = 0, total_precomp_us = 0;
	struct rusage ru_start, ru_end;
	long mem_before = get_memory_usage_bytes();
	long mem_peak = mem_before;
	getrusage(RUSAGE_SELF, &ru_start);
	uint64_t wall_all_start = bench_get_ns();

	for (int iter = 0; iter < N; iter++) {
		uint64_t iter_start = bench_get_ns();
		uint64_t txrx_ns = 0;

		/* ── Keygen (precomputation) ── */
		uint8_t eph_sk[32], eph_pk[32];
		{
			HS_TIME_START();
			uint8_t seed_buf[4]; *(uint32_t *)seed_buf = (uint32_t)(iter + 1);
			uint8_t sh[32]; size_t hl;
			psa_hash_compute(PSA_ALG_SHA_256, seed_buf, 4, sh, 32, &hl);
			sh[0] &= 248; sh[31] &= 127; sh[31] |= 64;
			memcpy(eph_sk, sh, 32);
			crypto_scalarmult_base(eph_pk, eph_sk);
			HS_TIME_END(variant, OP_KEYGEN);
		}
		uint64_t precomp_end = bench_get_ns();

		/* ── [EAP] Receive EAP-EDHOC-Start from server ── */
		uint8_t eap_id = 0;
		if (eap_recv_start(sockfd, &eap_id) != 0) return -1;

		/* ── Send MSG1 as EAP-Response ── */
		uint8_t message_1[35];
		message_1[0] = 0x00;
		message_1[1] = 0x02;
		memcpy(message_1 + 2, eph_pk, 32);
		message_1[34] = 0x00;
		if (eap_send_edhoc_msg(sockfd, 0/*Response*/, eap_id,
		                       message_1, 35, &txrx_ns) != 0) return -1;
		if (iter == 0) { g_eap_transport[variant].msg1_frags = g_eap_last_frag_count; g_eap_transport[variant].msg1_bytes = 35; }

		/* ── Receive MSG2 as EAP-Request ── */
		uint8_t msg2_buf[P2P_MSG_BUF_SIZE]; uint32_t msg2_len;
		if (eap_recv_edhoc_msg(sockfd, EAP_CODE_REQUEST,
		                       msg2_buf, &msg2_len, sizeof(msg2_buf),
		                       &eap_id, &txrx_ns) != 0) return -1;
		if (iter == 0) { g_eap_transport[variant].msg2_frags = g_eap_last_frag_count; g_eap_transport[variant].msg2_bytes = msg2_len; }

		uint8_t gy[32];
		memcpy(gy, msg2_buf, 32);
		uint8_t *ciphertext_2 = msg2_buf + 32;
		uint32_t ciphertext_2_len = msg2_len - 32;

		/* ── Crypto: scalar mult ── */
		uint8_t shared_xy[32];
		{
			HS_TIME_START();
			crypto_scalarmult(shared_xy, eph_sk, gy);
			HS_TIME_END(variant, OP_SCALAR_MULT);
		}

		/* ── TH_2 ── */
		uint8_t th2[32];
		{
			HS_TIME_START();
			uint8_t h_msg1[32]; crypto_hash_sha256(h_msg1, message_1, 35);
			uint8_t th2_input[64];
			memcpy(th2_input, gy, 32); memcpy(th2_input + 32, h_msg1, 32);
			crypto_hash_sha256(th2, th2_input, 64);
			HS_TIME_END(variant, OP_HASH);
		}

		/* ── PRK_2e ── */
		uint8_t prk_2e[32];
		{
			HS_TIME_START();
			crypto_auth_hmacsha256(prk_2e, shared_xy, 32, th2);
			HS_TIME_END(variant, OP_HKDF_EXTRACT);
		}

		/* ── Decrypt CIPHERTEXT_2 ── */
		uint8_t plaintext_2[128];
		{
			HS_TIME_START();
			uint8_t ks2[128];
			edhoc_kdf(prk_2e, 0, th2, 32, ks2, ciphertext_2_len);
			for (uint32_t i = 0; i < ciphertext_2_len; i++)
				plaintext_2[i] = ciphertext_2[i] ^ ks2[i];
			HS_TIME_END(variant, OP_HKDF_EXPAND);
		}

		uint8_t sig2[64]; memcpy(sig2, plaintext_2 + 2, 64);
		uint8_t prk_3e2m[32]; memcpy(prk_3e2m, prk_2e, 32);

		/* ── Verify Sig_2 ── */
		uint8_t mac2[32];
		{
			HS_TIME_START();
			uint8_t ctx2[128]; size_t cl = 0;
			ctx2[cl++] = plaintext_2[0]; ctx2[cl++] = plaintext_2[1];
			memcpy(ctx2 + cl, th2, 32); cl += 32;
			memcpy(ctx2 + cl, ed_pk_r, 32); cl += 32;
			edhoc_kdf(prk_3e2m, 2, ctx2, cl, mac2, 32);
			HS_TIME_END(variant, OP_HKDF_EXPAND);
		}
		{
			HS_TIME_START();
			crypto_sign_verify_detached(sig2, mac2, 32, ed_pk_r);
			HS_TIME_END(variant, OP_VERIFY);
		}

		/* ── TH_3 ── */
		uint8_t th3[32];
		{
			HS_TIME_START();
			uint8_t in3[256]; size_t il = 0;
			memcpy(in3, th2, 32); il += 32;
			memcpy(in3 + il, plaintext_2, ciphertext_2_len); il += ciphertext_2_len;
			memcpy(in3 + il, ed_pk_r, 32); il += 32;
			crypto_hash_sha256(th3, in3, il);
			HS_TIME_END(variant, OP_HASH);
		}

		uint8_t prk_4e3m[32]; memcpy(prk_4e3m, prk_3e2m, 32);

		/* ── Compute MAC_3 ── */
		uint8_t mac3[32];
		{
			HS_TIME_START();
			uint8_t ctx3[128]; size_t cl = 0;
			ctx3[cl++] = 0x02;
			memcpy(ctx3 + cl, th3, 32); cl += 32;
			memcpy(ctx3 + cl, ed_pk_i, 32); cl += 32;
			edhoc_kdf(prk_4e3m, 6, ctx3, cl, mac3, 32);
			HS_TIME_END(variant, OP_HKDF_EXPAND);
		}

		/* ── Sign_3 ── */
		uint8_t sig3[64];
		{
			HS_TIME_START();
			crypto_sign_detached(sig3, NULL, mac3, 32, ed_sk_i);
			HS_TIME_END(variant, OP_SIGNATURE);
		}

		/* ── Build + Encrypt MSG3 ── */
		uint8_t pt3[65]; pt3[0] = 0x02; memcpy(pt3 + 1, sig3, 64);
		uint8_t k3[16], iv3[13];
		{
			HS_TIME_START();
			edhoc_kdf(prk_3e2m, 3, th3, 32, k3, 16);
			edhoc_kdf(prk_3e2m, 4, th3, 32, iv3, 13);
			HS_TIME_END(variant, OP_HKDF_EXPAND);
		}
		uint8_t msg3_buf[128]; uint32_t msg3_len;
		{
			HS_TIME_START();
			mbedtls_gcm_context gcm; mbedtls_gcm_init(&gcm);
			mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, k3, 128);
			uint8_t tag[16];
			mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, 65,
			                          iv3, 13, th3, 32, pt3, msg3_buf, 16, tag);
			memcpy(msg3_buf + 65, tag, 16); msg3_len = 65 + 16;
			mbedtls_gcm_free(&gcm);
			HS_TIME_END(variant, OP_AEAD_ENCRYPT);
		}

		/* ── Send MSG3 as EAP-Response ── */
		if (eap_send_edhoc_msg(sockfd, 0/*Response*/, eap_id,
		                       msg3_buf, msg3_len, &txrx_ns) != 0) return -1;
		if (iter == 0) { g_eap_transport[variant].msg3_frags = g_eap_last_frag_count; g_eap_transport[variant].msg3_bytes = msg3_len; }

		/* ── Receive EAP-Success ── */
		if (eap_recv_success(sockfd) != 0) return -1;
		txrx_ns += 0;  /* EAP-Success receive is fast (already counted internally) */

		/* ── TH_4 ── */
		uint8_t th4[32];
		{
			HS_TIME_START();
			uint8_t th4_in[256]; size_t il = 0;
			memcpy(th4_in, th3, 32); il += 32;
			memcpy(th4_in + il, pt3, 65); il += 65;
			memcpy(th4_in + il, ed_pk_i, 32); il += 32;
			crypto_hash_sha256(th4, th4_in, il);
			HS_TIME_END(variant, OP_HASH);
		}

		/* ── PRK_out + MSK/EMSK ── */
		uint8_t prk_out[32];
		{
			HS_TIME_START();
			edhoc_kdf(prk_4e3m, 7, th4, 32, prk_out, 32);
			HS_TIME_END(variant, OP_HKDF_EXPAND);
		}
		uint8_t msk[64], emsk[64];
		eap_derive_msk_emsk(prk_out, msk, emsk);

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
 * RESPONDER — EAP-EDHOC Type 0 Classic (EAP Server)
 * =============================================================================
 */
int eap_handshake_type0_classic_responder(int sockfd, int variant)
{
	int N = P2P_BENCH_HANDSHAKE_ITERATIONS;

	uint8_t ed_pk_r[32], ed_sk_r[64];
	crypto_sign_keypair(ed_pk_r, ed_sk_r);

	uint8_t type, ed_pk_i[32]; uint32_t len;
	if (p2p_recv_msg(sockfd, &type, ed_pk_i, &len, 32) != 0) return -1;
	if (p2p_send_msg(sockfd, P2P_MSG_TYPE_HANDSHAKE_START, ed_pk_r, 32) != 0) return -1;

	double total_wall_us = 0, total_txrx_us = 0, total_precomp_us = 0;
	struct rusage ru_start, ru_end;
	long mem_before = get_memory_usage_bytes();
	long mem_peak = mem_before;
	getrusage(RUSAGE_SELF, &ru_start);
	uint64_t wall_all_start = bench_get_ns();

	for (int iter = 0; iter < N; iter++) {
		uint64_t iter_start = bench_get_ns();
		uint64_t txrx_ns = 0;

		/* ── Keygen (precomputation) ── */
		uint8_t eph_sk_r[32], eph_pk_r[32];
		{
			HS_TIME_START();
			uint8_t seed_buf[4]; *(uint32_t *)seed_buf = (uint32_t)(iter + 5000);
			uint8_t sh[32]; size_t hl;
			psa_hash_compute(PSA_ALG_SHA_256, seed_buf, 4, sh, 32, &hl);
			sh[0] &= 248; sh[31] &= 127; sh[31] |= 64;
			memcpy(eph_sk_r, sh, 32);
			crypto_scalarmult_base(eph_pk_r, eph_sk_r);
			HS_TIME_END(variant, OP_KEYGEN);
		}
		uint64_t precomp_end = bench_get_ns();

		/* ── [EAP] Send EAP-EDHOC-Start (Server initiates) ── */
		uint8_t eap_id = (uint8_t)(iter + 1);
		if (eap_send_start(sockfd, eap_id) != 0) return -1;
		txrx_ns += 0;  /* Start send time is negligible */

		/* ── Receive MSG1 as EAP-Response ── */
		uint8_t message_1[64]; uint32_t msg1_len;
		if (eap_recv_edhoc_msg(sockfd, EAP_CODE_RESPONSE,
		                       message_1, &msg1_len, sizeof(message_1),
		                       NULL, &txrx_ns) != 0) return -1;
		if (iter == 0) { g_eap_transport[variant].msg1_frags = g_eap_last_frag_count; g_eap_transport[variant].msg1_bytes = msg1_len; }
		uint8_t eph_pk_i[32]; memcpy(eph_pk_i, message_1 + 2, 32);

		/* ── TH_2 ── */
		uint8_t th2[32];
		{
			HS_TIME_START();
			uint8_t h_msg1[32]; crypto_hash_sha256(h_msg1, message_1, msg1_len);
			uint8_t th2_in[64];
			memcpy(th2_in, eph_pk_r, 32); memcpy(th2_in + 32, h_msg1, 32);
			crypto_hash_sha256(th2, th2_in, 64);
			HS_TIME_END(variant, OP_HASH);
		}

		/* ── Scalar mult ── */
		uint8_t shared_xy[32];
		{
			HS_TIME_START();
			crypto_scalarmult(shared_xy, eph_sk_r, eph_pk_i);
			HS_TIME_END(variant, OP_SCALAR_MULT);
		}

		/* ── PRK_2e ── */
		uint8_t prk_2e[32];
		{
			HS_TIME_START();
			crypto_auth_hmacsha256(prk_2e, shared_xy, 32, th2);
			HS_TIME_END(variant, OP_HKDF_EXTRACT);
		}
		uint8_t prk_3e2m[32]; memcpy(prk_3e2m, prk_2e, 32);

		/* ── Compute MAC_2 + Sign_2 ── */
		uint8_t c_r = 0x37, id_cred_r = 0x01;
		uint8_t mac2[32];
		{
			HS_TIME_START();
			uint8_t ctx2[128]; size_t cl = 0;
			ctx2[cl++] = c_r; ctx2[cl++] = id_cred_r;
			memcpy(ctx2 + cl, th2, 32); cl += 32;
			memcpy(ctx2 + cl, ed_pk_r, 32); cl += 32;
			edhoc_kdf(prk_3e2m, 2, ctx2, cl, mac2, 32);
			HS_TIME_END(variant, OP_HKDF_EXPAND);
		}
		uint8_t sig2[64];
		{
			HS_TIME_START();
			crypto_sign_detached(sig2, NULL, mac2, 32, ed_sk_r);
			HS_TIME_END(variant, OP_SIGNATURE);
		}

		/* ── Build + Encrypt MSG2 ── */
		uint8_t pt2[66]; pt2[0] = c_r; pt2[1] = id_cred_r;
		memcpy(pt2 + 2, sig2, 64);
		uint8_t ct2[66];
		{
			HS_TIME_START();
			uint8_t ks2[66];
			edhoc_kdf(prk_2e, 0, th2, 32, ks2, 66);
			for (int i = 0; i < 66; i++) ct2[i] = pt2[i] ^ ks2[i];
			HS_TIME_END(variant, OP_HKDF_EXPAND);
		}
		uint8_t msg2[128];
		memcpy(msg2, eph_pk_r, 32); memcpy(msg2 + 32, ct2, 66);
		uint32_t msg2_len = 32 + 66;

		/* ── Send MSG2 as EAP-Request (increment EAP id) ── */
		eap_id++;
		if (eap_send_edhoc_msg(sockfd, 1/*Request*/, eap_id,
		                       msg2, msg2_len, &txrx_ns) != 0) return -1;
		if (iter == 0) { g_eap_transport[variant].msg2_frags = g_eap_last_frag_count; g_eap_transport[variant].msg2_bytes = msg2_len; }

		/* ── Receive MSG3 as EAP-Response ── */
		uint8_t msg3[P2P_MSG_BUF_SIZE]; uint32_t msg3_len;
		if (eap_recv_edhoc_msg(sockfd, EAP_CODE_RESPONSE,
		                       msg3, &msg3_len, sizeof(msg3),
		                       NULL, &txrx_ns) != 0) return -1;
		if (iter == 0) { g_eap_transport[variant].msg3_frags = g_eap_last_frag_count; g_eap_transport[variant].msg3_bytes = msg3_len; }

		/* ── TH_3 ── */
		uint8_t th3[32];
		{
			HS_TIME_START();
			uint8_t in3[256]; size_t il = 0;
			memcpy(in3, th2, 32); il += 32;
			memcpy(in3 + il, pt2, 66); il += 66;
			memcpy(in3 + il, ed_pk_r, 32); il += 32;
			crypto_hash_sha256(th3, in3, il);
			HS_TIME_END(variant, OP_HASH);
		}

		/* ── Decrypt MSG3 ── */
		uint8_t k3[16], iv3[13];
		{
			HS_TIME_START();
			edhoc_kdf(prk_3e2m, 3, th3, 32, k3, 16);
			edhoc_kdf(prk_3e2m, 4, th3, 32, iv3, 13);
			HS_TIME_END(variant, OP_HKDF_EXPAND);
		}
		uint8_t pt3[128];
		{
			HS_TIME_START();
			mbedtls_gcm_context gcm; mbedtls_gcm_init(&gcm);
			mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, k3, 128);
			if (msg3_len > 16)
				mbedtls_gcm_auth_decrypt(&gcm, msg3_len - 16, iv3, 13,
				                         th3, 32, msg3 + msg3_len - 16, 16,
				                         msg3, pt3);
			mbedtls_gcm_free(&gcm);
			HS_TIME_END(variant, OP_AEAD_DECRYPT);
		}

		/* ── Verify Sig_3 ── */
		uint8_t prk_4e3m[32]; memcpy(prk_4e3m, prk_3e2m, 32);
		uint8_t mac3[32];
		{
			HS_TIME_START();
			uint8_t ctx3[128]; size_t cl = 0;
			ctx3[cl++] = 0x02;
			memcpy(ctx3 + cl, th3, 32); cl += 32;
			memcpy(ctx3 + cl, ed_pk_i, 32); cl += 32;
			edhoc_kdf(prk_4e3m, 6, ctx3, cl, mac3, 32);
			HS_TIME_END(variant, OP_HKDF_EXPAND);
		}
		uint8_t sig3[64]; uint32_t pt3_len = msg3_len - 16;
		memcpy(sig3, pt3 + 1, 64);
		{
			HS_TIME_START();
			crypto_sign_verify_detached(sig3, mac3, 32, ed_pk_i);
			HS_TIME_END(variant, OP_VERIFY);
		}

		/* ── Send EAP-Success ── */
		eap_id++;
		if (eap_send_success(sockfd, eap_id) != 0) return -1;

		/* ── TH_4 ── */
		uint8_t th4[32];
		{
			HS_TIME_START();
			uint8_t th4_in[256]; size_t il = 0;
			memcpy(th4_in, th3, 32); il += 32;
			memcpy(th4_in + il, pt3, pt3_len); il += pt3_len;
			memcpy(th4_in + il, ed_pk_i, 32); il += 32;
			crypto_hash_sha256(th4, th4_in, il);
			HS_TIME_END(variant, OP_HASH);
		}

		/* ── PRK_out + MSK/EMSK ── */
		uint8_t prk_out[32];
		{
			HS_TIME_START();
			edhoc_kdf(prk_4e3m, 7, th4, 32, prk_out, 32);
			HS_TIME_END(variant, OP_HKDF_EXPAND);
		}
		uint8_t msk[64], emsk[64];
		eap_derive_msk_emsk(prk_out, msk, emsk);

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
