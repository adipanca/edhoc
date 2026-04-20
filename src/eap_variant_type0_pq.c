#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 199309L
#endif
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
/*
 * =============================================================================
 * EAP-EDHOC Type 0 PQ — sig-sig with ML-DSA-65 + ML-KEM-768
 *
 * EAP-EDHOC Flow:
 *   Pre-session : I ↔ R exchange ML-DSA-65 PKs  (raw TCP, outside EAP)
 *   R → I : EAP-Request/EAP-EDHOC-Start
 *   I → R : EAP-Response(MSG_1)   [1187 bytes → 2 EAP fragments with MTU=1000]
 *   R → I : EAP-Request(MSG_2)    [~4400 bytes → 5 EAP fragments]
 *   I → R : EAP-Response(MSG_3)   [~3326 bytes → 4 EAP fragments]
 *   R → I : EAP-Success + MSK/EMSK
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
 * INITIATOR — EAP-EDHOC Type 0 PQ
 * =============================================================================
 */
int eap_handshake_type0_pq_initiator(int sockfd, int variant)
{
	int N = P2P_BENCH_HANDSHAKE_ITERATIONS;

	/* Long-term ML-DSA-65 credential */
	uint8_t sig_pk_i[PQ_SIG_PK_LEN], sig_sk_i[PQ_SIG_SK_LEN];
	pq_sig_keygen(sig_pk_i, sig_sk_i);

	/* Pre-session: exchange ML-DSA-65 public keys (raw TCP) */
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

		/* ── Keygen: ML-KEM-768 ephemeral ── */
		uint8_t eph_pk[PQ_KEM_PK_LEN], eph_sk[PQ_KEM_SK_LEN];
		{
			HS_TIME_START();
			pq_kem_keygen(eph_pk, eph_sk);
			HS_TIME_END(variant, OP_KEYGEN);
		}
		uint64_t precomp_end = bench_get_ns();

		/* ── [EAP] Receive EAP-EDHOC-Start ── */
		uint8_t eap_id = 0;
		if (eap_recv_start(sockfd, &eap_id) != 0) return -1;

		/* ── Send MSG1 as EAP-Response (fragmented: 1187 bytes → 2 frags) ── */
		uint8_t msg1[PQ_KEM_PK_LEN + 3];
		msg1[0] = 0x00; msg1[1] = 0x00;
		memcpy(msg1 + 2, eph_pk, PQ_KEM_PK_LEN);
		msg1[2 + PQ_KEM_PK_LEN] = 0x00;
		uint32_t msg1_len = PQ_KEM_PK_LEN + 3;
		if (eap_send_edhoc_msg(sockfd, 0, eap_id, msg1, msg1_len, &txrx_ns) != 0) return -1;
		if (iter == 0) { g_eap_transport[variant].msg1_frags = g_eap_last_frag_count; g_eap_transport[variant].msg1_bytes = msg1_len; }

		/* ── Receive MSG2 as EAP-Request (fragmented: ~4400 bytes) ── */
		uint8_t msg2[EAP_MSG_BUF_SIZE]; uint32_t msg2_len;
		if (eap_recv_edhoc_msg(sockfd, EAP_CODE_REQUEST,
		                       msg2, &msg2_len, sizeof(msg2),
		                       &eap_id, &txrx_ns) != 0) return -1;
		if (iter == 0) { g_eap_transport[variant].msg2_frags = g_eap_last_frag_count; g_eap_transport[variant].msg2_bytes = msg2_len; }

		uint8_t ct_eph[PQ_KEM_CT_LEN];
		memcpy(ct_eph, msg2, PQ_KEM_CT_LEN);
		uint8_t *ciphertext_2 = msg2 + PQ_KEM_CT_LEN;
		uint32_t ciphertext_2_len = msg2_len - PQ_KEM_CT_LEN;

		/* ── Decaps ── */
		uint8_t ss_eph[PQ_KEM_SS_LEN];
		{
			HS_TIME_START();
			pq_kem_decaps(ss_eph, ct_eph, eph_sk);
			HS_TIME_END(variant, OP_DECAPS);
		}

		/* ── TH_2 ── */
		uint8_t th2[PQ_HASH_LEN];
		{
			HS_TIME_START();
			uint8_t h1[PQ_HASH_LEN]; pq_hash_sha256(msg1, msg1_len, h1);
			uint8_t th2_in[PQ_HASH_LEN + PQ_KEM_CT_LEN];
			memcpy(th2_in, h1, PQ_HASH_LEN);
			memcpy(th2_in + PQ_HASH_LEN, ct_eph, PQ_KEM_CT_LEN);
			pq_hash_sha256(th2_in, PQ_HASH_LEN + PQ_KEM_CT_LEN, th2);
			HS_TIME_END(variant, OP_HASH);
		}

		/* ── PRK_2e ── */
		uint8_t prk_2e[PQ_PRK_LEN];
		{
			HS_TIME_START();
			pq_hkdf_extract(NULL, 0, ss_eph, PQ_KEM_SS_LEN, prk_2e);
			HS_TIME_END(variant, OP_HKDF_EXTRACT);
		}

		/* ── Decrypt CIPHERTEXT_2 ── */
		uint8_t plaintext_2[PQ_SIG_MAX_LEN + 16];
		{
			HS_TIME_START();
			uint8_t ks2[PQ_SIG_MAX_LEN + 16];
			pq_hkdf_expand(prk_2e, th2, PQ_HASH_LEN, ks2, ciphertext_2_len);
			for (uint32_t i = 0; i < ciphertext_2_len; i++)
				plaintext_2[i] = ciphertext_2[i] ^ ks2[i];
			HS_TIME_END(variant, OP_HKDF_EXPAND);
		}

		uint8_t prk_3e2m[PQ_PRK_LEN]; memcpy(prk_3e2m, prk_2e, PQ_PRK_LEN);
		uint32_t sig2_len = ciphertext_2_len - 2;
		uint8_t sig2[PQ_SIG_MAX_LEN]; memcpy(sig2, plaintext_2 + 2, sig2_len);

		/* ── MAC_2 + Verify Sig_2 ── */
		uint8_t mac2[32];
		{
			HS_TIME_START();
			uint8_t ctx2[PQ_SIG_PK_LEN + PQ_HASH_LEN + 16]; size_t cl = 0;
			ctx2[cl++] = plaintext_2[0]; ctx2[cl++] = plaintext_2[1];
			memcpy(ctx2 + cl, th2, PQ_HASH_LEN); cl += PQ_HASH_LEN;
			memcpy(ctx2 + cl, sig_pk_r, PQ_SIG_PK_LEN); cl += PQ_SIG_PK_LEN;
			pq_hkdf_expand(prk_3e2m, ctx2, cl, mac2, 32);
			HS_TIME_END(variant, OP_HKDF_EXPAND);
		}
		{
			HS_TIME_START();
			pq_sig_verify(mac2, 32, sig2, sig2_len, sig_pk_r);
			HS_TIME_END(variant, OP_VERIFY);
		}

		/* ── TH_3 ── */
		uint8_t th3[PQ_HASH_LEN];
		{
			HS_TIME_START();
			uint8_t in3[EAP_MSG_BUF_SIZE]; size_t il = 0;
			memcpy(in3, th2, PQ_HASH_LEN); il += PQ_HASH_LEN;
			memcpy(in3 + il, plaintext_2, ciphertext_2_len); il += ciphertext_2_len;
			memcpy(in3 + il, sig_pk_r, PQ_SIG_PK_LEN); il += PQ_SIG_PK_LEN;
			pq_hash_sha256(in3, il, th3);
			HS_TIME_END(variant, OP_HASH);
		}

		uint8_t prk_4e3m[PQ_PRK_LEN]; memcpy(prk_4e3m, prk_3e2m, PQ_PRK_LEN);

		/* ── MAC_3 + Sign_3 ── */
		uint8_t mac3[32];
		{
			HS_TIME_START();
			uint8_t ctx3[PQ_SIG_PK_LEN + PQ_HASH_LEN + 16]; size_t cl = 0;
			ctx3[cl++] = 0x02;
			memcpy(ctx3 + cl, th3, PQ_HASH_LEN); cl += PQ_HASH_LEN;
			memcpy(ctx3 + cl, sig_pk_i, PQ_SIG_PK_LEN); cl += PQ_SIG_PK_LEN;
			pq_hkdf_expand(prk_4e3m, ctx3, cl, mac3, 32);
			HS_TIME_END(variant, OP_HKDF_EXPAND);
		}
		uint8_t sig3[PQ_SIG_MAX_LEN]; size_t sig3_len = 0;
		{
			HS_TIME_START();
			pq_sig_sign(mac3, 32, sig_sk_i, sig3, &sig3_len);
			HS_TIME_END(variant, OP_SIGNATURE);
		}

		/* ── Derive K3/IV3 + AEAD Encrypt MSG3 ── */
		uint8_t pt3[1 + PQ_SIG_MAX_LEN]; pt3[0] = 0x02;
		memcpy(pt3 + 1, sig3, sig3_len);
		uint32_t pt3_len = 1 + (uint32_t)sig3_len;

		uint8_t k3[PQ_AEAD_KEY_LEN], iv3[PQ_AEAD_NONCE_LEN];
		{
			HS_TIME_START();
			derive_key_iv(prk_3e2m, INFO_K3, INFO_K3_LEN, k3, iv3);
			HS_TIME_END(variant, OP_HKDF_EXPAND);
		}
		uint8_t msg3_buf[PQ_SIG_MAX_LEN + 64]; uint32_t msg3_len;
		{
			HS_TIME_START();
			mbedtls_gcm_context gcm; mbedtls_gcm_init(&gcm);
			mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, k3, 128);
			uint8_t tag[16];
			mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, pt3_len,
			                          iv3, PQ_AEAD_NONCE_LEN, th3, PQ_HASH_LEN,
			                          pt3, msg3_buf, 16, tag);
			memcpy(msg3_buf + pt3_len, tag, 16);
			msg3_len = pt3_len + 16;
			mbedtls_gcm_free(&gcm);
			HS_TIME_END(variant, OP_AEAD_ENCRYPT);
		}

		/* ── Send MSG3 as EAP-Response (fragmented: ~3326 bytes) ── */
		if (eap_send_edhoc_msg(sockfd, 0, eap_id, msg3_buf, msg3_len, &txrx_ns) != 0) return -1;
		if (iter == 0) { g_eap_transport[variant].msg3_frags = g_eap_last_frag_count; g_eap_transport[variant].msg3_bytes = msg3_len; }

		/* ── Receive EAP-Success ── */
		if (eap_recv_success(sockfd) != 0) return -1;

		/* ── TH_4 ── */
		uint8_t th4[PQ_HASH_LEN];
		{
			HS_TIME_START();
			uint8_t th4_in[EAP_MSG_BUF_SIZE]; size_t il = 0;
			memcpy(th4_in, th3, PQ_HASH_LEN); il += PQ_HASH_LEN;
			memcpy(th4_in + il, pt3, pt3_len); il += pt3_len;
			memcpy(th4_in + il, sig_pk_i, PQ_SIG_PK_LEN); il += PQ_SIG_PK_LEN;
			pq_hash_sha256(th4_in, il, th4);
			HS_TIME_END(variant, OP_HASH);
		}

		/* ── PRK_out + MSK/EMSK ── */
		uint8_t prk_out[PQ_PRK_LEN];
		{
			HS_TIME_START();
			pq_hkdf_expand(prk_4e3m, th4, PQ_HASH_LEN, prk_out, PQ_PRK_LEN);
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
 * RESPONDER — EAP-EDHOC Type 0 PQ (EAP Server)
 * =============================================================================
 */
int eap_handshake_type0_pq_responder(int sockfd, int variant)
{
	int N = P2P_BENCH_HANDSHAKE_ITERATIONS;

	uint8_t sig_pk_r[PQ_SIG_PK_LEN], sig_sk_r[PQ_SIG_SK_LEN];
	pq_sig_keygen(sig_pk_r, sig_sk_r);

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
		uint64_t precomp_end = iter_start;

		/* ── [EAP] Send EAP-EDHOC-Start ── */
		uint8_t eap_id = (uint8_t)(iter + 1);
		if (eap_send_start(sockfd, eap_id) != 0) return -1;

		/* ── Receive MSG1 as EAP-Response (fragmented) ── */
		uint8_t msg1[EAP_MSG_BUF_SIZE]; uint32_t msg1_len;
		if (eap_recv_edhoc_msg(sockfd, EAP_CODE_RESPONSE,
		                       msg1, &msg1_len, sizeof(msg1),
		                       NULL, &txrx_ns) != 0) return -1;
		if (iter == 0) { g_eap_transport[variant].msg1_frags = g_eap_last_frag_count; g_eap_transport[variant].msg1_bytes = msg1_len; }

		uint8_t pk_eph[PQ_KEM_PK_LEN]; memcpy(pk_eph, msg1 + 2, PQ_KEM_PK_LEN);

		/* ── Encaps ── */
		uint8_t ct_eph[PQ_KEM_CT_LEN], ss_eph[PQ_KEM_SS_LEN];
		{
			HS_TIME_START();
			pq_kem_encaps(ct_eph, ss_eph, pk_eph);
			HS_TIME_END(variant, OP_ENCAPS);
		}

		/* ── TH_2 ── */
		uint8_t th2[PQ_HASH_LEN];
		{
			HS_TIME_START();
			uint8_t h1[PQ_HASH_LEN]; pq_hash_sha256(msg1, msg1_len, h1);
			uint8_t th2_in[PQ_HASH_LEN + PQ_KEM_CT_LEN];
			memcpy(th2_in, h1, PQ_HASH_LEN);
			memcpy(th2_in + PQ_HASH_LEN, ct_eph, PQ_KEM_CT_LEN);
			pq_hash_sha256(th2_in, PQ_HASH_LEN + PQ_KEM_CT_LEN, th2);
			HS_TIME_END(variant, OP_HASH);
		}

		/* ── PRK_2e ── */
		uint8_t prk_2e[PQ_PRK_LEN];
		{
			HS_TIME_START();
			pq_hkdf_extract(NULL, 0, ss_eph, PQ_KEM_SS_LEN, prk_2e);
			HS_TIME_END(variant, OP_HKDF_EXTRACT);
		}
		uint8_t prk_3e2m[PQ_PRK_LEN]; memcpy(prk_3e2m, prk_2e, PQ_PRK_LEN);

		/* ── MAC_2 + Sign_2 ── */
		uint8_t c_r = 0x37, id_cred_r = 0x01;
		uint8_t mac2[32];
		{
			HS_TIME_START();
			uint8_t ctx2[PQ_SIG_PK_LEN + PQ_HASH_LEN + 16]; size_t cl = 0;
			ctx2[cl++] = c_r; ctx2[cl++] = id_cred_r;
			memcpy(ctx2 + cl, th2, PQ_HASH_LEN); cl += PQ_HASH_LEN;
			memcpy(ctx2 + cl, sig_pk_r, PQ_SIG_PK_LEN); cl += PQ_SIG_PK_LEN;
			pq_hkdf_expand(prk_3e2m, ctx2, cl, mac2, 32);
			HS_TIME_END(variant, OP_HKDF_EXPAND);
		}
		uint8_t sig2[PQ_SIG_MAX_LEN]; size_t sig2_len = 0;
		{
			HS_TIME_START();
			pq_sig_sign(mac2, 32, sig_sk_r, sig2, &sig2_len);
			HS_TIME_END(variant, OP_SIGNATURE);
		}

		/* ── Build MSG2 ── */
		uint8_t pt2[2 + PQ_SIG_MAX_LEN]; pt2[0] = c_r; pt2[1] = id_cred_r;
		memcpy(pt2 + 2, sig2, sig2_len);
		uint32_t pt2_len = 2 + (uint32_t)sig2_len;
		uint8_t ct2[2 + PQ_SIG_MAX_LEN];
		{
			HS_TIME_START();
			uint8_t ks2[2 + PQ_SIG_MAX_LEN];
			pq_hkdf_expand(prk_2e, th2, PQ_HASH_LEN, ks2, pt2_len);
			for (uint32_t i = 0; i < pt2_len; i++) ct2[i] = pt2[i] ^ ks2[i];
			HS_TIME_END(variant, OP_HKDF_EXPAND);
		}
		uint8_t msg2[EAP_MSG_BUF_SIZE]; uint32_t msg2_len = 0;
		memcpy(msg2, ct_eph, PQ_KEM_CT_LEN); msg2_len += PQ_KEM_CT_LEN;
		memcpy(msg2 + msg2_len, ct2, pt2_len); msg2_len += pt2_len;

		/* ── Send MSG2 as EAP-Request (fragmented: ~4400 bytes) ── */
		eap_id++;
		if (eap_send_edhoc_msg(sockfd, 1, eap_id, msg2, msg2_len, &txrx_ns) != 0) return -1;
		if (iter == 0) { g_eap_transport[variant].msg2_frags = g_eap_last_frag_count; g_eap_transport[variant].msg2_bytes = msg2_len; }

		/* ── Receive MSG3 as EAP-Response (fragmented: ~3326 bytes) ── */
		uint8_t msg3[EAP_MSG_BUF_SIZE]; uint32_t msg3_len;
		if (eap_recv_edhoc_msg(sockfd, EAP_CODE_RESPONSE,
		                       msg3, &msg3_len, sizeof(msg3),
		                       NULL, &txrx_ns) != 0) return -1;
		if (iter == 0) { g_eap_transport[variant].msg3_frags = g_eap_last_frag_count; g_eap_transport[variant].msg3_bytes = msg3_len; }

		/* ── TH_3 ── */
		uint8_t th3[PQ_HASH_LEN];
		{
			HS_TIME_START();
			uint8_t in3[EAP_MSG_BUF_SIZE]; size_t il = 0;
			memcpy(in3, th2, PQ_HASH_LEN); il += PQ_HASH_LEN;
			memcpy(in3 + il, pt2, pt2_len); il += pt2_len;
			memcpy(in3 + il, sig_pk_r, PQ_SIG_PK_LEN); il += PQ_SIG_PK_LEN;
			pq_hash_sha256(in3, il, th3);
			HS_TIME_END(variant, OP_HASH);
		}

		/* ── Derive K3/IV3 + Decrypt MSG3 ── */
		uint8_t k3[PQ_AEAD_KEY_LEN], iv3[PQ_AEAD_NONCE_LEN];
		{
			HS_TIME_START();
			derive_key_iv(prk_3e2m, INFO_K3, INFO_K3_LEN, k3, iv3);
			HS_TIME_END(variant, OP_HKDF_EXPAND);
		}
		uint8_t pt3[PQ_SIG_MAX_LEN + 16]; uint32_t pt3_len;
		{
			HS_TIME_START();
			mbedtls_gcm_context gcm; mbedtls_gcm_init(&gcm);
			mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, k3, 128);
			pt3_len = msg3_len - 16;
			if (msg3_len > 16)
				mbedtls_gcm_auth_decrypt(&gcm, pt3_len,
				                         iv3, PQ_AEAD_NONCE_LEN, th3, PQ_HASH_LEN,
				                         msg3 + pt3_len, 16, msg3, pt3);
			mbedtls_gcm_free(&gcm);
			HS_TIME_END(variant, OP_AEAD_DECRYPT);
		}

		/* ── MAC_3 + Verify Sig_3 ── */
		uint8_t prk_4e3m[PQ_PRK_LEN]; memcpy(prk_4e3m, prk_3e2m, PQ_PRK_LEN);
		uint8_t mac3[32];
		{
			HS_TIME_START();
			uint8_t ctx3[PQ_SIG_PK_LEN + PQ_HASH_LEN + 16]; size_t cl = 0;
			ctx3[cl++] = 0x02;
			memcpy(ctx3 + cl, th3, PQ_HASH_LEN); cl += PQ_HASH_LEN;
			memcpy(ctx3 + cl, sig_pk_i, PQ_SIG_PK_LEN); cl += PQ_SIG_PK_LEN;
			pq_hkdf_expand(prk_4e3m, ctx3, cl, mac3, 32);
			HS_TIME_END(variant, OP_HKDF_EXPAND);
		}
		uint8_t sig3[PQ_SIG_MAX_LEN]; uint32_t sig3_len = pt3_len - 1;
		memcpy(sig3, pt3 + 1, sig3_len);
		{
			HS_TIME_START();
			pq_sig_verify(mac3, 32, sig3, sig3_len, sig_pk_i);
			HS_TIME_END(variant, OP_VERIFY);
		}

		/* ── Send EAP-Success ── */
		eap_id++;
		if (eap_send_success(sockfd, eap_id) != 0) return -1;

		/* ── TH_4 ── */
		uint8_t th4[PQ_HASH_LEN];
		{
			HS_TIME_START();
			uint8_t th4_in[EAP_MSG_BUF_SIZE]; size_t il = 0;
			memcpy(th4_in, th3, PQ_HASH_LEN); il += PQ_HASH_LEN;
			memcpy(th4_in + il, pt3, pt3_len); il += pt3_len;
			memcpy(th4_in + il, sig_pk_i, PQ_SIG_PK_LEN); il += PQ_SIG_PK_LEN;
			pq_hash_sha256(th4_in, il, th4);
			HS_TIME_END(variant, OP_HASH);
		}

		/* ── PRK_out + MSK/EMSK ── */
		uint8_t prk_out[PQ_PRK_LEN];
		{
			HS_TIME_START();
			pq_hkdf_expand(prk_4e3m, th4, PQ_HASH_LEN, prk_out, PQ_PRK_LEN);
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
