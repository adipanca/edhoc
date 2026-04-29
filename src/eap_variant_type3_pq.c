#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 199309L
#endif
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
/*
 * =============================================================================
 * EAP-EDHOC Type 3 PQ — 4-message KEM-KEM with ML-KEM-768, encrypted MSG1
 *
 * EAP-EDHOC Flow (4-message EDHOC mapped to EAP):
 *   Pre-session : I ↔ R exchange long-term KEM PKs  (raw TCP)
 *   R → I : EAP-Request/EAP-EDHOC-Start
 *   I → R : EAP-Response(MSG_1)   [~2295 B → 3 frags]
 *   R → I : EAP-Request(MSG_2)    [~2214 B → 3 frags]
 *   I → R : EAP-Response(MSG_3)   [~33 B → 1 frag]
 *   R → I : EAP-Request(MSG_4)    [~17 B → 1 frag]
 *   I → R : EAP-Response/ACK      [empty EAP-Response]
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

/* =============================================================================
 * INITIATOR — EAP-EDHOC Type 3 PQ
 * =============================================================================
 */
int eap_handshake_type3_pq_initiator(int sockfd, int variant)
{
	int N = P2P_BENCH_HANDSHAKE_ITERATIONS;

	/* Long-term KEM key pair */
	uint8_t lt_pk_i[PQ_KEM_PK_LEN], lt_sk_i[PQ_KEM_SK_LEN];
	pq_kem_keygen(lt_pk_i, lt_sk_i);

	/* Pre-session: exchange long-term KEM PKs (raw TCP) */
	if (p2p_send_msg(sockfd, P2P_MSG_TYPE_HANDSHAKE_START, lt_pk_i, PQ_KEM_PK_LEN) != 0) return -1;
	uint8_t type, lt_pk_r[PQ_KEM_PK_LEN]; uint32_t len;
	if (p2p_recv_msg(sockfd, &type, lt_pk_r, &len, PQ_KEM_PK_LEN) != 0) return -1;

	double total_wall_us = 0, total_txrx_us = 0, total_precomp_us = 0;
	struct rusage ru_start, ru_end;
	long mem_before = get_memory_usage_bytes();
	long mem_peak = mem_before;
	getrusage(RUSAGE_SELF, &ru_start);
	uint64_t wall_all_start = bench_get_ns();

	for (int iter = 0; iter < N; iter++) {
		uint64_t iter_start = bench_get_ns();
		uint64_t txrx_ns = 0;

		/* ── Ephemeral KEM keygen ── */
		uint8_t eph_pk[PQ_KEM_PK_LEN], eph_sk[PQ_KEM_SK_LEN];
		{
			HS_TIME_START();
			pq_kem_keygen(eph_pk, eph_sk);
			HS_TIME_END(variant, OP_KEYGEN);
		}
		uint64_t precomp_end = bench_get_ns();

		/* ── Encaps to R's static KEM key: ct_R, ss_R ── */
		uint8_t ct_R[PQ_KEM_CT_LEN], ss_R[PQ_KEM_SS_LEN];
		{
			HS_TIME_START();
			pq_kem_encaps(ct_R, ss_R, lt_pk_r);
			HS_TIME_END(variant, OP_ENCAPS);
		}

		/* ── PRK_1e ── */
		uint8_t prk_1e[PQ_PRK_LEN];
		{
			HS_TIME_START();
			pq_hkdf_extract(NULL, 0, ss_R, PQ_KEM_SS_LEN, prk_1e);
			HS_TIME_END(variant, OP_HKDF_EXTRACT);
		}

		/* ── K_1, IV_1 ── */
		uint8_t k1[PQ_AEAD_KEY_LEN], iv1[PQ_AEAD_NONCE_LEN];
		{
			HS_TIME_START();
			derive_key_iv(prk_1e, INFO_K1, INFO_K1_LEN, k1, iv1);
			HS_TIME_END(variant, OP_HKDF_EXPAND);
		}

		/* ── TH_1 = H(pk_eph, ct_R) ── */
		uint8_t th1[PQ_HASH_LEN];
		{
			HS_TIME_START();
			uint8_t th1_in[PQ_KEM_PK_LEN + PQ_KEM_CT_LEN];
			memcpy(th1_in, eph_pk, PQ_KEM_PK_LEN);
			memcpy(th1_in + PQ_KEM_PK_LEN, ct_R, PQ_KEM_CT_LEN);
			pq_hash_sha256(th1_in, PQ_KEM_PK_LEN + PQ_KEM_CT_LEN, th1);
			HS_TIME_END(variant, OP_HASH);
		}

		/* ── Encrypt MSG1 payload ── */
		uint8_t pt1[5] = {0x03, 0x00, 0x02, 0x37, 0x00};
		uint8_t ct1[64 + PQ_AEAD_TAG_LEN]; size_t ct1_len = 0;
		{
			HS_TIME_START();
			pq_aead_encrypt(k1, iv1, th1, PQ_HASH_LEN, pt1, 5, ct1, &ct1_len);
			HS_TIME_END(variant, OP_AEAD_ENCRYPT);
		}

		/* ── Build MSG1 = ct_R || pk_eph || len(2) || ct1 ── */
		uint8_t msg1[EAP_MSG_BUF_SIZE]; uint32_t msg1_len = 0;
		memcpy(msg1, ct_R, PQ_KEM_CT_LEN); msg1_len += PQ_KEM_CT_LEN;
		memcpy(msg1 + msg1_len, eph_pk, PQ_KEM_PK_LEN); msg1_len += PQ_KEM_PK_LEN;
		msg1[msg1_len++] = (uint8_t)(ct1_len >> 8);
		msg1[msg1_len++] = (uint8_t)(ct1_len & 0xFF);
		memcpy(msg1 + msg1_len, ct1, ct1_len); msg1_len += (uint32_t)ct1_len;

		/* ── [EAP] Receive EAP-Start ── */
		uint8_t eap_id = 0;
		if (eap_recv_start(sockfd, &eap_id) != 0) return -1;

		/* ── Send MSG1 as EAP-Response ── */
		if (eap_send_edhoc_msg(sockfd, 0, eap_id, msg1, msg1_len, &txrx_ns) != 0) return -1;
		if (iter == 0) { g_eap_transport[variant].msg1_frags = g_eap_last_frag_count; g_eap_transport[variant].msg1_bytes = msg1_len; }

		/* ── Receive MSG2 as EAP-Request ── */
		uint8_t msg2[EAP_MSG_BUF_SIZE]; uint32_t msg2_len;
		if (eap_recv_edhoc_msg(sockfd, EAP_CODE_REQUEST,
		                       msg2, &msg2_len, sizeof(msg2),
		                       &eap_id, &txrx_ns) != 0) return -1;
		if (iter == 0) { g_eap_transport[variant].msg2_frags = g_eap_last_frag_count; g_eap_transport[variant].msg2_bytes = msg2_len; }

		/* Parse MSG2: ct_eph || ct_I || len(2) || ct2 */
		uint32_t off = 0;
		uint8_t ct_eph[PQ_KEM_CT_LEN];
		memcpy(ct_eph, msg2 + off, PQ_KEM_CT_LEN); off += PQ_KEM_CT_LEN;
		uint8_t ct_I[PQ_KEM_CT_LEN];
		memcpy(ct_I, msg2 + off, PQ_KEM_CT_LEN); off += PQ_KEM_CT_LEN;
		uint16_t ct2_len = (msg2[off] << 8) | msg2[off + 1]; off += 2;
		uint8_t ct2[512 + PQ_AEAD_TAG_LEN];
		memcpy(ct2, msg2 + off, ct2_len);

		/* ── Decaps ephemeral: ss_eph ── */
		uint8_t ss_eph[PQ_KEM_SS_LEN];
		{
			HS_TIME_START();
			pq_kem_decaps(ss_eph, ct_eph, eph_sk);
			HS_TIME_END(variant, OP_DECAPS);
		}

		/* ── PRK_2m ── */
		uint8_t prk_2m[PQ_PRK_LEN];
		{
			HS_TIME_START();
			pq_hkdf_extract(prk_1e, PQ_PRK_LEN, ss_eph, PQ_KEM_SS_LEN, prk_2m);
			HS_TIME_END(variant, OP_HKDF_EXTRACT);
		}

		/* ── Decaps auth: ss_I ── */
		uint8_t ss_I[PQ_KEM_SS_LEN];
		{
			HS_TIME_START();
			pq_kem_decaps(ss_I, ct_I, lt_sk_i);
			HS_TIME_END(variant, OP_DECAPS);
		}

		/* ── PRK_2e3e3m ── */
		uint8_t prk_2e3e3m[PQ_PRK_LEN];
		{
			HS_TIME_START();
			pq_hkdf_extract(prk_2m, PQ_PRK_LEN, ss_I, PQ_KEM_SS_LEN, prk_2e3e3m);
			HS_TIME_END(variant, OP_HKDF_EXTRACT);
		}

		/* ── TH_2 ── */
		uint8_t th2[PQ_HASH_LEN];
		{
			HS_TIME_START();
			uint8_t h1[PQ_HASH_LEN]; pq_hash_sha256(msg1, msg1_len, h1);
			uint8_t th2_in[PQ_HASH_LEN + 2 * PQ_KEM_CT_LEN];
			memcpy(th2_in, h1, PQ_HASH_LEN);
			memcpy(th2_in + PQ_HASH_LEN, ct_eph, PQ_KEM_CT_LEN);
			memcpy(th2_in + PQ_HASH_LEN + PQ_KEM_CT_LEN, ct_I, PQ_KEM_CT_LEN);
			pq_hash_sha256(th2_in, PQ_HASH_LEN + 2 * PQ_KEM_CT_LEN, th2);
			HS_TIME_END(variant, OP_HASH);
		}

		/* ── K_2, IV_2 + Decrypt CT2 ── */
		uint8_t k2[PQ_AEAD_KEY_LEN], iv2[PQ_AEAD_NONCE_LEN];
		{
			HS_TIME_START();
			derive_key_iv(prk_2e3e3m, INFO_K2, INFO_K2_LEN, k2, iv2);
			HS_TIME_END(variant, OP_HKDF_EXPAND);
		}
		uint8_t pt2[512]; size_t pt2_len = 0;
		{
			HS_TIME_START();
			pq_aead_decrypt(k2, iv2, th2, PQ_HASH_LEN, ct2, ct2_len, pt2, &pt2_len);
			HS_TIME_END(variant, OP_AEAD_DECRYPT);
		}

		/* ── Verify MAC_2 ── */
		uint8_t mac2_exp[PQ_AEAD_TAG_LEN];
		{
			HS_TIME_START();
			uint8_t info[PQ_HASH_LEN + 64];
			memcpy(info, th2, PQ_HASH_LEN);
			memcpy(info + PQ_HASH_LEN, LBL_ID_CRED_R, LBL_ID_CRED_R_LEN);
			pq_hkdf_expand(prk_2m, info, PQ_HASH_LEN + LBL_ID_CRED_R_LEN,
			               mac2_exp, PQ_AEAD_TAG_LEN);
			HS_TIME_END(variant, OP_HKDF_EXPAND);
		}
		{
			HS_TIME_START();
			(void)sodium_memcmp(mac2_exp, pt2 + pt2_len - PQ_AEAD_TAG_LEN, PQ_AEAD_TAG_LEN);
			HS_TIME_END(variant, OP_VERIFY);
		}

		/* ── TH_3 ── */
		uint8_t th3[PQ_HASH_LEN];
		{
			HS_TIME_START();
			uint8_t th3_in[EAP_MSG_BUF_SIZE]; size_t l = 0;
			memcpy(th3_in, th2, PQ_HASH_LEN); l += PQ_HASH_LEN;
			memcpy(th3_in + l, pt2, pt2_len); l += pt2_len;
			memcpy(th3_in + l, lt_pk_r, PQ_KEM_PK_LEN); l += PQ_KEM_PK_LEN;
			pq_hash_sha256(th3_in, l, th3);
			HS_TIME_END(variant, OP_HASH);
		}

		/* ── MAC_3 ── */
		uint8_t mac3[PQ_AEAD_TAG_LEN];
		{
			HS_TIME_START();
			uint8_t info[PQ_HASH_LEN + 64];
			memcpy(info, th3, PQ_HASH_LEN);
			memcpy(info + PQ_HASH_LEN, LBL_ID_CRED_I, LBL_ID_CRED_I_LEN);
			pq_hkdf_expand(prk_2e3e3m, info, PQ_HASH_LEN + LBL_ID_CRED_I_LEN,
			               mac3, PQ_AEAD_TAG_LEN);
			HS_TIME_END(variant, OP_HKDF_EXPAND);
		}

		/* ── K_3, IV_3 + Encrypt MSG3 ── */
		uint8_t k3[PQ_AEAD_KEY_LEN], iv3[PQ_AEAD_NONCE_LEN];
		{
			HS_TIME_START();
			derive_key_iv(prk_2e3e3m, INFO_K3, INFO_K3_LEN, k3, iv3);
			HS_TIME_END(variant, OP_HKDF_EXPAND);
		}
		uint8_t pt3[1 + PQ_AEAD_TAG_LEN]; pt3[0] = 0x00; memcpy(pt3 + 1, mac3, PQ_AEAD_TAG_LEN);
		uint8_t ct3[64 + PQ_AEAD_TAG_LEN]; size_t ct3_len = 0;
		{
			HS_TIME_START();
			pq_aead_encrypt(k3, iv3, th3, PQ_HASH_LEN, pt3, 1 + PQ_AEAD_TAG_LEN, ct3, &ct3_len);
			HS_TIME_END(variant, OP_AEAD_ENCRYPT);
		}

		/* ── Send MSG3 as EAP-Response ── */
		if (eap_send_edhoc_msg(sockfd, 0, eap_id, ct3, (uint32_t)ct3_len, &txrx_ns) != 0) return -1;
		if (iter == 0) { g_eap_transport[variant].msg3_frags = g_eap_last_frag_count; g_eap_transport[variant].msg3_bytes = (uint32_t)ct3_len; }

		/* ── Receive MSG4 as EAP-Request ── */
		uint8_t msg4[EAP_MSG_BUF_SIZE]; uint32_t msg4_len;
		if (eap_recv_edhoc_msg(sockfd, EAP_CODE_REQUEST,
		                       msg4, &msg4_len, sizeof(msg4),
		                       &eap_id, &txrx_ns) != 0) return -1;
		if (iter == 0) { g_eap_transport[variant].msg4_frags = g_eap_last_frag_count; g_eap_transport[variant].msg4_bytes = msg4_len; }

		/* ── TH_4 ── */
		uint8_t th4[PQ_HASH_LEN];
		{
			HS_TIME_START();
			uint8_t th4_in[EAP_MSG_BUF_SIZE]; size_t l = 0;
			memcpy(th4_in, th3, PQ_HASH_LEN); l += PQ_HASH_LEN;
			memcpy(th4_in + l, pt3, 1 + PQ_AEAD_TAG_LEN); l += 1 + PQ_AEAD_TAG_LEN;
			memcpy(th4_in + l, lt_pk_i, PQ_KEM_PK_LEN); l += PQ_KEM_PK_LEN;
			pq_hash_sha256(th4_in, l, th4);
			HS_TIME_END(variant, OP_HASH);
		}

		/* ── K_4, IV_4 + Decrypt MSG4 ── */
		uint8_t k4[PQ_AEAD_KEY_LEN], iv4[PQ_AEAD_NONCE_LEN];
		{
			HS_TIME_START();
			derive_key_iv(prk_2e3e3m, INFO_K4, INFO_K4_LEN, k4, iv4);
			HS_TIME_END(variant, OP_HKDF_EXPAND);
		}
		uint8_t pt4[64]; size_t pt4_len = 0;
		{
			HS_TIME_START();
			pq_aead_decrypt(k4, iv4, th4, PQ_HASH_LEN, msg4, msg4_len, pt4, &pt4_len);
			HS_TIME_END(variant, OP_AEAD_DECRYPT);
		}

		/* ── PRK_out ── */
		uint8_t prk_out[PQ_PRK_LEN];
		{
			HS_TIME_START();
			pq_hkdf_expand(prk_2e3e3m, th4, PQ_HASH_LEN, prk_out, PQ_PRK_LEN);
			HS_TIME_END(variant, OP_HKDF_EXPAND);
		}

		/* ── Send empty EAP-Response ACK (acknowledging MSG4) ── */
		if (eap_send_edhoc_msg(sockfd, 0, eap_id, NULL, 0, &txrx_ns) != 0) return -1;

		/* ── Receive EAP-Success ── */
		if (eap_recv_success(sockfd) != 0) return -1;

		/* ── MSK/EMSK ── */
		uint8_t msk[64], emsk[64];
		eap_derive_msk_emsk(prk_out, msk, emsk);

		if (iter == 0) {
			long m = get_memory_usage_bytes(); if (m > mem_peak) mem_peak = m;
			struct eap_transport_stats *t = &g_eap_transport[variant];
			t->edhoc_messages = 4;
			t->total_fragments = t->msg1_frags + t->msg2_frags + t->msg3_frags + t->msg4_frags;
			t->frag_ack_roundtrips = (t->msg1_frags - 1) + (t->msg2_frags - 1) + (t->msg3_frags - 1) + (t->msg4_frags - 1);
			if (t->frag_ack_roundtrips < 0) t->frag_ack_roundtrips = 0;
			/* +1 for ACK of MSG4, +1 for EAP-Success */
			t->total_eap_roundtrips = 1/*Start*/ + t->edhoc_messages + 1/*ACK*/ + t->frag_ack_roundtrips + 1/*Success*/;
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
 * RESPONDER — EAP-EDHOC Type 3 PQ (EAP Server)
 * =============================================================================
 */
int eap_handshake_type3_pq_responder(int sockfd, int variant)
{
	int N = P2P_BENCH_HANDSHAKE_ITERATIONS;

	/* Long-term KEM key pair */
	uint8_t lt_pk_r[PQ_KEM_PK_LEN], lt_sk_r[PQ_KEM_SK_LEN];
	pq_kem_keygen(lt_pk_r, lt_sk_r);

	/* Pre-session: exchange long-term KEM PKs (raw TCP) */
	uint8_t type, lt_pk_i[PQ_KEM_PK_LEN]; uint32_t len;
	if (p2p_recv_msg(sockfd, &type, lt_pk_i, &len, PQ_KEM_PK_LEN) != 0) return -1;
	if (p2p_send_msg(sockfd, P2P_MSG_TYPE_HANDSHAKE_START, lt_pk_r, PQ_KEM_PK_LEN) != 0) return -1;

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
		uint8_t msg1[EAP_MSG_BUF_SIZE]; uint32_t msg1_len;
		if (eap_recv_edhoc_msg(sockfd, EAP_CODE_RESPONSE,
		                       msg1, &msg1_len, sizeof(msg1),
		                       NULL, &txrx_ns) != 0) return -1;
		if (iter == 0) { g_eap_transport[variant].msg1_frags = g_eap_last_frag_count; g_eap_transport[variant].msg1_bytes = msg1_len; }

		/* Parse MSG1 */
		uint32_t off = 0;
		uint8_t ct_R[PQ_KEM_CT_LEN];
		memcpy(ct_R, msg1 + off, PQ_KEM_CT_LEN); off += PQ_KEM_CT_LEN;
		uint8_t pk_eph[PQ_KEM_PK_LEN];
		memcpy(pk_eph, msg1 + off, PQ_KEM_PK_LEN); off += PQ_KEM_PK_LEN;
		uint16_t ct1_len = (msg1[off] << 8) | msg1[off + 1]; off += 2;
		uint8_t ct1[256 + PQ_AEAD_TAG_LEN];
		memcpy(ct1, msg1 + off, ct1_len);

		/* ── Decaps static: ss_R ── */
		uint8_t ss_R[PQ_KEM_SS_LEN];
		{
			HS_TIME_START();
			pq_kem_decaps(ss_R, ct_R, lt_sk_r);
			HS_TIME_END(variant, OP_DECAPS);
		}

		/* ── PRK_1e ── */
		uint8_t prk_1e[PQ_PRK_LEN];
		{
			HS_TIME_START();
			pq_hkdf_extract(NULL, 0, ss_R, PQ_KEM_SS_LEN, prk_1e);
			HS_TIME_END(variant, OP_HKDF_EXTRACT);
		}

		/* ── K_1, IV_1 + TH_1 + Decrypt CT1 ── */
		uint8_t k1[PQ_AEAD_KEY_LEN], iv1[PQ_AEAD_NONCE_LEN];
		{
			HS_TIME_START();
			derive_key_iv(prk_1e, INFO_K1, INFO_K1_LEN, k1, iv1);
			HS_TIME_END(variant, OP_HKDF_EXPAND);
		}
		uint8_t th1[PQ_HASH_LEN];
		{
			HS_TIME_START();
			uint8_t th1_in[PQ_KEM_PK_LEN + PQ_KEM_CT_LEN];
			memcpy(th1_in, pk_eph, PQ_KEM_PK_LEN);
			memcpy(th1_in + PQ_KEM_PK_LEN, ct_R, PQ_KEM_CT_LEN);
			pq_hash_sha256(th1_in, PQ_KEM_PK_LEN + PQ_KEM_CT_LEN, th1);
			HS_TIME_END(variant, OP_HASH);
		}
		uint8_t pt1[256]; size_t pt1_len = 0;
		{
			HS_TIME_START();
			pq_aead_decrypt(k1, iv1, th1, PQ_HASH_LEN, ct1, ct1_len, pt1, &pt1_len);
			HS_TIME_END(variant, OP_AEAD_DECRYPT);
		}

		/* ── Encaps ephemeral: ct_eph, ss_eph ── */
		uint8_t ct_eph[PQ_KEM_CT_LEN], ss_eph[PQ_KEM_SS_LEN];
		{
			HS_TIME_START();
			pq_kem_encaps(ct_eph, ss_eph, pk_eph);
			HS_TIME_END(variant, OP_ENCAPS);
		}

		/* ── PRK_2m ── */
		uint8_t prk_2m[PQ_PRK_LEN];
		{
			HS_TIME_START();
			pq_hkdf_extract(prk_1e, PQ_PRK_LEN, ss_eph, PQ_KEM_SS_LEN, prk_2m);
			HS_TIME_END(variant, OP_HKDF_EXTRACT);
		}

		/* ── Encaps to I's static KEM: ct_I, ss_I ── */
		uint8_t ct_I[PQ_KEM_CT_LEN], ss_I[PQ_KEM_SS_LEN];
		{
			HS_TIME_START();
			pq_kem_encaps(ct_I, ss_I, lt_pk_i);
			HS_TIME_END(variant, OP_ENCAPS);
		}

		/* ── PRK_2e3e3m ── */
		uint8_t prk_2e3e3m[PQ_PRK_LEN];
		{
			HS_TIME_START();
			pq_hkdf_extract(prk_2m, PQ_PRK_LEN, ss_I, PQ_KEM_SS_LEN, prk_2e3e3m);
			HS_TIME_END(variant, OP_HKDF_EXTRACT);
		}

		/* ── TH_2 ── */
		uint8_t th2[PQ_HASH_LEN];
		{
			HS_TIME_START();
			uint8_t h1[PQ_HASH_LEN]; pq_hash_sha256(msg1, msg1_len, h1);
			uint8_t th2_in[PQ_HASH_LEN + 2 * PQ_KEM_CT_LEN];
			memcpy(th2_in, h1, PQ_HASH_LEN);
			memcpy(th2_in + PQ_HASH_LEN, ct_eph, PQ_KEM_CT_LEN);
			memcpy(th2_in + PQ_HASH_LEN + PQ_KEM_CT_LEN, ct_I, PQ_KEM_CT_LEN);
			pq_hash_sha256(th2_in, PQ_HASH_LEN + 2 * PQ_KEM_CT_LEN, th2);
			HS_TIME_END(variant, OP_HASH);
		}

		/* ── MAC_2 ── */
		uint8_t mac2[PQ_AEAD_TAG_LEN];
		{
			HS_TIME_START();
			uint8_t info[PQ_HASH_LEN + 64];
			memcpy(info, th2, PQ_HASH_LEN);
			memcpy(info + PQ_HASH_LEN, LBL_ID_CRED_R, LBL_ID_CRED_R_LEN);
			pq_hkdf_expand(prk_2m, info, PQ_HASH_LEN + LBL_ID_CRED_R_LEN, mac2, PQ_AEAD_TAG_LEN);
			HS_TIME_END(variant, OP_HKDF_EXPAND);
		}

		/* ── K_2, IV_2 + Encrypt MSG2 payload ── */
		uint8_t k2[PQ_AEAD_KEY_LEN], iv2[PQ_AEAD_NONCE_LEN];
		{
			HS_TIME_START();
			derive_key_iv(prk_2e3e3m, INFO_K2, INFO_K2_LEN, k2, iv2);
			HS_TIME_END(variant, OP_HKDF_EXPAND);
		}
		uint8_t pt2[64 + PQ_AEAD_TAG_LEN]; size_t pt2_len = 0;
		pt2[pt2_len++] = 0x37; pt2[pt2_len++] = 0x01; pt2[pt2_len++] = 0x00;
		memcpy(pt2 + pt2_len, mac2, PQ_AEAD_TAG_LEN); pt2_len += PQ_AEAD_TAG_LEN;
		uint8_t ct2[512 + PQ_AEAD_TAG_LEN]; size_t ct2_aead_len = 0;
		{
			HS_TIME_START();
			pq_aead_encrypt(k2, iv2, th2, PQ_HASH_LEN, pt2, pt2_len, ct2, &ct2_aead_len);
			HS_TIME_END(variant, OP_AEAD_ENCRYPT);
		}

		/* ── Build MSG2 = ct_eph || ct_I || len(2) || ct2 ── */
		uint8_t msg2[EAP_MSG_BUF_SIZE]; uint32_t msg2_len = 0;
		memcpy(msg2, ct_eph, PQ_KEM_CT_LEN); msg2_len += PQ_KEM_CT_LEN;
		memcpy(msg2 + msg2_len, ct_I, PQ_KEM_CT_LEN); msg2_len += PQ_KEM_CT_LEN;
		msg2[msg2_len++] = (uint8_t)(ct2_aead_len >> 8);
		msg2[msg2_len++] = (uint8_t)(ct2_aead_len & 0xFF);
		memcpy(msg2 + msg2_len, ct2, ct2_aead_len); msg2_len += (uint32_t)ct2_aead_len;

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
		uint8_t th3[PQ_HASH_LEN];
		{
			HS_TIME_START();
			uint8_t th3_in[EAP_MSG_BUF_SIZE]; size_t l = 0;
			memcpy(th3_in, th2, PQ_HASH_LEN); l += PQ_HASH_LEN;
			memcpy(th3_in + l, pt2, pt2_len); l += pt2_len;
			memcpy(th3_in + l, lt_pk_r, PQ_KEM_PK_LEN); l += PQ_KEM_PK_LEN;
			pq_hash_sha256(th3_in, l, th3);
			HS_TIME_END(variant, OP_HASH);
		}

		/* ── K_3, IV_3 + Decrypt MSG3 ── */
		uint8_t k3[PQ_AEAD_KEY_LEN], iv3[PQ_AEAD_NONCE_LEN];
		{
			HS_TIME_START();
			derive_key_iv(prk_2e3e3m, INFO_K3, INFO_K3_LEN, k3, iv3);
			HS_TIME_END(variant, OP_HKDF_EXPAND);
		}
		uint8_t pt3[64 + PQ_AEAD_TAG_LEN]; size_t pt3_len = 0;
		{
			HS_TIME_START();
			pq_aead_decrypt(k3, iv3, th3, PQ_HASH_LEN, msg3, msg3_len, pt3, &pt3_len);
			HS_TIME_END(variant, OP_AEAD_DECRYPT);
		}

		/* ── Verify MAC_3 ── */
		uint8_t mac3_exp[PQ_AEAD_TAG_LEN];
		{
			HS_TIME_START();
			uint8_t info[PQ_HASH_LEN + 64];
			memcpy(info, th3, PQ_HASH_LEN);
			memcpy(info + PQ_HASH_LEN, LBL_ID_CRED_I, LBL_ID_CRED_I_LEN);
			pq_hkdf_expand(prk_2e3e3m, info, PQ_HASH_LEN + LBL_ID_CRED_I_LEN,
			               mac3_exp, PQ_AEAD_TAG_LEN);
			HS_TIME_END(variant, OP_HKDF_EXPAND);
		}
		{
			HS_TIME_START();
			(void)sodium_memcmp(mac3_exp, pt3 + 1, PQ_AEAD_TAG_LEN);
			HS_TIME_END(variant, OP_VERIFY);
		}

		/* ── PRK_out ── */
		uint8_t prk_out[PQ_PRK_LEN];
		{
			HS_TIME_START();
			pq_hkdf_expand(prk_2e3e3m, th3, PQ_HASH_LEN, prk_out, PQ_PRK_LEN);
			HS_TIME_END(variant, OP_HKDF_EXPAND);
		}

		/* ── TH_4 ── */
		uint8_t th4[PQ_HASH_LEN];
		{
			HS_TIME_START();
			uint8_t th4_in[EAP_MSG_BUF_SIZE]; size_t l = 0;
			memcpy(th4_in, th3, PQ_HASH_LEN); l += PQ_HASH_LEN;
			memcpy(th4_in + l, pt3, pt3_len); l += pt3_len;
			memcpy(th4_in + l, lt_pk_i, PQ_KEM_PK_LEN); l += PQ_KEM_PK_LEN;
			pq_hash_sha256(th4_in, l, th4);
			HS_TIME_END(variant, OP_HASH);
		}

		/* ── K_4, IV_4 + Encrypt MSG4 ── */
		uint8_t k4[PQ_AEAD_KEY_LEN], iv4[PQ_AEAD_NONCE_LEN];
		{
			HS_TIME_START();
			derive_key_iv(prk_2e3e3m, INFO_K4, INFO_K4_LEN, k4, iv4);
			HS_TIME_END(variant, OP_HKDF_EXPAND);
		}
		uint8_t pt4[1] = {0x00};
		uint8_t ct4[64 + PQ_AEAD_TAG_LEN]; size_t ct4_len = 0;
		{
			HS_TIME_START();
			pq_aead_encrypt(k4, iv4, th4, PQ_HASH_LEN, pt4, 1, ct4, &ct4_len);
			HS_TIME_END(variant, OP_AEAD_ENCRYPT);
		}

		/* ── Send MSG4 as EAP-Request ── */
		eap_id++;
		if (eap_send_edhoc_msg(sockfd, 1, eap_id, ct4, (uint32_t)ct4_len, &txrx_ns) != 0) return -1;
		if (iter == 0) { g_eap_transport[variant].msg4_frags = g_eap_last_frag_count; g_eap_transport[variant].msg4_bytes = (uint32_t)ct4_len; }

		/* ── Receive empty EAP-Response ACK ── */
		uint8_t ack_buf[EAP_MSG_BUF_SIZE]; uint32_t ack_len;
		if (eap_recv_edhoc_msg(sockfd, EAP_CODE_RESPONSE,
		                       ack_buf, &ack_len, sizeof(ack_buf),
		                       NULL, &txrx_ns) != 0) return -1;

		/* ── Send EAP-Success ── */
		eap_id++;
		if (eap_send_success(sockfd, eap_id) != 0) return -1;

		/* ── MSK/EMSK ── */
		uint8_t msk[64], emsk[64];
		eap_derive_msk_emsk(prk_out, msk, emsk);

		if (iter == 0) {
			long m = get_memory_usage_bytes(); if (m > mem_peak) mem_peak = m;
			struct eap_transport_stats *t = &g_eap_transport[variant];
			t->edhoc_messages = 4;
			t->total_fragments = t->msg1_frags + t->msg2_frags + t->msg3_frags + t->msg4_frags;
			t->frag_ack_roundtrips = (t->msg1_frags - 1) + (t->msg2_frags - 1) + (t->msg3_frags - 1) + (t->msg4_frags - 1);
			if (t->frag_ack_roundtrips < 0) t->frag_ack_roundtrips = 0;
			t->total_eap_roundtrips = 1 + t->edhoc_messages + 1 + t->frag_ack_roundtrips + 1;
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
