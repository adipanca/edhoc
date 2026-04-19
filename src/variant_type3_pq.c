#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 199309L
#endif
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
/*
 * =============================================================================
 * EDHOC Type 3 PQ — 4-message encrypted MSG1, 3 KEM operations
 *
 * Protocol flow:
 *   MSG1: ct_R, pk_eph, AEAD(METHOD, SUITES_I, ID_CRED_I, C_I)  (I → R)
 *   MSG2: ct_eph, ct_I, AEAD(C_R, ID_CRED_R, MAC_2)             (R → I)
 *   MSG3: AEAD(MAC_3)                                             (I → R)
 *   MSG4: AEAD(EAD_4)                                             (R → I)
 *
 * Key schedule:
 *   PRK_1e     = HKDF-Extract(0, ss_R)
 *   PRK_2m     = HKDF-Extract(PRK_1e, ss_eph)
 *   PRK_2e3e3m = HKDF-Extract(PRK_2m, ss_I)
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

/* =============================================================================
 * INITIATOR — Type 3 PQ (4 messages, encrypted MSG1)
 * =============================================================================
 */
int handshake_type3_pq_initiator(int sockfd, int variant)
{
	int N = P2P_BENCH_HANDSHAKE_ITERATIONS;

	/* Generate long-term KEM key pairs for both roles and exchange */
	uint8_t lt_pk_i[PQ_KEM_PK_LEN], lt_sk_i[PQ_KEM_SK_LEN];
	pq_kem_keygen(lt_pk_i, lt_sk_i);

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

		/* ══ (1) Initiator Setup ══ */
		/* Ephemeral KEM key generation */
		uint8_t eph_pk[PQ_KEM_PK_LEN], eph_sk[PQ_KEM_SK_LEN];
		{
			HS_TIME_START();
			pq_kem_keygen(eph_pk, eph_sk);
			HS_TIME_END(variant, OP_KEYGEN);
		}
		uint64_t precomp_end = bench_get_ns();

		/* PQ Encapsulate (to R's static key): ss_R, ct_R = kemEncaps(pk_R) */
		uint8_t ct_R[PQ_KEM_CT_LEN], ss_R[PQ_KEM_SS_LEN];
		{
			HS_TIME_START();
			pq_kem_encaps(ct_R, ss_R, lt_pk_r);
			HS_TIME_END(variant, OP_ENCAPS);
		}

		/* PRK_1e = HKDF-Extract(0, ss_R) */
		uint8_t prk_1e[PQ_PRK_LEN];
		{
			HS_TIME_START();
			pq_hkdf_extract(NULL, 0, ss_R, PQ_KEM_SS_LEN, prk_1e);
			HS_TIME_END(variant, OP_HKDF_EXTRACT);
		}

		/* K_1, IV_1 */
		uint8_t k1[PQ_AEAD_KEY_LEN], iv1[PQ_AEAD_NONCE_LEN];
		{
			HS_TIME_START();
			derive_key_iv(prk_1e, INFO_K1, INFO_K1_LEN, k1, iv1);
			HS_TIME_END(variant, OP_HKDF_EXPAND);
		}

		/* TH_1 = H(pk_eph, ct_R) for AAD */
		uint8_t th1[PQ_HASH_LEN];
		{
			HS_TIME_START();
			uint8_t th1_input[PQ_KEM_PK_LEN + PQ_KEM_CT_LEN];
			memcpy(th1_input, eph_pk, PQ_KEM_PK_LEN);
			memcpy(th1_input + PQ_KEM_PK_LEN, ct_R, PQ_KEM_CT_LEN);
			pq_hash_sha256(th1_input, PQ_KEM_PK_LEN + PQ_KEM_CT_LEN, th1);
			HS_TIME_END(variant, OP_HASH);
		}

		/* PLAINTEXT_1 = (METHOD, SUITES_I, ID_CRED_I, C_I, EAD_1) */
		uint8_t pt1[5] = { 0x03 /* METHOD */, 0x00 /* SUITES */, 0x02 /* ID_CRED_I */, 0x37 /* C_I */, 0x00 /* EAD_1 */ };
		uint8_t ct1_aead[64 + PQ_AEAD_TAG_LEN]; size_t ct1_aead_len = 0;
		{
			HS_TIME_START();
			pq_aead_encrypt(k1, iv1, th1, PQ_HASH_LEN, pt1, 5, ct1_aead, &ct1_aead_len);
			HS_TIME_END(variant, OP_AEAD_ENCRYPT);
		}

		/* ── Send MSG1: ct_R || pk_eph || aead_len(2) || AEAD(...) ── */
		uint8_t msg1[P2P_MSG_BUF_SIZE];
		uint32_t msg1_len = 0;
		memcpy(msg1, ct_R, PQ_KEM_CT_LEN); msg1_len += PQ_KEM_CT_LEN;
		memcpy(msg1 + msg1_len, eph_pk, PQ_KEM_PK_LEN); msg1_len += PQ_KEM_PK_LEN;
		msg1[msg1_len++] = (uint8_t)(ct1_aead_len >> 8);
		msg1[msg1_len++] = (uint8_t)(ct1_aead_len & 0xFF);
		memcpy(msg1 + msg1_len, ct1_aead, ct1_aead_len); msg1_len += ct1_aead_len;

		{
			uint64_t tx_start = bench_get_ns();
			p2p_send_msg(sockfd, P2P_MSG_TYPE_MSG1, msg1, msg1_len);
			txrx_ns += (bench_get_ns() - tx_start);
		}

		/* ── Receive MSG2: ct_eph || ct_I || aead_len(2) || AEAD(C_R, ID_CRED_R, MAC_2) ── */
		uint8_t msg2[P2P_MSG_BUF_SIZE]; uint32_t msg2_len;
		{
			uint64_t rx_start = bench_get_ns();
			p2p_recv_msg(sockfd, &type, msg2, &msg2_len, sizeof(msg2));
			txrx_ns += (bench_get_ns() - rx_start);
		}

		/* Parse MSG2 */
		uint32_t off = 0;
		uint8_t ct_eph[PQ_KEM_CT_LEN];
		memcpy(ct_eph, msg2 + off, PQ_KEM_CT_LEN); off += PQ_KEM_CT_LEN;
		uint8_t ct_I[PQ_KEM_CT_LEN];
		memcpy(ct_I, msg2 + off, PQ_KEM_CT_LEN); off += PQ_KEM_CT_LEN;
		uint16_t ct2_aead_len = (msg2[off] << 8) | msg2[off + 1]; off += 2;
		uint8_t ct2_aead[512 + PQ_AEAD_TAG_LEN];
		memcpy(ct2_aead, msg2 + off, ct2_aead_len);

		/* ══ (3) Initiator Verification ══ */

		/* PQ Decapsulate (ephemeral): ss_eph = kemDecaps(ct_eph, sk_eph) */
		uint8_t ss_eph[PQ_KEM_SS_LEN];
		{
			HS_TIME_START();
			pq_kem_decaps(ss_eph, ct_eph, eph_sk);
			HS_TIME_END(variant, OP_DECAPS);
		}

		/* PRK_2m = HKDF-Extract(PRK_1e, ss_eph) */
		uint8_t prk_2m[PQ_PRK_LEN];
		{
			HS_TIME_START();
			pq_hkdf_extract(prk_1e, PQ_PRK_LEN, ss_eph, PQ_KEM_SS_LEN, prk_2m);
			HS_TIME_END(variant, OP_HKDF_EXTRACT);
		}

		/* PQ Decapsulate (auth of I): ss_I = kemDecaps(ct_I, sk_I) */
		uint8_t ss_I[PQ_KEM_SS_LEN];
		{
			HS_TIME_START();
			pq_kem_decaps(ss_I, ct_I, lt_sk_i);
			HS_TIME_END(variant, OP_DECAPS);
		}

		/* PRK_2e3e3m = HKDF-Extract(PRK_2m, ss_I) */
		uint8_t prk_2e3e3m[PQ_PRK_LEN];
		{
			HS_TIME_START();
			pq_hkdf_extract(prk_2m, PQ_PRK_LEN, ss_I, PQ_KEM_SS_LEN, prk_2e3e3m);
			HS_TIME_END(variant, OP_HKDF_EXTRACT);
		}

		/* TH_2 = H(H(Message_1), ct_eph, ct_I) */
		uint8_t th2[PQ_HASH_LEN];
		{
			HS_TIME_START();
			uint8_t h_msg1[PQ_HASH_LEN];
			pq_hash_sha256(msg1, msg1_len, h_msg1);
			uint8_t th2_input[PQ_HASH_LEN + 2 * PQ_KEM_CT_LEN];
			memcpy(th2_input, h_msg1, PQ_HASH_LEN);
			memcpy(th2_input + PQ_HASH_LEN, ct_eph, PQ_KEM_CT_LEN);
			memcpy(th2_input + PQ_HASH_LEN + PQ_KEM_CT_LEN, ct_I, PQ_KEM_CT_LEN);
			pq_hash_sha256(th2_input, PQ_HASH_LEN + 2 * PQ_KEM_CT_LEN, th2);
			HS_TIME_END(variant, OP_HASH);
		}

		/* K_2, IV_2 → Decrypt CIPHERTEXT_2 */
		uint8_t k2[PQ_AEAD_KEY_LEN], iv2[PQ_AEAD_NONCE_LEN];
		{
			HS_TIME_START();
			derive_key_iv(prk_2e3e3m, INFO_K2, INFO_K2_LEN, k2, iv2);
			HS_TIME_END(variant, OP_HKDF_EXPAND);
		}

		uint8_t pt2[512]; size_t pt2_len = 0;
		{
			HS_TIME_START();
			pq_aead_decrypt(k2, iv2, th2, PQ_HASH_LEN, ct2_aead, ct2_aead_len, pt2, &pt2_len);
			HS_TIME_END(variant, OP_AEAD_DECRYPT);
		}
		/* pt2 = (C_R, ID_CRED_R, EAD_2, MAC_2) */
		/* MAC_2 is at the tail — last PQ_AEAD_TAG_LEN bytes of pt2 */

		/* Verify MAC_2 = KDF(PRK_2m, context) */
		uint8_t mac2_expected[PQ_AEAD_TAG_LEN];
		{
			HS_TIME_START();
			uint8_t mac2_info[PQ_HASH_LEN + 64];
			memcpy(mac2_info, th2, PQ_HASH_LEN);
			memcpy(mac2_info + PQ_HASH_LEN, LBL_ID_CRED_R, LBL_ID_CRED_R_LEN);
			pq_hkdf_expand(prk_2m, mac2_info, PQ_HASH_LEN + LBL_ID_CRED_R_LEN,
			               mac2_expected, PQ_AEAD_TAG_LEN);
			HS_TIME_END(variant, OP_HKDF_EXPAND);
		}
		{
			HS_TIME_START();
			(void)sodium_memcmp(mac2_expected, pt2 + pt2_len - PQ_AEAD_TAG_LEN, PQ_AEAD_TAG_LEN);
			HS_TIME_END(variant, OP_VERIFY);
		}

		/* TH_3 = H(TH_2, PLAINTEXT_2, CRED_R) */
		uint8_t th3[PQ_HASH_LEN];
		{
			HS_TIME_START();
			uint8_t th3_input[P2P_MSG_BUF_SIZE];
			size_t th3_in_len = 0;
			memcpy(th3_input, th2, PQ_HASH_LEN); th3_in_len += PQ_HASH_LEN;
			memcpy(th3_input + th3_in_len, pt2, pt2_len); th3_in_len += pt2_len;
			memcpy(th3_input + th3_in_len, lt_pk_r, PQ_KEM_PK_LEN); th3_in_len += PQ_KEM_PK_LEN;
			pq_hash_sha256(th3_input, th3_in_len, th3);
			HS_TIME_END(variant, OP_HASH);
		}

		/* MAC_3 = KDF(PRK_2e3e3m, context) */
		uint8_t mac3[PQ_AEAD_TAG_LEN];
		{
			HS_TIME_START();
			uint8_t mac3_info[PQ_HASH_LEN + 64];
			memcpy(mac3_info, th3, PQ_HASH_LEN);
			memcpy(mac3_info + PQ_HASH_LEN, LBL_ID_CRED_I, LBL_ID_CRED_I_LEN);
			pq_hkdf_expand(prk_2e3e3m, mac3_info, PQ_HASH_LEN + LBL_ID_CRED_I_LEN,
			               mac3, PQ_AEAD_TAG_LEN);
			HS_TIME_END(variant, OP_HKDF_EXPAND);
		}

		/* K_3, IV_3 → AEAD encrypt MSG3 */
		uint8_t k3[PQ_AEAD_KEY_LEN], iv3[PQ_AEAD_NONCE_LEN];
		{
			HS_TIME_START();
			derive_key_iv(prk_2e3e3m, INFO_K3, INFO_K3_LEN, k3, iv3);
			HS_TIME_END(variant, OP_HKDF_EXPAND);
		}

		/* PLAINTEXT_3 = (EAD_3, MAC_3) */
		uint8_t pt3[1 + PQ_AEAD_TAG_LEN];
		pt3[0] = 0x00; /* EAD_3 */
		memcpy(pt3 + 1, mac3, PQ_AEAD_TAG_LEN);

		uint8_t ct3_aead[64 + PQ_AEAD_TAG_LEN]; size_t ct3_aead_len = 0;
		{
			HS_TIME_START();
			pq_aead_encrypt(k3, iv3, th3, PQ_HASH_LEN, pt3, 1 + PQ_AEAD_TAG_LEN,
			                ct3_aead, &ct3_aead_len);
			HS_TIME_END(variant, OP_AEAD_ENCRYPT);
		}

		/* ── Send MSG3 ── */
		{
			uint64_t tx_start = bench_get_ns();
			p2p_send_msg(sockfd, P2P_MSG_TYPE_MSG3, ct3_aead, ct3_aead_len);
			txrx_ns += (bench_get_ns() - tx_start);
		}

		/* ── Receive MSG4: AEAD(EAD_4) ── */
		uint8_t msg4[P2P_MSG_BUF_SIZE]; uint32_t msg4_len;
		{
			uint64_t rx_start = bench_get_ns();
			p2p_recv_msg(sockfd, &type, msg4, &msg4_len, sizeof(msg4));
			txrx_ns += (bench_get_ns() - rx_start);
		}

		/* TH_4 = H(TH_3, PLAINTEXT_3, CRED_I) */
		uint8_t th4[PQ_HASH_LEN];
		{
			HS_TIME_START();
			uint8_t th4_input[P2P_MSG_BUF_SIZE];
			size_t th4_in_len = 0;
			memcpy(th4_input, th3, PQ_HASH_LEN); th4_in_len += PQ_HASH_LEN;
			memcpy(th4_input + th4_in_len, pt3, 1 + PQ_AEAD_TAG_LEN); th4_in_len += 1 + PQ_AEAD_TAG_LEN;
			memcpy(th4_input + th4_in_len, lt_pk_i, PQ_KEM_PK_LEN); th4_in_len += PQ_KEM_PK_LEN;
			pq_hash_sha256(th4_input, th4_in_len, th4);
			HS_TIME_END(variant, OP_HASH);
		}

		/* K_4, IV_4 → Decrypt MSG4 */
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

		/* PRK_out */
		{
			HS_TIME_START();
			uint8_t prk_out[PQ_PRK_LEN];
			pq_hkdf_expand(prk_2e3e3m, th4, PQ_HASH_LEN, prk_out, PQ_PRK_LEN);
			HS_TIME_END(variant, OP_HKDF_EXPAND);
		}

		uint64_t iter_end = bench_get_ns();
		total_wall_us += ns_to_us(iter_end - iter_start);
		if (iter == 0) { long m = get_memory_usage_bytes(); if (m > mem_peak) mem_peak = m; }
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
 * RESPONDER — Type 3 PQ (4 messages, encrypted MSG1)
 * =============================================================================
 */
int handshake_type3_pq_responder(int sockfd, int variant)
{
	int N = P2P_BENCH_HANDSHAKE_ITERATIONS;

	/* Generate long-term KEM key pair */
	uint8_t lt_pk_r[PQ_KEM_PK_LEN], lt_sk_r[PQ_KEM_SK_LEN];
	pq_kem_keygen(lt_pk_r, lt_sk_r);

	/* Recv initiator's lt pk, send own */
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
		uint64_t precomp_end = iter_start; /* No precomp for responder */

		/* ── Receive MSG1: ct_R || pk_eph || aead_len(2) || AEAD(...) ── */
		uint8_t msg1[P2P_MSG_BUF_SIZE]; uint32_t msg1_len;
		{
			uint64_t rx_start = bench_get_ns();
			p2p_recv_msg(sockfd, &type, msg1, &msg1_len, sizeof(msg1));
			txrx_ns += (bench_get_ns() - rx_start);
		}

		/* Parse MSG1 */
		uint32_t off = 0;
		uint8_t ct_R[PQ_KEM_CT_LEN];
		memcpy(ct_R, msg1 + off, PQ_KEM_CT_LEN); off += PQ_KEM_CT_LEN;
		uint8_t pk_eph[PQ_KEM_PK_LEN];
		memcpy(pk_eph, msg1 + off, PQ_KEM_PK_LEN); off += PQ_KEM_PK_LEN;
		uint16_t ct1_aead_len = (msg1[off] << 8) | msg1[off + 1]; off += 2;
		uint8_t ct1_aead[256 + PQ_AEAD_TAG_LEN];
		memcpy(ct1_aead, msg1 + off, ct1_aead_len);

		/* ══ (2) Responder Processing ══ */

		/* PQ Decapsulate: ss_R = kemDecaps(ct_R, sk_R) */
		uint8_t ss_R[PQ_KEM_SS_LEN];
		{
			HS_TIME_START();
			pq_kem_decaps(ss_R, ct_R, lt_sk_r);
			HS_TIME_END(variant, OP_DECAPS);
		}

		/* PRK_1e = HKDF-Extract(0, ss_R) */
		uint8_t prk_1e[PQ_PRK_LEN];
		{
			HS_TIME_START();
			pq_hkdf_extract(NULL, 0, ss_R, PQ_KEM_SS_LEN, prk_1e);
			HS_TIME_END(variant, OP_HKDF_EXTRACT);
		}

		/* K_1, IV_1 → decrypt CIPHERTEXT_1 */
		uint8_t k1[PQ_AEAD_KEY_LEN], iv1[PQ_AEAD_NONCE_LEN];
		{
			HS_TIME_START();
			derive_key_iv(prk_1e, INFO_K1, INFO_K1_LEN, k1, iv1);
			HS_TIME_END(variant, OP_HKDF_EXPAND);
		}

		/* TH_1 = H(pk_eph, ct_R) for AAD */
		uint8_t th1[PQ_HASH_LEN];
		{
			HS_TIME_START();
			uint8_t th1_input[PQ_KEM_PK_LEN + PQ_KEM_CT_LEN];
			memcpy(th1_input, pk_eph, PQ_KEM_PK_LEN);
			memcpy(th1_input + PQ_KEM_PK_LEN, ct_R, PQ_KEM_CT_LEN);
			pq_hash_sha256(th1_input, PQ_KEM_PK_LEN + PQ_KEM_CT_LEN, th1);
			HS_TIME_END(variant, OP_HASH);
		}

		uint8_t pt1[256]; size_t pt1_len = 0;
		{
			HS_TIME_START();
			pq_aead_decrypt(k1, iv1, th1, PQ_HASH_LEN, ct1_aead, ct1_aead_len, pt1, &pt1_len);
			HS_TIME_END(variant, OP_AEAD_DECRYPT);
		}
		/* pt1 = (METHOD, SUITES_I, ID_CRED_I, C_I, EAD_1) */

		/* PQ Encapsulate (ephemeral): ss_eph, ct_eph = kemEncaps(pk_eph) */
		uint8_t ct_eph[PQ_KEM_CT_LEN], ss_eph[PQ_KEM_SS_LEN];
		{
			HS_TIME_START();
			pq_kem_encaps(ct_eph, ss_eph, pk_eph);
			HS_TIME_END(variant, OP_ENCAPS);
		}

		/* PRK_2m = HKDF-Extract(PRK_1e, ss_eph) */
		uint8_t prk_2m[PQ_PRK_LEN];
		{
			HS_TIME_START();
			pq_hkdf_extract(prk_1e, PQ_PRK_LEN, ss_eph, PQ_KEM_SS_LEN, prk_2m);
			HS_TIME_END(variant, OP_HKDF_EXTRACT);
		}

		/* PQ Encapsulate (auth of I): ss_I, ct_I = kemEncaps(pk_I) */
		uint8_t ct_I[PQ_KEM_CT_LEN], ss_I[PQ_KEM_SS_LEN];
		{
			HS_TIME_START();
			pq_kem_encaps(ct_I, ss_I, lt_pk_i);
			HS_TIME_END(variant, OP_ENCAPS);
		}

		/* PRK_2e3e3m = HKDF-Extract(PRK_2m, ss_I) */
		uint8_t prk_2e3e3m[PQ_PRK_LEN];
		{
			HS_TIME_START();
			pq_hkdf_extract(prk_2m, PQ_PRK_LEN, ss_I, PQ_KEM_SS_LEN, prk_2e3e3m);
			HS_TIME_END(variant, OP_HKDF_EXTRACT);
		}

		/* TH_2 = H(H(Message_1), ct_eph, ct_I) */
		uint8_t th2[PQ_HASH_LEN];
		{
			HS_TIME_START();
			uint8_t h_msg1[PQ_HASH_LEN];
			pq_hash_sha256(msg1, msg1_len, h_msg1);
			uint8_t th2_input[PQ_HASH_LEN + 2 * PQ_KEM_CT_LEN];
			memcpy(th2_input, h_msg1, PQ_HASH_LEN);
			memcpy(th2_input + PQ_HASH_LEN, ct_eph, PQ_KEM_CT_LEN);
			memcpy(th2_input + PQ_HASH_LEN + PQ_KEM_CT_LEN, ct_I, PQ_KEM_CT_LEN);
			pq_hash_sha256(th2_input, PQ_HASH_LEN + 2 * PQ_KEM_CT_LEN, th2);
			HS_TIME_END(variant, OP_HASH);
		}

		/* MAC_2 = KDF(PRK_2m, context) */
		uint8_t mac2[PQ_AEAD_TAG_LEN];
		{
			HS_TIME_START();
			uint8_t mac2_info[PQ_HASH_LEN + 64];
			memcpy(mac2_info, th2, PQ_HASH_LEN);
			memcpy(mac2_info + PQ_HASH_LEN, LBL_ID_CRED_R, LBL_ID_CRED_R_LEN);
			pq_hkdf_expand(prk_2m, mac2_info, PQ_HASH_LEN + LBL_ID_CRED_R_LEN,
			               mac2, PQ_AEAD_TAG_LEN);
			HS_TIME_END(variant, OP_HKDF_EXPAND);
		}

		/* K_2, IV_2 */
		uint8_t k2[PQ_AEAD_KEY_LEN], iv2[PQ_AEAD_NONCE_LEN];
		{
			HS_TIME_START();
			derive_key_iv(prk_2e3e3m, INFO_K2, INFO_K2_LEN, k2, iv2);
			HS_TIME_END(variant, OP_HKDF_EXPAND);
		}

		/* PLAINTEXT_2 = (C_R, ID_CRED_R, EAD_2, MAC_2) */
		uint8_t c_r = 0x37, id_cred_r = 0x01;
		uint8_t pt2[64 + PQ_AEAD_TAG_LEN];
		size_t pt2_len = 0;
		pt2[pt2_len++] = c_r;
		pt2[pt2_len++] = id_cred_r;
		pt2[pt2_len++] = 0x00; /* EAD_2 placeholder */
		memcpy(pt2 + pt2_len, mac2, PQ_AEAD_TAG_LEN); pt2_len += PQ_AEAD_TAG_LEN;

		uint8_t ct2_aead[512 + PQ_AEAD_TAG_LEN]; size_t ct2_aead_len = 0;
		{
			HS_TIME_START();
			pq_aead_encrypt(k2, iv2, th2, PQ_HASH_LEN, pt2, pt2_len, ct2_aead, &ct2_aead_len);
			HS_TIME_END(variant, OP_AEAD_ENCRYPT);
		}

		/* ── Send MSG2: ct_eph || ct_I || aead_len(2) || AEAD(C_R, ID_CRED_R, EAD_2, MAC_2) ── */
		uint8_t msg2[P2P_MSG_BUF_SIZE];
		uint32_t msg2_len = 0;
		memcpy(msg2, ct_eph, PQ_KEM_CT_LEN); msg2_len += PQ_KEM_CT_LEN;
		memcpy(msg2 + msg2_len, ct_I, PQ_KEM_CT_LEN); msg2_len += PQ_KEM_CT_LEN;
		msg2[msg2_len++] = (uint8_t)(ct2_aead_len >> 8);
		msg2[msg2_len++] = (uint8_t)(ct2_aead_len & 0xFF);
		memcpy(msg2 + msg2_len, ct2_aead, ct2_aead_len); msg2_len += ct2_aead_len;

		{
			uint64_t tx_start = bench_get_ns();
			p2p_send_msg(sockfd, P2P_MSG_TYPE_MSG2, msg2, msg2_len);
			txrx_ns += (bench_get_ns() - tx_start);
		}

		/* ── Receive MSG3: AEAD(EAD_3, MAC_3) ── */
		uint8_t msg3[P2P_MSG_BUF_SIZE]; uint32_t msg3_len;
		{
			uint64_t rx_start = bench_get_ns();
			p2p_recv_msg(sockfd, &type, msg3, &msg3_len, sizeof(msg3));
			txrx_ns += (bench_get_ns() - rx_start);
		}

		/* ══ (4) Responder Final Verification ══ */

		/* TH_3 = H(TH_2, PLAINTEXT_2, CRED_R) */
		uint8_t th3[PQ_HASH_LEN];
		{
			HS_TIME_START();
			uint8_t th3_input[P2P_MSG_BUF_SIZE];
			size_t th3_in_len = 0;
			memcpy(th3_input, th2, PQ_HASH_LEN); th3_in_len += PQ_HASH_LEN;
			memcpy(th3_input + th3_in_len, pt2, pt2_len); th3_in_len += pt2_len;
			memcpy(th3_input + th3_in_len, lt_pk_r, PQ_KEM_PK_LEN); th3_in_len += PQ_KEM_PK_LEN;
			pq_hash_sha256(th3_input, th3_in_len, th3);
			HS_TIME_END(variant, OP_HASH);
		}

		/* K_3, IV_3 → decrypt MSG3 */
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
		/* pt3 = (EAD_3, MAC_3) */

		/* Verify MAC_3 = KDF(PRK_2e3e3m, context) */
		uint8_t mac3_expected[PQ_AEAD_TAG_LEN];
		{
			HS_TIME_START();
			uint8_t mac3_info[PQ_HASH_LEN + 64];
			memcpy(mac3_info, th3, PQ_HASH_LEN);
			memcpy(mac3_info + PQ_HASH_LEN, LBL_ID_CRED_I, LBL_ID_CRED_I_LEN);
			pq_hkdf_expand(prk_2e3e3m, mac3_info, PQ_HASH_LEN + LBL_ID_CRED_I_LEN,
			               mac3_expected, PQ_AEAD_TAG_LEN);
			HS_TIME_END(variant, OP_HKDF_EXPAND);
		}
		{
			HS_TIME_START();
			(void)sodium_memcmp(mac3_expected, pt3 + 1, PQ_AEAD_TAG_LEN);
			HS_TIME_END(variant, OP_VERIFY);
		}

		/* PRK_out */
		{
			HS_TIME_START();
			uint8_t prk_out[PQ_PRK_LEN];
			pq_hkdf_expand(prk_2e3e3m, th3, PQ_HASH_LEN, prk_out, PQ_PRK_LEN);
			HS_TIME_END(variant, OP_HKDF_EXPAND);
		}

		/* TH_4 = H(TH_3, PLAINTEXT_3, CRED_I) */
		uint8_t th4[PQ_HASH_LEN];
		{
			HS_TIME_START();
			uint8_t th4_input[P2P_MSG_BUF_SIZE];
			size_t th4_in_len = 0;
			memcpy(th4_input, th3, PQ_HASH_LEN); th4_in_len += PQ_HASH_LEN;
			memcpy(th4_input + th4_in_len, pt3, pt3_len); th4_in_len += pt3_len;
			memcpy(th4_input + th4_in_len, lt_pk_i, PQ_KEM_PK_LEN); th4_in_len += PQ_KEM_PK_LEN;
			pq_hash_sha256(th4_input, th4_in_len, th4);
			HS_TIME_END(variant, OP_HASH);
		}

		/* K_4, IV_4 + Send MSG4: AEAD(EAD_4) */
		uint8_t k4[PQ_AEAD_KEY_LEN], iv4[PQ_AEAD_NONCE_LEN];
		{
			HS_TIME_START();
			derive_key_iv(prk_2e3e3m, INFO_K4, INFO_K4_LEN, k4, iv4);
			HS_TIME_END(variant, OP_HKDF_EXPAND);
		}

		uint8_t pt4[1] = { 0x00 }; /* EAD_4 */
		uint8_t ct4_aead[64 + PQ_AEAD_TAG_LEN]; size_t ct4_aead_len = 0;
		{
			HS_TIME_START();
			pq_aead_encrypt(k4, iv4, th4, PQ_HASH_LEN, pt4, 1, ct4_aead, &ct4_aead_len);
			HS_TIME_END(variant, OP_AEAD_ENCRYPT);
		}

		{
			uint64_t tx_start = bench_get_ns();
			p2p_send_msg(sockfd, P2P_MSG_TYPE_MSG4, ct4_aead, ct4_aead_len);
			txrx_ns += (bench_get_ns() - tx_start);
		}

		uint64_t iter_end = bench_get_ns();
		total_wall_us += ns_to_us(iter_end - iter_start);
		if (iter == 0) { long m = get_memory_usage_bytes(); if (m > mem_peak) mem_peak = m; }
		total_txrx_us += ns_to_us(txrx_ns);
		total_precomp_us += ns_to_us(precomp_end - iter_start);
	}

	uint64_t wall_all_end = bench_get_ns();
	getrusage(RUSAGE_SELF, &ru_end);
	finalize_variant_stats(variant, N, total_wall_us, total_txrx_us, total_precomp_us,
	                       wall_all_start, wall_all_end, &ru_start, &ru_end, mem_before, mem_peak);

	return 0;
}
