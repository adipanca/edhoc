#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 199309L
#endif
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
/*
 * EDHOC-Hybrid: Type 3 Classic variant (initiator + responder)
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

int handshake_type3_classic_initiator(int sockfd, int variant)
{
	int N = P2P_BENCH_HANDSHAKE_ITERATIONS;

	uint8_t static_sk_i[32], static_pk_i[32];
	{
		uint8_t seed[4] = {0xAA, 0xBB, 0xCC, 0xDD};
		uint8_t sh[32]; size_t hl;
		psa_hash_compute(PSA_ALG_SHA_256, seed, 4, sh, 32, &hl);
		sh[0] &= 248; sh[31] &= 127; sh[31] |= 64;
		memcpy(static_sk_i, sh, 32);
		crypto_scalarmult_base(static_pk_i, static_sk_i);
	}

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

		uint8_t eph_sk[32], eph_pk[32];
		{
			HS_TIME_START();
			uint8_t seed_buf[4];
			*(uint32_t *)seed_buf = (uint32_t)(iter + 100);
			uint8_t sh[32]; size_t hl;
			psa_hash_compute(PSA_ALG_SHA_256, seed_buf, 4, sh, 32, &hl);
			sh[0] &= 248; sh[31] &= 127; sh[31] |= 64;
			memcpy(eph_sk, sh, 32);
			crypto_scalarmult_base(eph_pk, eph_sk);
			HS_TIME_END(variant, OP_KEYGEN);
		}
		uint64_t precomp_end = bench_get_ns();

		uint8_t message_1[35];
		message_1[0] = 0x03;
		message_1[1] = 0x02;
		memcpy(message_1 + 2, eph_pk, 32);
		message_1[34] = 0x00;
		{
			uint64_t tx_start = bench_get_ns();
			p2p_send_msg(sockfd, P2P_MSG_TYPE_MSG1, message_1, 35);
			txrx_ns += (bench_get_ns() - tx_start);
		}

		uint8_t msg2_buf[P2P_MSG_BUF_SIZE];
		uint32_t msg2_len;
		{
			uint64_t rx_start = bench_get_ns();
			p2p_recv_msg(sockfd, &type, msg2_buf, &msg2_len, sizeof(msg2_buf));
			txrx_ns += (bench_get_ns() - rx_start);
		}

		uint8_t gy[32];
		memcpy(gy, msg2_buf, 32);
		uint8_t *ciphertext_2 = msg2_buf + 32;
		uint32_t ciphertext_2_len = msg2_len - 32;

		uint8_t shared_xy[32];
		{
			HS_TIME_START();
			crypto_scalarmult(shared_xy, eph_sk, gy);
			HS_TIME_END(variant, OP_SCALAR_MULT);
		}

		uint8_t th2[32];
		{
			HS_TIME_START();
			uint8_t h_msg1[32];
			crypto_hash_sha256(h_msg1, message_1, 35);
			uint8_t th2_input[64];
			memcpy(th2_input, gy, 32);
			memcpy(th2_input + 32, h_msg1, 32);
			crypto_hash_sha256(th2, th2_input, 64);
			HS_TIME_END(variant, OP_HASH);
		}

		uint8_t prk_2e[32];
		{
			HS_TIME_START();
			crypto_auth_hmacsha256(prk_2e, shared_xy, 32, th2);
			HS_TIME_END(variant, OP_HKDF_EXTRACT);
		}

		uint8_t plaintext_2[128];
		{
			HS_TIME_START();
			uint8_t keystream_2[128];
			edhoc_kdf(prk_2e, 0, th2, 32, keystream_2, ciphertext_2_len);
			for (uint32_t i = 0; i < ciphertext_2_len; i++)
				plaintext_2[i] = ciphertext_2[i] ^ keystream_2[i];
			HS_TIME_END(variant, OP_HKDF_EXPAND);
		}

		/* PT2 = C_R(1) || ID_CRED_R(1) || MAC_2(32) */
		uint8_t mac2_recv[32];
		memcpy(mac2_recv, plaintext_2 + 2, 32);

		uint8_t salt_3e2m[32];
		{
			HS_TIME_START();
			edhoc_kdf(prk_2e, 1, th2, 32, salt_3e2m, 32);
			HS_TIME_END(variant, OP_HKDF_EXPAND);
		}

		uint8_t g_rx[32];
		{
			HS_TIME_START();
			crypto_scalarmult(g_rx, eph_sk, static_pk_r);
			HS_TIME_END(variant, OP_SCALAR_MULT);
		}

		uint8_t prk_3e2m[32];
		{
			HS_TIME_START();
			crypto_auth_hmacsha256(prk_3e2m, g_rx, 32, salt_3e2m);
			HS_TIME_END(variant, OP_HKDF_EXTRACT);
		}

		/* Recompute MAC_2 and verify */
		uint8_t mac2[32];
		{
			HS_TIME_START();
			uint8_t context_2[128];
			size_t ctx2_len = 0;
			context_2[ctx2_len++] = plaintext_2[0];
			context_2[ctx2_len++] = plaintext_2[1];
			memcpy(context_2 + ctx2_len, th2, 32); ctx2_len += 32;
			memcpy(context_2 + ctx2_len, static_pk_r, 32); ctx2_len += 32;
			edhoc_kdf(prk_3e2m, 2, context_2, ctx2_len, mac2, 32);
			HS_TIME_END(variant, OP_HKDF_EXPAND);
		}
		{
			HS_TIME_START();
			if (memcmp(mac2, mac2_recv, 32) != 0) {
				fprintf(stderr, "MAC_2 verification failed\n");
				return -1;
			}
			HS_TIME_END(variant, OP_VERIFY);
		}

		uint8_t th3[32];
		{
			HS_TIME_START();
			uint8_t th3_input[256];
			size_t th3_in_len = 0;
			memcpy(th3_input, th2, 32); th3_in_len += 32;
			memcpy(th3_input + th3_in_len, plaintext_2, ciphertext_2_len); th3_in_len += ciphertext_2_len;
			memcpy(th3_input + th3_in_len, static_pk_r, 32); th3_in_len += 32;
			crypto_hash_sha256(th3, th3_input, th3_in_len);
			HS_TIME_END(variant, OP_HASH);
		}

		uint8_t salt_4e3m[32];
		{
			HS_TIME_START();
			edhoc_kdf(prk_3e2m, 5, th3, 32, salt_4e3m, 32);
			HS_TIME_END(variant, OP_HKDF_EXPAND);
		}

		uint8_t g_iy[32];
		{
			HS_TIME_START();
			crypto_scalarmult(g_iy, static_sk_i, gy);
			HS_TIME_END(variant, OP_SCALAR_MULT);
		}

		uint8_t prk_4e3m[32];
		{
			HS_TIME_START();
			crypto_auth_hmacsha256(prk_4e3m, g_iy, 32, salt_4e3m);
			HS_TIME_END(variant, OP_HKDF_EXTRACT);
		}

		uint8_t mac3[32];
		{
			HS_TIME_START();
			uint8_t context_3[128];
			size_t ctx3_len = 0;
			context_3[ctx3_len++] = 0x02;
			memcpy(context_3 + ctx3_len, th3, 32); ctx3_len += 32;
			memcpy(context_3 + ctx3_len, static_pk_i, 32); ctx3_len += 32;
			edhoc_kdf(prk_4e3m, 6, context_3, ctx3_len, mac3, 32);
			HS_TIME_END(variant, OP_HKDF_EXPAND);
		}

		uint8_t plaintext_3[33];
		plaintext_3[0] = 0x02;
		memcpy(plaintext_3 + 1, mac3, 32);
		uint32_t pt3_len = 33;

		uint8_t k3[16], iv3[13];
		{
			HS_TIME_START();
			edhoc_kdf(prk_3e2m, 3, th3, 32, k3, 16);
			edhoc_kdf(prk_3e2m, 4, th3, 32, iv3, 13);
			HS_TIME_END(variant, OP_HKDF_EXPAND);
		}

		uint8_t msg3_buf[128 + 16];
		uint32_t msg3_len;
		{
			HS_TIME_START();
			mbedtls_gcm_context gcm;
			mbedtls_gcm_init(&gcm);
			mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, k3, 128);
			uint8_t tag[16];
			mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, pt3_len,
			                          iv3, 13, th3, 32,
			                          plaintext_3, msg3_buf, 16, tag);
			memcpy(msg3_buf + pt3_len, tag, 16);
			msg3_len = pt3_len + 16;
			mbedtls_gcm_free(&gcm);
			HS_TIME_END(variant, OP_AEAD_ENCRYPT);
		}

		{
			uint64_t tx_start = bench_get_ns();
			p2p_send_msg(sockfd, P2P_MSG_TYPE_MSG3, msg3_buf, msg3_len);
			txrx_ns += (bench_get_ns() - tx_start);
		}

		uint8_t done_buf[16]; uint32_t done_len;
		{
			uint64_t rx_start = bench_get_ns();
			p2p_recv_msg(sockfd, &type, done_buf, &done_len, sizeof(done_buf));
			txrx_ns += (bench_get_ns() - rx_start);
		}

		uint8_t th4[32];
		{
			HS_TIME_START();
			uint8_t th4_input[256];
			size_t th4_in_len = 0;
			memcpy(th4_input, th3, 32); th4_in_len += 32;
			memcpy(th4_input + th4_in_len, plaintext_3, pt3_len); th4_in_len += pt3_len;
			memcpy(th4_input + th4_in_len, static_pk_i, 32); th4_in_len += 32;
			crypto_hash_sha256(th4, th4_input, th4_in_len);
			HS_TIME_END(variant, OP_HASH);
		}

		{
			HS_TIME_START();
			uint8_t prk_out[32];
			edhoc_kdf(prk_4e3m, 7, th4, 32, prk_out, 32);
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

int handshake_type3_classic_responder(int sockfd, int variant)
{
	int N = P2P_BENCH_HANDSHAKE_ITERATIONS;

	uint8_t static_sk_r[32], static_pk_r[32];
	{
		uint8_t seed[4] = {0xBB, 0xCC, 0xDD, 0xEE};
		uint8_t sh[32]; size_t hl;
		psa_hash_compute(PSA_ALG_SHA_256, seed, 4, sh, 32, &hl);
		sh[0] &= 248; sh[31] &= 127; sh[31] |= 64;
		memcpy(static_sk_r, sh, 32);
		crypto_scalarmult_base(static_pk_r, static_sk_r);
	}

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

		uint8_t eph_sk_r[32], eph_pk_r[32];
		{
			HS_TIME_START();
			uint8_t seed_buf[4]; *(uint32_t *)seed_buf = (uint32_t)(iter + 6000);
			uint8_t sh[32]; size_t hl;
			psa_hash_compute(PSA_ALG_SHA_256, seed_buf, 4, sh, 32, &hl);
			sh[0] &= 248; sh[31] &= 127; sh[31] |= 64;
			memcpy(eph_sk_r, sh, 32);
			crypto_scalarmult_base(eph_pk_r, eph_sk_r);
			HS_TIME_END(variant, OP_KEYGEN);
		}
		uint64_t precomp_end = bench_get_ns();

		uint8_t message_1[64];
		uint32_t msg1_len;
		{
			uint64_t rx_start = bench_get_ns();
			p2p_recv_msg(sockfd, &type, message_1, &msg1_len, sizeof(message_1));
			txrx_ns += (bench_get_ns() - rx_start);
		}
		uint8_t eph_pk_i[32];
		memcpy(eph_pk_i, message_1 + 2, 32);

		uint8_t th2[32];
		{
			HS_TIME_START();
			uint8_t h_msg1[32];
			crypto_hash_sha256(h_msg1, message_1, msg1_len);
			uint8_t th2_input[64];
			memcpy(th2_input, eph_pk_r, 32);
			memcpy(th2_input + 32, h_msg1, 32);
			crypto_hash_sha256(th2, th2_input, 64);
			HS_TIME_END(variant, OP_HASH);
		}

		uint8_t shared_xy[32];
		{
			HS_TIME_START();
			crypto_scalarmult(shared_xy, eph_sk_r, eph_pk_i);
			HS_TIME_END(variant, OP_SCALAR_MULT);
		}

		uint8_t prk_2e[32];
		{
			HS_TIME_START();
			crypto_auth_hmacsha256(prk_2e, shared_xy, 32, th2);
			HS_TIME_END(variant, OP_HKDF_EXTRACT);
		}

		uint8_t salt_3e2m[32];
		{
			HS_TIME_START();
			edhoc_kdf(prk_2e, 1, th2, 32, salt_3e2m, 32);
			HS_TIME_END(variant, OP_HKDF_EXPAND);
		}

		uint8_t g_rx[32];
		{
			HS_TIME_START();
			crypto_scalarmult(g_rx, static_sk_r, eph_pk_i);
			HS_TIME_END(variant, OP_SCALAR_MULT);
		}

		uint8_t prk_3e2m[32];
		{
			HS_TIME_START();
			crypto_auth_hmacsha256(prk_3e2m, g_rx, 32, salt_3e2m);
			HS_TIME_END(variant, OP_HKDF_EXTRACT);
		}

		uint8_t c_r = 0x37;
		uint8_t id_cred_r = 0x01;
		uint8_t mac2[32];
		{
			HS_TIME_START();
			uint8_t context_2[128];
			size_t ctx2_len = 0;
			context_2[ctx2_len++] = c_r;
			context_2[ctx2_len++] = id_cred_r;
			memcpy(context_2 + ctx2_len, th2, 32); ctx2_len += 32;
			memcpy(context_2 + ctx2_len, static_pk_r, 32); ctx2_len += 32;
			edhoc_kdf(prk_3e2m, 2, context_2, ctx2_len, mac2, 32);
			HS_TIME_END(variant, OP_HKDF_EXPAND);
		}

		/* PT2 = C_R(1) || ID_CRED_R(1) || MAC_2(32) = 34 bytes */
		uint8_t plaintext_2[34];
		plaintext_2[0] = c_r;
		plaintext_2[1] = id_cred_r;
		memcpy(plaintext_2 + 2, mac2, 32);
		uint32_t pt2_len = 34;

		uint8_t ciphertext_2[34];
		{
			HS_TIME_START();
			uint8_t keystream_2[34];
			edhoc_kdf(prk_2e, 0, th2, 32, keystream_2, pt2_len);
			for (uint32_t i = 0; i < pt2_len; i++)
				ciphertext_2[i] = plaintext_2[i] ^ keystream_2[i];
			HS_TIME_END(variant, OP_HKDF_EXPAND);
		}

		uint8_t msg2[128];
		memcpy(msg2, eph_pk_r, 32);
		memcpy(msg2 + 32, ciphertext_2, pt2_len);
		uint32_t msg2_len = 32 + pt2_len;
		{
			uint64_t tx_start = bench_get_ns();
			p2p_send_msg(sockfd, P2P_MSG_TYPE_MSG2, msg2, msg2_len);
			txrx_ns += (bench_get_ns() - tx_start);
		}

		uint8_t msg3[P2P_MSG_BUF_SIZE]; uint32_t msg3_len;
		{
			uint64_t rx_start = bench_get_ns();
			p2p_recv_msg(sockfd, &type, msg3, &msg3_len, sizeof(msg3));
			txrx_ns += (bench_get_ns() - rx_start);
		}

		uint8_t th3[32];
		{
			HS_TIME_START();
			uint8_t th3_input[256];
			size_t th3_in_len = 0;
			memcpy(th3_input, th2, 32); th3_in_len += 32;
			memcpy(th3_input + th3_in_len, plaintext_2, pt2_len); th3_in_len += pt2_len;
			memcpy(th3_input + th3_in_len, static_pk_r, 32); th3_in_len += 32;
			crypto_hash_sha256(th3, th3_input, th3_in_len);
			HS_TIME_END(variant, OP_HASH);
		}

		uint8_t k3[16], iv3[13];
		{
			HS_TIME_START();
			edhoc_kdf(prk_3e2m, 3, th3, 32, k3, 16);
			edhoc_kdf(prk_3e2m, 4, th3, 32, iv3, 13);
			HS_TIME_END(variant, OP_HKDF_EXPAND);
		}

		uint8_t plaintext_3[128];
		{
			HS_TIME_START();
			mbedtls_gcm_context gcm;
			mbedtls_gcm_init(&gcm);
			mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, k3, 128);
			if (msg3_len > 16) {
				mbedtls_gcm_auth_decrypt(&gcm, msg3_len - 16, iv3, 13,
				                         th3, 32,
				                         msg3 + msg3_len - 16, 16,
				                         msg3, plaintext_3);
			}
			mbedtls_gcm_free(&gcm);
			HS_TIME_END(variant, OP_AEAD_DECRYPT);
		}

		/* PT3 = ID_CRED_I(1) || MAC_3(32) */
		uint8_t mac3_recv[32];
		uint32_t pt3_len = msg3_len - 16;
		memcpy(mac3_recv, plaintext_3 + 1, 32);

		uint8_t salt_4e3m[32];
		{
			HS_TIME_START();
			edhoc_kdf(prk_3e2m, 5, th3, 32, salt_4e3m, 32);
			HS_TIME_END(variant, OP_HKDF_EXPAND);
		}

		uint8_t g_iy[32];
		{
			HS_TIME_START();
			crypto_scalarmult(g_iy, eph_sk_r, static_pk_i);
			HS_TIME_END(variant, OP_SCALAR_MULT);
		}

		uint8_t prk_4e3m[32];
		{
			HS_TIME_START();
			crypto_auth_hmacsha256(prk_4e3m, g_iy, 32, salt_4e3m);
			HS_TIME_END(variant, OP_HKDF_EXTRACT);
		}

		/* Recompute MAC_3 and verify */
		uint8_t mac3[32];
		{
			HS_TIME_START();
			uint8_t context_3[128];
			size_t ctx3_len = 0;
			context_3[ctx3_len++] = 0x02;
			memcpy(context_3 + ctx3_len, th3, 32); ctx3_len += 32;
			memcpy(context_3 + ctx3_len, static_pk_i, 32); ctx3_len += 32;
			edhoc_kdf(prk_4e3m, 6, context_3, ctx3_len, mac3, 32);
			HS_TIME_END(variant, OP_HKDF_EXPAND);
		}
		{
			HS_TIME_START();
			if (memcmp(mac3, mac3_recv, 32) != 0) {
				fprintf(stderr, "MAC_3 verification failed\n");
				return -1;
			}
			HS_TIME_END(variant, OP_VERIFY);
		}

		{
			uint64_t tx_start = bench_get_ns();
			p2p_send_msg(sockfd, P2P_MSG_TYPE_DONE, NULL, 0);
			txrx_ns += (bench_get_ns() - tx_start);
		}

		uint8_t th4[32];
		{
			HS_TIME_START();
			uint8_t th4_input[256];
			size_t th4_in_len = 0;
			memcpy(th4_input, th3, 32); th4_in_len += 32;
			memcpy(th4_input + th4_in_len, plaintext_3, pt3_len); th4_in_len += pt3_len;
			memcpy(th4_input + th4_in_len, static_pk_i, 32); th4_in_len += 32;
			crypto_hash_sha256(th4, th4_input, th4_in_len);
			HS_TIME_END(variant, OP_HASH);
		}

		{
			HS_TIME_START();
			uint8_t prk_out[32];
			edhoc_kdf(prk_4e3m, 7, th4, 32, prk_out, 32);
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
