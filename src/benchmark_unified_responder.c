/*
 * =============================================================================
 * EDHOC-Hybrid: Unified Benchmark — Responder
 * =============================================================================
 *
 * Runs ALL benchmarks (P2P + EAP) in a single binary over one TCP connection.
 *   Phase 1: Pure crypto benchmarks (local)
 *   Phase 2: P2P full handshake (5 variants)
 *   Phase 3: EAP-EDHOC full handshake (5 variants)
 *   Phase 4: Write ALL CSV files
 *
 * Outputs all 9 CSV files (P2P + EAP) to output/
 *
 * Usage:
 *   ./build/responder [port]
 */

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 199309L
#endif
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

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

#include "edhoc_benchmark_eap.h"   /* includes edhoc_benchmark_p2p.h */
#include "edhoc_pq_kem.h"

#include "mbedtls/gcm.h"

#define OUTPUT_DIR "output"

/* Phase-switch sync value: P2P done, EAP next */
#define PHASE_SWITCH_SIGNAL  0xFE

/* Forward declarations */
static int wait_for_client(int port);
static void run_crypto_benchmarks(void);
static int run_p2p_handshakes(int sockfd);
static void run_eap_handshakes(int sockfd);
static void write_all_csv(void);

/* ── Global benchmark results ── */
static struct crypto_bench_stats g_crypto_stats[20];
static const char *g_crypto_alg_names[20];
static const char *g_crypto_op_names[20];
static int g_crypto_count = 0;

/* Active globals used by variant functions (via extern in headers) */
struct handshake_op_stats g_hs_ops[NUM_VARIANTS];
struct handshake_timing g_hs_timing[NUM_VARIANTS];
struct overhead_stats g_hs_overhead[NUM_VARIANTS];
struct eap_transport_stats g_eap_transport[NUM_VARIANTS];

/* Saved P2P results */
static struct handshake_op_stats p2p_saved_ops[NUM_VARIANTS];
static struct handshake_timing p2p_saved_timing[NUM_VARIANTS];
static struct overhead_stats p2p_saved_overhead[NUM_VARIANTS];

/* =============================================================================
 * MAIN
 * =============================================================================
 */
int main(int argc, char *argv[])
{
	int port = (argc > 1) ? atoi(argv[1]) : P2P_DEFAULT_PORT;

	if (sodium_init() < 0) {
		fprintf(stderr, "ERROR: sodium_init() failed\n");
		return 1;
	}
	psa_crypto_init();

	printf("\n");
	printf("╔══════════════════════════════════════════════════════════════╗\n");
	printf("║    EDHOC Unified Benchmark — RESPONDER (P2P + EAP)           ║\n");
	printf("╚══════════════════════════════════════════════════════════════╝\n");
	printf("  Listening on port: %d\n", port);
	printf("  Crypto iterations: %d\n", P2P_BENCH_CRYPTO_ITERATIONS);
	printf("  Handshake iterations: %d\n", P2P_BENCH_HANDSHAKE_ITERATIONS);
	printf("  EAP MTU: %d bytes/fragment\n", EAP_EDHOC_MTU);
	printf("\n");

	(void)!system("mkdir -p " OUTPUT_DIR);

	/* Phase 1: Pure crypto benchmarks (local) */
	printf("═══ Phase 1: Pure Cryptographic Operations ═══\n\n");
	run_crypto_benchmarks();

	/* Wait for initiator */
	printf("\n═══ Phase 2: Waiting for Initiator Connection ═══\n\n");
	int sockfd = wait_for_client(port);
	if (sockfd < 0) {
		fprintf(stderr, "ERROR: failed to accept client\n");
		return 1;
	}
	printf("  Initiator connected.\n\n");

	/* Phase 2: P2P handshake benchmarks */
	printf("═══ Phase 2: Full Handshake Benchmarks (P2P) ═══\n\n");
	int got_eap_phase = run_p2p_handshakes(sockfd);

	/* Save P2P results */
	memcpy(p2p_saved_ops, g_hs_ops, sizeof(g_hs_ops));
	memcpy(p2p_saved_timing, g_hs_timing, sizeof(g_hs_timing));
	memcpy(p2p_saved_overhead, g_hs_overhead, sizeof(g_hs_overhead));

	if (got_eap_phase) {
		/* Phase 3: EAP-EDHOC handshake benchmarks (same TCP connection) */
		printf("\n═══ Phase 3: Full Handshake Benchmarks (EAP-EDHOC) ═══\n\n");
		memset(g_hs_ops, 0, sizeof(g_hs_ops));
		memset(g_hs_timing, 0, sizeof(g_hs_timing));
		memset(g_hs_overhead, 0, sizeof(g_hs_overhead));
		memset(g_eap_transport, 0, sizeof(g_eap_transport));
		run_eap_handshakes(sockfd);
	}

	close(sockfd);

	/* Phase 4: Write ALL CSV files */
	printf("\n═══ Phase 4: Writing CSV Output ═══\n\n");
	write_all_csv();

	printf("\n  Unified benchmark complete (P2P + EAP).\n\n");
	return 0;
}

/* =============================================================================
 * TCP Server
 * =============================================================================
 */
static int wait_for_client(int port)
{
	int listenfd = socket(AF_INET, SOCK_STREAM, 0);
	if (listenfd < 0) return -1;

	int optval = 1;
	setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = htons(port);

	if (bind(listenfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		close(listenfd);
		return -1;
	}
	if (listen(listenfd, 1) < 0) {
		close(listenfd);
		return -1;
	}

	printf("  Waiting for initiator on port %d...\n", port);

	struct sockaddr_in caddr;
	socklen_t clen = sizeof(caddr);
	int connfd = accept(listenfd, (struct sockaddr *)&caddr, &clen);
	close(listenfd);

	if (connfd >= 0) {
		int flag = 1;
		setsockopt(connfd, IPPROTO_TCP, 1 /* TCP_NODELAY */, &flag, sizeof(flag));
		char ip_str[INET_ADDRSTRLEN];
		inet_ntop(AF_INET, &caddr.sin_addr, ip_str, sizeof(ip_str));
		printf("  Accepted connection from %s:%d\n", ip_str, ntohs(caddr.sin_port));
	}

	return connfd;
}

/* =============================================================================
 * Phase 1: Pure Crypto Benchmarks
 * =============================================================================
 */

static void bench_add(const char *alg, const char *op, struct crypto_bench_stats s)
{
	g_crypto_alg_names[g_crypto_count] = alg;
	g_crypto_op_names[g_crypto_count] = op;
	g_crypto_stats[g_crypto_count] = s;
	g_crypto_count++;
}

static void run_crypto_benchmarks(void)
{
	int N = P2P_BENCH_CRYPTO_ITERATIONS;
	double *samples = malloc(N * sizeof(double));

	printf("  Benchmarking X25519 KeyGen...\n");
	for (int i = 0; i < N; i++) {
		uint8_t pk[32], sk[32];
		uint8_t seed_buf[4]; *(uint32_t *)seed_buf = (uint32_t)i;
		uint64_t t0 = bench_get_ns();
		uint8_t seed_hash[32]; size_t hl = 0;
		psa_hash_compute(PSA_ALG_SHA_256, seed_buf, 4, seed_hash, 32, &hl);
		seed_hash[0] &= 248; seed_hash[31] &= 127; seed_hash[31] |= 64;
		memcpy(sk, seed_hash, 32);
		crypto_scalarmult_base(pk, sk);
		uint64_t t1 = bench_get_ns();
		samples[i] = ns_to_us(t1 - t0);
	}
	bench_add("X25519", "Keygen", compute_stats(samples, N, 32));

	printf("  Benchmarking ML-KEM-768 KeyGen...\n");
	for (int i = 0; i < N; i++) {
		uint8_t pk[PQ_KEM_PK_LEN], sk[PQ_KEM_SK_LEN];
		uint64_t t0 = bench_get_ns();
		pq_kem_keygen(pk, sk);
		uint64_t t1 = bench_get_ns();
		samples[i] = ns_to_us(t1 - t0);
	}
	bench_add("ML-KEM-768", "Keygen", compute_stats(samples, N, PQ_KEM_PK_LEN));

	printf("  Benchmarking X25519+MLKEM-768 KeyGen...\n");
	for (int i = 0; i < N; i++) {
		uint8_t pk_x[32], sk_x[32], pk_k[PQ_KEM_PK_LEN], sk_k[PQ_KEM_SK_LEN];
		uint8_t seed_buf[4]; *(uint32_t *)seed_buf = (uint32_t)i;
		uint64_t t0 = bench_get_ns();
		uint8_t seed_hash[32]; size_t hl = 0;
		psa_hash_compute(PSA_ALG_SHA_256, seed_buf, 4, seed_hash, 32, &hl);
		seed_hash[0] &= 248; seed_hash[31] &= 127; seed_hash[31] |= 64;
		memcpy(sk_x, seed_hash, 32);
		crypto_scalarmult_base(pk_x, sk_x);
		pq_kem_keygen(pk_k, sk_k);
		uint64_t t1 = bench_get_ns();
		samples[i] = ns_to_us(t1 - t0);
	}
	bench_add("X25519+MLKEM-768", "Keygen", compute_stats(samples, N, 32 + PQ_KEM_PK_LEN));

	printf("  Benchmarking X25519 Scalar Multiplication...\n");
	{
		uint8_t sk[32], shared[32];
		uint8_t seed_buf[4] = {0x42, 0, 0, 0};
		uint8_t seed_hash[32]; size_t hl = 0;
		psa_hash_compute(PSA_ALG_SHA_256, seed_buf, 4, seed_hash, 32, &hl);
		seed_hash[0] &= 248; seed_hash[31] &= 127; seed_hash[31] |= 64;
		memcpy(sk, seed_hash, 32);
		uint8_t peer_sk[32], peer_pk[32];
		seed_buf[0] = 0x43;
		psa_hash_compute(PSA_ALG_SHA_256, seed_buf, 4, seed_hash, 32, &hl);
		seed_hash[0] &= 248; seed_hash[31] &= 127; seed_hash[31] |= 64;
		memcpy(peer_sk, seed_hash, 32);
		crypto_scalarmult_base(peer_pk, peer_sk);
		for (int i = 0; i < N; i++) {
			uint64_t t0 = bench_get_ns();
			crypto_scalarmult(shared, sk, peer_pk);
			uint64_t t1 = bench_get_ns();
			samples[i] = ns_to_us(t1 - t0);
		}
	}
	bench_add("X25519", "Scalar multiplication", compute_stats(samples, N, 32));

	printf("  Benchmarking ML-KEM-768 Encaps...\n");
	{
		uint8_t pk[PQ_KEM_PK_LEN], sk[PQ_KEM_SK_LEN];
		pq_kem_keygen(pk, sk);
		for (int i = 0; i < N; i++) {
			uint8_t ct[PQ_KEM_CT_LEN], ss[PQ_KEM_SS_LEN];
			uint64_t t0 = bench_get_ns();
			pq_kem_encaps(ct, ss, pk);
			uint64_t t1 = bench_get_ns();
			samples[i] = ns_to_us(t1 - t0);
		}
	}
	bench_add("ML-KEM-768", "Encaps", compute_stats(samples, N, PQ_KEM_CT_LEN));

	printf("  Benchmarking ML-KEM-768 Decaps...\n");
	{
		uint8_t pk[PQ_KEM_PK_LEN], sk[PQ_KEM_SK_LEN];
		pq_kem_keygen(pk, sk);
		uint8_t ct[PQ_KEM_CT_LEN], ss[PQ_KEM_SS_LEN];
		pq_kem_encaps(ct, ss, pk);
		for (int i = 0; i < N; i++) {
			uint8_t ss2[PQ_KEM_SS_LEN];
			uint64_t t0 = bench_get_ns();
			pq_kem_decaps(ss2, ct, sk);
			uint64_t t1 = bench_get_ns();
			samples[i] = ns_to_us(t1 - t0);
		}
	}
	bench_add("ML-KEM-768", "Decaps", compute_stats(samples, N, PQ_KEM_SS_LEN));

	printf("  Benchmarking X25519+MLKEM-768 Encaps...\n");
	{
		uint8_t pk_k[PQ_KEM_PK_LEN], sk_k[PQ_KEM_SK_LEN];
		pq_kem_keygen(pk_k, sk_k);
		uint8_t sk_x[32], peer_pk[32];
		uint8_t seed_buf[4] = {0x44, 0, 0, 0};
		uint8_t seed_hash[32]; size_t hl = 0;
		psa_hash_compute(PSA_ALG_SHA_256, seed_buf, 4, seed_hash, 32, &hl);
		seed_hash[0] &= 248; seed_hash[31] &= 127; seed_hash[31] |= 64;
		memcpy(sk_x, seed_hash, 32);
		seed_buf[0] = 0x45;
		psa_hash_compute(PSA_ALG_SHA_256, seed_buf, 4, seed_hash, 32, &hl);
		seed_hash[0] &= 248; seed_hash[31] &= 127; seed_hash[31] |= 64;
		uint8_t peer_sk[32]; memcpy(peer_sk, seed_hash, 32);
		crypto_scalarmult_base(peer_pk, peer_sk);
		for (int i = 0; i < N; i++) {
			uint8_t ct[PQ_KEM_CT_LEN], ss[PQ_KEM_SS_LEN], shared[32];
			uint64_t t0 = bench_get_ns();
			crypto_scalarmult(shared, sk_x, peer_pk);
			pq_kem_encaps(ct, ss, pk_k);
			uint64_t t1 = bench_get_ns();
			samples[i] = ns_to_us(t1 - t0);
		}
	}
	bench_add("X25519+MLKEM-768", "Encaps", compute_stats(samples, N, 32 + PQ_KEM_CT_LEN));

	printf("  Benchmarking X25519+MLKEM-768 Decaps...\n");
	{
		uint8_t pk_k[PQ_KEM_PK_LEN], sk_k[PQ_KEM_SK_LEN];
		pq_kem_keygen(pk_k, sk_k);
		uint8_t ct[PQ_KEM_CT_LEN], ss[PQ_KEM_SS_LEN];
		pq_kem_encaps(ct, ss, pk_k);
		uint8_t sk_x[32], peer_pk[32];
		uint8_t seed_buf[4] = {0x46, 0, 0, 0};
		uint8_t seed_hash[32]; size_t hl = 0;
		psa_hash_compute(PSA_ALG_SHA_256, seed_buf, 4, seed_hash, 32, &hl);
		seed_hash[0] &= 248; seed_hash[31] &= 127; seed_hash[31] |= 64;
		memcpy(sk_x, seed_hash, 32);
		seed_buf[0] = 0x47;
		psa_hash_compute(PSA_ALG_SHA_256, seed_buf, 4, seed_hash, 32, &hl);
		seed_hash[0] &= 248; seed_hash[31] &= 127; seed_hash[31] |= 64;
		uint8_t peer_sk[32]; memcpy(peer_sk, seed_hash, 32);
		crypto_scalarmult_base(peer_pk, peer_sk);
		for (int i = 0; i < N; i++) {
			uint8_t ss2[PQ_KEM_SS_LEN], shared[32];
			uint64_t t0 = bench_get_ns();
			crypto_scalarmult(shared, sk_x, peer_pk);
			pq_kem_decaps(ss2, ct, sk_k);
			uint64_t t1 = bench_get_ns();
			samples[i] = ns_to_us(t1 - t0);
		}
	}
	bench_add("X25519+MLKEM-768", "Decaps", compute_stats(samples, N, 32 + PQ_KEM_SS_LEN));

	printf("  Benchmarking Ed25519 Signature...\n");
	{
		uint8_t pk[32], sk[64];
		crypto_sign_keypair(pk, sk);
		uint8_t msg[64]; memset(msg, 0xAB, sizeof(msg));
		for (int i = 0; i < N; i++) {
			uint8_t sig[64];
			uint64_t t0 = bench_get_ns();
			crypto_sign_detached(sig, NULL, msg, sizeof(msg), sk);
			uint64_t t1 = bench_get_ns();
			samples[i] = ns_to_us(t1 - t0);
		}
	}
	bench_add("Ed25519", "Signature", compute_stats(samples, N, 64));

	printf("  Benchmarking Ed25519 Verify...\n");
	{
		uint8_t pk[32], sk[64];
		crypto_sign_keypair(pk, sk);
		uint8_t msg[64]; memset(msg, 0xAB, sizeof(msg));
		uint8_t sig[64];
		crypto_sign_detached(sig, NULL, msg, sizeof(msg), sk);
		for (int i = 0; i < N; i++) {
			uint64_t t0 = bench_get_ns();
			crypto_sign_verify_detached(sig, msg, sizeof(msg), pk);
			uint64_t t1 = bench_get_ns();
			samples[i] = ns_to_us(t1 - t0);
		}
	}
	bench_add("Ed25519", "Verify", compute_stats(samples, N, 32));

	printf("  Benchmarking ML-DSA-65 Signature...\n");
	{
		uint8_t pk[PQ_SIG_PK_LEN], sk[PQ_SIG_SK_LEN];
		pq_sig_keygen(pk, sk);
		uint8_t msg[64]; memset(msg, 0xAB, sizeof(msg));
		for (int i = 0; i < N; i++) {
			uint8_t sig[PQ_SIG_MAX_LEN]; size_t sig_len = 0;
			uint64_t t0 = bench_get_ns();
			pq_sig_sign(msg, sizeof(msg), sk, sig, &sig_len);
			uint64_t t1 = bench_get_ns();
			samples[i] = ns_to_us(t1 - t0);
		}
	}
	bench_add("ML-DSA-65", "Signature", compute_stats(samples, N, PQ_SIG_MAX_LEN));

	printf("  Benchmarking ML-DSA-65 Verify...\n");
	{
		uint8_t pk[PQ_SIG_PK_LEN], sk[PQ_SIG_SK_LEN];
		pq_sig_keygen(pk, sk);
		uint8_t msg[64]; memset(msg, 0xAB, sizeof(msg));
		uint8_t sig[PQ_SIG_MAX_LEN]; size_t sig_len = 0;
		pq_sig_sign(msg, sizeof(msg), sk, sig, &sig_len);
		for (int i = 0; i < N; i++) {
			uint64_t t0 = bench_get_ns();
			pq_sig_verify(msg, sizeof(msg), sig, sig_len, pk);
			uint64_t t1 = bench_get_ns();
			samples[i] = ns_to_us(t1 - t0);
		}
	}
	bench_add("ML-DSA-65", "Verify", compute_stats(samples, N, PQ_SIG_PK_LEN));

	printf("  Benchmarking SHA-256...\n");
	{
		uint8_t msg[256], hash[32]; memset(msg, 0xCD, sizeof(msg));
		for (int i = 0; i < N; i++) {
			uint64_t t0 = bench_get_ns();
			crypto_hash_sha256(hash, msg, sizeof(msg));
			uint64_t t1 = bench_get_ns();
			samples[i] = ns_to_us(t1 - t0);
		}
	}
	bench_add("SHA-256", "HASH", compute_stats(samples, N, 32));

	printf("  Benchmarking HKDF-Extract...\n");
	{
		uint8_t salt[32], ikm[32], prk[32];
		memset(salt, 0x11, 32); memset(ikm, 0x22, 32);
		for (int i = 0; i < N; i++) {
			uint64_t t0 = bench_get_ns();
			crypto_auth_hmacsha256(prk, ikm, 32, salt);
			uint64_t t1 = bench_get_ns();
			samples[i] = ns_to_us(t1 - t0);
		}
	}
	bench_add("HKDF", "HKDF-EXTRACT", compute_stats(samples, N, 32));

	printf("  Benchmarking HKDF-Expand...\n");
	{
		uint8_t prk[32], info[32], okm[32];
		memset(prk, 0x33, 32); memset(info, 0x44, 32);
		for (int i = 0; i < N; i++) {
			uint64_t t0 = bench_get_ns();
			uint8_t tmp[33]; memcpy(tmp, info, 32); tmp[32] = 0x01;
			crypto_auth_hmacsha256(okm, tmp, 33, prk);
			uint64_t t1 = bench_get_ns();
			samples[i] = ns_to_us(t1 - t0);
		}
	}
	bench_add("HKDF", "HKDF-EXPANDS", compute_stats(samples, N, 32));

	printf("  Benchmarking AES-GCM Encrypt...\n");
	{
		uint8_t key[16], nonce[12], pt[64], ct[64 + 16], tag[16];
		memset(key, 0x55, 16); memset(nonce, 0x66, 12); memset(pt, 0x77, 64);
		mbedtls_gcm_context gcm;
		mbedtls_gcm_init(&gcm);
		mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 128);
		for (int i = 0; i < N; i++) {
			uint64_t t0 = bench_get_ns();
			mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, 64,
			                          nonce, 12, NULL, 0, pt, ct, 16, tag);
			uint64_t t1 = bench_get_ns();
			samples[i] = ns_to_us(t1 - t0);
		}
		mbedtls_gcm_free(&gcm);
	}
	bench_add("AES-GCM", "AEAD_ENCRYPT", compute_stats(samples, N, 16));

	printf("  Benchmarking AES-GCM Decrypt...\n");
	{
		uint8_t key[16], nonce[12], pt[64], ct[64], tag[16], pt2[64];
		memset(key, 0x55, 16); memset(nonce, 0x66, 12); memset(pt, 0x77, 64);
		mbedtls_gcm_context gcm;
		mbedtls_gcm_init(&gcm);
		mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 128);
		mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, 64,
		                          nonce, 12, NULL, 0, pt, ct, 16, tag);
		for (int i = 0; i < N; i++) {
			uint64_t t0 = bench_get_ns();
			mbedtls_gcm_auth_decrypt(&gcm, 64, nonce, 12, NULL, 0,
			                         tag, 16, ct, pt2);
			uint64_t t1 = bench_get_ns();
			samples[i] = ns_to_us(t1 - t0);
		}
		mbedtls_gcm_free(&gcm);
	}
	bench_add("AES-GCM", "AEAD_DECRYPT", compute_stats(samples, N, 16));

	free(samples);
	printf("  Crypto benchmarks complete (%d operations).\n", g_crypto_count);
}

/* =============================================================================
 * Phase 2: P2P Handshakes (event loop)
 * Returns 1 if phase-switch to EAP was received, 0 if 0xFF (all done).
 * =============================================================================
 */
static int run_p2p_handshakes(int sockfd)
{
	memset(g_hs_ops, 0, sizeof(g_hs_ops));
	memset(g_hs_timing, 0, sizeof(g_hs_timing));
	memset(g_hs_overhead, 0, sizeof(g_hs_overhead));

	int (*handlers[])(int, int) = {
		[VARIANT_TYPE0_CLASSIC] = handshake_type0_classic_responder,
		[VARIANT_TYPE0_PQ]      = handshake_type0_pq_responder,
		[VARIANT_TYPE3_CLASSIC] = handshake_type3_classic_responder,
		[VARIANT_TYPE3_PQ]      = handshake_type3_pq_responder,
		[VARIANT_TYPE3_HYBRID]  = handshake_type3_hybrid_responder,
	};

	while (1) {
		uint8_t type, buf[16]; uint32_t len;
		if (p2p_recv_msg(sockfd, &type, buf, &len, sizeof(buf)) != 0) break;
		if (type != P2P_MSG_TYPE_SYNC) break;

		int variant_id = buf[0];

		/* Phase switch: P2P done, EAP phase next */
		if (variant_id == PHASE_SWITCH_SIGNAL) {
			printf("  P2P phase complete. Switching to EAP...\n");
			p2p_send_msg(sockfd, P2P_MSG_TYPE_SYNC_ACK, NULL, 0);
			return 1;
		}

		/* All done (no EAP phase) */
		if (variant_id == 0xFF) {
			printf("  All variants complete.\n");
			return 0;
		}

		if (variant_id < 0 || variant_id >= NUM_VARIANTS) {
			fprintf(stderr, "  ERROR: unknown variant %d\n", variant_id);
			continue;
		}

		printf("  [P2P %d/5] %s (Responder)...\n", variant_id + 1,
		       VARIANT_NAMES[variant_id]);

		if (p2p_send_msg(sockfd, P2P_MSG_TYPE_SYNC_ACK, NULL, 0) != 0) break;

		stack_paint();
		if (handlers[variant_id](sockfd, variant_id) != 0) {
			fprintf(stderr, "  ERROR: handshake failed for %s\n",
			        VARIANT_NAMES[variant_id]);
		} else {
			printf("    → avg total: %.2f us, txrx: %.2f us\n",
			       g_hs_timing[variant_id].total_us,
			       g_hs_timing[variant_id].txrx_us);
		}
		{
			long scanned = stack_scan();
			if (scanned > 0)
				g_hs_overhead[variant_id].memory_bytes = scanned;
		}
	}

	return 0;
}

/* =============================================================================
 * Phase 3: EAP-EDHOC Handshakes (event loop)
 * =============================================================================
 */
static void run_eap_handshakes(int sockfd)
{
	int (*handlers[])(int, int) = {
		[VARIANT_TYPE0_CLASSIC] = eap_handshake_type0_classic_responder,
		[VARIANT_TYPE0_PQ]      = eap_handshake_type0_pq_responder,
		[VARIANT_TYPE3_CLASSIC] = eap_handshake_type3_classic_responder,
		[VARIANT_TYPE3_PQ]      = eap_handshake_type3_pq_responder,
		[VARIANT_TYPE3_HYBRID]  = eap_handshake_type3_hybrid_responder,
	};

	while (1) {
		uint8_t type, buf[16]; uint32_t len;
		if (p2p_recv_msg(sockfd, &type, buf, &len, sizeof(buf)) != 0) break;
		if (type != P2P_MSG_TYPE_SYNC) break;

		int variant_id = buf[0];
		if (variant_id == 0xFF) {
			printf("  All EAP variants complete.\n");
			break;
		}

		if (variant_id < 0 || variant_id >= NUM_VARIANTS) {
			fprintf(stderr, "  ERROR: unknown variant %d\n", variant_id);
			continue;
		}

		printf("  [EAP %d/5] %s (Responder)...\n", variant_id + 1,
		       VARIANT_NAMES[variant_id]);

		if (p2p_send_msg(sockfd, P2P_MSG_TYPE_SYNC_ACK, NULL, 0) != 0) break;

		stack_paint();
		if (handlers[variant_id](sockfd, variant_id) != 0) {
			fprintf(stderr, "  ERROR: EAP handshake failed for %s\n",
			        VARIANT_NAMES[variant_id]);
		} else {
			printf("    → avg total: %.2f us, txrx: %.2f us\n",
			       g_hs_timing[variant_id].total_us,
			       g_hs_timing[variant_id].txrx_us);
		}
		{
			long scanned = stack_scan();
			if (scanned > 0)
				g_hs_overhead[variant_id].memory_bytes = scanned;
		}
	}

	printf("\n  === EAP Transport Stats (Responder) ===\n");
	print_eap_transport_summary(g_eap_transport);
}

/* =============================================================================
 * Phase 4: Write ALL CSV files
 * =============================================================================
 */
static void write_all_csv(void)
{
	/* ── Crypto CSV (same data for both P2P and EAP) ── */
	csv_write_crypto(OUTPUT_DIR "/benchmark_crypto_responder.csv",
	                 g_crypto_stats, g_crypto_alg_names, g_crypto_op_names,
	                 g_crypto_count);
	csv_write_crypto(OUTPUT_DIR "/benchmark_crypto_eap_responder.csv",
	                 g_crypto_stats, g_crypto_alg_names, g_crypto_op_names,
	                 g_crypto_count);

	/* ── P2P handshake CSVs (from saved results) ── */
	csv_write_handshake_ops(OUTPUT_DIR "/benchmark_fullhandshake_operation_p2p_responder.csv",
	                        "Responder", p2p_saved_ops, P2P_BENCH_HANDSHAKE_ITERATIONS);
	csv_write_overhead(OUTPUT_DIR "/benchmark_fullhandshake_overhead_p2p_responder.csv",
	                   "Responder", p2p_saved_overhead);
	csv_write_processing(OUTPUT_DIR "/benchmark_fullhandshake_processing_p2p_responder.csv",
	                     "Responder", p2p_saved_timing);

	/* ── EAP handshake CSVs (from current globals) ── */
	csv_write_handshake_ops(OUTPUT_DIR "/benchmark_fullhandshake_operation_eap_responder.csv",
	                        "Responder", g_hs_ops, P2P_BENCH_HANDSHAKE_ITERATIONS);
	csv_write_overhead(OUTPUT_DIR "/benchmark_fullhandshake_overhead_eap_responder.csv",
	                   "Responder", g_hs_overhead);
	csv_write_processing(OUTPUT_DIR "/benchmark_fullhandshake_processing_eap_responder.csv",
	                     "Responder", g_hs_timing);

	/* ── EAP transport CSV ── */
	csv_write_eap_transport(OUTPUT_DIR "/benchmark_eap_transport_responder.csv",
	                        g_eap_transport);

	printf("  Written 9 CSV files (P2P + EAP) for Responder.\n");
}
