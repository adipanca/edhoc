/*
 * =============================================================================
 * EDHOC-Hybrid: Unified Benchmark — Initiator
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
 *   ./build/initiator <server_ip> [port]
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
static int connect_to_server(const char *ip, int port);
static void run_crypto_benchmarks(void);
static void run_p2p_handshakes(int sockfd);
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
	if (argc < 2) {
		fprintf(stderr, "Usage: %s <server_ip> [port]\n", argv[0]);
		return 1;
	}

	const char *server_ip = argv[1];
	int port = (argc > 2) ? atoi(argv[2]) : P2P_DEFAULT_PORT;

	if (sodium_init() < 0) {
		fprintf(stderr, "ERROR: sodium_init() failed\n");
		return 1;
	}
	psa_crypto_init();

	printf("\n");
	printf("╔══════════════════════════════════════════════════════════════╗\n");
	printf("║    EDHOC Unified Benchmark — INITIATOR (P2P + EAP)           ║\n");
	printf("╚══════════════════════════════════════════════════════════════╝\n");
	printf("  Server: %s:%d\n", server_ip, port);
	printf("  Crypto iterations: %d\n", P2P_BENCH_CRYPTO_ITERATIONS);
	printf("  Handshake iterations: %d\n", P2P_BENCH_HANDSHAKE_ITERATIONS);
	printf("  EAP MTU: %d bytes/fragment\n", EAP_EDHOC_MTU);
	printf("\n");

	(void)!system("mkdir -p " OUTPUT_DIR);

	/* Phase 1: Pure crypto benchmarks (local, no network) */
	printf("═══ Phase 1: Pure Cryptographic Operations ═══\n\n");
	run_crypto_benchmarks();

	/* Connect to server (single TCP connection for both phases) */
	int sockfd = connect_to_server(server_ip, port);
	if (sockfd < 0) {
		fprintf(stderr, "ERROR: cannot connect to server %s:%d\n",
		        server_ip, port);
		return 1;
	}
	printf("  Connected to server.\n\n");

	/* Phase 2: P2P handshake benchmarks */
	printf("═══ Phase 2: Full Handshake Benchmarks (P2P) ═══\n\n");
	run_p2p_handshakes(sockfd);

	/* Save P2P results */
	memcpy(p2p_saved_ops, g_hs_ops, sizeof(g_hs_ops));
	memcpy(p2p_saved_timing, g_hs_timing, sizeof(g_hs_timing));
	memcpy(p2p_saved_overhead, g_hs_overhead, sizeof(g_hs_overhead));

	/* Phase 3: EAP-EDHOC handshake benchmarks (same TCP connection) */
	printf("\n═══ Phase 3: Full Handshake Benchmarks (EAP-EDHOC) ═══\n\n");
	memset(g_hs_ops, 0, sizeof(g_hs_ops));
	memset(g_hs_timing, 0, sizeof(g_hs_timing));
	memset(g_hs_overhead, 0, sizeof(g_hs_overhead));
	memset(g_eap_transport, 0, sizeof(g_eap_transport));
	run_eap_handshakes(sockfd);

	close(sockfd);

	/* Phase 4: Write ALL CSV files */
	printf("\n═══ Phase 4: Writing CSV Output ═══\n\n");
	write_all_csv();

	printf("\n  Unified benchmark complete (P2P + EAP).\n\n");
	return 0;
}

/* =============================================================================
 * TCP Connection
 * =============================================================================
 */
static int connect_to_server(const char *ip, int port)
{
	int sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0) return -1;

	int flag = 1;
	setsockopt(sockfd, IPPROTO_TCP, 1 /* TCP_NODELAY */, &flag, sizeof(flag));

	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	if (inet_pton(AF_INET, ip, &addr.sin_addr) <= 0) {
		close(sockfd);
		return -1;
	}

	if (connect(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		close(sockfd);
		return -1;
	}

	return sockfd;
}

/* =============================================================================
 * Phase 1: Pure Crypto Benchmarks
 * =============================================================================
 */

static void bench_add(const char *alg, const char *op,
                      struct crypto_bench_stats s)
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
 * Sync with responder before each variant
 * =============================================================================
 */
static int sync_variant(int sockfd, int variant_id)
{
	uint8_t payload[1] = { (uint8_t)variant_id };
	if (p2p_send_msg(sockfd, P2P_MSG_TYPE_SYNC, payload, 1) != 0) return -1;
	uint8_t type, buf[16]; uint32_t len;
	if (p2p_recv_msg(sockfd, &type, buf, &len, sizeof(buf)) != 0) return -1;
	if (type != P2P_MSG_TYPE_SYNC_ACK) return -1;
	return 0;
}

/* =============================================================================
 * Phase 2: P2P Handshakes
 * =============================================================================
 */
static void run_p2p_handshakes(int sockfd)
{
	memset(g_hs_ops, 0, sizeof(g_hs_ops));
	memset(g_hs_timing, 0, sizeof(g_hs_timing));
	memset(g_hs_overhead, 0, sizeof(g_hs_overhead));

	struct {
		int variant;
		const char *name;
		int (*func)(int, int);
	} variants[] = {
		{ VARIANT_TYPE0_CLASSIC, "Type 0 Classic",  handshake_type0_classic_initiator },
		{ VARIANT_TYPE0_PQ,      "Type 0 PQ",       handshake_type0_pq_initiator      },
		{ VARIANT_TYPE3_CLASSIC, "Type 3 Classic",   handshake_type3_classic_initiator  },
		{ VARIANT_TYPE3_PQ,      "Type 3 PQ",        handshake_type3_pq_initiator       },
		{ VARIANT_TYPE3_HYBRID,  "Type 3 Hybrid",    handshake_type3_hybrid_initiator   },
	};

	for (int i = 0; i < 5; i++) {
		printf("  [P2P %d/5] %s (Initiator)...\n", i + 1, variants[i].name);

		if (sync_variant(sockfd, variants[i].variant) != 0) {
			fprintf(stderr, "  ERROR: sync failed for %s\n", variants[i].name);
			continue;
		}

		stack_paint();
		if (variants[i].func(sockfd, variants[i].variant) != 0) {
			fprintf(stderr, "  ERROR: handshake failed for %s\n", variants[i].name);
		} else {
			printf("    → avg total: %.2f us, txrx: %.2f us\n",
			       g_hs_timing[variants[i].variant].total_us,
			       g_hs_timing[variants[i].variant].txrx_us);
		}
		{
			long scanned = stack_scan();
			if (scanned > 0)
				g_hs_overhead[variants[i].variant].memory_bytes = scanned;
		}
	}

	/* Signal end of P2P phase (0xFE = phase switch to EAP) */
	if (sync_variant(sockfd, PHASE_SWITCH_SIGNAL) != 0) {
		fprintf(stderr, "  WARNING: phase switch sync failed\n");
	}
	printf("  P2P phase complete.\n");
}

/* =============================================================================
 * Phase 3: EAP-EDHOC Handshakes
 * =============================================================================
 */
static void run_eap_handshakes(int sockfd)
{
	struct {
		int variant;
		const char *name;
		int (*func)(int, int);
	} variants[] = {
		{ VARIANT_TYPE0_CLASSIC, "Type 0 Classic (EAP)",  eap_handshake_type0_classic_initiator },
		{ VARIANT_TYPE0_PQ,      "Type 0 PQ (EAP)",       eap_handshake_type0_pq_initiator      },
		{ VARIANT_TYPE3_CLASSIC, "Type 3 Classic (EAP)",  eap_handshake_type3_classic_initiator },
		{ VARIANT_TYPE3_PQ,      "Type 3 PQ (EAP)",       eap_handshake_type3_pq_initiator      },
		{ VARIANT_TYPE3_HYBRID,  "Type 3 Hybrid (EAP)",   eap_handshake_type3_hybrid_initiator  },
	};

	for (int i = 0; i < 5; i++) {
		printf("  [EAP %d/5] %s (Initiator)...\n", i + 1, variants[i].name);

		if (sync_variant(sockfd, variants[i].variant) != 0) {
			fprintf(stderr, "  ERROR: sync failed for %s\n", variants[i].name);
			continue;
		}

		stack_paint();
		if (variants[i].func(sockfd, variants[i].variant) != 0) {
			fprintf(stderr, "  ERROR: EAP handshake failed for %s\n", variants[i].name);
		} else {
			printf("    → avg total: %.2f us, txrx: %.2f us\n",
			       g_hs_timing[variants[i].variant].total_us,
			       g_hs_timing[variants[i].variant].txrx_us);
		}
		{
			long scanned = stack_scan();
			if (scanned > 0)
				g_hs_overhead[variants[i].variant].memory_bytes = scanned;
		}
	}

	/* Signal end of all benchmarks (0xFF) */
	uint8_t end_payload[1] = { 0xFF };
	p2p_send_msg(sockfd, P2P_MSG_TYPE_SYNC, end_payload, 1);

	printf("\n  === EAP Transport Stats (Initiator) ===\n");
	print_eap_transport_summary(g_eap_transport);
	printf("  EAP phase complete.\n");
}

/* =============================================================================
 * Phase 4: Write ALL CSV files
 * =============================================================================
 */
static void write_all_csv(void)
{
	/* ── P2P crypto CSV (same data as EAP — crypto ops are identical) ── */
	csv_write_crypto(OUTPUT_DIR "/benchmark_crypto_initiator.csv",
	                 g_crypto_stats, g_crypto_alg_names, g_crypto_op_names,
	                 g_crypto_count);
	csv_write_crypto(OUTPUT_DIR "/benchmark_crypto_eap_initiator.csv",
	                 g_crypto_stats, g_crypto_alg_names, g_crypto_op_names,
	                 g_crypto_count);

	/* ── P2P handshake CSVs (from saved results) ── */
	csv_write_handshake_ops(OUTPUT_DIR "/benchmark_fullhandshake_operation_p2p_initiator.csv",
	                        "Initiator", p2p_saved_ops, P2P_BENCH_HANDSHAKE_ITERATIONS);
	csv_write_overhead(OUTPUT_DIR "/benchmark_fullhandshake_overhead_p2p_initiator.csv",
	                   "Initiator", p2p_saved_overhead);
	csv_write_processing(OUTPUT_DIR "/benchmark_fullhandshake_processing_p2p_initiator.csv",
	                     "Initiator", p2p_saved_timing);

	/* ── EAP handshake CSVs (from current globals) ── */
	csv_write_handshake_ops(OUTPUT_DIR "/benchmark_fullhandshake_operation_eap_initiator.csv",
	                        "Initiator", g_hs_ops, P2P_BENCH_HANDSHAKE_ITERATIONS);
	csv_write_overhead(OUTPUT_DIR "/benchmark_fullhandshake_overhead_eap_initiator.csv",
	                   "Initiator", g_hs_overhead);
	csv_write_processing(OUTPUT_DIR "/benchmark_fullhandshake_processing_eap_initiator.csv",
	                     "Initiator", g_hs_timing);

	/* ── EAP transport CSV ── */
	csv_write_eap_transport(OUTPUT_DIR "/benchmark_eap_transport_initiator.csv",
	                        g_eap_transport);

	printf("  Written 9 CSV files (P2P + EAP) for Initiator.\n");
}
