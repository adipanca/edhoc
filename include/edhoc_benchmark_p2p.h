/*
 * =============================================================================
 * EDHOC-Hybrid: P2P Benchmark Header
 * =============================================================================
 */

#ifndef EDHOC_BENCHMARK_P2P_H
#define EDHOC_BENCHMARK_P2P_H

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 199309L
#endif

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>

/* ── Configuration ── */
#define P2P_BENCH_CRYPTO_ITERATIONS      1000
#define P2P_BENCH_HANDSHAKE_ITERATIONS   100
#define P2P_DEFAULT_PORT                 19500
#define P2P_MSG_BUF_SIZE                 16384

/* ── Protocol message framing ── */
#define P2P_MSG_TYPE_HANDSHAKE_START     0x01
#define P2P_MSG_TYPE_MSG1                0x10
#define P2P_MSG_TYPE_MSG2                0x11
#define P2P_MSG_TYPE_MSG3                0x12
#define P2P_MSG_TYPE_MSG4                0x13
#define P2P_MSG_TYPE_MSG5                0x14
#define P2P_MSG_TYPE_DONE                0x20
#define P2P_MSG_TYPE_SYNC                0x30
#define P2P_MSG_TYPE_SYNC_ACK           0x31

/* ── Variant IDs ── */
#define VARIANT_TYPE0_CLASSIC   0
#define VARIANT_TYPE0_PQ        1
#define VARIANT_TYPE3_CLASSIC   2
#define VARIANT_TYPE3_PQ        3
#define VARIANT_TYPE3_HYBRID    4
#define NUM_VARIANTS            5

static const char *VARIANT_NAMES[] = {
	"Type0_classic",
	"Type0_PQ",
	"Type3_Classic",
	"Type3_PQ",
	"Type3_Hybrid"
};

/* ── Crypto operation IDs ── */
#define OP_KEYGEN          0
#define OP_SCALAR_MULT     1
#define OP_ENCAPS          2
#define OP_DECAPS          3
#define OP_HKDF_EXTRACT    4
#define OP_HKDF_EXPAND     5
#define OP_HASH            6
#define OP_AEAD_ENCRYPT    7
#define OP_AEAD_DECRYPT    8
#define OP_SIGNATURE       9
#define OP_VERIFY          10
#define NUM_OPS            11

static const char *OP_NAMES[] = {
	"KeyGen", "Scalar multiplication", "Encaps", "Decaps",
	"HKDF-EXTRACT", "HKDF-EXPANDS", "HASH",
	"AEAD_ENCRYPT", "AEAD_DECRYPT", "Signature", "Verify"
};

/* ── Timing utilities ── */
static inline uint64_t bench_get_ns(void) {
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}
static inline double ns_to_us(uint64_t ns) { return (double)ns / 1000.0; }

/* ── Structures ── */
struct crypto_bench_stats {
	double avg_us, stddev_us, min_us, max_us, median_us;
	int iterations, key_length;
};
struct op_accumulator { uint64_t total_ns; int call_count; };
struct handshake_op_stats { struct op_accumulator ops[NUM_OPS]; };
struct handshake_timing {
	double processing_us, txrx_us, precomputation_us, overhead_us, total_us;
};
struct overhead_stats {
	double cpu_time_us, cpu_usage_pct; long memory_bytes; double memory_us;
};

/* ── Timing macros ── */
#define HS_TIME_START() uint64_t _hs_t0 = bench_get_ns()
#define HS_TIME_END(variant, op) do { \
	uint64_t _hs_t1 = bench_get_ns(); \
	g_hs_ops[variant].ops[op].total_ns += (_hs_t1 - _hs_t0); \
	g_hs_ops[variant].ops[op].call_count++; \
} while(0)

/* ── Extern globals (defined in main initiator/responder files) ── */
extern struct handshake_op_stats g_hs_ops[];
extern struct handshake_timing g_hs_timing[];
extern struct overhead_stats g_hs_overhead[];

/* ── Helper: compute stats ── */
static inline int compare_double(const void *a, const void *b) {
	double da = *(const double *)a, db = *(const double *)b;
	return (da < db) ? -1 : (da > db) ? 1 : 0;
}
static inline struct crypto_bench_stats compute_stats(double *samples, int n, int key_len) {
	struct crypto_bench_stats s;
	s.iterations = n; s.key_length = key_len;
	s.min_us = 1e18; s.max_us = 0;
	double sum = 0;
	for (int i = 0; i < n; i++) {
		sum += samples[i];
		if (samples[i] < s.min_us) s.min_us = samples[i];
		if (samples[i] > s.max_us) s.max_us = samples[i];
	}
	s.avg_us = sum / n;
	double var = 0;
	for (int i = 0; i < n; i++) { double d = samples[i] - s.avg_us; var += d * d; }
	s.stddev_us = sqrt(var / n);
	qsort(samples, n, sizeof(double), compare_double);
	s.median_us = (n % 2 == 0) ? (samples[n/2-1] + samples[n/2]) / 2.0 : samples[n/2];
	return s;
}

/* ── TCP helpers ── */
int p2p_send_msg(int sockfd, uint8_t type, const uint8_t *data, uint32_t len);
int p2p_recv_msg(int sockfd, uint8_t *type_out, uint8_t *buf, uint32_t *len_out, uint32_t buf_size);

/* ── CSV output ── */
void csv_write_crypto(const char *filename, struct crypto_bench_stats stats[],
                      const char *alg_names[], const char *op_names_arr[], int count);
void csv_write_handshake_ops(const char *filename, const char *role,
                             struct handshake_op_stats variant_stats[], int iterations);
void csv_write_overhead(const char *filename, const char *role, struct overhead_stats ostats[]);
void csv_write_processing(const char *filename, const char *role, struct handshake_timing timings[]);
long get_memory_usage_bytes(void);

/* ── Timing/overhead finalization (called at end of each variant function) ── */
#include <sys/resource.h>
void finalize_variant_stats(int variant, int N,
                            double total_wall_us, double total_txrx_us,
                            double total_precomp_us,
                            uint64_t wall_all_start, uint64_t wall_all_end,
                            const struct rusage *ru_start, const struct rusage *ru_end,
                            long mem_before, long mem_peak);

/* ── Stack painting for peak stack usage measurement ── */
void stack_paint(void);
long stack_scan(void);

/* ── Shared crypto helpers ── */
void edhoc_kdf(const uint8_t *prk, uint8_t label,
               const uint8_t *context, size_t ctx_len,
               uint8_t *out, size_t out_len);
int derive_key_iv(const uint8_t *prk, const uint8_t *label, size_t label_len,
                  uint8_t *key, uint8_t *iv);

/* ── Label constants ── */
extern const uint8_t INFO_K1[], INFO_IV1[], INFO_K2[], INFO_IV2[];
extern const uint8_t INFO_K3[], INFO_IV3[], INFO_K4[], INFO_IV4[];
extern const uint8_t INFO_K5[], INFO_IV5[];
extern const uint8_t INFO_MAC2[], INFO_MAC3[], INFO_OUT[];
extern const uint8_t LBL_ID_CRED_I[], LBL_ID_CRED_R[];
extern const size_t INFO_K1_LEN, INFO_K2_LEN, INFO_K3_LEN, INFO_K4_LEN, INFO_K5_LEN;
extern const size_t LBL_ID_CRED_I_LEN, LBL_ID_CRED_R_LEN;

/* ── Variant handshake functions ── */
int handshake_type0_classic_initiator(int sockfd, int variant);
int handshake_type0_classic_responder(int sockfd, int variant);
int handshake_type0_pq_initiator(int sockfd, int variant);
int handshake_type0_pq_responder(int sockfd, int variant);
int handshake_type3_classic_initiator(int sockfd, int variant);
int handshake_type3_classic_responder(int sockfd, int variant);
int handshake_type3_pq_initiator(int sockfd, int variant);
int handshake_type3_pq_responder(int sockfd, int variant);
int handshake_type3_hybrid_initiator(int sockfd, int variant);
int handshake_type3_hybrid_responder(int sockfd, int variant);

#endif /* EDHOC_BENCHMARK_P2P_H */
