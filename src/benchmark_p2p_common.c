/*
 * EDHOC-Hybrid: P2P Benchmark Common Utilities
 * TCP framing, CSV writing, memory measurement, shared crypto helpers.
 */

#include "edhoc_benchmark_p2p.h"
#include "edhoc_pq_kem.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/resource.h>
#include <arpa/inet.h>
#include <sodium.h>

/* ── Label constants ── */
const uint8_t INFO_K1[]  = "EDHOC-PQ-K1";
const uint8_t INFO_IV1[] = "EDHOC-PQ-IV1";
const uint8_t INFO_K2[]  = "EDHOC-PQ-K2";
const uint8_t INFO_IV2[] = "EDHOC-PQ-IV2";
const uint8_t INFO_K3[]  = "EDHOC-PQ-K3";
const uint8_t INFO_IV3[] = "EDHOC-PQ-IV3";
const uint8_t INFO_K4[]  = "EDHOC-PQ-K4";
const uint8_t INFO_IV4[] = "EDHOC-PQ-IV4";
const uint8_t INFO_K5[]  = "EDHOC-PQ-K5";
const uint8_t INFO_IV5[] = "EDHOC-PQ-IV5";
const uint8_t INFO_MAC2[]= "EDHOC-PQ-MAC2";
const uint8_t INFO_MAC3[]= "EDHOC-PQ-MAC3";
const uint8_t INFO_OUT[] = "EDHOC-PQ-PRK_out";
const uint8_t LBL_ID_CRED_I[]= "EDHOC-PQ-Initiator";
const uint8_t LBL_ID_CRED_R[]= "EDHOC-PQ-Responder";

const size_t INFO_K1_LEN = sizeof("EDHOC-PQ-K1") - 1;
const size_t INFO_K2_LEN = sizeof("EDHOC-PQ-K2") - 1;
const size_t INFO_K3_LEN = sizeof("EDHOC-PQ-K3") - 1;
const size_t INFO_K4_LEN = sizeof("EDHOC-PQ-K4") - 1;
const size_t INFO_K5_LEN = sizeof("EDHOC-PQ-K5") - 1;
const size_t LBL_ID_CRED_I_LEN = sizeof("EDHOC-PQ-Initiator") - 1;
const size_t LBL_ID_CRED_R_LEN = sizeof("EDHOC-PQ-Responder") - 1;

/* ── Shared crypto helpers ── */

void edhoc_kdf(const uint8_t *prk, uint8_t label,
               const uint8_t *context, size_t ctx_len,
               uint8_t *out, size_t out_len)
{
	uint8_t info[256];
	size_t info_len = 0;
	info[info_len++] = label;
	if (ctx_len > 0 && context != NULL) {
		memcpy(info + info_len, context, ctx_len);
		info_len += ctx_len;
	}

	uint8_t t[32];
	size_t done = 0;
	uint8_t counter = 1;

	while (done < out_len) {
		uint8_t msg[32 + 256 + 1];
		size_t msg_len = 0;
		if (counter > 1) { memcpy(msg, t, 32); msg_len = 32; }
		memcpy(msg + msg_len, info, info_len); msg_len += info_len;
		msg[msg_len++] = counter;
		crypto_auth_hmacsha256(t, msg, msg_len, prk);
		size_t copy = (out_len - done < 32) ? out_len - done : 32;
		memcpy(out + done, t, copy);
		done += copy;
		counter++;
	}
}

int derive_key_iv(const uint8_t *prk, const uint8_t *label, size_t label_len,
                  uint8_t *key, uint8_t *iv)
{
	uint8_t info[64];
	memcpy(info, label, label_len);
	if (pq_hkdf_expand(prk, info, label_len, key, PQ_AEAD_KEY_LEN) != 0) return -1;
	info[0] ^= 0xFF;
	if (pq_hkdf_expand(prk, info, label_len, iv, PQ_AEAD_NONCE_LEN) != 0) return -1;
	return 0;
}

/* ── TCP Framed Message Send/Receive ── */

static int send_all(int sockfd, const uint8_t *buf, size_t len)
{
	size_t sent = 0;
	while (sent < len) {
		ssize_t n = send(sockfd, buf + sent, len - sent, 0);
		if (n <= 0) {
			if (n < 0 && errno == EINTR) continue;
			return -1;
		}
		sent += (size_t)n;
	}
	return 0;
}

static int recv_all(int sockfd, uint8_t *buf, size_t len)
{
	size_t got = 0;
	while (got < len) {
		ssize_t n = recv(sockfd, buf + got, len - got, 0);
		if (n <= 0) {
			if (n < 0 && errno == EINTR) continue;
			return -1;
		}
		got += (size_t)n;
	}
	return 0;
}

int p2p_send_msg(int sockfd, uint8_t type, const uint8_t *data, uint32_t len)
{
	uint8_t hdr[5];
	hdr[0] = type;
	hdr[1] = (uint8_t)(len >> 24);
	hdr[2] = (uint8_t)(len >> 16);
	hdr[3] = (uint8_t)(len >> 8);
	hdr[4] = (uint8_t)(len);
	if (send_all(sockfd, hdr, 5) != 0) return -1;
	if (len > 0 && data != NULL) {
		if (send_all(sockfd, data, len) != 0) return -1;
	}
	return 0;
}

int p2p_recv_msg(int sockfd, uint8_t *type_out, uint8_t *buf,
                 uint32_t *len_out, uint32_t buf_size)
{
	uint8_t hdr[5];
	if (recv_all(sockfd, hdr, 5) != 0) return -1;
	*type_out = hdr[0];
	uint32_t plen = ((uint32_t)hdr[1] << 24) | ((uint32_t)hdr[2] << 16) |
	                ((uint32_t)hdr[3] << 8)  | ((uint32_t)hdr[4]);
	if (plen > buf_size) return -1;
	*len_out = plen;
	if (plen > 0) {
		if (recv_all(sockfd, buf, plen) != 0) return -1;
	}
	return 0;
}

/* ── CSV Output ── */

void csv_write_crypto(const char *filename,
                      struct crypto_bench_stats stats[], const char *alg_names[],
                      const char *op_names_arr[], int count)
{
	FILE *fp = fopen(filename, "w");
	if (!fp) { fprintf(stderr, "ERROR: cannot open %s\n", filename); return; }
	fprintf(fp, "algorithm,operation,avg_us,stddev_us,min_us,max_us,median_us,iterations,key_length\n");
	for (int i = 0; i < count; i++) {
		fprintf(fp, "%s,%s,%.2f,%.2f,%.2f,%.2f,%.2f,%d,%d\n",
		        alg_names[i], op_names_arr[i],
		        stats[i].avg_us, stats[i].stddev_us,
		        stats[i].min_us, stats[i].max_us,
		        stats[i].median_us, stats[i].iterations, stats[i].key_length);
	}
	fclose(fp);
	printf("  [CSV] Written: %s\n", filename);
}

void csv_write_handshake_ops(const char *filename, const char *role,
                             struct handshake_op_stats variant_stats[],
                             int iterations)
{
	FILE *fp = fopen(filename, "w");
	if (!fp) { fprintf(stderr, "ERROR: cannot open %s\n", filename); return; }
	fprintf(fp, "type,role,operation,avg_time_us,calls_per_handshake,total_per_handshake_us,iterations\n");
	for (int v = 0; v < NUM_VARIANTS; v++) {
		int relevant_ops[NUM_OPS]; int n_ops = 0;
		switch (v) {
		case VARIANT_TYPE0_CLASSIC:
			relevant_ops[n_ops++] = OP_KEYGEN;
			relevant_ops[n_ops++] = OP_SCALAR_MULT;
			relevant_ops[n_ops++] = OP_HKDF_EXTRACT;
			relevant_ops[n_ops++] = OP_HKDF_EXPAND;
			relevant_ops[n_ops++] = OP_HASH;
			relevant_ops[n_ops++] = OP_AEAD_ENCRYPT;
			relevant_ops[n_ops++] = OP_AEAD_DECRYPT;
			relevant_ops[n_ops++] = OP_SIGNATURE;
			relevant_ops[n_ops++] = OP_VERIFY;
			break;
		case VARIANT_TYPE0_PQ:
			relevant_ops[n_ops++] = OP_KEYGEN;
			relevant_ops[n_ops++] = OP_ENCAPS;
			relevant_ops[n_ops++] = OP_DECAPS;
			relevant_ops[n_ops++] = OP_HKDF_EXTRACT;
			relevant_ops[n_ops++] = OP_HKDF_EXPAND;
			relevant_ops[n_ops++] = OP_HASH;
			relevant_ops[n_ops++] = OP_AEAD_ENCRYPT;
			relevant_ops[n_ops++] = OP_AEAD_DECRYPT;
			relevant_ops[n_ops++] = OP_SIGNATURE;
			relevant_ops[n_ops++] = OP_VERIFY;
			break;
		case VARIANT_TYPE3_CLASSIC:
			relevant_ops[n_ops++] = OP_KEYGEN;
			relevant_ops[n_ops++] = OP_SCALAR_MULT;
			relevant_ops[n_ops++] = OP_HKDF_EXTRACT;
			relevant_ops[n_ops++] = OP_HKDF_EXPAND;
			relevant_ops[n_ops++] = OP_HASH;
			relevant_ops[n_ops++] = OP_AEAD_ENCRYPT;
			relevant_ops[n_ops++] = OP_AEAD_DECRYPT;
			break;
		case VARIANT_TYPE3_PQ:
			relevant_ops[n_ops++] = OP_KEYGEN;
			relevant_ops[n_ops++] = OP_ENCAPS;
			relevant_ops[n_ops++] = OP_DECAPS;
			relevant_ops[n_ops++] = OP_HKDF_EXTRACT;
			relevant_ops[n_ops++] = OP_HKDF_EXPAND;
			relevant_ops[n_ops++] = OP_HASH;
			relevant_ops[n_ops++] = OP_AEAD_ENCRYPT;
			relevant_ops[n_ops++] = OP_AEAD_DECRYPT;
			break;
		case VARIANT_TYPE3_HYBRID:
			relevant_ops[n_ops++] = OP_KEYGEN;
			relevant_ops[n_ops++] = OP_ENCAPS;
			relevant_ops[n_ops++] = OP_DECAPS;
			relevant_ops[n_ops++] = OP_HKDF_EXTRACT;
			relevant_ops[n_ops++] = OP_HKDF_EXPAND;
			relevant_ops[n_ops++] = OP_HASH;
			relevant_ops[n_ops++] = OP_AEAD_ENCRYPT;
			relevant_ops[n_ops++] = OP_AEAD_DECRYPT;
			break;
		}
		for (int i = 0; i < n_ops; i++) {
			int op = relevant_ops[i];
			struct op_accumulator *a = &variant_stats[v].ops[op];
			double avg = (a->call_count > 0)
			             ? ns_to_us(a->total_ns) / (double)iterations : 0.0;
			int calls = (iterations > 0)
			            ? (a->call_count + iterations - 1) / iterations : 0;
			fprintf(fp, "%s,%s,%s,%.2f,%d,%.2f,%d\n",
			        VARIANT_NAMES[v], role, OP_NAMES[op],
			        avg, calls, avg * calls, iterations);
		}
		if (v < NUM_VARIANTS - 1) fprintf(fp, "\n");
	}
	fclose(fp);
	printf("  [CSV] Written: %s\n", filename);
}

void csv_write_overhead(const char *filename, const char *role,
                        struct overhead_stats ostats[])
{
	FILE *fp = fopen(filename, "w");
	if (!fp) { fprintf(stderr, "ERROR: cannot open %s\n", filename); return; }
	fprintf(fp, "type,role,cpu_time_us,cpu_usage_percentage,memory_bytes,memory_us\n");
	for (int v = 0; v < NUM_VARIANTS; v++) {
		fprintf(fp, "%s,%s,%.2f,%.2f,%ld,%.2f\n",
		        VARIANT_NAMES[v], role,
		        ostats[v].cpu_time_us, ostats[v].cpu_usage_pct,
		        ostats[v].memory_bytes, ostats[v].memory_us);
	}
	fclose(fp);
	printf("  [CSV] Written: %s\n", filename);
}

void csv_write_processing(const char *filename, const char *role,
                          struct handshake_timing timings[])
{
	FILE *fp = fopen(filename, "w");
	if (!fp) { fprintf(stderr, "ERROR: cannot open %s\n", filename); return; }
	fprintf(fp, "type,role,processing_us,txrx_us,precomputation_us,overhead_us,total_us\n");
	for (int v = 0; v < NUM_VARIANTS; v++) {
		fprintf(fp, "%s,%s,%.2f,%.2f,%.2f,%.2f,%.2f\n",
		        VARIANT_NAMES[v], role,
		        timings[v].processing_us, timings[v].txrx_us,
		        timings[v].precomputation_us, timings[v].overhead_us,
		        timings[v].total_us);
	}
	fclose(fp);
	printf("  [CSV] Written: %s\n", filename);
}

long get_memory_usage_bytes(void)
{
	FILE *fp = fopen("/proc/self/status", "r");
	if (!fp) return 0;
	char line[256];
	long vmrss = 0;
	while (fgets(line, sizeof(line), fp)) {
		if (strncmp(line, "VmRSS:", 6) == 0) {
			sscanf(line + 6, "%ld", &vmrss);
			vmrss *= 1024;
			break;
		}
	}
	fclose(fp);
	return vmrss;
}

/* ── Stack painting for peak stack usage measurement ──
 *
 * Technique adapted from embedded "stack painting" method:
 * 1. stack_paint(): Allocate a large buffer on the stack, fill with 0xDEADBEEF,
 *    record its base address, then return.
 * 2. Call the function-under-test.  Its stack frame reuses the same region,
 *    overwriting the painted pattern from the top downward.
 * 3. stack_scan(): Scan the painted region from the bottom (lowest address)
 *    upward.  The first non-0xDEADBEEF word marks the deepest stack point
 *    reached, giving us the peak stack usage including all called functions.
 */

#define STACK_PAINT_WORDS  65536   /* 256 KB */
#define STACK_PATTERN      0xDEADBEEFU

static uintptr_t s_paint_base  = 0;
static int       s_paint_words = 0;

__attribute__((noinline, noclone))
void stack_paint(void)
{
	volatile uint32_t buf[STACK_PAINT_WORDS];
	for (int i = 0; i < STACK_PAINT_WORDS; i++)
		buf[i] = STACK_PATTERN;
	s_paint_base  = (uintptr_t)&buf[0];
	s_paint_words = STACK_PAINT_WORDS;
}

__attribute__((noinline, noclone))
long stack_scan(void)
{
	if (!s_paint_base || !s_paint_words) return 0;
	volatile uint32_t *p = (volatile uint32_t *)s_paint_base;
	int i;
	for (i = 0; i < s_paint_words; i++) {
		if (p[i] != STACK_PATTERN) break;
	}
	long used = (long)(s_paint_words - i) * 4;
	s_paint_base  = 0;
	s_paint_words = 0;
	return used;
}

/* ── Finalize timing and overhead stats for a variant ── */
void finalize_variant_stats(int variant, int N,
                            double total_wall_us, double total_txrx_us,
                            double total_precomp_us,
                            uint64_t wall_all_start, uint64_t wall_all_end,
                            const struct rusage *ru_start, const struct rusage *ru_end,
                            long mem_before, long mem_peak)
{
	double avg_wall    = total_wall_us / N;
	double avg_txrx    = total_txrx_us / N;
	double avg_precomp = total_precomp_us / N;

	/*
	 * Sum individually-timed crypto operations (from HS_TIME_START/END).
	 * This gives us the actual measured crypto processing time.
	 */
	uint64_t sum_ops_ns = 0;
	for (int op = 0; op < NUM_OPS; op++)
		sum_ops_ns += g_hs_ops[variant].ops[op].total_ns;
	double avg_ops_us = ns_to_us(sum_ops_ns) / N;

	/*
	 * Processing CSV decomposition:
	 *   processing_us     = measured crypto time minus precomputation
	 *   txrx_us           = measured network send/recv time
	 *   precomputation_us = measured keygen/setup before first message
	 *   overhead_us       = residual (buffer manipulation, memcpy, encoding)
	 *   total_us          = processing + txrx + precomp + overhead (exact)
	 */
	double processing = avg_ops_us - avg_precomp;
	if (processing < 0) processing = 0;

	double overhead = avg_wall - processing - avg_txrx - avg_precomp;
	if (overhead < 0) {
		processing += overhead;
		if (processing < 0) processing = 0;
		overhead = 0;
	}

	g_hs_timing[variant].processing_us     = processing;
	g_hs_timing[variant].txrx_us           = avg_txrx;
	g_hs_timing[variant].precomputation_us = avg_precomp;
	g_hs_timing[variant].overhead_us       = overhead;
	g_hs_timing[variant].total_us          = processing + avg_txrx + avg_precomp + overhead;

	/*
	 * Overhead CSV — CPU metrics:
	 *   cpu_time_us   = total_us - txrx_us  (pure CPU time, no I/O wait)
	 *   cpu_usage_%   = cpu_time_us / total_us × 100
	 */
	double cpu_time = g_hs_timing[variant].total_us - g_hs_timing[variant].txrx_us;
	g_hs_overhead[variant].cpu_time_us  = cpu_time;
	g_hs_overhead[variant].cpu_usage_pct =
		(g_hs_timing[variant].total_us > 0)
		? (cpu_time / g_hs_timing[variant].total_us) * 100.0 : 0;

	/*
	 * Overhead CSV — Memory metrics:
	 *   memory_bytes — peak stack usage, measured via stack painting.
	 *                  Set by caller after stack_scan(); fallback here.
	 *   memory_us    — time for buffer/memory operations (memcpy, message
	 *                  construction, field extraction).  In this codebase all
	 *                  non-crypto non-I/O time IS buffer manipulation, so
	 *                  memory_us = overhead_us.
	 */
	long mem_delta = mem_peak - mem_before;
	if (mem_delta <= 0)
		mem_delta = ru_end->ru_maxrss * 1024L - mem_before;
	if (mem_delta <= 0)
		mem_delta = ru_end->ru_maxrss * 1024L;
	g_hs_overhead[variant].memory_bytes = mem_delta;  /* fallback; overridden by stack_scan */
	g_hs_overhead[variant].memory_us    = overhead;
}
