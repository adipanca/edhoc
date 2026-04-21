#define _POSIX_C_SOURCE 200809L

#include "benchmark.h"

#include <arpa/inet.h>
#include <math.h>
#include <mbedtls/gcm.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

const char *SECTION_NAMES[SECTION_COUNT] = {
    "Section2", "Section32", "Section33", "Section34", "Section35"
};

const char *ROLE_NAMES[2] = {"Initiator", "Responder"};

const char *OP_NAMES[OP_COUNT] = {
    "KeyGen",
    "Encaps",
    "Decaps",
    "HKDF-EXTRACT",
    "HKDF-EXPANDS",
    "HASH",
    "AEAD_ENCRYPT",
    "AEAD_DECRYPT",
    "Signature",
    "Verify",
};

static int write_all(int fd, const uint8_t *buf, size_t len)
{
    size_t off = 0;
    while (off < len) {
        ssize_t n = send(fd, buf + off, len - off, 0);
        if (n <= 0) return -1;
        off += (size_t)n;
    }
    return 0;
}

static int read_all(int fd, uint8_t *buf, size_t len)
{
    size_t off = 0;
    while (off < len) {
        ssize_t n = recv(fd, buf + off, len - off, 0);
        if (n <= 0) return -1;
        off += (size_t)n;
    }
    return 0;
}

double now_us(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1000000.0 + (double)ts.tv_nsec / 1000.0;
}

double cpu_now_us(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &ts);
    return (double)ts.tv_sec * 1000000.0 + (double)ts.tv_nsec / 1000.0;
}

uint64_t memory_now_bytes(void)
{
    struct rusage ru;
    if (getrusage(RUSAGE_SELF, &ru) != 0) return 0;
    return (uint64_t)ru.ru_maxrss * 1024ULL;
}

int send_frame(int sockfd, uint8_t type, const uint8_t *payload, uint32_t len, double *txrx_us)
{
    uint8_t hdr[5];
    uint32_t be_len = htonl(len);
    hdr[0] = type;
    memcpy(&hdr[1], &be_len, sizeof(be_len));

    double t0 = now_us();
    if (write_all(sockfd, hdr, sizeof(hdr)) != 0) return -1;
    if (len > 0 && payload != NULL) {
        if (write_all(sockfd, payload, len) != 0) return -1;
    }
    double t1 = now_us();
    if (txrx_us != NULL) *txrx_us += (t1 - t0);
    return 0;
}

int recv_frame(int sockfd, uint8_t *type, uint8_t *payload, uint32_t cap, uint32_t *len, double *txrx_us)
{
    uint8_t hdr[5];
    double t0 = now_us();
    if (read_all(sockfd, hdr, sizeof(hdr)) != 0) return -1;
    double t1 = now_us();

    uint32_t be_len;
    memcpy(&be_len, &hdr[1], sizeof(be_len));
    uint32_t n = ntohl(be_len);
    if (n > cap) return -1;

    if (n > 0) {
        t0 = now_us();
        if (read_all(sockfd, payload, n) != 0) return -1;
        t1 = now_us();
    }

    if (type != NULL) *type = hdr[0];
    if (len != NULL) *len = n;
    if (txrx_us != NULL) *txrx_us += (t1 - t0);
    return 0;
}

void record_op(struct role_stats *stats, int section, int op, double delta_us)
{
    stats->by_section[section][op].sum_us += delta_us;
    stats->by_section[section][op].calls += 1;
}

int aes_gcm_encrypt(const uint8_t key[AES_KEY_LEN], const uint8_t iv[AES_IV_LEN],
                    const uint8_t *aad, size_t aad_len,
                    const uint8_t *pt, size_t pt_len,
                    uint8_t *out_ct_and_tag, size_t *out_len)
{
    mbedtls_gcm_context ctx;
    uint8_t *tag = out_ct_and_tag + pt_len;
    mbedtls_gcm_init(&ctx);

    if (mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, 128) != 0) {
        mbedtls_gcm_free(&ctx);
        return -1;
    }
    if (mbedtls_gcm_crypt_and_tag(&ctx, MBEDTLS_GCM_ENCRYPT,
                                  pt_len, iv, AES_IV_LEN,
                                  aad, aad_len,
                                  pt, out_ct_and_tag,
                                  AES_TAG_LEN, tag) != 0) {
        mbedtls_gcm_free(&ctx);
        return -1;
    }
    mbedtls_gcm_free(&ctx);
    *out_len = pt_len + AES_TAG_LEN;
    return 0;
}

int aes_gcm_decrypt(const uint8_t key[AES_KEY_LEN], const uint8_t iv[AES_IV_LEN],
                    const uint8_t *aad, size_t aad_len,
                    const uint8_t *ct_and_tag, size_t in_len,
                    uint8_t *out_pt, size_t *out_len)
{
    if (in_len < AES_TAG_LEN) return -1;

    size_t ct_len = in_len - AES_TAG_LEN;
    const uint8_t *tag = ct_and_tag + ct_len;

    mbedtls_gcm_context ctx;
    mbedtls_gcm_init(&ctx);
    if (mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, 128) != 0) {
        mbedtls_gcm_free(&ctx);
        return -1;
    }
    if (mbedtls_gcm_auth_decrypt(&ctx,
                                 ct_len,
                                 iv, AES_IV_LEN,
                                 aad, aad_len,
                                 tag, AES_TAG_LEN,
                                 ct_and_tag,
                                 out_pt) != 0) {
        mbedtls_gcm_free(&ctx);
        return -1;
    }
    mbedtls_gcm_free(&ctx);
    *out_len = ct_len;
    return 0;
}

static int cmp_double(const void *a, const void *b)
{
    const double da = *(const double *)a;
    const double db = *(const double *)b;
    if (da < db) return -1;
    if (da > db) return 1;
    return 0;
}

struct basic_stats compute_stats(double *samples, size_t n)
{
    struct basic_stats s = {0};
    if (n == 0) return s;

    double sum = 0;
    s.min = samples[0];
    s.max = samples[0];
    for (size_t i = 0; i < n; i++) {
        sum += samples[i];
        if (samples[i] < s.min) s.min = samples[i];
        if (samples[i] > s.max) s.max = samples[i];
    }
    s.avg = sum / (double)n;

    double var = 0;
    for (size_t i = 0; i < n; i++) {
        double d = samples[i] - s.avg;
        var += d * d;
    }
    s.stddev = sqrt(var / (double)n);

    qsort(samples, n, sizeof(double), cmp_double);
    if ((n % 2) == 0) {
        s.median = (samples[n / 2 - 1] + samples[n / 2]) / 2.0;
    } else {
        s.median = samples[n / 2];
    }
    return s;
}

int write_crypto_csv(const char *path, const struct crypto_row *rows, size_t n)
{
    FILE *fp = fopen(path, "w");
    if (!fp) return -1;

    fprintf(fp, "algorithm,operation,avg_us,stddev_us,min_us,max_us,median_us,iterations,key_length\n");
    for (size_t i = 0; i < n; i++) {
        fprintf(fp, "%s,%s,%.2f,%.2f,%.2f,%.2f,%.2f,%llu,%llu\n",
                rows[i].algorithm,
                rows[i].operation,
                rows[i].stats.avg,
                rows[i].stats.stddev,
                rows[i].stats.min,
                rows[i].stats.max,
                rows[i].stats.median,
                (unsigned long long)rows[i].iterations,
                (unsigned long long)rows[i].key_length);
    }
    fclose(fp);
    return 0;
}

static void write_op_row(FILE *fp, const char *section, const char *role,
                         const struct op_accum *a, const char *op_name, int iterations)
{
    double avg = (a->calls > 0) ? (a->sum_us / (double)a->calls) : 0.0;
    double total = avg * (double)a->calls / (double)(iterations > 0 ? iterations : 1);
    double calls_per_hs = (iterations > 0) ? ((double)a->calls / (double)iterations) : 0.0;
    fprintf(fp, "%s,%s,%s,%.2f,%.2f,%.2f,%d\n",
            section, role, op_name, avg, calls_per_hs, total, iterations);
}

int write_operation_csv(const char *path, const char *role,
                        const struct role_stats *stats, int iterations)
{
    FILE *fp = fopen(path, "w");
    if (!fp) return -1;

    fprintf(fp, "type,role,operation,avg_time_us,calls_per_handshake,total_per_handshake_us,iterations\n");

    for (int s = 0; s < SECTION_COUNT; s++) {
        write_op_row(fp, SECTION_NAMES[s], role, &stats->by_section[s][OP_KEYGEN], "KeyGen", iterations);
        write_op_row(fp, SECTION_NAMES[s], role, &stats->by_section[s][OP_ENCAPS], "Encaps", iterations);
        write_op_row(fp, SECTION_NAMES[s], role, &stats->by_section[s][OP_DECAPS], "Decaps", iterations);

        write_op_row(fp, SECTION_NAMES[s], role, &stats->by_section[s][OP_HKDF_EXTRACT], "HKDF-EXTRACT", iterations);
        write_op_row(fp, SECTION_NAMES[s], role, &stats->by_section[s][OP_HKDF_EXPAND], "HKDF-EXPANDS", iterations);
        write_op_row(fp, SECTION_NAMES[s], role, &stats->by_section[s][OP_HASH], "HASH", iterations);
        write_op_row(fp, SECTION_NAMES[s], role, &stats->by_section[s][OP_AEAD_ENC], "AEAD_ENCRYPT", iterations);
        write_op_row(fp, SECTION_NAMES[s], role, &stats->by_section[s][OP_AEAD_DEC], "AEAD_DECRYPT", iterations);
        write_op_row(fp, SECTION_NAMES[s], role, &stats->by_section[s][OP_SIGNATURE], "Signature", iterations);
        write_op_row(fp, SECTION_NAMES[s], role, &stats->by_section[s][OP_VERIFY], "Verify", iterations);

        if (s != SECTION_COUNT - 1) {
            fprintf(fp, "\n");
        }
    }

    fclose(fp);
    return 0;
}

int write_overhead_csv(const char *path, const char *role,
                       const struct overhead_accum *overhead)
{
    FILE *fp = fopen(path, "w");
    if (!fp) return -1;

    fprintf(fp, "type,role,cpu_time_us,cpu_usage_percentage,memory_bytes,memory_us\n");
    for (int s = 0; s < SECTION_COUNT; s++) {
        fprintf(fp, "%s,%s,%.2f,%.2f,%llu,%.2f\n",
                SECTION_NAMES[s],
                role,
                overhead->cpu_time_us[s],
                overhead->cpu_usage_percentage[s],
                (unsigned long long)overhead->memory_bytes[s],
                overhead->memory_us[s]);
    }

    fclose(fp);
    return 0;
}

int write_processing_csv(const char *path, const char *role,
                         const struct timing_accum *timing)
{
    FILE *fp = fopen(path, "w");
    if (!fp) return -1;

    fprintf(fp, "type,role,processing_us,txrx_us,precomputation_us,overhead_us,total_us\n");
    for (int s = 0; s < SECTION_COUNT; s++) {
        fprintf(fp, "%s,%s,%.2f,%.2f,%.2f,%.2f,%.2f\n",
                SECTION_NAMES[s],
                role,
                timing->processing_us[s],
                timing->txrx_us[s],
                timing->precomp_us[s],
                timing->overhead_us[s],
                timing->total_us[s]);
    }

    fclose(fp);
    return 0;
}
