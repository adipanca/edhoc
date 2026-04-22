#ifndef P2P_BENCHMARK_H
#define P2P_BENCHMARK_H

#include <stddef.h>
#include <stdint.h>

#define ROLE_INITIATOR 0
#define ROLE_RESPONDER 1

#define SECTION_COUNT 5
#define OP_COUNT 10

#define MSG_TYPE_1 1
#define MSG_TYPE_2 2
#define MSG_TYPE_3 3
#define MSG_TYPE_4 4

#define SHA256_LEN 32
#define AES_KEY_LEN 16
#define AES_IV_LEN 12
#define AES_TAG_LEN 16

enum section_id {
    SECTION2 = 0,
    SECTION32 = 1,
    SECTION33 = 2,
    SECTION34 = 3,
    SECTION35 = 4,
};

enum operation_id {
    OP_KEYGEN = 0,
    OP_ENCAPS = 1,
    OP_DECAPS = 2,
    OP_HKDF_EXTRACT = 3,
    OP_HKDF_EXPAND = 4,
    OP_HASH = 5,
    OP_AEAD_ENC = 6,
    OP_AEAD_DEC = 7,
    OP_SIGNATURE = 8,
    OP_VERIFY = 9,
};

struct op_accum {
    double sum_us;
    uint64_t calls;
};

struct role_stats {
    struct op_accum by_section[SECTION_COUNT][OP_COUNT];
};

struct timing_accum {
    double processing_us[SECTION_COUNT];
    double txrx_us[SECTION_COUNT];
    double precomp_us[SECTION_COUNT];
    double overhead_us[SECTION_COUNT];
    double total_us[SECTION_COUNT];
};

struct overhead_accum {
    double cpu_time_us[SECTION_COUNT];
    double wall_time_us[SECTION_COUNT];
    double cpu_to_wall_ratio[SECTION_COUNT];
    uint64_t protocol_state_bytes[SECTION_COUNT];
    uint64_t rss_peak_bytes[SECTION_COUNT];
    double crypto_time_est_us[SECTION_COUNT];
    double io_wait_us[SECTION_COUNT];
    double residual_overhead_us[SECTION_COUNT];
};

struct basic_stats {
    double avg;
    double stddev;
    double min;
    double max;
    double median;
};

struct crypto_row {
    const char *algorithm;
    const char *operation;
    struct basic_stats stats;
    uint64_t iterations;
    uint64_t key_length;
};

extern const char *SECTION_NAMES[SECTION_COUNT];
extern const char *ROLE_NAMES[2];
extern const char *OP_NAMES[OP_COUNT];

double now_us(void);
double cpu_now_us(void);
uint64_t memory_now_bytes(void);

int send_frame(int sockfd, uint8_t type, const uint8_t *payload, uint32_t len, double *txrx_us);
int recv_frame(int sockfd, uint8_t *type, uint8_t *payload, uint32_t cap, uint32_t *len, double *txrx_us);

void record_op(struct role_stats *stats, int section, int op, double delta_us);

int aes_gcm_encrypt(const uint8_t key[AES_KEY_LEN], const uint8_t iv[AES_IV_LEN],
                    const uint8_t *aad, size_t aad_len,
                    const uint8_t *pt, size_t pt_len,
                    uint8_t *out_ct_and_tag, size_t *out_len);

int aes_gcm_decrypt(const uint8_t key[AES_KEY_LEN], const uint8_t iv[AES_IV_LEN],
                    const uint8_t *aad, size_t aad_len,
                    const uint8_t *ct_and_tag, size_t in_len,
                    uint8_t *out_pt, size_t *out_len);

struct basic_stats compute_stats(double *samples, size_t n);

int write_crypto_csv(const char *path, const struct crypto_row *rows, size_t n);
int write_operation_csv(const char *path, const char *role,
                        const struct role_stats *stats, int iterations);
int write_overhead_csv(const char *path, const char *role,
                       const struct overhead_accum *overhead);
int write_processing_csv(const char *path, const char *role,
                         const struct timing_accum *timing);

uint64_t estimate_protocol_state_bytes(const struct role_stats *stats,
                                       int section,
                                       int iterations);
double estimate_crypto_time_us(const struct role_stats *stats,
                               int section,
                               int iterations);

#endif
