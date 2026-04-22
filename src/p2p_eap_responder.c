#include "benchmark.h"
#include "eap_wrap.h"
#include "edhoc_plaintext.h"
#include "pqclean_adapter.h"

#include <errno.h>
#include <netinet/in.h>
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#define CRED_EXCHANGE_TYPE 0xF0
#define EAP_MTU_DEFAULT 256
#define EAP_METHOD_TYPE_EXPERIMENTAL 57

#ifndef BENCH_TAG
#define BENCH_TAG ""
#endif

#ifdef BENCH_AAA
#include "aaa_radius.h"
struct aaa_accum {
    double rtt_us_sum[SECTION_COUNT];
    double req_bytes_sum[SECTION_COUNT];
    double resp_bytes_sum[SECTION_COUNT];
    uint64_t count[SECTION_COUNT];
    uint64_t accept[SECTION_COUNT];
    uint64_t reject[SECTION_COUNT];
    uint64_t err[SECTION_COUNT];
};
static struct aaa_accum g_aaa;
static const char *g_aaa_host = "127.0.0.1";
static uint16_t g_aaa_port = 3812;
static const char *g_aaa_secret = "testing123";
static const char *g_aaa_password = "edhoc-pass";
static const char *g_aaa_user_for_section[SECTION_COUNT] = {
    "edhoc_Section2",
    "edhoc_Section32",
    "edhoc_Section33",
    "edhoc_Section34",
    "edhoc_Section35"
};
static void aaa_tick(int sec)
{
    double rtt = 0; size_t rb = 0, sb = 0;
    int code = aaa_radius_pap_auth(g_aaa_host, g_aaa_port, g_aaa_secret,
                                   g_aaa_user_for_section[sec], g_aaa_password,
                                   &rtt, &rb, &sb);
    if (code <= 0) {
        g_aaa.err[sec] += 1;
        return;
    }
    g_aaa.rtt_us_sum[sec] += rtt;
    g_aaa.req_bytes_sum[sec] += (double)rb;
    g_aaa.resp_bytes_sum[sec] += (double)sb;
    g_aaa.count[sec] += 1;
    if (code == 2) g_aaa.accept[sec] += 1;
    else if (code == 3) g_aaa.reject[sec] += 1;
}
static int write_aaa_csv(const char *path)
{
    FILE *f = fopen(path, "w");
    if (!f) return -1;
    fprintf(f, "section,calls,accepts,rejects,errors,rtt_avg_us,req_bytes_avg,resp_bytes_avg,total_bytes_avg\n");
    for (int s = 0; s < SECTION_COUNT; s++) {
        double n = (double)(g_aaa.count[s] ? g_aaa.count[s] : 1);
        fprintf(f, "%s,%llu,%llu,%llu,%llu,%.3f,%.1f,%.1f,%.1f\n",
                SECTION_NAMES[s],
                (unsigned long long)g_aaa.count[s],
                (unsigned long long)g_aaa.accept[s],
                (unsigned long long)g_aaa.reject[s],
                (unsigned long long)g_aaa.err[s],
                g_aaa.rtt_us_sum[s] / n,
                g_aaa.req_bytes_sum[s] / n,
                g_aaa.resp_bytes_sum[s] / n,
                (g_aaa.req_bytes_sum[s] + g_aaa.resp_bytes_sum[s]) / n);
    }
    fclose(f);
    return 0;
}
#define BENCH_AAA_TICK(sec) aaa_tick(sec)
#else
#define BENCH_AAA_TICK(sec) ((void)0)
#endif

static struct eap_wrap_ctx g_eap;

static int send_wrapped_frame(int sockfd, uint8_t type, const uint8_t *payload, uint32_t len, double *txrx_us)
{
    return eap_send_wrapped_frame(&g_eap, sockfd, type, payload, len, txrx_us);
}

static int recv_wrapped_frame(int sockfd, uint8_t *type, uint8_t *payload, uint32_t cap, uint32_t *len, double *txrx_us)
{
    return eap_recv_wrapped_frame(&g_eap, sockfd, type, payload, cap, len, txrx_us);
}

static int send_wrapped_frame_ex(int sockfd, uint8_t type,
                                 const uint8_t *payload, uint32_t len,
                                 double *txrx_us,
                                 uint32_t *frags,
                                 uint32_t *wire_bytes)
{
    return eap_send_wrapped_frame_ex(&g_eap, sockfd, type, payload, len, txrx_us, frags, wire_bytes);
}

static int recv_wrapped_frame_ex(int sockfd, uint8_t *type,
                                 uint8_t *payload, uint32_t cap, uint32_t *len,
                                 double *txrx_us,
                                 uint32_t *frags,
                                 uint32_t *wire_bytes)
{
    return eap_recv_wrapped_frame_ex(&g_eap, sockfd, type, payload, cap, len, txrx_us, frags, wire_bytes);
}

struct local_identity {
    uint8_t sig_pk[MLDSA65_PK_LEN];
    uint8_t sig_sk[MLDSA65_SK_LEN];
    uint8_t kem_pk[MLKEM768_PK_LEN];
    uint8_t kem_sk[MLKEM768_SK_LEN];
};

struct peer_identity {
    uint8_t sig_pk[MLDSA65_PK_LEN];
    uint8_t kem_pk[MLKEM768_PK_LEN];
};

static int listen_server(int port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons((uint16_t)port);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(fd);
        return -1;
    }
    if (listen(fd, 1) != 0) {
        close(fd);
        return -1;
    }

    int cfd = accept(fd, NULL, NULL);
    close(fd);
    return cfd;
}

static double timed_hash(struct role_stats *s, int sec, const uint8_t *data, size_t len, uint8_t out[32])
{
    double t0 = now_us();
    crypto_hash_sha256(out, data, len);
    double t1 = now_us();
    record_op(s, sec, OP_HASH, t1 - t0);
    return t1 - t0;
}

static void timed_hkdf_extract(struct role_stats *s, int sec,
                               const uint8_t *salt, size_t salt_len,
                               const uint8_t *ikm, size_t ikm_len,
                               uint8_t out[32])
{
    double t0 = now_us();
    hkdf_extract_sha256(salt, salt_len, ikm, ikm_len, out);
    double t1 = now_us();
    record_op(s, sec, OP_HKDF_EXTRACT, t1 - t0);
}

static int timed_aead_encrypt(struct role_stats *s, int sec,
                              const uint8_t key[16], const uint8_t iv[12],
                              const uint8_t *aad, size_t aad_len,
                              const uint8_t *pt, size_t pt_len,
                              uint8_t *ct, size_t *ct_len)
{
    double t0 = now_us();
    int rc = aes_gcm_encrypt(key, iv, aad, aad_len, pt, pt_len, ct, ct_len);
    double t1 = now_us();
    record_op(s, sec, OP_AEAD_ENC, t1 - t0);
    return rc;
}

static int timed_aead_decrypt(struct role_stats *s, int sec,
                              const uint8_t key[16], const uint8_t iv[12],
                              const uint8_t *aad, size_t aad_len,
                              const uint8_t *ct, size_t ct_len,
                              uint8_t *pt, size_t *pt_len)
{
    double t0 = now_us();
    int rc = aes_gcm_decrypt(key, iv, aad, aad_len, ct, ct_len, pt, pt_len);
    double t1 = now_us();
    record_op(s, sec, OP_AEAD_DEC, t1 - t0);
    return rc;
}

#define ID_CRED_LEN EDHOC_ID_CRED_LEN
#define MAC_LEN EDHOC_MAC_LEN

static void compute_id_cred(const uint8_t *sig_pk, uint8_t out[ID_CRED_LEN])
{
    crypto_hash_sha256(out, sig_pk, MLDSA65_PK_LEN);
}

static void compute_id_cred_kem(const uint8_t *kem_pk, uint8_t out[ID_CRED_LEN])
{
    crypto_hash_sha256(out, kem_pk, MLKEM768_PK_LEN);
}

static void hex64(const uint8_t in[64], char out[129])
{
    static const char *h = "0123456789abcdef";
    for (int i = 0; i < 64; i++) {
        out[2 * i] = h[(in[i] >> 4) & 0xF];
        out[2 * i + 1] = h[in[i] & 0xF];
    }
    out[128] = '\0';
}

static void derive_msk_emsk(const uint8_t prk[32], uint8_t msk[64], uint8_t emsk[64])
{
    static const uint8_t info_msk[] = "EAP-EDHOC-MSK";
    static const uint8_t info_emsk[] = "EAP-EDHOC-EMSK";

    hkdf_expand_sha256(prk, info_msk, sizeof(info_msk) - 1, msk, 64);
    hkdf_expand_sha256(prk, info_emsk, sizeof(info_emsk) - 1, emsk, 64);
}

static int write_eap_keymat_csv(const char *path,
                                const uint8_t msk[SECTION_COUNT][64],
                                const uint8_t emsk[SECTION_COUNT][64])
{
    FILE *fp = fopen(path, "w");
    if (!fp) return -1;

    fprintf(fp, "section,msk,emsk\n");
    for (int s = 0; s < SECTION_COUNT; s++) {
        char msk_hex[129], emsk_hex[129];
        hex64(msk[s], msk_hex);
        hex64(emsk[s], emsk_hex);
        fprintf(fp, "%s,%s,%s\n", SECTION_NAMES[s], msk_hex, emsk_hex);
    }

    fclose(fp);
    return 0;
}

struct frag_accum {
    double msg_bytes_sum[4];
    double msg_wire_sum[4];
    double msg_frags_sum[4];
    double msg_count[4];
    double ack_frags_sum;
    double ack_wire_sum;
};

static int write_fragmentation_csv(const char *path,
                                   const struct frag_accum acc[SECTION_COUNT],
                                   const struct role_stats *op_stats,
                                   int iterations,
                                   int mtu)
{
    FILE *fp = fopen(path, "w");
    if (!fp) return -1;

    fprintf(fp, "section,mtu,msg1_bytes,msg1_wire,msg1_frags,msg2_bytes,msg2_wire,msg2_frags,msg3_bytes,msg3_wire,msg3_frags,msg4_bytes,msg4_wire,msg4_frags,ack_msg4_wire,ack_msg4_frags,total_fragments,tx_fragments,rx_fragments,total_wire_bytes,total_rt,num_sign,num_verify,num_encaps,num_decaps\n");

    for (int s = 0; s < SECTION_COUNT; s++) {
        double b[4] = {0}, w[4] = {0}, f[4] = {0};
        double total_f = 0;
        double tx_f = 0;
        double rx_f = 0;
        double total_w = 0;
        double ack_frags = 0;
        double ack_wire = 0;
        int total_rt = (s == SECTION33 || s == SECTION34 || s == SECTION35) ? 4 : 3;

        for (int m = 0; m < 4; m++) {
            if (acc[s].msg_count[m] > 0.0) {
                b[m] = acc[s].msg_bytes_sum[m] / acc[s].msg_count[m];
                w[m] = acc[s].msg_wire_sum[m] / acc[s].msg_count[m];
                f[m] = acc[s].msg_frags_sum[m] / acc[s].msg_count[m];
                total_f += f[m];
                total_w += w[m];
            }
        }

        if (s == SECTION33 || s == SECTION34 || s == SECTION35) {
            ack_frags = acc[s].ack_frags_sum / (double)iterations;
            ack_wire = acc[s].ack_wire_sum / (double)iterations;
            total_f += ack_frags;
            total_w += ack_wire;
        }

        tx_f = f[1] + f[3];
        rx_f = f[0] + f[2] + ack_frags;

        {
            double num_sign = (double)op_stats->by_section[s][OP_SIGNATURE].calls / (double)iterations;
            double num_verify = (double)op_stats->by_section[s][OP_VERIFY].calls / (double)iterations;
            double num_encaps = (double)op_stats->by_section[s][OP_ENCAPS].calls / (double)iterations;
            double num_decaps = (double)op_stats->by_section[s][OP_DECAPS].calls / (double)iterations;

            fprintf(fp,
                    "%s,%d,%.0f,%.0f,%.2f,%.0f,%.0f,%.2f,%.0f,%.0f,%.2f,%.0f,%.0f,%.2f,%.0f,%.2f,%.2f,%.2f,%.2f,%.0f,%d,%.2f,%.2f,%.2f,%.2f\n",
                    SECTION_NAMES[s], mtu,
                    b[0], w[0], f[0],
                    b[1], w[1], f[1],
                    b[2], w[2], f[2],
                    b[3], w[3], f[3],
                    ack_wire,
                    ack_frags,
                    total_f,
                    tx_f,
                    rx_f,
                    total_w,
                    total_rt,
                    num_sign,
                    num_verify,
                    num_encaps,
                    num_decaps);
        }
    }

    fclose(fp);
    return 0;
}

static void timed_hkdf_expand_len(struct role_stats *s, int sec,
                                  const uint8_t prk[32],
                                  const uint8_t *info, size_t info_len,
                                  uint8_t *out, size_t out_len)
{
    double t0 = now_us();
    hkdf_expand_sha256(prk, info, info_len, out, out_len);
    double t1 = now_us();
    record_op(s, sec, OP_HKDF_EXPAND, t1 - t0);
}

static void timed_kdf_label(struct role_stats *s, int sec,
                            const uint8_t prk[32],
                            uint8_t label,
                            const uint8_t *ctx, size_t ctx_len,
                            uint8_t *out, size_t out_len)
{
    uint8_t info[8192];
    size_t info_len = 0;
    info[info_len++] = label;
    info[info_len++] = (uint8_t)((ctx_len >> 8) & 0xFF);
    info[info_len++] = (uint8_t)(ctx_len & 0xFF);
    if (ctx_len > 0) {
        memcpy(info + info_len, ctx, ctx_len);
        info_len += ctx_len;
    }
    timed_hkdf_expand_len(s, sec, prk, info, info_len, out, out_len);
}

static void hash_concat2(struct role_stats *s, int sec,
                         const uint8_t *a, size_t a_len,
                         const uint8_t *b, size_t b_len,
                         uint8_t out[32])
{
    uint8_t buf[12000];
    memcpy(buf, a, a_len);
    memcpy(buf + a_len, b, b_len);
    timed_hash(s, sec, buf, a_len + b_len, out);
}

static void xor_buf(uint8_t *dst, const uint8_t *a, const uint8_t *b, size_t len)
{
    for (size_t i = 0; i < len; i++) dst[i] = a[i] ^ b[i];
}

static int section_run_responder(int sockfd, int sec,
                                 struct role_stats *ops,
                                 struct timing_accum *timing,
                                 struct overhead_accum *ov,
                                 const struct local_identity *me,
                                 const struct peer_identity *peer,
                                 uint8_t out_msk[64],
                                 uint8_t out_emsk[64],
                                 struct frag_accum *frag,
                                 int iterations)
{
    uint8_t id_r_sign[ID_CRED_LEN], id_r_kem[ID_CRED_LEN];
    uint8_t id_i_sign[ID_CRED_LEN];
    uint8_t id_r[ID_CRED_LEN], id_i_expected[ID_CRED_LEN];

    compute_id_cred(me->sig_pk, id_r_sign);
    compute_id_cred_kem(me->kem_pk, id_r_kem);
    compute_id_cred(peer->sig_pk, id_i_sign);

    if (sec == SECTION2 || sec == SECTION34) {
        memcpy(id_r, id_r_kem, ID_CRED_LEN);
    } else {
        memcpy(id_r, id_r_sign, ID_CRED_LEN);
    }
    memcpy(id_i_expected, id_i_sign, ID_CRED_LEN);

    double total_wall = 0;
    double total_txrx = 0;
    double total_precomp = 0;
    double total_cpu = 0;
    uint64_t mem_peak = 0;

    for (int it = 0; it < iterations; it++) {
        uint8_t type = 0;
        uint8_t recv_buf[9000];
        uint32_t recv_len = 0;
        uint8_t prk_export[32] = {0};
        int has_prk_export = 0;
        uint32_t frame_frags = 0;
        uint32_t frame_wire = 0;

        double txrx_us = 0;
        double wall0 = now_us();
        double cpu0 = cpu_now_us();
        uint64_t mem0 = memory_now_bytes();
        if (mem0 > mem_peak) mem_peak = mem0;

        double pre0 = now_us();
        uint8_t eph_kem_pk[MLKEM768_PK_LEN];
        uint8_t eph_kem_sk[MLKEM768_SK_LEN];
        double t0 = now_us();
        pq_mlkem768_keygen(eph_kem_pk, eph_kem_sk);
        double t1 = now_us();
        record_op(ops, sec, OP_KEYGEN, t1 - t0);
        double pre1 = now_us();
        total_precomp += (pre1 - pre0);

        if (recv_wrapped_frame_ex(sockfd, &type, recv_buf, sizeof(recv_buf), &recv_len, &txrx_us, &frame_frags, &frame_wire) != 0) return -1;
        if (type != MSG_TYPE_1) return -1;
        frag->msg_bytes_sum[0] += (double)recv_len;
        frag->msg_wire_sum[0] += (double)frame_wire;
        frag->msg_frags_sum[0] += (double)frame_frags;
        frag->msg_count[0] += 1.0;

        uint32_t off = 0;
        uint8_t pk_eph_i[MLKEM768_PK_LEN];
        memcpy(pk_eph_i, recv_buf + off, MLKEM768_PK_LEN);
        off += MLKEM768_PK_LEN;

        uint8_t ss_r[MLKEM768_SS_LEN];
        if (sec == SECTION2) {
            t0 = now_us();
            pq_mlkem768_decaps(ss_r, recv_buf + off, me->kem_sk);
            t1 = now_us();
            record_op(ops, sec, OP_DECAPS, t1 - t0);
            off += MLKEM768_CT_LEN;
        }

        uint8_t ct_eph[MLKEM768_CT_LEN], ss_eph[MLKEM768_SS_LEN];
        t0 = now_us();
        pq_mlkem768_encaps(ct_eph, ss_eph, pk_eph_i);
        t1 = now_us();
        record_op(ops, sec, OP_ENCAPS, t1 - t0);

        uint8_t hm1[32], th2[32], prk2e[32], salt3e2m[32], prk3e2m[32];
        timed_hash(ops, sec, recv_buf, recv_len, hm1);
        hash_concat2(ops, sec, ct_eph, MLKEM768_CT_LEN, hm1, 32, th2);
        timed_hkdf_extract(ops, sec, th2, 32, ss_eph, MLKEM768_SS_LEN, prk2e);
        uint8_t pt2_base[8192], pt2a[8192], c2[8192], keystream2[8192];
        size_t pt2_base_len = 0, pt2a_len = 0;
        uint8_t c_r = 0x01;
        uint8_t zero_mac[MAC_LEN] = {0};

        if (sec == SECTION2) {
            uint8_t ctx2[1 + ID_CRED_LEN + 32], mac2[MAC_LEN];
            timed_kdf_label(ops, sec, prk2e, 1, th2, 32, salt3e2m, 32);
            timed_hkdf_extract(ops, sec, salt3e2m, 32, ss_r, MLKEM768_SS_LEN, prk3e2m);
            memcpy(prk_export, prk3e2m, 32);
            has_prk_export = 1;

            ctx2[0] = c_r;
            memcpy(ctx2 + 1, id_r, ID_CRED_LEN);
            memcpy(ctx2 + 1 + ID_CRED_LEN, th2, 32);
            timed_kdf_label(ops, sec, prk3e2m, 2, ctx2, sizeof(ctx2), mac2, MAC_LEN);

            if (encode_plaintext2(pt2_base, sizeof(pt2_base), &pt2_base_len, c_r, id_r, th2, mac2, NULL, 0) != 0) return -1;
            if (encode_plaintext2a(pt2a, sizeof(pt2a), &pt2a_len, pt2_base, pt2_base_len, NULL, 0) != 0) return -1;
        } else {
            uint8_t mac2_for_pt2[MAC_LEN];
            memcpy(mac2_for_pt2, zero_mac, MAC_LEN);

            if (sec == SECTION33) {
                uint8_t ctx2[1 + ID_CRED_LEN + 32];
                ctx2[0] = c_r;
                memcpy(ctx2 + 1, id_r, ID_CRED_LEN);
                memcpy(ctx2 + 1 + ID_CRED_LEN, th2, 32);
                timed_kdf_label(ops, sec, prk2e, 2, ctx2, sizeof(ctx2), mac2_for_pt2, MAC_LEN);
            }

            if (encode_plaintext2(pt2_base, sizeof(pt2_base), &pt2_base_len, c_r, id_r, th2, mac2_for_pt2, NULL, 0) != 0) return -1;

            if (sec == SECTION32 || sec == SECTION33 || sec == SECTION35) {
                uint8_t sig2[MLDSA65_SIG_MAX_LEN];
                size_t sig2_len = 0;
                t0 = now_us();
                pq_mldsa65_sign(sig2, &sig2_len, pt2_base, pt2_base_len, me->sig_sk);
                t1 = now_us();
                record_op(ops, sec, OP_SIGNATURE, t1 - t0);
                if (encode_plaintext2a(pt2a, sizeof(pt2a), &pt2a_len, pt2_base, pt2_base_len, sig2, sig2_len) != 0) return -1;
            } else {
                if (encode_plaintext2a(pt2a, sizeof(pt2a), &pt2a_len, pt2_base, pt2_base_len, NULL, 0) != 0) return -1;
            }
        }

        timed_kdf_label(ops, sec, prk2e, 0, th2, 32, keystream2, pt2a_len);
        xor_buf(c2, pt2a, keystream2, pt2a_len);

        uint8_t payload2[9000];
        uint32_t payload2_len = 0;
        memcpy(payload2 + payload2_len, ct_eph, MLKEM768_CT_LEN);
        payload2_len += MLKEM768_CT_LEN;
        memcpy(payload2 + payload2_len, c2, pt2a_len);
        payload2_len += (uint32_t)pt2a_len;

        if (send_wrapped_frame_ex(sockfd, MSG_TYPE_2, payload2, payload2_len, &txrx_us, &frame_frags, &frame_wire) != 0) return -1;
        frag->msg_bytes_sum[1] += (double)payload2_len;
        frag->msg_wire_sum[1] += (double)frame_wire;
        frag->msg_frags_sum[1] += (double)frame_frags;
        frag->msg_count[1] += 1.0;

        if (recv_wrapped_frame_ex(sockfd, &type, recv_buf, sizeof(recv_buf), &recv_len, &txrx_us, &frame_frags, &frame_wire) != 0) return -1;
        if (type != MSG_TYPE_3) return -1;
        frag->msg_bytes_sum[2] += (double)recv_len;
        frag->msg_wire_sum[2] += (double)frame_wire;
        frag->msg_frags_sum[2] += (double)frame_frags;
        frag->msg_count[2] += 1.0;

        if (sec == SECTION2) {
            off = 0;
        } else if (sec == SECTION32 || sec == SECTION34 || sec == SECTION35) {
            uint8_t ss_r2[MLKEM768_SS_LEN];
            t0 = now_us();
            pq_mlkem768_decaps(ss_r2, recv_buf, me->kem_sk);
            t1 = now_us();
            record_op(ops, sec, OP_DECAPS, t1 - t0);
            timed_kdf_label(ops, sec, prk2e, 1, th2, 32, salt3e2m, 32);
            timed_hkdf_extract(ops, sec, salt3e2m, 32, ss_r2, MLKEM768_SS_LEN, prk3e2m);
            memcpy(prk_export, prk3e2m, 32);
            has_prk_export = 1;
            off = MLKEM768_CT_LEN;
        } else {
            memcpy(prk3e2m, prk2e, 32);
            memcpy(prk_export, prk3e2m, 32);
            has_prk_export = 1;
            off = 0;
        }

        uint8_t th3[32], k3[16], iv3[12], mac3[32], ctx3[ID_CRED_LEN + 32];
        {
            uint8_t tmp[12000];
            size_t n = 0;
            memcpy(tmp + n, th2, 32); n += 32;
            memcpy(tmp + n, pt2_base, pt2_base_len); n += pt2_base_len;
            memcpy(tmp + n, id_r, ID_CRED_LEN); n += ID_CRED_LEN;
            timed_hash(ops, sec, tmp, n, th3);
        }
        timed_kdf_label(ops, sec, prk3e2m, 8, th3, 32, k3, sizeof(k3));
        timed_kdf_label(ops, sec, prk3e2m, 9, th3, 32, iv3, sizeof(iv3));
        memcpy(ctx3, id_i_expected, ID_CRED_LEN);
        memcpy(ctx3 + ID_CRED_LEN, th3, 32);
        timed_kdf_label(ops, sec, prk3e2m, 6, ctx3, sizeof(ctx3), mac3, sizeof(mac3));

        uint8_t pt3[4096];
        size_t pt3_len = 0;
        if (timed_aead_decrypt(ops, sec, k3, iv3, th3, 32,
                               recv_buf + off, recv_len - off,
                               pt3, &pt3_len) != 0) {
            return -1;
        }

        {
            uint8_t id_i_recv[ID_CRED_LEN];
            const uint8_t *sig3 = NULL;
            size_t sig3_len = 0;
            const uint8_t *ead3 = NULL;
            size_t ead3_len = 0;
            uint8_t sig3_input[8192];
            size_t sig3_input_len = 0;

            if (decode_plaintext3(pt3, pt3_len, id_i_recv, &sig3, &sig3_len, &ead3, &ead3_len) != 0) return -1;
            if (memcmp(id_i_recv, id_i_expected, ID_CRED_LEN) != 0) return -1;

            memcpy(sig3_input + sig3_input_len, id_i_recv, ID_CRED_LEN);
            sig3_input_len += ID_CRED_LEN;
            memcpy(sig3_input + sig3_input_len, th3, 32);
            sig3_input_len += 32;
            memcpy(sig3_input + sig3_input_len, mac3, MAC_LEN);
            sig3_input_len += MAC_LEN;
            sig3_input[sig3_input_len++] = (uint8_t)((ead3_len >> 8) & 0xFF);
            sig3_input[sig3_input_len++] = (uint8_t)(ead3_len & 0xFF);
            if (ead3_len > 0) {
                memcpy(sig3_input + sig3_input_len, ead3, ead3_len);
                sig3_input_len += ead3_len;
            }

            int rc;
            t0 = now_us();
            rc = pq_mldsa65_verify(sig3, sig3_len, sig3_input, sig3_input_len, peer->sig_pk);
            t1 = now_us();
            record_op(ops, sec, OP_VERIFY, t1 - t0);
            if (rc != 0) return -1;
        }

        if (sec == SECTION33 || sec == SECTION34 || sec == SECTION35) {
            uint8_t ct_i[MLKEM768_CT_LEN], ss_i[MLKEM768_SS_LEN], th4[32], salt4[32], prk4[32], k4[16], iv4[12], pt4[64], msg4[9000];
            size_t ct4_len = 0;
            t0 = now_us();
            pq_mlkem768_encaps(ct_i, ss_i, peer->kem_pk);
            t1 = now_us();
            record_op(ops, sec, OP_ENCAPS, t1 - t0);

            {
                uint8_t tmp[12000];
                size_t n = 0;
                memcpy(tmp + n, th3, 32); n += 32;
                memcpy(tmp + n, pt3, pt3_len); n += pt3_len;
                memcpy(tmp + n, id_i_expected, ID_CRED_LEN); n += ID_CRED_LEN;
                timed_hash(ops, sec, tmp, n, th4);
            }

            timed_kdf_label(ops, sec, prk3e2m, 5, th4, 32, salt4, 32);
            timed_hkdf_extract(ops, sec, salt4, 32, ss_i, MLKEM768_SS_LEN, prk4);
            memcpy(prk_export, prk4, 32);
            has_prk_export = 1;
            timed_kdf_label(ops, sec, prk4, 8, th4, 32, k4, sizeof(k4));
            timed_kdf_label(ops, sec, prk4, 9, th4, 32, iv4, sizeof(iv4));

            if (sec == SECTION34) {
                uint8_t ctx2r[1 + ID_CRED_LEN + 32], mac2[MAC_LEN];
                ctx2r[0] = c_r;
                memcpy(ctx2r + 1, id_r, ID_CRED_LEN);
                memcpy(ctx2r + 1 + ID_CRED_LEN, th4, 32);
                timed_kdf_label(ops, sec, prk4, 2, ctx2r, sizeof(ctx2r), mac2, MAC_LEN);
                if (encode_plaintext4(pt4, sizeof(pt4), &ct4_len, 1, mac2, NULL, 0) != 0) return -1;
                if (timed_aead_encrypt(ops, sec, k4, iv4, th4, 32, pt4, ct4_len, msg4 + MLKEM768_CT_LEN, &ct4_len) != 0) return -1;
            } else {
                if (encode_plaintext4(pt4, sizeof(pt4), &ct4_len, 0, zero_mac, NULL, 0) != 0) return -1;
                if (timed_aead_encrypt(ops, sec, k4, iv4, th4, 32, pt4, ct4_len, msg4 + MLKEM768_CT_LEN, &ct4_len) != 0) return -1;
            }

            memcpy(msg4, ct_i, MLKEM768_CT_LEN);
            if (send_wrapped_frame_ex(sockfd, MSG_TYPE_4, msg4, (uint32_t)(MLKEM768_CT_LEN + ct4_len), &txrx_us, &frame_frags, &frame_wire) != 0) return -1;
            frag->msg_bytes_sum[3] += (double)(MLKEM768_CT_LEN + ct4_len);
            frag->msg_wire_sum[3] += (double)frame_wire;
            frag->msg_frags_sum[3] += (double)frame_frags;
            frag->msg_count[3] += 1.0;

            {
                uint8_t ack_type = 0;
                uint8_t ack_payload[1];
                uint32_t ack_len = 0;
                if (recv_wrapped_frame_ex(sockfd, &ack_type, ack_payload, sizeof(ack_payload), &ack_len, &txrx_us, &frame_frags, &frame_wire) != 0) return -1;
                if (ack_type != MSG_TYPE_4 || ack_len != 0) return -1;
                frag->ack_frags_sum += (double)frame_frags;
                frag->ack_wire_sum += (double)frame_wire;
            }
        }

        double wall1 = now_us();
        double cpu1 = cpu_now_us();
        uint64_t mem1 = memory_now_bytes();
        if (mem1 > mem_peak) mem_peak = mem1;

        total_wall += (wall1 - wall0);
        total_txrx += txrx_us;
        total_cpu += (cpu1 - cpu0);

        if (it == 0 && has_prk_export) {
            derive_msk_emsk(prk_export, out_msk, out_emsk);
        }

        BENCH_AAA_TICK(sec);
    }

    timing->total_us[sec] = total_wall / iterations;
    timing->txrx_us[sec] = total_txrx / iterations;
    timing->precomp_us[sec] = total_precomp / iterations;
    timing->processing_us[sec] = timing->total_us[sec] - timing->txrx_us[sec] - timing->precomp_us[sec];
    if (timing->processing_us[sec] < 0) timing->processing_us[sec] = 0;
    timing->overhead_us[sec] = 0;

    ov->cpu_time_us[sec] = total_cpu / iterations;
    ov->wall_time_us[sec] = total_wall / iterations;
    ov->cpu_to_wall_ratio[sec] = (total_wall > 0.0) ? (total_cpu / total_wall) : 0.0;
    ov->protocol_state_bytes[sec] = estimate_protocol_state_bytes(ops, sec, iterations);
    ov->rss_peak_bytes[sec] = mem_peak;
    ov->crypto_time_est_us[sec] = estimate_crypto_time_us(ops, sec, iterations);
    ov->io_wait_us[sec] = total_txrx / iterations;
    ov->residual_overhead_us[sec] = ov->wall_time_us[sec] - ov->crypto_time_est_us[sec] - ov->io_wait_us[sec];
    if (ov->residual_overhead_us[sec] < 0) ov->residual_overhead_us[sec] = 0;

    return 0;
}

static int run_crypto_benchmark(struct crypto_row *rows, size_t *out_rows, int iterations)
{
    double *samples = calloc((size_t)iterations, sizeof(double));
    if (!samples) return -1;

    size_t n = 0;

    uint8_t pk_k[MLKEM768_PK_LEN], sk_k[MLKEM768_SK_LEN];
    for (int i = 0; i < iterations; i++) {
        double t0 = now_us();
        pq_mlkem768_keygen(pk_k, sk_k);
        double t1 = now_us();
        samples[i] = t1 - t0;
    }
    rows[n++] = (struct crypto_row){"ML-KEM-768", "Keygen", compute_stats(samples, iterations), (uint64_t)iterations, MLKEM768_PK_LEN};

    for (int i = 0; i < iterations; i++) {
        uint8_t ct[MLKEM768_CT_LEN], ss[MLKEM768_SS_LEN];
        double t0 = now_us();
        pq_mlkem768_encaps(ct, ss, pk_k);
        double t1 = now_us();
        samples[i] = t1 - t0;
    }
    rows[n++] = (struct crypto_row){"ML-KEM-768", "Encaps", compute_stats(samples, iterations), (uint64_t)iterations, MLKEM768_CT_LEN};

    uint8_t ct_k[MLKEM768_CT_LEN], ss_k[MLKEM768_SS_LEN];
    pq_mlkem768_encaps(ct_k, ss_k, pk_k);
    for (int i = 0; i < iterations; i++) {
        uint8_t ss2[MLKEM768_SS_LEN];
        double t0 = now_us();
        pq_mlkem768_decaps(ss2, ct_k, sk_k);
        double t1 = now_us();
        samples[i] = t1 - t0;
    }
    rows[n++] = (struct crypto_row){"ML-KEM-768", "Decaps", compute_stats(samples, iterations), (uint64_t)iterations, MLKEM768_SS_LEN};

    uint8_t sig_pk[MLDSA65_PK_LEN], sig_sk[MLDSA65_SK_LEN];
    pq_mldsa65_keygen(sig_pk, sig_sk);
    uint8_t msg[64];
    randombytes_buf(msg, sizeof(msg));
    for (int i = 0; i < iterations; i++) {
        uint8_t sig[MLDSA65_SIG_MAX_LEN];
        size_t sig_len = 0;
        double t0 = now_us();
        pq_mldsa65_sign(sig, &sig_len, msg, sizeof(msg), sig_sk);
        double t1 = now_us();
        samples[i] = t1 - t0;
    }
    rows[n++] = (struct crypto_row){"MLDSA65", "Signature", compute_stats(samples, iterations), (uint64_t)iterations, MLDSA65_SIG_MAX_LEN};

    uint8_t sig[MLDSA65_SIG_MAX_LEN];
    size_t sig_len = 0;
    pq_mldsa65_sign(sig, &sig_len, msg, sizeof(msg), sig_sk);
    for (int i = 0; i < iterations; i++) {
        double t0 = now_us();
        pq_mldsa65_verify(sig, sig_len, msg, sizeof(msg), sig_pk);
        double t1 = now_us();
        samples[i] = t1 - t0;
    }
    rows[n++] = (struct crypto_row){"MLDSA65", "Verify", compute_stats(samples, iterations), (uint64_t)iterations, MLDSA65_PK_LEN};

    free(samples);
    *out_rows = n;
    return 0;
}

int main(int argc, char **argv)
{
    int port = (argc > 1) ? atoi(argv[1]) : 9000;
    int iterations = (argc > 2) ? atoi(argv[2]) : 50;
    int crypto_iterations = (argc > 3) ? atoi(argv[3]) : 300;
    int eap_mtu = (argc > 4) ? atoi(argv[4]) : EAP_MTU_DEFAULT;
    int eap_method_type = (argc > 5) ? atoi(argv[5]) : EAP_METHOD_TYPE_EXPERIMENTAL;
#ifdef BENCH_AAA
    if (argc > 6) g_aaa_host = argv[6];
    if (argc > 7) g_aaa_port = (uint16_t)atoi(argv[7]);
    if (argc > 8) g_aaa_secret = argv[8];
#endif

    if (sodium_init() < 0) {
        fprintf(stderr, "sodium_init failed\n");
        return 1;
    }

    mkdir("output", 0755);

    int sockfd = listen_server(port);
    if (sockfd < 0) {
        fprintf(stderr, "cannot bind/listen on port %d (%s)\n", port, strerror(errno));
        return 1;
    }

    if (eap_wrap_init(&g_eap, EAP_WRAP_RESPONDER, (uint8_t)eap_method_type, (uint16_t)eap_mtu) != 0) {
        fprintf(stderr, "invalid EAP settings (mtu/method)\n");
        close(sockfd);
        return 1;
    }

    struct local_identity me;
    struct peer_identity peer;
    pq_mldsa65_keygen(me.sig_pk, me.sig_sk);
    pq_mlkem768_keygen(me.kem_pk, me.kem_sk);

    double dummy = 0;
    uint8_t type = 0;
    uint8_t recv_buf[4096];
    uint32_t recv_len = 0;

    if (eap_send_identity_request(&g_eap, sockfd, &dummy) != 0) return 1;
    if (eap_expect_identity_response(&g_eap, sockfd, &dummy) != 0) return 1;
    if (eap_send_start(&g_eap, sockfd, &dummy) != 0) return 1;

    if (recv_wrapped_frame(sockfd, &type, recv_buf, sizeof(recv_buf), &recv_len, &dummy) != 0) return 1;
    if (type != CRED_EXCHANGE_TYPE) return 1;

    size_t off = 0;
    memcpy(peer.sig_pk, recv_buf + off, MLDSA65_PK_LEN);
    off += MLDSA65_PK_LEN;
    memcpy(peer.kem_pk, recv_buf + off, MLKEM768_PK_LEN);

    uint8_t cred_payload[MLDSA65_PK_LEN + MLKEM768_PK_LEN];
    size_t cred_len = 0;
    memcpy(cred_payload + cred_len, me.sig_pk, MLDSA65_PK_LEN);
    cred_len += MLDSA65_PK_LEN;
    memcpy(cred_payload + cred_len, me.kem_pk, MLKEM768_PK_LEN);
    cred_len += MLKEM768_PK_LEN;

    if (send_wrapped_frame(sockfd, CRED_EXCHANGE_TYPE, cred_payload, (uint32_t)cred_len, &dummy) != 0) return 1;

    struct role_stats op_stats;
    struct timing_accum timing;
    struct overhead_accum overhead;
    struct frag_accum frag_stats[SECTION_COUNT];
    uint8_t msk[SECTION_COUNT][64];
    uint8_t emsk[SECTION_COUNT][64];
    memset(&op_stats, 0, sizeof(op_stats));
    memset(&timing, 0, sizeof(timing));
    memset(&overhead, 0, sizeof(overhead));
    memset(frag_stats, 0, sizeof(frag_stats));
    memset(msk, 0, sizeof(msk));
    memset(emsk, 0, sizeof(emsk));

    for (int sec = 0; sec < SECTION_COUNT; sec++) {
        if (section_run_responder(sockfd, sec, &op_stats, &timing, &overhead, &me, &peer, msk[sec], emsk[sec], &frag_stats[sec], iterations) != 0) {
            fprintf(stderr, "section %s failed\n", SECTION_NAMES[sec]);
            close(sockfd);
            return 1;
        }
    }

    if (eap_send_success(&g_eap, sockfd, &dummy) != 0) {
        close(sockfd);
        return 1;
    }

    struct crypto_row rows[16];
    size_t nrows = 0;
    if (run_crypto_benchmark(rows, &nrows, crypto_iterations) != 0) {
        close(sockfd);
        return 1;
    }

    write_crypto_csv("output/benchmark_crypto_eap" BENCH_TAG "_responder.csv", rows, nrows);
    write_operation_csv("output/benchmark_fullhandshake_operation_p2p_eap" BENCH_TAG "_responder.csv", ROLE_NAMES[ROLE_RESPONDER], &op_stats, iterations);
    write_overhead_csv("output/benchmark_fullhandshake_overhead_p2p_eap" BENCH_TAG "_responder.csv", ROLE_NAMES[ROLE_RESPONDER], &overhead);
    write_processing_csv("output/benchmark_fullhandshake_processing_p2p_eap" BENCH_TAG "_responder.csv", ROLE_NAMES[ROLE_RESPONDER], &timing);
    write_eap_keymat_csv("output/benchmark_eap_keymat" BENCH_TAG "_responder.csv", msk, emsk);
    write_fragmentation_csv("output/benchmark_fragmentation_eap" BENCH_TAG "_responder.csv", frag_stats, &op_stats, iterations, eap_mtu);
#ifdef BENCH_AAA
    write_aaa_csv("output/benchmark_aaa_auth_p2p_eap_aaa_responder.csv");
#endif

    close(sockfd);
    return 0;
}
