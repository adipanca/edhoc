#include "benchmark.h"
#include "eap_wrap.h"

#include <string.h>

#define MSG_TYPE_EAP_PACKET 0xE1

#define EAP_CODE_REQUEST 1
#define EAP_CODE_RESPONSE 2
#define EAP_CODE_SUCCESS 3

#define EAP_DATA_HDR_LEN 2
#define EAP_HDR_LEN 5
#define EAP_WRAP_HDR_LEN (EAP_HDR_LEN + EAP_DATA_HDR_LEN)

#define EAP_FLAG_S 0x10
#define EAP_FLAG_M 0x08
#define EAP_FLAG_L_MASK 0x07

#define EAP_EDHOC_SIGNAL_START 0xFA
#define EAP_EDHOC_SIGNAL_IDENTITY 0xFB

static uint8_t tx_code(const struct eap_wrap_ctx *ctx)
{
    return (ctx->role == EAP_WRAP_INITIATOR) ? EAP_CODE_RESPONSE : EAP_CODE_REQUEST;
}

static uint8_t rx_code(const struct eap_wrap_ctx *ctx)
{
    return (ctx->role == EAP_WRAP_INITIATOR) ? EAP_CODE_REQUEST : EAP_CODE_RESPONSE;
}

int eap_wrap_init(struct eap_wrap_ctx *ctx, uint8_t role, uint8_t method_type, uint16_t mtu)
{
    if (ctx == NULL) return -1;
    if (mtu <= EAP_WRAP_HDR_LEN) return -1;

    ctx->role = role;
    ctx->method_type = method_type;
    ctx->mtu = mtu;
    ctx->next_identifier = 1;
    return 0;
}

static int eap_send_signal(struct eap_wrap_ctx *ctx, int sockfd, uint8_t signal, uint8_t code, double *txrx_us)
{
    uint8_t pkt[EAP_WRAP_HDR_LEN + 1];
    uint16_t eap_len = (uint16_t)(EAP_WRAP_HDR_LEN + 1);

    pkt[0] = code;
    pkt[1] = ctx->next_identifier++;
    pkt[2] = (uint8_t)((eap_len >> 8) & 0xFF);
    pkt[3] = (uint8_t)(eap_len & 0xFF);
    pkt[4] = ctx->method_type;
    pkt[5] = EAP_FLAG_S;
    pkt[6] = signal;

    return send_frame(sockfd, MSG_TYPE_EAP_PACKET, pkt, sizeof(pkt), txrx_us);
}

static int eap_expect_signal(struct eap_wrap_ctx *ctx, int sockfd, uint8_t expected_signal, uint8_t expected_code, double *txrx_us)
{
    uint8_t transport_type = 0;
    uint8_t pkt[256];
    uint32_t len = 0;
    uint16_t eap_len = 0;

    if (recv_frame(sockfd, &transport_type, pkt, sizeof(pkt), &len, txrx_us) != 0) return -1;
    if (transport_type != MSG_TYPE_EAP_PACKET) return -1;
    if (len < (EAP_WRAP_HDR_LEN + 1)) return -1;
    if (pkt[0] != expected_code) return -1;
    if (pkt[4] != ctx->method_type) return -1;

    eap_len = (uint16_t)(((uint16_t)pkt[2] << 8) | pkt[3]);
    if (eap_len != len) return -1;
    if ((pkt[5] & EAP_FLAG_S) == 0) return -1;
    if (pkt[6] != expected_signal) return -1;

    return 0;
}

int eap_send_identity_request(struct eap_wrap_ctx *ctx, int sockfd, double *txrx_us)
{
    return eap_send_signal(ctx, sockfd, EAP_EDHOC_SIGNAL_IDENTITY, EAP_CODE_REQUEST, txrx_us);
}

int eap_expect_identity_request(struct eap_wrap_ctx *ctx, int sockfd, double *txrx_us)
{
    return eap_expect_signal(ctx, sockfd, EAP_EDHOC_SIGNAL_IDENTITY, EAP_CODE_REQUEST, txrx_us);
}

int eap_send_identity_response(struct eap_wrap_ctx *ctx, int sockfd, double *txrx_us)
{
    return eap_send_signal(ctx, sockfd, EAP_EDHOC_SIGNAL_IDENTITY, EAP_CODE_RESPONSE, txrx_us);
}

int eap_expect_identity_response(struct eap_wrap_ctx *ctx, int sockfd, double *txrx_us)
{
    return eap_expect_signal(ctx, sockfd, EAP_EDHOC_SIGNAL_IDENTITY, EAP_CODE_RESPONSE, txrx_us);
}

int eap_send_start(struct eap_wrap_ctx *ctx, int sockfd, double *txrx_us)
{
    return eap_send_signal(ctx, sockfd, EAP_EDHOC_SIGNAL_START, EAP_CODE_REQUEST, txrx_us);
}

int eap_expect_start(struct eap_wrap_ctx *ctx, int sockfd, double *txrx_us)
{
    return eap_expect_signal(ctx, sockfd, EAP_EDHOC_SIGNAL_START, EAP_CODE_REQUEST, txrx_us);
}

int eap_send_success(struct eap_wrap_ctx *ctx, int sockfd, double *txrx_us)
{
    uint8_t pkt[EAP_HDR_LEN];
    uint16_t eap_len = EAP_HDR_LEN;

    pkt[0] = EAP_CODE_SUCCESS;
    pkt[1] = ctx->next_identifier++;
    pkt[2] = (uint8_t)((eap_len >> 8) & 0xFF);
    pkt[3] = (uint8_t)(eap_len & 0xFF);
    pkt[4] = 0;

    return send_frame(sockfd, MSG_TYPE_EAP_PACKET, pkt, sizeof(pkt), txrx_us);
}

int eap_expect_success(struct eap_wrap_ctx *ctx, int sockfd, double *txrx_us)
{
    (void)ctx;

    uint8_t transport_type = 0;
    uint8_t pkt[64];
    uint32_t len = 0;
    uint16_t eap_len = 0;

    if (recv_frame(sockfd, &transport_type, pkt, sizeof(pkt), &len, txrx_us) != 0) return -1;
    if (transport_type != MSG_TYPE_EAP_PACKET) return -1;
    if (len != EAP_HDR_LEN) return -1;
    if (pkt[0] != EAP_CODE_SUCCESS) return -1;

    eap_len = (uint16_t)(((uint16_t)pkt[2] << 8) | pkt[3]);
    if (eap_len != EAP_HDR_LEN) return -1;

    return 0;
}

int eap_send_wrapped_frame_ex(struct eap_wrap_ctx *ctx,
                              int sockfd,
                              uint8_t edhoc_type,
                              const uint8_t *payload,
                              uint32_t len,
                              double *txrx_us,
                              uint32_t *out_fragments,
                              uint32_t *out_wire_bytes)
{
    uint32_t off = 0;
    uint32_t remaining = len;
    uint32_t total_len = len;
    uint8_t code = tx_code(ctx);
    uint8_t identifier = ctx->next_identifier++;
    uint16_t chunk_cap = (uint16_t)(ctx->mtu - EAP_WRAP_HDR_LEN);
    uint8_t first = 1;
    uint32_t frag_count = 0;
    uint32_t wire_bytes = 0;

    if (chunk_cap == 0) return -1;

    while (off < len || (len == 0 && off == 0)) {
        uint8_t pkt[2048];
        uint8_t len_field[4] = {0};
        uint8_t len_field_len = 0;
        uint16_t header_extra = 0;
        uint16_t chunk_len;
        uint16_t eap_len;
        uint8_t flags = 0;

        if (chunk_cap > sizeof(pkt) - EAP_WRAP_HDR_LEN) {
            chunk_cap = (uint16_t)(sizeof(pkt) - EAP_WRAP_HDR_LEN);
        }

        if (first && total_len > chunk_cap) {
            if (total_len <= 0xFFU) len_field_len = 1;
            else if (total_len <= 0xFFFFU) len_field_len = 2;
            else if (total_len <= 0xFFFFFFU) len_field_len = 3;
            else len_field_len = 4;

            for (uint8_t i = 0; i < len_field_len; i++) {
                len_field[len_field_len - 1 - i] = (uint8_t)((total_len >> (8 * i)) & 0xFF);
            }
            header_extra = len_field_len;
            if (chunk_cap <= header_extra) return -1;
        }

        {
            uint32_t max_payload = (uint32_t)(chunk_cap - header_extra);
            chunk_len = (uint16_t)(remaining > max_payload ? max_payload : remaining);
        }
        if (len == 0) {
            chunk_len = 0;
        }

        if (first) {
            flags |= EAP_FLAG_S;
            flags |= (len_field_len & EAP_FLAG_L_MASK);
        }
        if ((off + chunk_len) < len) flags |= EAP_FLAG_M;

        eap_len = (uint16_t)(EAP_WRAP_HDR_LEN + header_extra + chunk_len);
        pkt[0] = code;
        pkt[1] = identifier;
        pkt[2] = (uint8_t)((eap_len >> 8) & 0xFF);
        pkt[3] = (uint8_t)(eap_len & 0xFF);
        pkt[4] = ctx->method_type;
        pkt[5] = flags;
        pkt[6] = edhoc_type;
        if (len_field_len > 0) {
            memcpy(pkt + EAP_WRAP_HDR_LEN, len_field, len_field_len);
        }
        if (chunk_len > 0) {
            memcpy(pkt + EAP_WRAP_HDR_LEN + len_field_len, payload + off, chunk_len);
        }

        if (send_frame(sockfd, MSG_TYPE_EAP_PACKET, pkt, eap_len, txrx_us) != 0) return -1;
        frag_count += 1;
        wire_bytes += (uint32_t)eap_len;

        if (len == 0) {
            break;
        }
        off += chunk_len;
        remaining -= chunk_len;
        first = 0;
    }

    if (out_fragments != NULL) *out_fragments = frag_count;
    if (out_wire_bytes != NULL) *out_wire_bytes = wire_bytes;

    return 0;
}

int eap_send_wrapped_frame(struct eap_wrap_ctx *ctx,
                           int sockfd,
                           uint8_t edhoc_type,
                           const uint8_t *payload,
                           uint32_t len,
                           double *txrx_us)
{
    return eap_send_wrapped_frame_ex(ctx, sockfd, edhoc_type, payload, len, txrx_us, NULL, NULL);
}

int eap_recv_wrapped_frame_ex(struct eap_wrap_ctx *ctx,
                              int sockfd,
                              uint8_t *edhoc_type,
                              uint8_t *payload,
                              uint32_t cap,
                              uint32_t *len,
                              double *txrx_us,
                              uint32_t *out_fragments,
                              uint32_t *out_wire_bytes)
{
    uint8_t code = rx_code(ctx);
    uint8_t identifier = 0;
    uint8_t seen = 0;
    uint8_t transport_type = 0;
    uint32_t expected_total = 0;
    uint8_t have_expected_total = 0;
    uint32_t total = 0;
    uint32_t frag_count = 0;
    uint32_t wire_bytes = 0;

    for (;;) {
        uint8_t pkt[2048];
        uint32_t pkt_len = 0;
        uint16_t eap_len;
        uint16_t frag_len;
        uint8_t flags;
        uint8_t l_bits;
        size_t payload_off = EAP_WRAP_HDR_LEN;

        if (recv_frame(sockfd, &transport_type, pkt, sizeof(pkt), &pkt_len, txrx_us) != 0) return -1;
        if (transport_type != MSG_TYPE_EAP_PACKET) return -1;
        frag_count += 1;
        wire_bytes += pkt_len;
        if (pkt_len < EAP_WRAP_HDR_LEN) return -1;
        if (pkt[0] != code) return -1;
        if (pkt[4] != ctx->method_type) return -1;

        eap_len = (uint16_t)(((uint16_t)pkt[2] << 8) | pkt[3]);
        if (eap_len != pkt_len) return -1;

        flags = pkt[5];
        l_bits = flags & EAP_FLAG_L_MASK;
        if ((flags & EAP_FLAG_S) != 0 && seen != 0) return -1;
        if ((flags & 0xE0) != 0) return -1;

        if (!seen) {
            identifier = pkt[1];
            *edhoc_type = pkt[6];
            seen = 1;
            if ((flags & EAP_FLAG_S) == 0) return -1;
            if (l_bits > 4) return -1;

            if (l_bits > 0) {
                expected_total = 0;
                if (pkt_len < (uint32_t)(EAP_WRAP_HDR_LEN + l_bits)) return -1;
                for (uint8_t i = 0; i < l_bits; i++) {
                    expected_total = (expected_total << 8) | pkt[payload_off + i];
                }
                payload_off += l_bits;
                have_expected_total = 1;
            }
        } else {
            if (pkt[1] != identifier) return -1;
            if (pkt[6] != *edhoc_type) return -1;
            if ((flags & EAP_FLAG_S) != 0) return -1;
            if (l_bits != 0) return -1;
        }

        frag_len = (uint16_t)(pkt_len - payload_off);
        if (total + frag_len > cap) return -1;
        if (frag_len > 0) {
            memcpy(payload + total, pkt + payload_off, frag_len);
            total += frag_len;
        }

        if ((flags & EAP_FLAG_M) == 0) break;
    }

    if (have_expected_total && total != expected_total) return -1;

    *len = total;
    if (out_fragments != NULL) *out_fragments = frag_count;
    if (out_wire_bytes != NULL) *out_wire_bytes = wire_bytes;
    return 0;
}

int eap_recv_wrapped_frame(struct eap_wrap_ctx *ctx,
                           int sockfd,
                           uint8_t *edhoc_type,
                           uint8_t *payload,
                           uint32_t cap,
                           uint32_t *len,
                           double *txrx_us)
{
    return eap_recv_wrapped_frame_ex(ctx, sockfd, edhoc_type, payload, cap, len, txrx_us, NULL, NULL);
}
