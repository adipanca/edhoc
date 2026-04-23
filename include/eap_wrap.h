#ifndef EAP_WRAP_H
#define EAP_WRAP_H

#include <stddef.h>
#include <stdint.h>

struct eap_wrap_ctx {
    uint8_t role;
    uint8_t method_type;
    uint16_t mtu;
    uint8_t next_identifier;
};

enum eap_wrap_role {
    EAP_WRAP_INITIATOR = 0,
    EAP_WRAP_RESPONDER = 1,
};

int eap_wrap_init(struct eap_wrap_ctx *ctx, uint8_t role, uint8_t method_type, uint16_t mtu);

int eap_send_identity_request(struct eap_wrap_ctx *ctx, int sockfd, double *txrx_us);
int eap_expect_identity_request(struct eap_wrap_ctx *ctx, int sockfd, double *txrx_us);
int eap_send_identity_response(struct eap_wrap_ctx *ctx, int sockfd, double *txrx_us);
int eap_expect_identity_response(struct eap_wrap_ctx *ctx, int sockfd, double *txrx_us);

int eap_send_start(struct eap_wrap_ctx *ctx, int sockfd, double *txrx_us);
int eap_expect_start(struct eap_wrap_ctx *ctx, int sockfd, double *txrx_us);

int eap_send_success(struct eap_wrap_ctx *ctx, int sockfd, double *txrx_us);
int eap_expect_success(struct eap_wrap_ctx *ctx, int sockfd, double *txrx_us);

int eap_send_wrapped_frame(struct eap_wrap_ctx *ctx,
                           int sockfd,
                           uint8_t edhoc_type,
                           const uint8_t *payload,
                           uint32_t len,
                           double *txrx_us);

int eap_send_wrapped_frame_ex(struct eap_wrap_ctx *ctx,
                              int sockfd,
                              uint8_t edhoc_type,
                              const uint8_t *payload,
                              uint32_t len,
                              double *txrx_us,
                              uint32_t *out_fragments,
                              uint32_t *out_wire_bytes);

int eap_recv_wrapped_frame(struct eap_wrap_ctx *ctx,
                           int sockfd,
                           uint8_t *edhoc_type,
                           uint8_t *payload,
                           uint32_t cap,
                           uint32_t *len,
                           double *txrx_us);

int eap_recv_wrapped_frame_ex(struct eap_wrap_ctx *ctx,
                              int sockfd,
                              uint8_t *edhoc_type,
                              uint8_t *payload,
                              uint32_t cap,
                              uint32_t *len,
                              double *txrx_us,
                              uint32_t *out_fragments,
                              uint32_t *out_wire_bytes);

#endif
