/*
 * =============================================================================
 * EDHOC-Hybrid: EAP-EDHOC Benchmark Header
 * Based on draft-ietf-emu-eap-edhoc
 * =============================================================================
 *
 * EAP-EDHOC wraps EDHOC messages in EAP Request/Response packets over TCP.
 *
 * EAP Packet Format (over TCP):
 *   [Code(1)] [Id(1)] [Length(2)] [Type(1)] [Flags(1)] [TotalLen(4,if L-bit)] [Data...]
 *
 * Codes: 1=Request, 2=Response, 3=Success, 4=Failure
 * Type:  0xFE = 254 (Experimental, per IANA; used for EAP-EDHOC)
 * Flags: L=0x80 (Length present), M=0x40 (More fragments), S=0x20 (Start)
 *
 * EAP-EDHOC Handshake Flow:
 *   Server → Peer: EAP-Request/EAP-EDHOC-Start   (S-flag, empty payload)
 *   Peer → Server: EAP-Response/EAP-EDHOC(MSG_1) [fragmented if large]
 *   Server → Peer: EAP-Request/EAP-EDHOC(MSG_2)  [fragmented if large]
 *   Peer → Server: EAP-Response/EAP-EDHOC(MSG_3) [fragmented if large]
 *   Server → Peer: EAP-Success                   (triggers MSK derivation)
 *
 * MSK/EMSK Derivation (per draft-ietf-emu-eap-edhoc):
 *   MSK  (64B) = EDHOC-Exporter(0, "EAP-EDHOC MSK",  64) from PRK_out
 *   EMSK (64B) = EDHOC-Exporter(1, "EAP-EDHOC EMSK", 64) from PRK_out
 */

#ifndef EDHOC_BENCHMARK_EAP_H
#define EDHOC_BENCHMARK_EAP_H

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 199309L
#endif

#include "edhoc_benchmark_p2p.h"   /* Reuse all structs, macros, timing helpers */

/* ── EAP Protocol Constants ── */
#define EAP_CODE_REQUEST     1
#define EAP_CODE_RESPONSE    2
#define EAP_CODE_SUCCESS     3
#define EAP_CODE_FAILURE     4

/*
 * EAP Method Type for EAP-EDHOC.
 * IANA allocation still in progress (draft-ietf-emu-eap-edhoc).
 * Using 0xFE (254 = Expanded Type / Experimental) as per IANA RFC 3748 §6.2.
 */
#define EAP_TYPE_EDHOC       0xFE

/* EAP Flags (bit field in Flags byte) */
#define EAP_FLAG_L           0x80   /* Total-Length field present */
#define EAP_FLAG_M           0x40   /* More fragments */
#define EAP_FLAG_S           0x20   /* EAP-EDHOC Start */

/* EAP MTU for EDHOC data (bytes per fragment).
 * 802.11 default MTU is 1020; we use 1000 to leave room for EAP overhead.
 * Classic variants (~35-200 byte msgs) will use 1 fragment.
 * PQ/Hybrid variants (1200+ byte msgs) will need 2+ fragments. */
#define EAP_EDHOC_MTU        1000

/* ── EAP Default Port ── */
#define EAP_DEFAULT_PORT     9877

/* ── EAP Message Buffer ── */
#define EAP_MSG_BUF_SIZE     16384

/* ── EAP Transport Stats (fragment/round-trip tracking per variant) ── */
struct eap_transport_stats {
	int msg1_frags;          /* fragments for MSG1 */
	int msg2_frags;          /* fragments for MSG2 */
	int msg3_frags;          /* fragments for MSG3 */
	int msg4_frags;          /* fragments for MSG4 (Type3_PQ only, else 0) */
	uint32_t msg1_bytes;     /* raw EDHOC payload bytes for MSG1 */
	uint32_t msg2_bytes;     /* raw EDHOC payload bytes for MSG2 */
	uint32_t msg3_bytes;     /* raw EDHOC payload bytes for MSG3 */
	uint32_t msg4_bytes;     /* raw EDHOC payload bytes for MSG4 */
	int total_fragments;     /* total fragments across all messages */
	int frag_ack_roundtrips; /* number of fragment ACKs (each is 1 extra RT) */
	int edhoc_messages;      /* 3 or 4 */
	int total_eap_roundtrips;/* Start + msgs + frag_acks + Success */
};

extern struct eap_transport_stats g_eap_transport[];

/* Global fragment counter set by eap_send/recv_edhoc_msg */
extern int g_eap_last_frag_count;

/* ── EAP Layer Functions (defined in eap_layer.c) ── */

/*
 * eap_send_edhoc_msg:
 *   Sends EDHOC data as one or more EAP Request/Response packets.
 *   Handles fragmentation if data_len > EAP_EDHOC_MTU.
 *   If is_request=1: sends EAP-Request(code=1); else EAP-Response(code=2).
 *   id: EAP identifier for this exchange.
 *   overhead_ns: accumulates EAP framing overhead time (not crypto).
 */
int eap_send_edhoc_msg(int sockfd, int is_request, uint8_t id,
                       const uint8_t *data, uint32_t data_len,
                       uint64_t *overhead_ns);

/*
 * eap_recv_edhoc_msg:
 *   Receives and reassembles fragmented EAP packets.
 *   Handles ACK sending for each received fragment.
 *   Returns assembled EDHOC data in buf[].
 *   expected_code: 1=Request, 2=Response.
 *   id_out: outputs the EAP identifier of the received (last) packet.
 *   overhead_ns: accumulates EAP framing overhead time.
 */
int eap_recv_edhoc_msg(int sockfd, int expected_code,
                       uint8_t *buf, uint32_t *len_out, uint32_t buf_size,
                       uint8_t *id_out, uint64_t *overhead_ns);

/*
 * eap_send_start:
 *   Server sends EAP-Request with S-flag (EAP-EDHOC Start).
 *   This initiates the EAP-EDHOC session.
 */
int eap_send_start(int sockfd, uint8_t id);

/*
 * eap_recv_start:
 *   Peer (initiator) receives EAP-Request/Start from server.
 *   Records id_out for use in subsequent Response.
 *   Does NOT send an ACK — peer responds directly with MSG_1.
 */
int eap_recv_start(int sockfd, uint8_t *id_out);

/*
 * eap_send_success / eap_send_failure:
 *   Server sends EAP-Success or EAP-Failure.
 */
int eap_send_success(int sockfd, uint8_t id);
int eap_send_failure(int sockfd, uint8_t id);

/*
 * eap_recv_success:
 *   Peer (initiator) receives EAP-Success.
 *   Returns 0 on success, -1 on error.
 */
int eap_recv_success(int sockfd);

/*
 * eap_derive_msk_emsk:
 *   Derives MSK (64 bytes) and EMSK (64 bytes) from PRK_out.
 *   Uses HKDF-Expand based EDHOC-Exporter as per RFC 9528 §4.2.1.
 */
void eap_derive_msk_emsk(const uint8_t *prk_out,
                         uint8_t *msk, uint8_t *emsk);

/* ── EAP handshake function declarations ── */
/* Each variant runs N iterations of the EDHOC handshake wrapped in EAP */

int eap_handshake_type0_classic_initiator(int sockfd, int variant);
int eap_handshake_type0_classic_responder(int sockfd, int variant);

int eap_handshake_type0_pq_initiator(int sockfd, int variant);
int eap_handshake_type0_pq_responder(int sockfd, int variant);

int eap_handshake_type3_classic_initiator(int sockfd, int variant);
int eap_handshake_type3_classic_responder(int sockfd, int variant);

int eap_handshake_type3_pq_initiator(int sockfd, int variant);
int eap_handshake_type3_pq_responder(int sockfd, int variant);

int eap_handshake_type3_hybrid_initiator(int sockfd, int variant);
int eap_handshake_type3_hybrid_responder(int sockfd, int variant);

/* ── EAP Transport Stats CSV / Print ── */
void csv_write_eap_transport(const char *filename,
							 struct eap_transport_stats stats[]);
void print_eap_transport_summary(struct eap_transport_stats stats[]);

/* p2p_send_msg / p2p_recv_msg are still available from edhoc_benchmark_p2p.h
 * for the pre-handshake static key exchange (not part of EAP session). */

#endif /* EDHOC_BENCHMARK_EAP_H */
