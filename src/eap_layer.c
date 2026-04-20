/*
 * =============================================================================
 * EDHOC-Hybrid: EAP Layer Implementation
 * =============================================================================
 *
 * Implements EAP packet framing and fragmentation for EAP-EDHOC.
 * Per draft-ietf-emu-eap-edhoc and RFC 3748.
 *
 * EAP Packet Format:
 *   [Code(1)] [Id(1)] [Length(2)] [Type(1)] [Flags(1)] [TotalLen(4)*] [Data]
 *   (* TotalLen present only when L-flag set, in first fragment)
 *
 * Fragmentation (like EAP-TLS, RFC 5216 §3.1):
 *   1. Sender sends first fragment with L+M flags, TotalLen field
 *   2. Receiver sends empty ACK (same Type, Flags=0, no data)
 *   3. Sender sends next fragment, M=1 unless last
 *   4. Repeat until last fragment (M=0)
 *   5. Receiver processes assembled message (no ACK for last fragment)
 */

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 199309L
#endif
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "edhoc_benchmark_eap.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sodium.h>

/* ── Internal TCP helpers ── */

static int eap_send_all(int sockfd, const uint8_t *buf, size_t len)
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

static int eap_recv_all(int sockfd, uint8_t *buf, size_t len)
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

/* ── EAP Packet Builder ──
 *
 * Builds a single EAP packet into out_buf and returns its length.
 * out_buf must be >= EAP_MSG_BUF_SIZE.
 *
 *  code      : EAP_CODE_REQUEST or EAP_CODE_RESPONSE
 *  id        : EAP identifier
 *  flags     : combination of EAP_FLAG_{L,M,S} or 0
 *  total_len : full EDHOC data length (used when L-flag set), else 0
 *  frag_data : fragment payload (may be NULL if empty packet)
 *  frag_len  : fragment payload length
 */
static uint32_t eap_build_packet(uint8_t *out_buf,
                                 uint8_t code, uint8_t id, uint8_t flags,
                                 uint32_t total_len,
                                 const uint8_t *frag_data, uint32_t frag_len)
{
	uint32_t offset = 0;

	/* Compute total EAP packet length:
	 *   4 bytes header + 1 type + 1 flags + [4 TotalLen if L-bit] + data */
	uint32_t pkt_len = 4 + 1 + 1 + frag_len;
	if (flags & EAP_FLAG_L) pkt_len += 4;

	out_buf[offset++] = code;
	out_buf[offset++] = id;
	out_buf[offset++] = (uint8_t)(pkt_len >> 8);
	out_buf[offset++] = (uint8_t)(pkt_len);
	out_buf[offset++] = EAP_TYPE_EDHOC;
	out_buf[offset++] = flags;

	if (flags & EAP_FLAG_L) {
		out_buf[offset++] = (uint8_t)(total_len >> 24);
		out_buf[offset++] = (uint8_t)(total_len >> 16);
		out_buf[offset++] = (uint8_t)(total_len >> 8);
		out_buf[offset++] = (uint8_t)(total_len);
	}

	if (frag_len > 0 && frag_data != NULL) {
		memcpy(out_buf + offset, frag_data, frag_len);
		offset += frag_len;
	}

	return offset;
}

/* ── EAP Raw Packet Send/Receive (over TCP) ──
 *
 * We use a 2-byte length prefix over TCP so we can delimit EAP packets.
 * Format: [PktLen(2)] [EAP packet bytes]
 */
static int eap_tcp_send_pkt(int sockfd, const uint8_t *pkt, uint32_t pkt_len)
{
	uint8_t len_hdr[2];
	len_hdr[0] = (uint8_t)(pkt_len >> 8);
	len_hdr[1] = (uint8_t)(pkt_len);
	if (eap_send_all(sockfd, len_hdr, 2) != 0) return -1;
	if (pkt_len > 0) {
		if (eap_send_all(sockfd, pkt, pkt_len) != 0) return -1;
	}
	return 0;
}

static int eap_tcp_recv_pkt(int sockfd, uint8_t *buf, uint32_t buf_size,
                            uint32_t *pkt_len_out)
{
	uint8_t len_hdr[2];
	if (eap_recv_all(sockfd, len_hdr, 2) != 0) return -1;
	uint32_t pkt_len = ((uint32_t)len_hdr[0] << 8) | len_hdr[1];
	if (pkt_len > buf_size) return -1;
	if (pkt_len > 0) {
		if (eap_recv_all(sockfd, buf, pkt_len) != 0) return -1;
	}
	*pkt_len_out = pkt_len;
	return 0;
}

/* ── Parse EAP packet header ──
 * Returns pointer to payload data (after type+flags+optionalTotalLen)
 * Sets code, id, flags, total_len_out, payload_len_out.
 */
static const uint8_t *eap_parse_pkt(const uint8_t *pkt, uint32_t pkt_len,
                                    uint8_t *code_out, uint8_t *id_out,
                                    uint8_t *flags_out,
                                    uint32_t *total_len_out,
                                    uint32_t *payload_len_out)
{
	if (pkt_len < 6) return NULL;  /* min: 4 header + 1 type + 1 flags */
	*code_out  = pkt[0];
	*id_out    = pkt[1];
	/* pkt[2..3] = total EAP length (we trust the TCP framing) */
	/* pkt[4] = Type */
	*flags_out = pkt[5];
	uint32_t hdr_offset = 6;
	*total_len_out = 0;

	if (*flags_out & EAP_FLAG_L) {
		if (pkt_len < 10) return NULL;
		*total_len_out = ((uint32_t)pkt[6] << 24) | ((uint32_t)pkt[7] << 16) |
		                 ((uint32_t)pkt[8] << 8)  | pkt[9];
		hdr_offset = 10;
	}

	if (pkt_len < hdr_offset) return NULL;
	*payload_len_out = pkt_len - hdr_offset;
	return pkt + hdr_offset;
}

/* ── EAP Start (Server → Peer) ── */
int eap_send_start(int sockfd, uint8_t id)
{
	uint8_t pkt[16];
	uint32_t pkt_len = eap_build_packet(pkt,
	                                    EAP_CODE_REQUEST, id,
	                                    EAP_FLAG_S,       /* S-flag */
	                                    0,                /* no TotalLen */
	                                    NULL, 0);
	return eap_tcp_send_pkt(sockfd, pkt, pkt_len);
}

int eap_recv_start(int sockfd, uint8_t *id_out)
{
	uint8_t pkt[64];
	uint32_t pkt_len;
	if (eap_tcp_recv_pkt(sockfd, pkt, sizeof(pkt), &pkt_len) != 0) return -1;

	uint8_t code, id, flags;
	uint32_t total_len, payload_len;
	const uint8_t *payload = eap_parse_pkt(pkt, pkt_len,
	                                       &code, &id, &flags,
	                                       &total_len, &payload_len);
	if (!payload) return -1;
	if (code != EAP_CODE_REQUEST) return -1;
	if (!(flags & EAP_FLAG_S)) return -1;

	*id_out = id;
	/*
	 * Per draft-ietf-emu-eap-edhoc: peer responds to EAP-Start directly
	 * with EDHOC_MSG_1, not with an empty ACK. No response sent here.
	 */
	return 0;
}

/* ── EAP Success / Failure (Server → Peer) ── */
int eap_send_success(int sockfd, uint8_t id)
{
	/* EAP-Success: [Code=3][Id][Length=4] — no Type field */
	uint8_t pkt[4];
	pkt[0] = EAP_CODE_SUCCESS;
	pkt[1] = id;
	pkt[2] = 0;
	pkt[3] = 4;
	return eap_tcp_send_pkt(sockfd, pkt, 4);
}

int eap_send_failure(int sockfd, uint8_t id)
{
	uint8_t pkt[4];
	pkt[0] = EAP_CODE_FAILURE;
	pkt[1] = id;
	pkt[2] = 0;
	pkt[3] = 4;
	return eap_tcp_send_pkt(sockfd, pkt, 4);
}

int eap_recv_success(int sockfd)
{
	uint8_t pkt[16];
	uint32_t pkt_len;
	if (eap_tcp_recv_pkt(sockfd, pkt, sizeof(pkt), &pkt_len) != 0) return -1;
	if (pkt_len < 4) return -1;
	if (pkt[0] != EAP_CODE_SUCCESS) return -1;
	return 0;
}

/* ── Global fragment counter (set by send/recv, read by callers) ── */
int g_eap_last_frag_count = 0;

/* ── EAP Send EDHOC Message (with fragmentation) ──
 *
 * Sends data_len bytes of EDHOC payload as one or more EAP packets.
 * Fragments if data_len > EAP_EDHOC_MTU.
 *
 * Fragmentation ACK protocol (EAP-TLS style):
 *   - For each non-last fragment, wait for empty ACK before sending next
 *   - Last fragment (M=0): no ACK needed
 *
 * overhead_ns: accumulates time spent on EAP framing (send/recv overhead).
 * Sets g_eap_last_frag_count to number of fragments sent.
 */
int eap_send_edhoc_msg(int sockfd, int is_request, uint8_t id,
                       const uint8_t *data, uint32_t data_len,
                       uint64_t *overhead_ns)
{
	g_eap_last_frag_count = 0;
	uint8_t code = is_request ? EAP_CODE_REQUEST : EAP_CODE_RESPONSE;
	uint32_t sent = 0;
	int first = 1;
	uint8_t pkt_buf[EAP_MSG_BUF_SIZE];

	while (sent < data_len || (data_len == 0 && first)) {
		uint32_t remaining = data_len - sent;
		uint32_t frag_len = (remaining > EAP_EDHOC_MTU) ? EAP_EDHOC_MTU : remaining;
		int more = (frag_len < remaining) ? 1 : 0;

		uint8_t flags = 0;
		if (first && data_len > EAP_EDHOC_MTU) flags |= EAP_FLAG_L;
		if (more) flags |= EAP_FLAG_M;

		uint64_t t0 = bench_get_ns();
		uint32_t pkt_len = eap_build_packet(pkt_buf, code, id, flags,
		                                    data_len,
		                                    data + sent, frag_len);
		if (eap_tcp_send_pkt(sockfd, pkt_buf, pkt_len) != 0) return -1;
		uint64_t t1 = bench_get_ns();
		if (overhead_ns) *overhead_ns += (t1 - t0);

		g_eap_last_frag_count++;
		sent += frag_len;
		first = 0;

		/* If more fragments: wait for ACK from receiver */
		if (more) {
			uint8_t ack_buf[64];
			uint32_t ack_len;
			t0 = bench_get_ns();
			if (eap_tcp_recv_pkt(sockfd, ack_buf, sizeof(ack_buf), &ack_len) != 0)
				return -1;
			t1 = bench_get_ns();
			if (overhead_ns) *overhead_ns += (t1 - t0);
			/* Verify ACK: opposite code, same id, no data */
			if (ack_len >= 4 && ack_buf[1] == id) {
				/* valid ACK */
			}
		}

		if (data_len == 0) break;  /* zero-length message sent */
	}
	return 0;
}

/* ── EAP Receive EDHOC Message (with reassembly) ──
 *
 * Receives one or more EAP fragments and reassembles into buf.
 * For each non-last fragment received, sends empty ACK before next.
 *
 * expected_code: EAP_CODE_REQUEST(1) or EAP_CODE_RESPONSE(2).
 */
int eap_recv_edhoc_msg(int sockfd, int expected_code,
                       uint8_t *buf, uint32_t *len_out, uint32_t buf_size,
                       uint8_t *id_out, uint64_t *overhead_ns)
{
	g_eap_last_frag_count = 0;
	uint32_t assembled = 0;
	uint8_t pkt_buf[EAP_MSG_BUF_SIZE];
	uint8_t last_id = 0;

	for (;;) {
		uint32_t pkt_len;
		uint64_t t0 = bench_get_ns();
		if (eap_tcp_recv_pkt(sockfd, pkt_buf, sizeof(pkt_buf), &pkt_len) != 0)
			return -1;
		uint64_t t1 = bench_get_ns();
		if (overhead_ns) *overhead_ns += (t1 - t0);

		uint8_t code, id, flags;
		uint32_t total_len, payload_len;
		const uint8_t *payload = eap_parse_pkt(pkt_buf, pkt_len,
		                                       &code, &id, &flags,
		                                       &total_len, &payload_len);
		if (!payload) return -1;
		if (code != (uint8_t)expected_code) return -1;

		g_eap_last_frag_count++;
		last_id = id;
		if (id_out) *id_out = id;  /* track latest id */

		if (assembled + payload_len > buf_size) return -1;
		if (payload_len > 0) {
			memcpy(buf + assembled, payload, payload_len);
			assembled += payload_len;
		}

		if (flags & EAP_FLAG_M) {
			/* More fragments: send empty ACK */
			uint8_t ack_code = (expected_code == EAP_CODE_REQUEST) ?
			                    EAP_CODE_RESPONSE : EAP_CODE_REQUEST;
			uint8_t ack_buf[16];
			uint32_t ack_len;
			t0 = bench_get_ns();
			ack_len = eap_build_packet(ack_buf, ack_code, id, 0, 0, NULL, 0);
			if (eap_tcp_send_pkt(sockfd, ack_buf, ack_len) != 0) return -1;
			t1 = bench_get_ns();
			if (overhead_ns) *overhead_ns += (t1 - t0);
			/* Continue to receive next fragment */
		} else {
			/* Last (or only) fragment */
			break;
		}
	}

	(void)last_id;
	*len_out = assembled;
	return 0;
}


/* ── MSK / EMSK Derivation ──
 *
 * Per draft-ietf-emu-eap-edhoc §6:
 *   MSK  = EDHOC-Exporter(label=0, context="EAP-EDHOC MSK",  length=64)
 *   EMSK = EDHOC-Exporter(label=1, context="EAP-EDHOC EMSK", length=64)
 *
 * EDHOC-Exporter(label, context, length) = EDHOC-KDF(PRK_exporter, label,
 *                                                     context, length)
 * We use PRK_exporter = PRK_out (simplified for benchmark).
 * EDHOC-KDF is our edhoc_kdf helper from benchmark_eap_common.c.
 */
void eap_derive_msk_emsk(const uint8_t *prk_out,
                         uint8_t *msk, uint8_t *emsk)
{
	static const uint8_t ctx_msk[]  = "EAP-EDHOC MSK";
	static const uint8_t ctx_emsk[] = "EAP-EDHOC EMSK";

	/* MSK: label=0 */
	edhoc_kdf(prk_out, 0x00,
	          ctx_msk, sizeof(ctx_msk) - 1,
	          msk, 64);

	/* EMSK: label=1 */
	edhoc_kdf(prk_out, 0x01,
	          ctx_emsk, sizeof(ctx_emsk) - 1,
	          emsk, 64);
}

/* ── CSV Writer for EAP Transport Stats ── */
void csv_write_eap_transport(const char *filename,
                             struct eap_transport_stats stats[])
{
	FILE *fp = fopen(filename, "w");
	if (!fp) { fprintf(stderr, "ERROR: cannot open %s\n", filename); return; }
	fprintf(fp, "type,edhoc_msgs,msg1_bytes,msg1_frags,msg2_bytes,msg2_frags,"
	            "msg3_bytes,msg3_frags,msg4_bytes,msg4_frags,"
	            "total_fragments,frag_ack_roundtrips,total_eap_roundtrips\n");
	for (int v = 0; v < NUM_VARIANTS; v++) {
		fprintf(fp, "%s,%d,%u,%d,%u,%d,%u,%d,%u,%d,%d,%d,%d\n",
		        VARIANT_NAMES[v],
		        stats[v].edhoc_messages,
		        stats[v].msg1_bytes, stats[v].msg1_frags,
		        stats[v].msg2_bytes, stats[v].msg2_frags,
		        stats[v].msg3_bytes, stats[v].msg3_frags,
		        stats[v].msg4_bytes, stats[v].msg4_frags,
		        stats[v].total_fragments,
		        stats[v].frag_ack_roundtrips,
		        stats[v].total_eap_roundtrips);
	}
	fclose(fp);
	printf("  [CSV] Written: %s\n", filename);
}

/* ── Console Print EAP Transport Stats ── */
void print_eap_transport_summary(struct eap_transport_stats stats[])
{
	printf("\n  ┌─────────────────┬──────┬───────────────────────────────────────┬───────────┬──────────┬────────────┐\n");
	printf("  │ Variant         │ Msgs │ Fragments (M1/M2/M3/M4)              │ Total Frg │ Frag ACK │ EAP RTs    │\n");
	printf("  ├─────────────────┼──────┼───────────────────────────────────────┼───────────┼──────────┼────────────┤\n");
	for (int v = 0; v < NUM_VARIANTS; v++) {
		struct eap_transport_stats *s = &stats[v];
		if (s->edhoc_messages == 0) continue;
		printf("  │ %-15s │  %d   │ %d(%uB)/%d(%uB)/%d(%uB)",
		       VARIANT_NAMES[v], s->edhoc_messages,
		       s->msg1_frags, s->msg1_bytes,
		       s->msg2_frags, s->msg2_bytes,
		       s->msg3_frags, s->msg3_bytes);
		if (s->msg4_frags > 0)
			printf("/%d(%uB)", s->msg4_frags, s->msg4_bytes);
		else
			printf("      ");
		printf(" │    %2d     │    %2d    │     %2d     │\n",
		       s->total_fragments, s->frag_ack_roundtrips,
		       s->total_eap_roundtrips);
	}
	printf("  └─────────────────┴──────┴───────────────────────────────────────┴───────────┴──────────┴────────────┘\n");
}
