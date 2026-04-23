#ifndef AAA_RADIUS_H
#define AAA_RADIUS_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Minimal RADIUS PAP client for AAA-mode benchmarking.
 *
 * Sends a single RFC 2865 Access-Request (PAP) to the given AAA server
 * and waits for an Access-Accept / Access-Reject response.
 *
 * Returns:
 *   2  -> Access-Accept
 *   3  -> Access-Reject
 *  <0  -> transport / encoding error
 *
 * On success (>0) it also fills:
 *   *rtt_us       end-to-end UDP RTT in microseconds (CLOCK_MONOTONIC)
 *   *req_bytes    length of the RADIUS request datagram
 *   *resp_bytes   length of the RADIUS response datagram
 *
 * Any pointer may be NULL if the corresponding metric is not needed.
 */
int aaa_radius_pap_auth(const char *server_ip,
                        uint16_t server_port,
                        const char *shared_secret,
                        const char *username,
                        const char *password,
                        double *rtt_us,
                        size_t *req_bytes,
                        size_t *resp_bytes);

#ifdef __cplusplus
}
#endif

#endif
