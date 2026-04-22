/*
 * AAA-mode EAP responder = identical EDHOC/EAP responder logic plus a
 * RADIUS Access-Request hop to the FreeRADIUS AAA server after every
 * section iteration. Implemented by re-including the standalone EAP
 * responder source with BENCH_AAA / BENCH_TAG defined so output CSVs
 * land in distinct files.
 */
#define BENCH_AAA
#define BENCH_TAG "_aaa"
#include "p2p_eap_responder.c"
