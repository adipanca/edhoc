/*
 * AAA-mode EAP initiator = identical EDHOC/EAP initiator logic, only
 * the output CSV filenames differ (suffixed with "_aaa") so the AAA
 * benchmark run does not overwrite the EAP-standalone artifacts.
 */
#define BENCH_TAG "_aaa"
#include "p2p_eap_initiator.c"
