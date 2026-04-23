#!/usr/bin/env bash
# Wrapper that runs all 3 benchmark modes (Non-EAP, EAP standalone, EAP+AAA)
# sequentially on the initiator/client side using one base port.
#
# Usage:
#   ./build/initiator <responder_ip> <base_port>
#
# Derived ports:
#   <base_port>     -> Non-EAP        (p2p_initiator)
#   <base_port>+1   -> EAP standalone (p2p_eap_initiator)
#   <base_port>+2   -> EAP + AAA hop  (p2p_eap_aaa_initiator)
#
# Tunables via env (must match responder side):
#   ITER          (default 5)
#   CRYPTO_ITER   (default 5)
#   MTU           (default 256)
#   EAP_METHOD    (default 57)
#   START_DELAY   (default 1)   seconds to wait for responder readiness per mode
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." >/dev/null 2>&1 && pwd)"
CONFIG_FILE="${CONFIG_FILE:-$REPO_ROOT/config/benchmark.conf}"
[ -f "$CONFIG_FILE" ] && . "$CONFIG_FILE"

RESP_IP=${1:-${RESPONDER_IP:-127.0.0.1}}
BASE_PORT=${2:-${BASE_PORT:-15000}}
ITER=${ITER:-5}
CRYPTO_ITER=${CRYPTO_ITER:-5}
MTU=${MTU:-256}
EAP_METHOD=${EAP_METHOD:-57}
START_DELAY=${START_DELAY:-1}

BUILD_DIR="$REPO_ROOT/build"
OUTPUT_DIR="$REPO_ROOT/output"
DETAIL_DIR="$OUTPUT_DIR/detail"
RESULT_DIR="$OUTPUT_DIR/result"
mkdir -p "$DETAIL_DIR" "$RESULT_DIR"

PORT_NONEAP=$BASE_PORT
PORT_EAP=$((BASE_PORT + 1))
PORT_AAA=$((BASE_PORT + 2))

cd "$REPO_ROOT"

run_step() {
    local label=$1; shift
    echo "[initiator] === $label ==="
    echo "[initiator] cmd: $*"
    sleep "$START_DELAY"
    "$@"
}

run_step "Mode 1 (Non-EAP)" \
    "$BUILD_DIR/p2p_initiator" "$RESP_IP" "$PORT_NONEAP" "$ITER" "$CRYPTO_ITER"

run_step "Mode 2 (EAP standalone)" \
    "$BUILD_DIR/p2p_eap_initiator" "$RESP_IP" "$PORT_EAP" "$ITER" "$CRYPTO_ITER" "$MTU" "$EAP_METHOD"

run_step "Mode 3 (EAP + AAA hop)" \
    "$BUILD_DIR/p2p_eap_aaa_initiator" "$RESP_IP" "$PORT_AAA" "$ITER" "$CRYPTO_ITER" "$MTU" "$EAP_METHOD"

echo "[initiator] === merging CSVs from $DETAIL_DIR into $RESULT_DIR ==="
python3 "$REPO_ROOT/scripts/merge_benchmarks.py" \
    --output-dir "$DETAIL_DIR" \
    --result-dir "$RESULT_DIR"

echo "[initiator] DONE"
