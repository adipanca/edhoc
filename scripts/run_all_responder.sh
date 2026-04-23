#!/usr/bin/env bash
# Wrapper that runs all 3 benchmark modes (Non-EAP, EAP standalone, EAP+AAA)
# sequentially on the responder/server side using one base port.
#
# Usage:
#   ./build/responder <base_port>
#
# Derived ports:
#   <base_port>     -> Non-EAP        (p2p_responder)
#   <base_port>+1   -> EAP standalone (p2p_eap_responder)
#   <base_port>+2   -> EAP + AAA hop  (p2p_eap_aaa_responder)
#
# Tunables via env:
#   ITER          (default 5)   number of handshake iterations per section
#   CRYPTO_ITER   (default 5)   per-operation crypto benchmark iterations
#   MTU           (default 256) EAP MTU
#   EAP_METHOD    (default 57)  EAP method type
#   AAA_PORT      (default 3812) FreeRADIUS auth port
#   SKIP_FREERADIUS=1 to skip starting FreeRADIUS (assume already running)
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." >/dev/null 2>&1 && pwd)"
CONFIG_FILE="${CONFIG_FILE:-$REPO_ROOT/config/benchmark.conf}"
[ -f "$CONFIG_FILE" ] && . "$CONFIG_FILE"

BASE_PORT=${1:-${BASE_PORT:-15000}}
ITER=${ITER:-5}
CRYPTO_ITER=${CRYPTO_ITER:-5}
MTU=${MTU:-256}
EAP_METHOD=${EAP_METHOD:-57}
AAA_PORT=${AAA_PORT:-3812}

BUILD_DIR="$REPO_ROOT/build"
OUTPUT_DIR="$REPO_ROOT/output"
DETAIL_DIR="$OUTPUT_DIR/detail"
RESULT_DIR="$OUTPUT_DIR/result"
mkdir -p "$DETAIL_DIR" "$RESULT_DIR"

PORT_NONEAP=$BASE_PORT
PORT_EAP=$((BASE_PORT + 1))
PORT_AAA=$((BASE_PORT + 2))

cd "$REPO_ROOT"

FR_PID=""
cleanup() {
    if [ -n "$FR_PID" ] && kill -0 "$FR_PID" 2>/dev/null; then
        echo "[responder] stopping FreeRADIUS (pid=$FR_PID)"
        kill "$FR_PID" 2>/dev/null || true
        wait "$FR_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

start_freeradius() {
    if [ "${SKIP_FREERADIUS:-0}" = "1" ]; then
        echo "[responder] SKIP_FREERADIUS=1, assuming FreeRADIUS already up"
        return
    fi
    if ss -lun 2>/dev/null | grep -q ":${AAA_PORT}\b"; then
        echo "[responder] FreeRADIUS already listening on UDP/$AAA_PORT, reusing"
        return
    fi
    if [ ! -d "$OUTPUT_DIR/freeradius_aaa/raddb" ]; then
        echo "[responder] running prepare.sh (first-time FreeRADIUS setup)"
        "$REPO_ROOT/scripts/freeradius_aaa/prepare.sh"
    fi
    echo "[responder] starting FreeRADIUS on UDP/$AAA_PORT"
    "$REPO_ROOT/scripts/freeradius_aaa/run_server.sh" \
        > "$OUTPUT_DIR/freeradius_aaa/run.log" 2>&1 &
    FR_PID=$!
    # Wait up to 8s for the port to come up.
    for _ in $(seq 1 40); do
        if ss -lun 2>/dev/null | grep -q ":${AAA_PORT}\b"; then
            echo "[responder] FreeRADIUS up (pid=$FR_PID)"
            return
        fi
        sleep 0.2
    done
    echo "[responder] WARNING: FreeRADIUS did not start within 8s; AAA mode will likely fail" >&2
}

run_step() {
    local label=$1; shift
    echo "[responder] === $label ==="
    echo "[responder] cmd: $*"
    "$@"
}

# Mode 1 - Non-EAP
run_step "Mode 1 (Non-EAP)" \
    "$BUILD_DIR/p2p_responder" "$PORT_NONEAP" "$ITER" "$CRYPTO_ITER"

# Mode 2 - EAP standalone
run_step "Mode 2 (EAP standalone)" \
    "$BUILD_DIR/p2p_eap_responder" "$PORT_EAP" "$ITER" "$CRYPTO_ITER" "$MTU" "$EAP_METHOD"

# Mode 3 - EAP + AAA
start_freeradius
run_step "Mode 3 (EAP + AAA hop)" \
    "$BUILD_DIR/p2p_eap_aaa_responder" "$PORT_AAA" "$ITER" "$CRYPTO_ITER" "$MTU" "$EAP_METHOD"

# Merge per-mode CSVs into output/result/
echo "[responder] === merging CSVs from $DETAIL_DIR into $RESULT_DIR ==="
python3 "$REPO_ROOT/scripts/merge_benchmarks.py" \
    --output-dir "$DETAIL_DIR" \
    --result-dir "$RESULT_DIR"

echo "[responder] DONE"
