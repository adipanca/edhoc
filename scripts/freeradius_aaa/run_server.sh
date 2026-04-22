#!/usr/bin/env bash
# Run the FreeRADIUS AAA server with the EDHOC benchmark configuration.
# Prefers the locally-built submodule binary; falls back to the system
# /usr/sbin/freeradius if the submodule was not built.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
FR_DIR="$ROOT_DIR/lib/freeradius-server"
OUT_DIR="$ROOT_DIR/output/freeradius_aaa"
RDB_DIR="$OUT_DIR/raddb"
LOG_FILE="$OUT_DIR/freeradius_benchmark.log"
DICT_DIR="$OUT_DIR/dictionary"
DEBUG="${DEBUG:-0}"

if [[ ! -d "$RDB_DIR" ]]; then
  echo "ERROR: prepared config missing at $RDB_DIR" >&2
  echo "Run: scripts/freeradius_aaa/prepare.sh first" >&2
  exit 1
fi

if [[ -x "$FR_DIR/build/bin/local/radiusd" ]]; then
  RAD_BIN="$FR_DIR/build/bin/local/radiusd"
elif [[ -x "/usr/sbin/freeradius" ]]; then
  RAD_BIN="/usr/sbin/freeradius"
elif command -v radiusd >/dev/null 2>&1; then
  RAD_BIN="$(command -v radiusd)"
else
  echo "ERROR: no radiusd / freeradius binary found." >&2
  exit 1
fi

mkdir -p "$OUT_DIR"

ARGS=( -f -d "$RDB_DIR" -l stdout )
[[ -f "$DICT_DIR/dictionary" ]] && ARGS+=( -D "$DICT_DIR" )
[[ "$DEBUG" == "1" ]] && ARGS+=( -X )

echo "Starting FreeRADIUS AAA server"
echo "  binary : $RAD_BIN"
echo "  raddb  : $RDB_DIR"
echo "  log    : $LOG_FILE"
echo "  port   : 3812/udp"
exec "$RAD_BIN" "${ARGS[@]}" 2>&1 | tee "$LOG_FILE"
