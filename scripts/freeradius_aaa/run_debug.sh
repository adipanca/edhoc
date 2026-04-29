#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
FR_DIR="$ROOT_DIR/lib/freeradius-server"
RDB_DIR="$ROOT_DIR/output/freeradius_aaa/raddb"
PID_FILE="$ROOT_DIR/output/freeradius_aaa/freeradius.pid"
LOG_FILE="$ROOT_DIR/output/freeradius_aaa/freeradius_debug.log"
DICT_DIR="$ROOT_DIR/output/freeradius_aaa/dictionary"

if [[ ! -d "$DICT_DIR" ]]; then
  DICT_DIR="$FR_DIR/share/dictionary"
fi

if [[ ! -d "$RDB_DIR" ]]; then
  echo "ERROR: Missing prepared config at $RDB_DIR"
  echo "Run: scripts/freeradius_aaa/prepare.sh"
  exit 1
fi

if [[ ! -d "$DICT_DIR" ]]; then
  echo "ERROR: Dictionary directory not found at $DICT_DIR"
  exit 1
fi

if [[ -x "$FR_DIR/build/bin/local/radiusd" ]]; then
  RAD_BIN="$FR_DIR/build/bin/local/radiusd"
elif command -v radiusd >/dev/null 2>&1; then
  RAD_BIN="$(command -v radiusd)"
elif [[ -x /usr/sbin/freeradius ]]; then
  RAD_BIN="/usr/sbin/freeradius"
else
  echo "ERROR: radiusd binary not found. Build FreeRADIUS first or install package:"
  echo "  sudo apt install freeradius freeradius-utils"
  exit 1
fi

mkdir -p "$(dirname "$LOG_FILE")"

echo "Starting FreeRADIUS debug mode..."
echo "  binary : $RAD_BIN"
echo "  raddb  : $RDB_DIR"
echo "  dict   : $DICT_DIR"
echo "  log    : $LOG_FILE"

if [[ "$RAD_BIN" == "$FR_DIR"/* ]]; then
  export LD_LIBRARY_PATH="$FR_DIR/build/lib/local:$FR_DIR/build/lib:${LD_LIBRARY_PATH:-}"
  export FR_LIBRARY_PATH="$FR_DIR/build/lib/local"

  if [[ -d "$FR_DIR/build/lib/local/.libs" ]]; then
    find "$FR_DIR/build/lib/local/.libs" -maxdepth 1 -type f -name '*.so' \
      -exec ln -sf {} "$FR_DIR/build/lib/local"/ \;
  fi
  if [[ -d "$FR_DIR/build/lib/.libs" ]]; then
    find "$FR_DIR/build/lib/.libs" -maxdepth 1 -type f -name '*.so' \
      -exec ln -sf {} "$FR_DIR/build/lib"/ \;
  fi
fi

"$RAD_BIN" -X -d "$RDB_DIR" -D "$DICT_DIR" -n radiusd | tee "$LOG_FILE"
