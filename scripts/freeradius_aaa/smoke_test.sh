#!/usr/bin/env bash
set -euo pipefail

SERVER="${1:-127.0.0.1}"
PORT="${2:-1812}"
SECRET="${3:-testing123}"
USER="${4:-edhoc_Type0_classic}"
PASS="${5:-edhoc-pass}"

if ! command -v radclient >/dev/null 2>&1; then
  echo "ERROR: radclient not found"
  exit 1
fi

printf 'User-Name = "%s"\nUser-Password = "%s"\nNAS-IP-Address = 127.0.0.1\n' "$USER" "$PASS" \
  | radclient -x -t 2 -r 1 "$SERVER:$PORT" auth "$SECRET"
