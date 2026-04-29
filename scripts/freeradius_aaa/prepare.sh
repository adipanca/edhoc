#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
FR_DIR="$ROOT_DIR/lib/freeradius-server"
OUT_DIR="$ROOT_DIR/output/freeradius_aaa"
RDB_DIR="$OUT_DIR/raddb"
DICT_DIR="$OUT_DIR/dictionary"

# Pick raddb/dictionary source: prefer submodule, fall back to system FreeRADIUS install
if [[ -d "$FR_DIR/raddb" ]]; then
  SRC_RDB="$FR_DIR/raddb"
  SRC_DICT="$FR_DIR/share/dictionary"
elif sudo test -d /etc/freeradius/3.0; then
  SRC_RDB="/etc/freeradius/3.0"
  SRC_DICT="/usr/share/freeradius"
else
  echo "ERROR: FreeRADIUS not found (submodule or system install)."
  echo "Either run 'git submodule update --init --recursive' or 'sudo apt install freeradius freeradius-utils'."
  exit 1
fi

rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR"
sudo cp -a "$SRC_RDB" "$RDB_DIR" 2>/dev/null || cp -a "$SRC_RDB" "$RDB_DIR"
cp -a "$SRC_DICT" "$DICT_DIR"
sudo chown -R "$USER":"$USER" "$RDB_DIR" 2>/dev/null || true
chmod -R u+w "$RDB_DIR"

# Keep AAA benchmark minimal (PAP/files) and avoid EAP/TLS module load.
rm -f "$RDB_DIR/mods-enabled/eap" "$RDB_DIR/mods-enabled/eap_inner" "$RDB_DIR/mods-enabled/cache_eap"

if [[ -f "$RDB_DIR/sites-enabled/default" ]]; then
  # Use non-default auth port to avoid conflict with system freeradius service.
  sed -i 's/port = 1812/port = 3812/g' "$RDB_DIR/sites-enabled/default"
  # Default config uses "port = 0" (uses /etc/services -> 1812). Replace first two
  # uncommented occurrences (auth, acct) to avoid colliding with system FreeRADIUS.
  awk 'BEGIN{n=0} /^[[:space:]]*port[[:space:]]*=[[:space:]]*0[[:space:]]*$/ {sub(/= 0/, ((n%2==0)?"= 3812":"= 3813")); n++} {print}' \
    "$RDB_DIR/sites-enabled/default" > "$RDB_DIR/sites-enabled/default.new" && \
    mv "$RDB_DIR/sites-enabled/default.new" "$RDB_DIR/sites-enabled/default"

  # Comment out any eap { ... } block (handles variations in whitespace/contents)
  perl -0777 -i -pe 's/^([\t ]*)eap[\t ]*\{[^{}]*\}/${1}# eap block disabled for EDHOC AAA benchmark/mg' "$RDB_DIR/sites-enabled/default"
  sed -i 's/^\([[:space:]]*\)eap[[:space:]]*$/\1# eap (disabled for EDHOC AAA benchmark)/' "$RDB_DIR/sites-enabled/default"
fi

if [[ -f "$RDB_DIR/sites-enabled/inner-tunnel" ]]; then
  perl -0777 -i -pe 's/^([\t ]*)eap[\t ]*\{[^{}]*\}/${1}# eap block disabled for EDHOC AAA benchmark/mg' "$RDB_DIR/sites-enabled/inner-tunnel"
  sed -i 's/^\([[:space:]]*\)eap[[:space:]]*$/\1# eap (disabled for EDHOC AAA benchmark)/' "$RDB_DIR/sites-enabled/inner-tunnel"
  sed -i 's/port = 18120/port = 38120/g' "$RDB_DIR/sites-enabled/inner-tunnel"
fi

# Reuse the built-in localhost client (127.0.0.1, secret testing123)
# and ensure no duplicate EDHOC client stanza exists.
perl -0777 -i -pe 's/\n# EDHOC AAA benchmark client\nclient edhocbench \{.*?\n\}\n/\n/s' "$RDB_DIR/clients.conf"

if ! grep -q "edhoc_Type0_classic" "$RDB_DIR/mods-config/files/authorize"; then
cat >> "$RDB_DIR/mods-config/files/authorize" <<'EOF'

# EDHOC AAA benchmark test users
edhoc_Type0_classic Cleartext-Password := "edhoc-pass"
edhoc_Type0_PQ Cleartext-Password := "edhoc-pass"
edhoc_Type3_Classic Cleartext-Password := "edhoc-pass"
edhoc_Type3_PQ Cleartext-Password := "edhoc-pass"
edhoc_Type3_Hybrid Cleartext-Password := "edhoc-pass"
EOF
fi

echo "Prepared FreeRADIUS AAA config at: $RDB_DIR"
echo "Next: scripts/freeradius_aaa/run_debug.sh"
