#!/usr/bin/env bash
# Prepare a self-contained FreeRADIUS configuration tree under
# output/freeradius_aaa/raddb that supports the EDHOC AAA benchmark
# (PAP authentication for all five Papon EDHOC variants / sections).
#
# Source priority:
#   1. lib/freeradius-server submodule when it carries a v3-style raddb
#      (radiusd.conf present).
#   2. system /etc/freeradius/3.0 (Debian/Ubuntu package layout).
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
FR_DIR="$ROOT_DIR/lib/freeradius-server"
OUT_DIR="$ROOT_DIR/output/freeradius_aaa"
RDB_DIR="$OUT_DIR/raddb"
DICT_DIR="$OUT_DIR/dictionary"

SRC_RADDB=""
SRC_DICT=""
SUDO=""
if [[ -f "$FR_DIR/raddb/radiusd.conf" ]]; then
  SRC_RADDB="$FR_DIR/raddb"
  SRC_DICT="$FR_DIR/share/dictionary"
elif sudo -n test -d "/etc/freeradius/3.0" 2>/dev/null; then
  SRC_RADDB="/etc/freeradius/3.0"
  SRC_DICT="/usr/share/freeradius"
  SUDO="sudo"
else
  echo "ERROR: FreeRADIUS v3 config not found (submodule or system /etc/freeradius/3.0)." >&2
  exit 1
fi

rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR" "$OUT_DIR/log" "$OUT_DIR/run" "$OUT_DIR/db"

$SUDO cp -aL "$SRC_RADDB" "$RDB_DIR"
[[ -n "$SUDO" ]] && sudo chown -R "$(id -u)":"$(id -g)" "$RDB_DIR"
[[ -d "$SRC_DICT" ]] && cp -aL "$SRC_DICT" "$DICT_DIR" || true

# 1. Drop EAP/TLS modules so we run pure PAP and avoid loading TLS deps.
rm -f "$RDB_DIR/mods-enabled/eap" \
      "$RDB_DIR/mods-enabled/eap_inner" \
      "$RDB_DIR/mods-enabled/cache_eap" 2>/dev/null || true

# 2. Run as the current (non-root) user; redirect log/run/db dirs into
#    output/ which is writable.
CUR_USER="$(id -un)"
CUR_GROUP="$(id -gn)"
if [[ -f "$RDB_DIR/radiusd.conf" ]]; then
  sed -i "s/^[[:space:]]*user[[:space:]]*=.*/	user = ${CUR_USER}/"   "$RDB_DIR/radiusd.conf"
  sed -i "s/^[[:space:]]*group[[:space:]]*=.*/	group = ${CUR_GROUP}/" "$RDB_DIR/radiusd.conf"
  sed -i "s|^[[:space:]]*logdir[[:space:]]*=.*|logdir = $OUT_DIR/log|" "$RDB_DIR/radiusd.conf"
  sed -i "s|^[[:space:]]*run_dir[[:space:]]*=.*|run_dir = $OUT_DIR/run|" "$RDB_DIR/radiusd.conf"
  sed -i "s|^[[:space:]]*db_dir[[:space:]]*=.*|db_dir = $OUT_DIR/db|"   "$RDB_DIR/radiusd.conf"
fi

# 3. Comment out 'eap { ok = return ... }' blocks in the virtual servers
#    and any bare 'eap' policy invocations now that the module is gone.
for vs in "$RDB_DIR/sites-enabled/default" "$RDB_DIR/sites-enabled/inner-tunnel"; do
  [[ -f "$vs" ]] || continue
  perl -0777 -i -pe '
    s/^([\t ]*)eap\s*\{[^}]*\}/$1# eap block disabled for EDHOC AAA benchmark/mg;
  ' "$vs" || true
  sed -i 's/^\([[:space:]]*\)eap[[:space:]]*$/\1# eap (disabled for EDHOC AAA benchmark)/' "$vs"
done

# 4. Switch every 'listen { ... port = 0 ... }' block in sites-enabled
#    so the auth listener uses 3812 and acct uses 3813. The default
#    config uses 'port = 0' which falls back to /etc/services 1812/1813
#    and would collide with a system FreeRADIUS service.
for vs in "$RDB_DIR/sites-enabled/default" "$RDB_DIR/sites-enabled/inner-tunnel"; do
  [[ -f "$vs" ]] || continue
  python3 - "$vs" <<'PYEOF'
import sys, re
path = sys.argv[1]
with open(path) as f:
    src = f.read()
out = []
i = 0
N = len(src)
pat = re.compile(r'(^|\n)([ \t]*)listen[ \t]*\{', re.M)
while i < N:
    m = pat.search(src, i)
    if not m:
        out.append(src[i:]); break
    j = m.start(2) if m.group(1) == '\n' else m.start()
    if m.group(1) == '\n':
        # include the leading newline in the preserved text
        out.append(src[i:m.start()+1])
    else:
        out.append(src[i:j])
    k = src.index('{', m.end()-1)
    depth = 1; p = k + 1
    while p < N and depth > 0:
        if src[p] == '{': depth += 1
        elif src[p] == '}': depth -= 1
        p += 1
    block = src[j:p]
    typ = re.search(r'^[ \t]*type[ \t]*=[ \t]*(\w+)', block, re.M)
    if typ and typ.group(1) == 'auth':
        block = re.sub(r'(^[ \t]*)port[ \t]*=[ \t]*(?:0|1812)\b', r'\1port = 3812', block, count=1, flags=re.M)
    elif typ and typ.group(1) == 'acct':
        block = re.sub(r'(^[ \t]*)port[ \t]*=[ \t]*(?:0|1813)\b', r'\1port = 3813', block, count=1, flags=re.M)
    out.append(block)
    i = p
with open(path, 'w') as f:
    f.write(''.join(out))
PYEOF
done

# 5. Add one PAP test user per Papon EDHOC section/variant.
USERS_FILE=""
for cand in "$RDB_DIR/mods-config/files/authorize" "$RDB_DIR/users"; do
  [[ -f "$cand" ]] && USERS_FILE="$cand" && break
done
if [[ -z "$USERS_FILE" ]]; then
  echo "ERROR: cannot locate the FreeRADIUS users file." >&2
  exit 1
fi
if ! grep -q "edhoc_Section2" "$USERS_FILE"; then
cat >> "$USERS_FILE" <<'EOF'

# EDHOC AAA benchmark test users (one per Papon section / variant)
edhoc_Section2  Cleartext-Password := "edhoc-pass"
edhoc_Section32 Cleartext-Password := "edhoc-pass"
edhoc_Section33 Cleartext-Password := "edhoc-pass"
edhoc_Section34 Cleartext-Password := "edhoc-pass"
edhoc_Section35 Cleartext-Password := "edhoc-pass"
EOF
fi

# 6. Make sure the localhost client / shared secret is present.
if ! grep -qE '^\s*client\s+localhost\s*\{' "$RDB_DIR/clients.conf"; then
cat >> "$RDB_DIR/clients.conf" <<'EOF'

client localhost {
    ipaddr = 127.0.0.1
    secret = testing123
    require_message_authenticator = no
}
EOF
fi

echo "Prepared FreeRADIUS AAA config at: $RDB_DIR"
echo "  auth port : 3812 (UDP)"
echo "  client    : 127.0.0.1 / testing123"
echo "  users     : edhoc_Section{2,32,33,34,35}  pass = edhoc-pass"
echo "Next: scripts/freeradius_aaa/run_server.sh"
