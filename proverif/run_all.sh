#!/usr/bin/env bash
# proverif/run_all.sh -- run all 5 EAP-EDHOC-PQ-AAA ProVerif models.
#
# Q1..Q7 are evaluated as written in each section{N}.pv file.
# To evaluate Q8 (FS), Q9 (AEAD-key/IV reuse), or Q10 (Quantum Resilience),
# uncomment the inline `[Q8 FS LEAK]` / `[Q9 AEAD LEAK]` / `[Q10 PQ LEAK]`
# blocks in the corresponding section file, then re-run.
#
# Usage:
#   ./run_all.sh                 # runs all five sections
#   ./run_all.sh section33.pv    # run a single file
#
# Outputs: per-section .log file with full ProVerif trace and a RESULT summary.

set -u
HERE=$(cd "$(dirname "$0")" && pwd)
cd "$HERE"

FILES=("$@")
if [[ ${#FILES[@]} -eq 0 ]]; then
  FILES=(section2.pv section32.pv section33.pv section34.pv section35.pv)
fi

mkdir -p logs
for f in "${FILES[@]}"; do
  base=${f%.pv}
  log="logs/${base}.log"
  echo "==== running $f -> $log ===="
  proverif "$f" >"$log" 2>&1 || true
  echo "---- $f RESULT summary ----"
  grep -E '^RESULT' "$log" || echo "(no RESULT lines yet -- check $log)"
  echo
done
