#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Conformance runner for the Rust NOA-receipt verifier (impl-rust) vs the Python
# reference (impl-py/noa_verify.py). GROUND TRUTH = impl-py exit code.
#
# For every receipt vector it runs BOTH verifiers with IDENTICAL arguments and asserts the exit codes
# match. One mismatch fails the whole run (no partial credit — a single silently-accepted attack is a
# complete failure). Non-receipt fixtures (trust inputs / docs) are excluded explicitly, with the reason.
#
# Exit: 0 = every checked vector agreed with impl-py; 1 = at least one mismatch.
# ─────────────────────────────────────────────────────────────────────────────
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"          # worktree root: holds conformance/ + impl-py/
BIN="$SCRIPT_DIR/target/release/noa-verify"
PY="${PYTHON:-python3}"
PYV="$ROOT/impl-py/noa_verify.py"
CONF="$ROOT/conformance"
G="$CONF/golden/0.3.0"
V="$CONF/vectors"

if [[ ! -x "$BIN" ]]; then
  echo "FATAL: $BIN not built. Run: (cd $SCRIPT_DIR && cargo build --release)"; exit 2
fi

PASS=0; FAIL=0
declare -a FAILED=()

# run_case <category> <label> <arg...>
# runs impl-py and the rust bin with the same args; compares exit codes.
run_case() {
  local cat="$1"; local label="$2"; shift 2
  "$PY" "$PYV" "$@" >/dev/null 2>&1; local pe=$?
  "$BIN" "$@" >/dev/null 2>&1; local re=$?
  local names=( VALID UNVERIFIED TAMPERED MALFORMED USAGE UNTRUSTED )
  # map exit 5 -> index 5 (UNTRUSTED); exits 0..4 map directly
  local pn="${names[$pe]:-EXIT$pe}"; local rn="${names[$re]:-EXIT$re}"
  if [[ "$pe" == "$re" ]]; then
    PASS=$((PASS+1))
    printf '  PASS  [%-13s] %-52s py=%s(%d) rust=%s(%d)\n' "$cat" "$label" "$pn" "$pe" "$rn" "$re"
  else
    FAIL=$((FAIL+1)); FAILED+=("$label")
    printf '  FAIL  [%-13s] %-52s py=%s(%d) rust=%s(%d)\n' "$cat" "$label" "$pn" "$pe" "$rn" "$re"
  fi
}

echo "════════════════════════════════════════════════════════════════════════"
echo " NOA-receipt conformance: impl-rust  vs  impl-py (ground truth)"
echo " rust: $BIN"
echo " py  : $PY $PYV"
echo "════════════════════════════════════════════════════════════════════════"

echo
echo "── GOLDEN v0.3.0 backcompat (MANIFEST scenarios, static file combos) ──"
run_case golden      "genesis + keyring (VALID)"                 "$G/genesis/chain.json" "$G/genesis/keyring.json"
run_case golden      "genesis, no keyring (UNVERIFIED)"          "$G/genesis/chain.json"
run_case golden      "multi + keyring (VALID)"                   "$G/multi/chain.json" "$G/multi/keyring.json"
run_case golden      "multi, no keyring (UNVERIFIED)"            "$G/multi/chain.json"
run_case golden      "multi + keyring + checkpoint (VALID)"      "$G/multi/chain.json" "$G/multi/keyring.json" --checkpoint "$G/multi/checkpoint.json"
run_case golden      "identity + keyring + manifest (VALID)"     "$G/identity/chain.json" "$G/identity/keyring.json" --identity "$G/identity/manifest.json"
run_case golden      "identity + keyring, no manifest (VALID)"   "$G/identity/chain.json" "$G/identity/keyring.json"
run_case golden      "impersonation, no manifest (VALID kid-lvl)" "$G/identity/impersonation-chain.json" "$G/identity/keyring.json"
run_case golden      "impersonation + manifest (UNTRUSTED)"      "$G/identity/impersonation-chain.json" "$G/identity/keyring.json" --identity "$G/identity/manifest.json"

echo
echo "── ATTACK vectors (keyring = vectors/keyring.json; checkpoint where relevant) ──"
KR="$V/keyring.json"
run_case attack      "tampered-content"                          "$V/attack/tampered-content.json" "$KR"
run_case attack      "wrong-signature"                           "$V/attack/wrong-signature.json" "$KR"
run_case attack      "unknown-kid"                               "$V/attack/unknown-kid.json" "$KR"
run_case attack      "key-swap"                                  "$V/attack/key-swap.json" "$KR"
run_case attack      "key-swap-resigned"                         "$V/attack/key-swap-resigned.json" "$KR"
run_case attack      "seq-gap"                                   "$V/attack/seq-gap.json" "$KR"
run_case attack      "head-truncated"                            "$V/attack/head-truncated.json" "$KR"
run_case attack      "dup-seq"                                   "$V/attack/dup-seq.json" "$KR"
run_case attack      "cross-chain-splice"                        "$V/attack/cross-chain-splice.json" "$KR"
run_case attack      "relinked"                                  "$V/attack/relinked.json" "$KR"
run_case attack      "forged-genesis"                            "$V/attack/forged-genesis.json" "$KR"
run_case attack      "tail-truncated (+ checkpoint)"             "$V/attack/tail-truncated.json" "$KR" --checkpoint "$V/checkpoint.json"
run_case attack      "forged-checkpoint (+ forged cp)"           "$V/attack/forged-checkpoint-chain.json" "$KR" --checkpoint "$V/attack/forged-checkpoint-cp.json"
run_case attack      "forged-checkpoint-cp as receipts (MALF)"   "$V/attack/forged-checkpoint-cp.json" "$KR"

echo
echo "── MALFORMED vectors (strict parse / structural → MALFORMED) ──"
for f in "$V"/malformed/*.json; do
  run_case malformed  "$(basename "$f")"                         "$f" "$KR"
done

echo
echo "── VALID top-level vector ──"
run_case valid       "valid-chain + keyring (VALID)"             "$V/valid-chain.json" "$KR"
run_case valid       "valid-chain, no keyring (UNVERIFIED)"      "$V/valid-chain.json"

echo
echo "── EXHAUSTIVE FILE SWEEP: every *.json under conformance/{golden,vectors} run"
echo "   identically (bare, no keyring) on BOTH — nothing silently skipped ──"
SWEEP_PASS=0; SWEEP_FAIL=0
while IFS= read -r f; do
  "$PY" "$PYV" "$f" >/dev/null 2>&1; pe=$?
  "$BIN" "$f" >/dev/null 2>&1; re=$?
  if [[ "$pe" == "$re" ]]; then
    SWEEP_PASS=$((SWEEP_PASS+1))
  else
    SWEEP_FAIL=$((SWEEP_FAIL+1)); FAILED+=("sweep:$f (py=$pe rust=$re)")
    printf '  SWEEP-FAIL  %-60s py=%d rust=%d\n' "${f#$ROOT/}" "$pe" "$re"
  fi
done < <(find "$G" "$V" -type f -name '*.json' | sort)
printf '  sweep: %d/%d files agreed (bare receipts path)\n' "$SWEEP_PASS" $((SWEEP_PASS+SWEEP_FAIL))

echo
echo "── EXCLUDED non-receipt fixtures (not receipt chains; run only as trust inputs) ──"
cat <<'EOF'
  conformance/golden/0.3.0/MANIFEST.json        — golden manifest (documentation/oracle), not a chain
  conformance/golden/0.3.0/README.md            — docs
  conformance/golden/0.3.0/*/keyring.json       — trust root (kid -> SPKI), consumed as [keyring.json]
  conformance/golden/0.3.0/identity/manifest.json — identity manifest, consumed via --identity
  conformance/golden/0.3.0/multi/checkpoint.json  — signed checkpoint, consumed via --checkpoint
  conformance/vectors/keyring.json              — trust root, consumed as [keyring.json]
  conformance/vectors/checkpoint.json           — signed checkpoint, consumed via --checkpoint
  conformance/vectors/attack/forged-checkpoint-cp.json — attacker checkpoint, consumed via --checkpoint
  (each is nonetheless swept above as a bare receipts arg → both verifiers agree at MALFORMED)
  NOTE: the golden "multi-truncated dropLast" MANIFEST scenario is a DYNAMIC transform (no static file),
        so its static analogue here is the attack/tail-truncated vector (+ checkpoint) above.
EOF

echo
echo "════════════════════════════════════════════════════════════════════════"
TOTAL=$((PASS+FAIL))
echo " CURATED CASES : $PASS/$TOTAL matched impl-py"
echo " SWEEP         : $SWEEP_PASS/$((SWEEP_PASS+SWEEP_FAIL)) matched impl-py"
if [[ "$FAIL" -eq 0 && "$SWEEP_FAIL" -eq 0 ]]; then
  echo " RESULT        : PASS (all receipt-vectors verdict-identical to impl-py)"
  echo "════════════════════════════════════════════════════════════════════════"
  exit 0
else
  echo " RESULT        : FAIL"
  for x in "${FAILED[@]}"; do echo "   - $x"; done
  echo "════════════════════════════════════════════════════════════════════════"
  exit 1
fi
