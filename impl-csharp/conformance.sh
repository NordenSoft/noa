#!/usr/bin/env bash
#
# Cross-implementation conformance: the C# verifier (impl-csharp) vs the Python reference
# (impl-py/noa_verify.py, GROUND TRUTH). For every receipt vector under conformance/golden/0.3.0,
# conformance/vectors, and conformance/vectors/attack, BOTH verifiers run with identical arguments
# and their EXIT CODES must match. impl-py is authoritative; a mismatch fails the whole run.
#
# Exit-code legend: 0 VALID · 1 UNVERIFIED · 2 TAMPERED · 3 MALFORMED · 4 USAGE · 5 UNTRUSTED
#
# Usage:  impl-csharp/conformance.sh
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO"

PY="impl-py/noa_verify.py"
EXE="$SCRIPT_DIR/bin/Release/net10.0/noa-verify.dll"

# Build once (quiet) if the binary is missing.
if [ ! -f "$EXE" ]; then
  echo "building impl-csharp (Release)..."
  dotnet build -c Release "$SCRIPT_DIR" >/dev/null || { echo "BUILD FAILED"; exit 2; }
fi

TOTAL=0; PASS=0; FAIL=0

run_case() {
  label="$1"; shift
  python3 "$PY" "$@" >/dev/null 2>&1; py_code=$?
  dotnet "$EXE" "$@" >/dev/null 2>&1; cs_code=$?
  TOTAL=$((TOTAL+1))
  if [ "$py_code" = "$cs_code" ]; then
    PASS=$((PASS+1))
    printf '  PASS  py=%s cs=%s  %s\n' "$py_code" "$cs_code" "$label"
  else
    FAIL=$((FAIL+1))
    printf '  FAIL  py=%s cs=%s  %s\n' "$py_code" "$cs_code" "$label"
  fi
}

KR="conformance/vectors/keyring.json"
CP="conformance/vectors/checkpoint.json"
GEN="conformance/golden/0.3.0"

echo "== golden/0.3.0 (frozen v0.3.0-signed artifacts) =="
run_case "golden genesis + keyring (VALID)"                     "$GEN/genesis/chain.json" "$GEN/genesis/keyring.json"
run_case "golden genesis no-keyring (UNVERIFIED)"              "$GEN/genesis/chain.json"
run_case "golden multi + keyring (VALID)"                      "$GEN/multi/chain.json" "$GEN/multi/keyring.json"
run_case "golden multi no-keyring (UNVERIFIED)"               "$GEN/multi/chain.json"
run_case "golden multi + keyring + checkpoint (VALID)"        "$GEN/multi/chain.json" "$GEN/multi/keyring.json" --checkpoint "$GEN/multi/checkpoint.json"
run_case "golden identity + keyring (VALID kid-level)"        "$GEN/identity/chain.json" "$GEN/identity/keyring.json"
run_case "golden identity + keyring + manifest (VALID)"       "$GEN/identity/chain.json" "$GEN/identity/keyring.json" --identity "$GEN/identity/manifest.json"
run_case "golden impersonation + keyring (VALID kid-level)"   "$GEN/identity/impersonation-chain.json" "$GEN/identity/keyring.json"
run_case "golden impersonation + keyring + manifest (UNTRUSTED)" "$GEN/identity/impersonation-chain.json" "$GEN/identity/keyring.json" --identity "$GEN/identity/manifest.json"

echo "== conformance/vectors (happy path) =="
run_case "vectors valid-chain + keyring (VALID)"              "conformance/vectors/valid-chain.json" "$KR"
run_case "vectors valid-chain no-keyring (UNVERIFIED)"       "conformance/vectors/valid-chain.json"
run_case "vectors valid-chain + keyring + checkpoint (VALID)" "conformance/vectors/valid-chain.json" "$KR" --checkpoint "$CP"

echo "== conformance/vectors/attack (integrity/security) =="
run_case "attack tampered-content (TAMPERED)"                "conformance/vectors/attack/tampered-content.json" "$KR"
run_case "attack forged-genesis (TAMPERED)"                  "conformance/vectors/attack/forged-genesis.json" "$KR"
run_case "attack key-swap (TAMPERED)"                        "conformance/vectors/attack/key-swap.json" "$KR"
run_case "attack key-swap-resigned (TAMPERED)"              "conformance/vectors/attack/key-swap-resigned.json" "$KR"
run_case "attack unknown-kid + keyring (TAMPERED)"          "conformance/vectors/attack/unknown-kid.json" "$KR"
run_case "attack unknown-kid no-keyring (UNVERIFIED)"       "conformance/vectors/attack/unknown-kid.json"
run_case "attack seq-gap (TAMPERED)"                        "conformance/vectors/attack/seq-gap.json" "$KR"
run_case "attack head-truncated (TAMPERED)"                "conformance/vectors/attack/head-truncated.json" "$KR"
run_case "attack cross-chain-splice (TAMPERED)"            "conformance/vectors/attack/cross-chain-splice.json" "$KR"
run_case "attack dup-seq (TAMPERED)"                        "conformance/vectors/attack/dup-seq.json" "$KR"
run_case "attack wrong-signature (TAMPERED)"                "conformance/vectors/attack/wrong-signature.json" "$KR"
run_case "attack relinked (TAMPERED)"                        "conformance/vectors/attack/relinked.json" "$KR"
run_case "attack tail-truncated + checkpoint (TAMPERED)"    "conformance/vectors/attack/tail-truncated.json" "$KR" --checkpoint "$CP"
run_case "attack tail-truncated no-checkpoint (VALID)"      "conformance/vectors/attack/tail-truncated.json" "$KR"
run_case "attack forged-checkpoint-chain + forged-cp (TAMPERED)" "conformance/vectors/attack/forged-checkpoint-chain.json" "$KR" --checkpoint "conformance/vectors/attack/forged-checkpoint-cp.json"

echo "== conformance/vectors/malformed (parser/structural rejects) =="
for f in deep-nest duplicate-key float-number lone-high-surrogate lone-low-surrogate pii-smuggle proto-pollution reversed-surrogate-pair trailing-garbage; do
  run_case "malformed $f (MALFORMED)" "conformance/vectors/malformed/$f.json" "$KR"
done

echo
echo "excluded (non-receipt fixtures — consumed as auxiliary inputs, not standalone receipt chains):"
echo "  - conformance/vectors/keyring.json                     : keyring (kid -> SPKI)"
echo "  - conformance/vectors/checkpoint.json                  : signed checkpoint"
echo "  - conformance/vectors/attack/forged-checkpoint-cp.json : signed checkpoint (aux for forged-checkpoint-chain)"
echo "  - conformance/golden/0.3.0/*/keyring.json              : keyrings"
echo "  - conformance/golden/0.3.0/identity/manifest.json      : identity manifest"
echo "  - conformance/golden/0.3.0/multi/checkpoint.json       : signed checkpoint"
echo "  - conformance/golden/0.3.0/MANIFEST.json, README.md    : metadata/docs"
echo "  - conformance/federation/*, conformance/l2/*           : out of scope (separate L2/federation profiles, not receipt-chain CLI vectors)"

echo
echo "TOTAL=$TOTAL  PASS=$PASS  FAIL=$FAIL"
if [ "$FAIL" -ne 0 ]; then
  echo "CONFORMANCE FAILED: $FAIL vector(s) disagree with impl-py"
  exit 1
fi
echo "CONFORMANCE PASS: C# verifier agrees with impl-py on all $TOTAL receipt vectors"
exit 0
