#!/usr/bin/env bash
# Pure curl + shell agent-side round trip against the local relay stack (no Node, no Python).
# Prereq: `node run-local-stack.mjs` is running in another terminal (same directory), which wrote
# session.env here. Uses `jq` if present for pretty field-extraction; falls back to grep/sed
# (the response bodies we read here are flat/known-shape, so the fallback is exact, not a guess).
#
# Demonstrates, against the REAL relay (packages/relay), over REAL HTTP:
#   1. create a hold (agent auth, Idempotency-Key)
#   2. wait for the signed verdict (long-poll)
#   3. replay the SAME Idempotency-Key + body -> idempotent (no second hold)
#   4. an unauthorized attempt -> 401
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SESSION_ENV="${SESSION_ENV:-$HERE/session.env}"

if [[ ! -f "$SESSION_ENV" ]]; then
  echo "error: $SESSION_ENV not found — start the stack first: node $HERE/run-local-stack.mjs" >&2
  exit 1
fi
# shellcheck disable=SC1090
source "$SESSION_ENV"

if command -v jq >/dev/null 2>&1; then
  jf() { jq -r "$1"; } # jf '.foo' <<<"$json"
else
  # Fallback for a flat top-level string/number field: works for holdId/status/error on THIS API's
  # known response shapes (no nested arrays in the fields this script reads).
  jf() {
    local field; field="$(printf '%s' "$1" | tr -d '.')"
    grep -oE "\"${field}\"[[:space:]]*:[[:space:]]*(\"[^\"]*\"|[0-9]+)" | head -1 | sed -E 's/^"[^"]+"[[:space:]]*:[[:space:]]*"?//; s/"$//'
  }
fi

PARAMS_HASH="sha256:$(printf 'systemctl restart nginx' | shasum -a 256 | cut -d' ' -f1)"
IDEM_KEY="shell-demo-$(date +%s)-$$"
ACTION_BODY="{\"action\":{\"canonical\":\"infra.restart-service\",\"riskClass\":\"HIGH\",\"paramsHash\":\"${PARAMS_HASH}\"}}"

echo "== 1. POST /v1/holds (agent auth + Idempotency-Key: $IDEM_KEY) =="
CREATE_JSON="$(curl -s -X POST "$RELAY_BASE_URL/v1/holds" \
  -H "Authorization: Bearer $AGENT_API_KEY" \
  -H "Idempotency-Key: $IDEM_KEY" \
  -H "Content-Type: application/json" \
  -d "$ACTION_BODY")"
echo "$CREATE_JSON"
HOLD_ID="$(printf '%s' "$CREATE_JSON" | jf '.holdId')"
if [[ -z "$HOLD_ID" || "$HOLD_ID" == "null" ]]; then
  echo "error: no holdId in response — is the stack running?" >&2
  exit 1
fi
echo "holdId=$HOLD_ID"
echo

echo "== 2. GET /v1/holds/\$id/wait?timeout=10 (long-poll for the signed verdict) =="
WAIT_JSON="$(curl -s "$RELAY_BASE_URL/v1/holds/$HOLD_ID/wait?timeout=10" -H "Authorization: Bearer $AGENT_API_KEY")"
echo "$WAIT_JSON"
STATUS="$(printf '%s' "$WAIT_JSON" | jf '.status')"
echo "verdict status=$STATUS"
echo

echo "== 3. replay: SAME Idempotency-Key + SAME body -> idempotent (no new hold) =="
REPLAY_JSON="$(curl -s -w '\nHTTP_STATUS:%{http_code}' -X POST "$RELAY_BASE_URL/v1/holds" \
  -H "Authorization: Bearer $AGENT_API_KEY" \
  -H "Idempotency-Key: $IDEM_KEY" \
  -H "Content-Type: application/json" \
  -d "$ACTION_BODY")"
echo "$REPLAY_JSON"
echo

echo "== 4. unauthorized attempt: no Authorization header -> 401 =="
UNAUTH_JSON="$(curl -s -w '\nHTTP_STATUS:%{http_code}' -X POST "$RELAY_BASE_URL/v1/holds" \
  -H "Idempotency-Key: unauth-$IDEM_KEY" \
  -H "Content-Type: application/json" \
  -d "$ACTION_BODY")"
echo "$UNAUTH_JSON"
echo

echo "== 4b. unauthorized attempt: garbage bearer -> 401 =="
BAD_BEARER_JSON="$(curl -s -w '\nHTTP_STATUS:%{http_code}' -X POST "$RELAY_BASE_URL/v1/holds" \
  -H "Authorization: Bearer noa_agent_not-a-real-key" \
  -H "Idempotency-Key: badkey-$IDEM_KEY" \
  -H "Content-Type: application/json" \
  -d "$ACTION_BODY")"
echo "$BAD_BEARER_JSON"
echo

echo "done: holdId=$HOLD_ID final status=$STATUS"
