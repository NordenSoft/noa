#!/usr/bin/env python3
"""Pure Python 3 stdlib agent-side round trip against the local relay stack.

No pip dependencies (urllib.request + json + subprocess only). Prereq:
`node run-local-stack.mjs` running in another terminal (same directory),
which wrote session.json here.

Demonstrates, against the REAL relay (packages/relay), over REAL HTTP:
  1. create a hold (agent auth, Idempotency-Key)
  2. wait for the signed verdict (long-poll)
  3. replay the SAME Idempotency-Key + body -> idempotent (no second hold)
  4. an unauthorized attempt -> 401
  5. offline signature verification of the returned receipt

HONESTY on step 5: Python's stdlib has NO Ed25519 verifier (that needs the
`cryptography` package, a pip dependency this example deliberately does not
take — the brief for this example is "stdlib only"). So this script does NOT
re-implement Ed25519 verification in pure Python. Instead it writes the
returned receipt + the published keyring to disk and shells out to the
top-level `noa verify` CLI (a Node binary, but the SAME one any operator
already has after `npm install noa-receipt` / `npx noa-receipt verify`) and
prints its exit code + JSON verdict. That CLI call — not a hand-rolled
verifier — is the actual offline proof.
"""
import hashlib
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
SESSION_JSON = os.environ.get("SESSION_JSON", os.path.join(HERE, "session.json"))
KEYRING_JSON = os.environ.get("KEYRING_JSON", os.path.join(HERE, "keyring.json"))
# repo-root/dist/src/cli.js — examples/http-agent -> e2e-demo -> packages -> repo root (4 up)
CLI_JS = os.path.abspath(os.path.join(HERE, "..", "..", "..", "..", "dist", "src", "cli.js"))


def http(method, url, headers=None, body=None):
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers=headers or {})
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req) as resp:
            text = resp.read().decode("utf-8")
            return resp.status, (json.loads(text) if text else None)
    except urllib.error.HTTPError as e:
        text = e.read().decode("utf-8")
        return e.code, (json.loads(text) if text else None)


def main():
    if not os.path.isfile(SESSION_JSON):
        print(f"error: {SESSION_JSON} not found — start the stack first: "
              f"node {os.path.join(HERE, 'run-local-stack.mjs')}", file=sys.stderr)
        return 1
    with open(SESSION_JSON, "r", encoding="utf-8") as f:
        session = json.load(f)
    relay_base_url = session["relayBaseUrl"]
    agent_api_key = session["agentApiKey"]
    agent_auth = {"Authorization": f"Bearer {agent_api_key}"}

    params_hash = "sha256:" + hashlib.sha256(b"send-payout to vendor#42").hexdigest()
    idem_key = f"python-demo-{int(time.time())}-{os.getpid()}"
    action_body = {"action": {"canonical": "payments.send-payout", "riskClass": "HIGH", "paramsHash": params_hash}}

    print(f"== 1. POST /v1/holds (agent auth + Idempotency-Key: {idem_key}) ==")
    status, created = http("POST", f"{relay_base_url}/v1/holds",
                            headers={**agent_auth, "Idempotency-Key": idem_key}, body=action_body)
    print(status, created)
    if status != 201 or not created or "holdId" not in created:
        print("error: hold creation failed", file=sys.stderr)
        return 1
    hold_id = created["holdId"]
    print(f"holdId={hold_id}\n")

    print("== 2. GET /v1/holds/{id}/wait?timeout=10 (long-poll for the signed verdict) ==")
    status, waited = http("GET", f"{relay_base_url}/v1/holds/{hold_id}/wait?timeout=10", headers=agent_auth)
    print(json.dumps(waited, indent=2))
    verdict_status = waited.get("status") if waited else None
    print(f"verdict status={verdict_status}\n")

    print("== 3. replay: SAME Idempotency-Key + SAME body -> idempotent (no new hold) ==")
    status, replayed = http("POST", f"{relay_base_url}/v1/holds",
                             headers={**agent_auth, "Idempotency-Key": idem_key}, body=action_body)
    print(status, replayed, "\n")

    print("== 4. unauthorized attempt: no Authorization header -> 401 ==")
    status, unauth = http("POST", f"{relay_base_url}/v1/holds",
                           headers={"Idempotency-Key": f"unauth-{idem_key}"}, body=action_body)
    print(status, unauth, "\n")

    print("== 4b. unauthorized attempt: garbage bearer -> 401 ==")
    status, bad = http("POST", f"{relay_base_url}/v1/holds",
                        headers={"Authorization": "Bearer noa_agent_not-a-real-key",
                                 "Idempotency-Key": f"badkey-{idem_key}"}, body=action_body)
    print(status, bad, "\n")

    print("== 5. offline receipt verification (delegates to the `noa verify` CLI — see docstring) ==")
    receipt = waited.get("decisionReceipt") if waited else None
    if not receipt:
        print("no decisionReceipt to verify (hold not yet decided within the wait window)", file=sys.stderr)
        return 1
    receipt_path = os.path.join(HERE, "last-receipt-chain.json")
    with open(receipt_path, "w", encoding="utf-8") as f:
        json.dump([receipt], f)
    if not os.path.isfile(KEYRING_JSON):
        print(f"error: {KEYRING_JSON} not found (written by run-local-stack.mjs)", file=sys.stderr)
        return 1
    cmd = ["node", CLI_JS, "verify", receipt_path, "--keyring", KEYRING_JSON]
    print("$ " + " ".join(cmd))
    proc = subprocess.run(cmd, capture_output=True, text=True)
    print(proc.stdout, end="")
    if proc.stderr:
        print(proc.stderr, file=sys.stderr, end="")
    print(f"noa verify exit code: {proc.returncode} (0 = VALID)")

    print(f"\ndone: holdId={hold_id} final status={verdict_status}")
    return 0 if proc.returncode == 0 and verdict_status == "APPROVED" else 1


if __name__ == "__main__":
    sys.exit(main())
