# NOA — Agent Action Receipt

[![CI](https://github.com/NordenSoft/noa/actions/workflows/ci.yml/badge.svg)](https://github.com/NordenSoft/noa/actions/workflows/ci.yml)

193 tests green, including TS↔Python cross-implementation conformance in CI — the independent
Python reference verifier is required to agree with the TS verifier on every conformance vector.

> **What this repo is:** the open-source of **one organ** of NOA — the **governance &
> receipt layer**: the part that gates an AI agent's real-world actions and issues a
> tamper-evident, independently verifiable receipt.
>
> **What NOA is:** a *brain* for AI agents — an agent-cognition OS (memory, identity,
> homeostasis, governance) that you connect your own agent to. This repository opens
> **the governance organ only**, under Apache-2.0. The rest of the brain is the product.

**The receipt every AI action leaves behind. Verifiable by anyone. Owned by no one.**

> *Tamper-**evident** provenance: it proves a record was produced under the stated rules and
> wasn't altered — not that the action was right, and not proof-of-action. [Honest limits →](THREAT-MODEL.md)*

---

## The organ, concretely

Before an agent takes a real-world action — pay, refund, email, delete, deploy, write to
a database — this layer decides:

> **safe → allow · risky → human approval · forbidden → block**

…and emits a **tamper-evident, hash-chained receipt** you can verify yourself, **offline**,
with no dependency on us.

> 🌐 [noatrust.com](https://noatrust.com) · 📜 Apache-2.0 · 🧪 Early access

## Why

AI agents are starting to *do* things, not just answer. Once a wrong action runs, it's done.
Observability tools tell you what happened — *afterwards*. This layer decides what *should*
happen **before** it runs, and leaves an independently verifiable provenance record.

> **What it is, precisely:** tamper-*evident* provenance — it proves a record was produced under
> the stated rules and not edited mid-chain. It is **not** proof-of-action, non-repudiation, or a
> freshness guarantee, and it can't detect an action for which no receipt was emitted. In a keyring
> with more than one trusted key it proves *a trusted key signed this*, not *which `agent.id` acted*.
> The honest limits (replay, key compromise, fork/equivocation, tail-truncation, cross-agent
> attribution in multi-key keyrings) are written down in
> [THREAT-MODEL.md](THREAT-MODEL.md) — read them before you rely on this.

## The Receipt

A small, append-only, hash-chained record: *which agent, what action, under which policy,
what verdict, reversible-how* — link-hashed to the previous one, so altering any past record
breaks the chain. Params are never carried raw — only their hash. (Caller-supplied identifiers
are opaque and must not contain PII; the format can't enforce that — see THREAT-MODEL.)

```json
{
  "spec": "noa.receipt/0.1",
  "action": { "canonical": "payment.refund", "riskClass": "HIGH" },
  "governance": { "verdict": "EXECUTED", "approval": { "by": "you@acme.com" } },
  "chain": { "seq": 42, "prevHash": "sha256:…", "hash": "sha256:…" }
}
```

Full format: [`docs/receipt-spec.md`](docs/receipt-spec.md). Signatures are **mandatory** (Ed25519),
the signing key is bound into the hash, and verification runs **offline** — no account, no network.

## Verify a chain offline (no account, no network)

```bash
npm install          # zero runtime deps (Node ≥ 20 stdlib only; @types/node is type-only)
npm test             # build + generate conformance vectors + run the full conformance suite

# verify a signed chain against a keyring + checkpoint
node dist/src/cli.js verify conformance/vectors/valid-chain.json \
  --keyring conformance/vectors/keyring.json \
  --checkpoint conformance/vectors/checkpoint.json
# -> { "status": "VALID", "signaturesVerified": true, "tailChecked": true, ... }   exit 0
```

Exit codes are CI-ready: `0` VALID · `1` unverified-sig (no keyring) · `2` TAMPERED · `3`
MALFORMED · `4` usage · `5` UNTRUSTED (identity binding failed). Every tampered/forged/truncated/key-swapped vector under
[`conformance/`](conformance/vectors) is rejected — and the verifier is honest: without a
keyring it will **not** claim VALID, and without a checkpoint it **warns** that tail-truncation
can't be detected offline.

## Your first receipt (copy, paste, run)

In your own project — no clone, no build step, just the published package:

```bash
npm install noa-receipt
node --input-type=module <<'EOF'
import { generateKeyPair, buildReceipt, verifyChain } from "noa-receipt";

const kp = generateKeyPair("demo-key-1");
const signer = { kid: kp.kid, privateKey: kp.privateKey };
const keyring = { [kp.kid]: kp.publicKey };

const receipt = buildReceipt(
  {
    id: "rcpt_0",
    ts: new Date().toISOString(),
    scope: { chain: "quickstart:demo" },
    agent: { id: "quickstart-agent", model: "vendor/model-v1", principal: "SERVICE" },
    action: {
      id: "payment.refund",
      canonical: "payment.refund",
      riskClass: "LOW",
      paramsHash: "sha256:" + "0".repeat(64), // never carry raw params — only their hash
      reversible: false,
      rollbackRef: null,
    },
    governance: { mode: "on", verdict: "EXECUTED", ruleId: "low-risk-auto", approval: null, sandboxed: false },
  },
  null, // no previous receipt: this is the genesis of the chain
  signer,
);

const result = verifyChain([receipt], { keyring });
console.log(result.status); // -> "VALID"
EOF
# -> VALID
```

Cut the receipt *before* the action runs, verify it *offline*, and the signed hash-chain proves it
wasn't altered — the same building block the [killer demo](examples/killer-demo/demo.mjs) chains
into a full deferred → rejected → executed story.

## Status (honest)

- ✅ **Receipt spec (v0.1)** — mandatory Ed25519, key-pinning, genesis + tail-truncation rules.
- ✅ **Offline verifier** — library + `noa verify` CLI, zero runtime deps, hostile-input hardened.
- ✅ **JSON-Schema + conformance suite** — 14 attack + 9 malformed vectors, all rejected.
- 🚧 **SDK `noa.guard()` · MCP proxy · hosted control-plane** — examples in [`examples/`](examples), hardening in progress.
- ⚠️ **0.2.0 (breaking):** COSE_Sign1 alg-id `-8` (generic EdDSA) → `-19` (Ed25519, RFC 9864) — closes the Ed448 alg-confusion surface; old `{1:-8}` envelopes no longer verify.
- This is **early access**, and it is **one organ** of NOA — not the whole brain. The full
  agent-cognition platform (cognition, memory, BYO-agent hosting) is separate and proprietary.

## The standard

A receipt is only as valuable as the breadth of parties who accept it — so it must be
**vendor-neutral**. The goal is an open standard — the intended home is a neutral foundation
(e.g. the Linux Foundation's Agentic AI Foundation), not a NOA-owned format. No single vendor
can be the neutral steward
auditors, insurers, and counterparties trust — which is exactly why this organ is open.

## Get involved

- ⭐ Star to follow the organ/SDK/verifier releases.
- 📨 [Request early access](https://noatrust.com/#early-access).
- 🧩 Issues/discussions welcome — emitters and acceptors especially.

## License

[Apache-2.0](LICENSE).
