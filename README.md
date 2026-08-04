# NOA — Agent Action Receipt

[![CI](https://github.com/NordenSoft/noa/actions/workflows/ci.yml/badge.svg)](https://github.com/NordenSoft/noa/actions/workflows/ci.yml)

**1891 tests green** across nine suites, including TS↔Python cross-implementation conformance in CI
— the independent Python reference verifier is required to agree with the TS verifier on every
conformance vector. Counted 2026-08-04 by running every suite: kernel 534 · gate 241 · relay 166 ·
approval-artifacts 179 · evidence 130 · signer-core 79 · adapter-core 332 · mcp-proxy 104 ·
framework-adapters 126.

**Published on npm (Apache-2.0):** `noa-receipt` 0.6.0 · `noa-mcp-adapter-core` 0.3.1 · `noa-mcp-proxy` 0.3.1
— install and use today, no account. `npx noa-receipt verify <chain>` verifies offline.

> **What this repo is:** the open-source of **one organ** of NOA — the **governance &
> receipt layer**: the part that gates an AI agent's real-world actions and issues a
> tamper-evident, independently verifiable receipt.
>
> ⚠ **Read "gates" precisely (2026-07-29).** It gates **an honest integration**. This package cannot
> stop a compromised caller from calling the provider directly, and in the gate's RAW mode the
> description a human approves is not cryptographically bound to the action that executes. Both are
> measured, not theoretical — see the trust-boundary box below, [NON-CLAIMS.md](NON-CLAIMS.md)
> NC-6.6, and `packages/gate/README.md`. A pre-action control that an attacker can route around is a
> **safety** feature against mistakes, not yet a **security** control against adversaries.
>
> **What NOA is:** a *brain* for AI agents — an agent-cognition OS (memory, identity,
> homeostasis, governance) that you connect your own agent to. This repository opens
> **the governance organ only**, under Apache-2.0. The rest of the brain is the product.

**The receipt every AI action leaves behind. Verifiable by anyone. Owned by no one.**

> *Tamper-**evident** provenance: it proves a record was produced under the stated rules and
> wasn't altered — not that the action was right, and not proof-of-action. [Honest limits →](THREAT-MODEL.md) · [What this does NOT prove →](NON-CLAIMS.md)*

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
> [THREAT-MODEL.md](THREAT-MODEL.md) and, consolidated and normative,
> [NON-CLAIMS.md](NON-CLAIMS.md) — read them before you rely on this.

> ### ⚠ Where this TypeScript package sits in the trust boundary (2026-07-29)
>
> **This package is a best-effort compatibility and orchestration layer. It does not meet the
> in-realm security objective, and it no longer claims to.**
>
> If an attacker can run code in the same JavaScript realm — a dependency, a bundler shim, an
> instrumentation hook, anything evaluated before or alongside this library — they can influence a
> verdict. Four independent cross-vendor adversarial rounds each closed the sites a review named and
> each found the same class one call further out, every time while the project's own gates reported
> green. The conclusion is structural, not a backlog item: *in a shared realm, the set of operations
> trusted code performs is not enumerable by that trusted code.*
>
> **What to use instead, today.** The isolated Go kernel is **specified in
> [ADR-0002](docs/ADR-0002-isolated-native-trust-boundary.md) and NOT YET BUILT** — do not plan
> around it as if it shipped. What *does* ship is the CLI: `npx noa verify <receipts.json>
> [keyring.json]` runs in a **separate process with no third-party dependencies**
> (`"dependencies": {}`), so a hostile *document* has no way to poison that process's realm — there
> is no host module loaded before it. For an attacker who controls only the data you verify, the
> CLI boundary holds today.
>
> Its ceiling, stated with it: the CLI's **output is not authenticated**, so a compromised caller can
> still discard or misreport a correct verdict. That is the consumption-integrity limit in
> [NON-CLAIMS.md](NON-CLAIMS.md) NC-6.2.
>
> **This sentence used to end "…and it is what the kernel's signed-response envelope is for." That
> was withdrawn on 2026-07-29.** A signed verdict returned *into* a compromised caller is not an
> enforcement control: the caller's transport and its signature check are both poisonable, and both
> were measured to be
> ([ROUND5-FINDINGS.md](docs/ROUND5-FINDINGS.md) R5-01, [T7-trust-root.md](docs/T7-trust-root.md) §1).
> An envelope tells an *honest* caller that an answer is genuine. It does nothing for a caller that
> has already been taken over — and that caller was the one we claimed to protect.
>
> **What replaces it:** a critical action must be *technically impossible* without authority held by
> the independent boundary — credentials the kernel holds and uses on your behalf, or a short-lived
> single-use grant the third party validates itself. Not a verdict handed back to code that may be
> lying to itself. See [NON-CLAIMS.md](NON-CLAIMS.md) NC-6.6.
>
> Use the in-process API for development, tooling, and contexts where you already trust every line of
> code in the process.
>
> The receipt **format** is unaffected: receipts signed today keep verifying, and all independent
> verifiers still agree on them.

## The Receipt

A small, append-only, hash-chained record: *which agent, what action, under which policy,
what verdict, reversible-how* — link-hashed to the previous one, so altering any past record
breaks the chain. Params are never carried raw — only their hash. (Caller-supplied identifiers
are opaque and must not contain PII; the format can't enforce that — see THREAT-MODEL.)

```json
{
  "spec": "noa.receipt/0.1",
  "action": { "canonical": "payment.refund", "riskClass": "HIGH" },
  "governance": { "verdict": "EXECUTED", "approval": { "by": "approver_01J9X4Q2" } },
  "chain": { "seq": 42, "prevHash": "sha256:…", "hash": "sha256:…" }
}
```

Full format: [`docs/receipt-spec.md`](docs/receipt-spec.md). Signatures are **mandatory** (Ed25519),
the signing key is bound into the hash, and verification runs **offline** — no account, no network.
Production key management: [docs/trust-root-checklist.md](https://github.com/NordenSoft/noa/blob/main/docs/trust-root-checklist.md).

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
[`conformance/`](https://github.com/NordenSoft/noa/tree/main/conformance/vectors) is rejected — and the verifier is honest: without a
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

// Verifier inputs are BYTES or JSON TEXT, never caller-owned objects: an object's getters
// would run inside the trust boundary. A JSON string is accepted directly.
const result = verifyChain(JSON.stringify([receipt]), { keyring: JSON.stringify(keyring) });
console.log(result.status); // -> "VALID"
EOF
# -> VALID
```

Cut the receipt *before* the action runs, verify it *offline*, and the signed hash-chain proves it
wasn't altered — the same building block the [killer demo](https://github.com/NordenSoft/noa/blob/main/examples/killer-demo/demo.mjs) chains
into a full deferred → rejected → executed story.

## Status (honest)

- ✅ **Receipt spec (v0.1)** — mandatory Ed25519, key-pinning, genesis + tail-truncation rules.
- ✅ **Offline verifier** — library + `noa verify` CLI, zero runtime deps, hostile-input hardened.
- ✅ **JSON-Schema + conformance suite** — 16 attack + 9 malformed vectors, all rejected. (Counted in `conformance/vectors/` on 2026-08-04; the figure had read `14` since two vectors were added.)
- ✅ **MCP proxy (`noa-mcp-proxy`) + tool-gating SDK core (`noa-mcp-adapter-core`)** — live on npm (0.3.1), including the runtime **human-approval gate** (`--approval-rules`: a risky call is held as a signed DEFERRED receipt until a human approves, producing a DEFERRED→ALLOWED→EXECUTED chain).
- 🚧 **Hosted control-plane + the one-tap approval app** — on the roadmap, not shipped.
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
