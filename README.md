# NOA — Agent Action Receipt

> **What this repo is:** the open-source of **one organ** of NOA — the **governance &
> receipt layer**: the part that gates an AI agent's real-world actions and issues a
> tamper-evident, independently verifiable receipt.
>
> **What NOA is:** a *brain* for AI agents — an agent-cognition OS (memory, identity,
> homeostasis, governance) that you connect your own agent to. This repository opens
> **the governance organ only**, under Apache-2.0. The rest of the brain is the product.

**The receipt every AI action leaves behind. Verifiable by anyone. Owned by no one.**

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
happen **before** it runs, and leaves an independently verifiable proof.

> **What it is, precisely:** tamper-*evident* provenance — it proves a record was produced under
> the stated rules and not edited mid-chain. It is **not** proof-of-action, non-repudiation, or a
> freshness guarantee, and it can't detect an action for which no receipt was emitted. The honest
> limits (replay, key compromise, fork/equivocation, tail-truncation) are written down in
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
npm install          # zero runtime dependencies (Node ≥ 20 stdlib only)
npm test             # build + generate conformance vectors + run 59 tests

# verify a signed chain against a keyring + checkpoint
node dist/src/cli.js verify conformance/vectors/valid-chain.json \
  --keyring conformance/vectors/keyring.json \
  --checkpoint conformance/vectors/checkpoint.json
# -> { "status": "VALID", "signaturesVerified": true, "tailChecked": true, ... }   exit 0
```

Exit codes are CI-ready: `0` VALID · `1` unverified-sig (no keyring) · `2` TAMPERED · `3`
MALFORMED · `4` usage. Every tampered/forged/truncated/key-swapped vector under
[`conformance/`](conformance/vectors) is rejected — and the verifier is honest: without a
keyring it will **not** claim VALID, and without a checkpoint it **warns** that tail-truncation
can't be detected offline.

In code:

```ts
import { buildReceipt, verifyChain, generateKeyPair } from "@noa/receipt";
```

## Status (honest)

- ✅ **Receipt spec (v0.1)** — mandatory Ed25519, key-pinning, genesis + tail-truncation rules.
- ✅ **Offline verifier** — library + `noa verify` CLI, zero runtime deps, hostile-input hardened.
- ✅ **JSON-Schema + conformance suite** — 59 tests, 14 attack + 9 malformed vectors, all rejected.
- 🚧 **SDK `noa.guard()` · MCP proxy · hosted control-plane** — examples in [`examples/`](examples), hardening in progress.
- This is **early access**, and it is **one organ** of NOA — not the whole brain. The full
  agent-cognition platform (cognition, memory, BYO-agent hosting) is separate and proprietary.

## The standard

A receipt is only as valuable as the breadth of parties who accept it — so it must be
**vendor-neutral**. The goal is an open standard (proposed to the Linux Foundation's
Agentic AI Foundation), not a NOA-owned format. No single vendor can be the neutral steward
auditors, insurers, and counterparties trust — which is exactly why this organ is open.

## Get involved

- ⭐ Star to follow the organ/SDK/verifier releases.
- 📨 [Request early access](https://noatrust.com/#early-access).
- 🧩 Issues/discussions welcome — emitters and acceptors especially.

## License

[Apache-2.0](LICENSE).
