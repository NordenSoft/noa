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

## The Receipt

A small, append-only, hash-chained record: *which agent, what action, under which policy,
what verdict, reversible-how* — link-hashed to the previous one, so altering any past record
breaks the chain. PII-free by design (only hashes of params).

```json
{
  "spec": "noa.receipt/0.1",
  "action": { "canonical": "payment.refund", "riskClass": "HIGH" },
  "governance": { "verdict": "EXECUTED", "approval": { "by": "you@acme.com" } },
  "chain": { "seq": 42, "prevHash": "sha256:…", "hash": "sha256:…" }
}
```

Full format: [`docs/receipt-spec.md`](docs/receipt-spec.md). Verify a chain offline — no account, no network.

## Status (honest)

- ✅ **Receipt format spec (v0.1)** — in this repo.
- 🚧 **Kernel organ · SDK · MCP proxy · offline verifier CLI** — opening incrementally. Star/watch to follow.
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
