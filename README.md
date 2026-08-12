# NOA — Agent Action Receipt

> The open kernel of the **NOA Mandate** family — the receipt protocol, reference
> implementations and conformance suite that NOA Mandate products build on.

**NOA Receipt is an open protocol for signed, independently verifiable receipts of AI-agent
actions: before an agent does something real, a governance layer decides *allow · hold for a human ·
block*, and emits a tamper-evident, hash-chained record that anyone can verify offline — no account,
no network, no dependency on us.** This repository is the kernel: the protocol, the reference
implementations, and the conformance suite that holds every one of them to the identical verdict on
every vector.

[![CI](https://github.com/NordenSoft/noa/actions/workflows/ci.yml/badge.svg)](https://github.com/NordenSoft/noa/actions/workflows/ci.yml)
[![doc-truth](https://github.com/NordenSoft/noa/actions/workflows/doc-truth.yml/badge.svg)](https://github.com/NordenSoft/noa/actions/workflows/doc-truth.yml)
[![npm noa-receipt](https://img.shields.io/npm/v/noa-receipt?label=noa-receipt)](https://www.npmjs.com/package/noa-receipt)
[![npm noa-mcp-adapter-core](https://img.shields.io/npm/v/noa-mcp-adapter-core?label=noa-mcp-adapter-core)](https://www.npmjs.com/package/noa-mcp-adapter-core)
[![npm noa-mcp-proxy](https://img.shields.io/npm/v/noa-mcp-proxy?label=noa-mcp-proxy)](https://www.npmjs.com/package/noa-mcp-proxy)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

> Every version number on this page comes from a self-updating registry badge, and this README (plus
> SECURITY.md) is gated mechanically on every push by
> [`scripts/lint-doc-truth.mjs`](scripts/lint-doc-truth.mjs) against 8 specific rules: a version
> literal next to a package name must match the npm registry, a claimed npm publication must actually
> resolve, no hardcoded test count, every relative link resolves, the attack/malformed-vector and
> implementation counts are re-derived from the repository, the quickstart's `bash` blocks are
> *executed* end to end, `npx noa` (a stranger's package) is refused, and the license badge matches
> `package.json`. It checks those specific, countable claims — not prose, tone or completeness, and
> deleting a claim always satisfies it. A README that can drift silently is a README nobody can rely on.

> *Tamper-**evident** provenance: it proves a record was produced under the stated rules and was not
> altered afterwards — never that the action was right, and never that the action happened.
> [What we deliberately do not claim →](#what-we-deliberately-do-not-claim)*

---

## 60-second quickstart

Copy-paste, in an empty directory. Nothing here contacts NOA, and every block below is executed by
CI on every push — if one of them stops working, the build goes red.

```bash
mkdir -p noa-quickstart && cd noa-quickstart
npm init -y > /dev/null
npm install noa-receipt        # no runtime dependencies; Node >= 20 stdlib only
```

```bash
# Sign a receipt for an action, then write the chain and the PUBLIC keyring to disk.
node --input-type=module <<'EOF'
import { writeFileSync } from "node:fs";
import { generateKeyPair, buildReceipt } from "noa-receipt";

const kp = generateKeyPair("demo-key-1");

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
  null,                                        // no previous receipt: this is the genesis of the chain
  { kid: kp.kid, privateKey: kp.privateKey },
);

writeFileSync("chain.json", JSON.stringify([receipt], null, 2));
writeFileSync("keyring.json", JSON.stringify({ [kp.kid]: kp.publicKey }, null, 2));
console.log("wrote chain.json + keyring.json");
EOF
```

```bash
# Verify it offline, in a separate process. Prints status VALID and exits 0.
./node_modules/.bin/noa verify chain.json --keyring keyring.json
```

```bash
# Now alter one field of the signed record and watch the chain reject it.
sed 's/"quickstart-agent"/"someone-elses-agent"/' chain.json > tampered.json
if ./node_modules/.bin/noa verify tampered.json --keyring keyring.json; then
  echo "UNEXPECTED: a tampered chain verified"; exit 1
else
  echo "rejected as expected, exit code $? (2 = TAMPERED)"
fi
```

Exit codes are CI-ready: `0` VALID · `1` UNVERIFIED (no keyring supplied) · `2` TAMPERED · `3`
MALFORMED · `4` usage · `5` UNTRUSTED (identity binding failed) · `6` witness quorum incomplete.

> ⚠ **The CLI binary is called `noa`, but the npm package named `noa` is not ours** — it belongs to
> an unrelated third party. Run the local binary as above, or `npx --package noa-receipt noa verify
> …`, which names the package explicitly. This README is linted for that mistake.

The verifier is honest about its own limits in the same output: without a keyring it will not claim
VALID, and without a checkpoint it *warns* that tail-truncation cannot be detected offline.

## How it works

- **Decide before, not observe after.** A policy classifies an action — safe, risky, forbidden — and
  the governance layer allows it, holds it for a human, or blocks it.
- **Commit to the decision.** A receipt records *which agent · what action · under which policy ·
  what verdict · reversible how*, signed with Ed25519. Signatures are mandatory and the signing key
  is bound into the hash.
- **Chain it.** Each receipt link-hashes the previous one, so altering any past record breaks every
  record after it.
- **Never carry raw parameters.** Only `action.paramsHash` travels, so a receipt is publishable
  without leaking the payload.
- **Verify anywhere.** Verification is a pure function of bytes: offline, no account, no network, and
  five independent implementations are held to identical verdicts through a two-hop comparison chain
  (Python against the TS reference; Go, Rust and C# against Python) — with the exact per-class
  coverage, caveats included, in [`conformance/MATRIX.md`](conformance/MATRIX.md).

```json
{
  "spec": "noa.receipt/0.1",
  "action": { "canonical": "payment.refund", "riskClass": "HIGH" },
  "governance": { "verdict": "EXECUTED", "approval": { "by": "approver_01J9X4Q2" } },
  "chain": { "seq": 42, "prevHash": "sha256:…", "hash": "sha256:…" }
}
```

Full wire format: [`docs/receipt-spec.md`](docs/receipt-spec.md). Production key handling:
[`docs/trust-root-checklist.md`](docs/trust-root-checklist.md). A worked
deferred → rejected → executed story: [`examples/killer-demo/demo.mjs`](examples/killer-demo/demo.mjs).

## What we deliberately do NOT claim

This is the part of the project that took the most engineering to be able to state precisely, and it
is normative: **[NON-CLAIMS.md](NON-CLAIMS.md)**. Past overclaims are not edited away — they are kept
in [CORRECTIONS.md](CORRECTIONS.md).

- A signature proves *someone said this*, never *this is true* (NC-1.1) and never *this is still
  true* (NC-1.2).
- A receipt does **not** prove the described action actually occurred; the remote system of record is
  the only witness to a side effect, and it does not sign our receipts (NC-1.3).
- A valid chain does **not** prove completeness — it cannot prove no receipt was withheld (NC-1.5).
- An approval proves a key holder authorized these bytes; not that a human understood them (NC-3.1),
  and not that the approval screen was ever rendered (NC-3.4).
- The same-realm TypeScript verifier does **not** meet the security objective against an attacker who
  runs code in your process; the separate-process CLI is what holds today (NC-6.0, NC-6.2).
- A verdict handed back to a compromised caller is **not** an enforcement control (NC-6.6).
- No certification is claimed or in progress — no SOC 2, no ISO 27001, no FedRAMP (NC-5.3).
- `v1.0` does **not** claim external anchoring; nothing here contacts a witness or a log (NC-4.3,
  NC-4.5).

Read [THREAT-MODEL.md](THREAT-MODEL.md) before you rely on any of this.

## What is live, and what is roadmap

**Live — measured in this repository, gated on every push:**

- The `noa.receipt/0.1` wire format, **frozen**, with a JSON Schema and a published spec.
- Three packages on npm under Apache-2.0 (the badges above are the live versions).
- **five** independent verifier implementations, held to identical verdicts through a two-hop
  comparison chain in CI — Python against the TS reference, then Go, Rust and C# against Python, no
  partial credit per vector class — see the table below and
  [`conformance/MATRIX.md`](conformance/MATRIX.md).
- A conformance corpus of **16** attack vectors and **9** malformed vectors that the verifiers must
  reject on every push — with the per-class coverage, and the three classes (`hash`, `impersonation`,
  `dup-key`) the cross-implementation runner does not explicitly tag for TypeScript, written down in
  `conformance/MATRIX.md` rather than glossed.
- An offline CLI verifier that runs in its own process with no third-party dependencies.
- A runtime human-approval gate in the MCP proxy: a risky call is held as a signed `DEFERRED`
  receipt until a human approves it, producing a `DEFERRED → ALLOWED → EXECUTED` chain
  (`--approval-rules`).

**Roadmap — specified, decided or planned, and NOT shipped.** The decision roadmap is
[04_ROADMAP.md](04_ROADMAP.md); the volatile execution state is
[00_CURRENT_STATE.md](00_CURRENT_STATE.md).

- A semantic interoperability contract for consumers, and an externally reproducible conformance
  profile (roadmap §1–§2).
- Resolution of the documented protocol-quality gaps — canonical encoding, COSE companion behaviour,
  error taxonomy, key lifecycle, revocation and freshness (§3).
- Standards engagement. An individual Internet-Draft `-00` exists; that is **not** working-group
  adoption, and this project does not call itself standardized (§4).
- A controlled pilot with a real relying-party decision. Package downloads are distribution evidence,
  never adoption evidence (§5).
- The isolated native trust boundary is **specified and not built**
  ([ADR-0002](docs/ADR-0002-isolated-native-trust-boundary.md)) — do not plan around it as if it
  shipped. Likewise the hosted control-plane and the one-tap approval app.

Project status, in the vocabulary [AGENTS.md](AGENTS.md) defines: `PROTOTYPE`, with active
`SPECIFICATION` work. Not `PILOT`, not `STANDARDIZATION`, not `PRODUCTION`.

## Packages

| Package | npm | What it does |
|---|---|---|
| `noa-receipt` | [npm](https://www.npmjs.com/package/noa-receipt) | The kernel: build, sign, hash-chain and verify receipts, plus the `noa verify` CLI. No runtime dependencies. |
| `noa-mcp-adapter-core` | [npm](https://www.npmjs.com/package/noa-mcp-adapter-core) | The shared pre-flight decision engine — one `preCheck()` every MCP integration calls instead of re-deriving the policy. |
| `noa-mcp-proxy` | [npm](https://www.npmjs.com/package/noa-mcp-proxy) | A transparent MCP proxy in front of an existing, unmodified tool server: reflects its tool surface and gates every `tools/call`, fail-closed. |

Further modules live under [`packages/`](packages/) — gate, relay, evidence, approval artifacts,
framework adapters, signer sidecar, TSA anchor. They are part of this repository's gates but are
**not published to npm**, and this README does not present them as if they were.

## Independent implementations

Five verifiers, written separately, held to one bar: for every conformance vector an implementation
must produce the **identical verdict** to its own comparison target — a two-hop chain, not five direct
comparisons to TypeScript: Python is compared directly to the TS reference, and Go, Rust and C# are
each compared directly to Python (not to TS), exactly as the table below and
[`conformance/MATRIX.md`](conformance/MATRIX.md) state. One mismatch fails the whole class for that
implementation — no partial credit, because a single silently-accepted attack is a complete security
failure regardless of how many adjacent checks still pass.

| Implementation | Path | Conformance parity |
|---|---|---|
| TypeScript (reference) | [`src/`](src/) | Emits the signed vectors; agreement with the independent Python verifier is asserted on every push ([`impl-py/conformance.mjs`](impl-py/conformance.mjs)). |
| Python | [`impl-py/`](impl-py/) | Own JCS, own from-scratch RFC 8032 Ed25519, zero shared crypto with TS. Ground truth for the Go, Rust and C# verifiers below. |
| Go | [`impl-go/`](impl-go/) | Exit code must match the Python reference on every vector ([`impl-go/conformance_test.sh`](impl-go/conformance_test.sh)). |
| Rust | [`impl-rust/`](impl-rust/) | Same bar, same corpus ([`impl-rust/conformance.sh`](impl-rust/conformance.sh)). |
| C# | [`impl-csharp/`](impl-csharp/) | Same bar, same corpus ([`impl-csharp/conformance.sh`](impl-csharp/conformance.sh)). |

All five run in the `five-verifier-conformance` job of
[`.github/workflows/ci.yml`](.github/workflows/ci.yml) on every push and pull request. What this
proves is implementation independence on identical bytes; it does not prove *organizational*
independence, and this project does not claim it.

## Working in this repository

```
npm ci
npm run build                  # tsc
npm test                       # build + regenerate vectors + the kernel suite
node dist/src/cli.js verify conformance/vectors/valid-chain.json \
  --keyring conformance/vectors/keyring.json \
  --checkpoint conformance/vectors/checkpoint.json
```

Test counts are deliberately **not** printed in this file: a number here would be stale the day after
it was typed, and the doc-truth gate rejects one. CI is the live count.

## Security

Report privately through
[GitHub security advisories](https://github.com/NordenSoft/noa/security/advisories/new); the policy,
the supported-version table and the disclosure expectations are in [SECURITY.md](SECURITY.md). The
adversarial history — what was found, what was fixed, and what was withdrawn as unachievable — is in
[THREAT-MODEL.md](THREAT-MODEL.md) and [NON-CLAIMS.md](NON-CLAIMS.md).

## Contributing

Start with [AGENTS.md](AGENTS.md) — it defines the evidence vocabulary this project argues in
(`NORMATIVE`, `OBSERVED`, `VERIFIED`, `ASSUMED`, `SOURCE_ABSENT`, `NON-CLAIM`) and the source-authority
order. Then [CONTRIBUTING.md](CONTRIBUTING.md), [VERSIONING.md](VERSIONING.md) and
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). Issues and discussions are welcome — emitters and acceptors
of receipts especially.

The one rule worth stating here: **a claim in this repository is a measurement, not an aspiration.**
Adding a non-claim is an ordinary commit; removing one is a reviewed event that has to run the proof.

## License

[Apache-2.0](LICENSE) · [NOTICE](NOTICE) · [noatrust.com](https://noatrust.com)
