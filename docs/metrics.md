# NOA leading-indicator metrics

> Companion to [`receipt-spec.md`](./receipt-spec.md) §9 (L2 policy-compliance). Implemented by
> [`scripts/noa-metrics.mjs`](../scripts/noa-metrics.mjs) — standalone, node ≥ 20 stdlib only,
> no third-party deps, no build required.

`noa-metrics` scans a directory of NOA receipt chains and prints three **leading indicators** of
federation health. They are structural counts — they do not verify signatures or re-run policies
(that is the job of `noa verify` / `verifyReceiptCompliance`). Their value is *cheap, early signal*:
is the corpus drawn from a diverse set of real issuers, and are receipts actually carrying L2
policy commitments?

## The three metrics

### (1) Chain-diversity gate

```
distinctIssuers = |{ receipt.agent.id : receipt ∈ corpus }|
nonDogfood      = distinct issuers NOT on the --dogfood allowlist
PASS  ⇔  distinctIssuers ≥ --min-orgs (default 5)  AND  nonDogfood ≥ 1
```

`agent.id` is the **issuer** identity (spec §2). "Orgs" in the gate = distinct issuer agent.ids.
Distinct tenants and chains are reported as corroboration but do not alone pass the gate. The
`--dogfood` allowlist (default `agent-refunds`, the repo's own demo agent) marks internal/test
issuers so the gate requires at least one genuinely external one.

### (2) L2-exercise-ratio

```
exercised = receipts carrying a well-formed governance.compliance block
            AND a recorded compliance.verdict ∈ {ALLOW, DENY}
L2-exercise-ratio = exercised / total
```

Per spec §9 and `src/policy/compliance.ts`, the recorded `compliance.verdict` is *"re-run at commit
time"*, and `verifyReceiptCompliance` **requires** a re-run to reproduce it (verdict reconciliation).
So a block with a recorded verdict is one whose policy replay was **actually run and is
reconcilable/verified**. A block without a verdict is replayable but not exercised.

### (3) Replayable-policy-fraction

```
replayable = receipts whose governance.compliance block is well-formed:
             policyHash + readSetHash + inputsHash all = sha256:<64hex>
replayable-policy-fraction = replayable / total
```

Those three commitments pin a published policy identity (`policyHash`), a **closed read-set**
(`readSetHash` — the determinism precondition: no ambient state), and the recorded inputs
(`inputsHash`) — exactly what `verifyReceiptCompliance` needs to re-run the deterministic evaluator
offline. **Metric (2) ⊆ (3)**: every exercised receipt is replayable.

The script also reports the **deterministic-policy corpus**: any `noa.l2-conformance/0.2` file in the
repo pins `validatePolicy`-accepted, integer-only/pure-logic policies + their reproducible verdict
cases. This is surfaced so that "0 receipts carry compliance" is never misread as "no replayable
policy exists."

## Honesty razors (also printed by the script)

- A receipt hash proves the on-receipt **shape** admits replay; it does **not** prove the referenced
  policy is integer-only/pure-logic (the actual determinism property) — that needs the out-of-band
  policy. Hence the deterministic-policy-corpus signal.
- These metrics are **structural**; they do not authenticate carriers (no keyring). For attested L2
  results, run `verifyReceiptCompliance(receipt, policy, inputs, { keyring })`.
- A **FAIL / 0 ratio** on the bundled `conformance/` corpus is the *correct* indicator: those vectors
  are a single dogfood chain (`agent-refunds`, `store_demo`, test key) with zero on-receipt L2
  commitments. The only deterministic policy in the repo is the standalone conformance corpus.

## Usage

```
./scripts/noa-metrics.mjs                       # scan ./conformance (default)
./scripts/noa-metrics.mjs --dir path/to/chains  # scan a custom dir (recursive)
./scripts/noa-metrics.mjs --dogfood a,b --min-orgs 5
./scripts/noa-metrics.mjs --json                # machine-readable JSON
./scripts/noa-metrics.mjs --demo                # synthetic PASS-path demo (labelled)
./scripts/noa-metrics.mjs --strict-gate         # exit 1 when the diversity gate FAILs (CI)
```

Exit codes: `0` computed OK (gate PASS/FAIL is reported, not fatal) · `1` `--strict-gate` and the
diversity gate FAILED · `2` usage error or no receipts found.

### Suggested `package.json` entry (not added — add if desired)

```json
"metrics": "node scripts/noa-metrics.mjs",
"metrics:gate": "node scripts/noa-metrics.mjs --strict-gate"
```

## Sample run — bundled conformance vectors (real output)

```
$ ./scripts/noa-metrics.mjs
NOA leading-indicator metrics
────────────────────────────────────────────────────────────────────────
corpus dir           .../conformance
files scanned        27
receipts found       41   [attack:34, malformed:4, valid/other:3]
deterministic policy 1 policy/-ies, 7 pinned case/s (l2-conformance corpus)
skipped files        9   [checkpoint:2, unknown:2, array-not-receipts:5]
parse errors         1 (intentionally-malformed vectors, excluded)

(1) CHAIN-DIVERSITY GATE   ❌ FAIL
distinct issuer agent.ids   1   (threshold >= 5)
non-dogfood issuers        0   (need >= 1)
distinct tenants           2
issuers:
  • agent-refunds                 40 rcpt  tenants=[store_demo,store_other]   (dogfood)

(2) L2-EXERCISE-RATIO   (policy replay actually run + verified)
exercised / total           0 / 41   =  0.000   (0.0%)
compliance block present    0

(3) REPLAYABLE-POLICY-FRACTION   (policy deterministically replayable by shape)
replayable / total          0 / 41   =  0.000   (0.0%)
deterministic policy corpus 1 policy/-ies, 7 cases pinned (noa.l2-conformance/0.2)
  • refund-guard-v1  (7 cases, policySpec=noa.policy/0.2)
```

This is the honest baseline: a single-issuer dogfood corpus with no on-receipt L2 commitments; the
only deterministic policy in the repo is the standalone conformance corpus. Run `--demo` to see a
synthetic corpus that exercises all three indicators with non-zero, differentiated values
(diversity PASS · L2-exercise 4/7 · replayable 5/7).
