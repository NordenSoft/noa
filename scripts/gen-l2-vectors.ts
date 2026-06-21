/**
 * Deterministic L2 conformance-vector generator — the PRIMARY L2 deliverable (round-2 audit: the
 * conformance corpus matters more than the evaluator code; it pins behaviour for any re-implementer).
 *
 * Emits, per policy: the policy, its policyHash + readSetHash, and a corpus of {inputs → expected
 * verdict + ruleFired} cases (allow / deny / default-deny / required-absent / fail-closed). A second
 * implementation of refEval MUST reproduce every verdict + the same hashes. Output is committed;
 * CI fails on drift.
 */

import { mkdirSync, writeFileSync, rmSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { policyHash, readSetHash, type Policy } from "../src/policy/dsl.js";
import { evaluate } from "../src/policy/eval.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const OUT = join(__dirname, "..", "..", "conformance", "l2");

const REFUND_GUARD: Policy = {
  spec: "noa.policy/0.2",
  id: "refund-guard-v1",
  requiredPaths: ["action", "amountMinor"],
  rules: [
    { id: "block-million", when: { op: "ge", path: "amountMinor", value: 100_000_000 }, then: "DENY" },
    {
      id: "allow-small-refund",
      when: {
        op: "and",
        clauses: [
          { op: "eq", path: "action", value: "payment.refund" },
          { op: "lt", path: "amountMinor", value: 100_000_000 },
        ],
      },
      then: "ALLOW",
    },
  ],
};

// inputs cover allow / block-rule / default-deny / required-absent / fail-closed (float, type-mismatch)
const CASES: Array<{ name: string; inputs: Record<string, unknown> }> = [
  { name: "small-refund-allow", inputs: { action: "payment.refund", amountMinor: 4200 } },
  { name: "million-refund-block", inputs: { action: "payment.refund", amountMinor: 100_000_000 } },
  { name: "over-million-block", inputs: { action: "payment.refund", amountMinor: 250_000_000 } },
  { name: "non-refund-default-deny", inputs: { action: "db.delete", amountMinor: 1 } },
  { name: "missing-required-amount", inputs: { action: "payment.refund" } },
  { name: "float-amount-fail-closed", inputs: { action: "payment.refund", amountMinor: 1.5 } },
  { name: "type-mismatch-fail-closed", inputs: { action: "payment.refund", amountMinor: "lots" } },
];

const vectors = {
  spec: "noa.l2-conformance/0.2",
  engine: "noa-refeval/0.2",
  note: "A conforming refEval MUST reproduce every verdict + ruleFired + the policyHash/readSetHash below.",
  policies: [
    {
      policy: REFUND_GUARD,
      policyHash: policyHash(REFUND_GUARD),
      readSetHash: readSetHash(REFUND_GUARD),
      cases: CASES.map((c) => {
        const r = evaluate(REFUND_GUARD, c.inputs as never);
        return { name: c.name, inputs: c.inputs, verdict: r.verdict, ruleFired: r.ruleFired };
      }),
    },
  ],
};

rmSync(OUT, { recursive: true, force: true });
mkdirSync(OUT, { recursive: true });
writeFileSync(join(OUT, "refund-guard.vectors.json"), JSON.stringify(vectors, null, 2) + "\n");
process.stdout.write(`generated L2 conformance vectors (${CASES.length} cases) -> ${OUT}\n`);
