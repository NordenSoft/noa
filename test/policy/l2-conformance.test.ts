import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { evaluate } from "../../src/policy/eval.js";
import { policyHash, readSetHash, type Policy } from "../../src/policy/dsl.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const VEC = join(__dirname, "..", "..", "..", "conformance", "l2", "refund-guard.vectors.json");

interface L2Vectors {
  policies: Array<{
    policy: Policy;
    policyHash: string;
    readSetHash: string;
    cases: Array<{ name: string; inputs: Record<string, unknown>; verdict: string; ruleFired: string | null }>;
  }>;
}

test("L2 conformance: re-evaluating every committed vector reproduces verdict + ruleFired + hashes", () => {
  const v = JSON.parse(readFileSync(VEC, "utf8")) as L2Vectors;
  assert.ok(v.policies.length > 0, "must have at least one policy block");
  for (const block of v.policies) {
    // hashes must reproduce (any re-implementer must compute the same)
    assert.equal(policyHash(block.policy), block.policyHash, "policyHash mismatch");
    assert.equal(readSetHash(block.policy), block.readSetHash, "readSetHash mismatch");
    for (const c of block.cases) {
      const r = evaluate(block.policy, c.inputs as never);
      assert.equal(r.verdict, c.verdict, `verdict mismatch for case "${c.name}"`);
      assert.equal(r.ruleFired, c.ruleFired, `ruleFired mismatch for case "${c.name}"`);
    }
  }
});

test("L2 conformance: the corpus actually exercises allow + block + default-deny + fail-closed", () => {
  const v = JSON.parse(readFileSync(VEC, "utf8")) as L2Vectors;
  const verdicts = new Set(v.policies.flatMap((p) => p.cases.map((c) => c.verdict)));
  const rules = new Set(v.policies.flatMap((p) => p.cases.map((c) => c.ruleFired)));
  assert.ok(verdicts.has("ALLOW") && verdicts.has("DENY"), "must cover both ALLOW and DENY");
  assert.ok([...rules].some((r) => r === null), "must cover default-deny (ruleFired null)");
  assert.ok([...rules].some((r) => (r ?? "").startsWith("required-input-absent")), "must cover required-absent");
  assert.ok([...rules].some((r) => r === "eval-error"), "must cover fail-closed eval-error");
});
