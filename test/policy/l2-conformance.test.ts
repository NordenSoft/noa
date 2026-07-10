import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { evaluate } from "../../src/policy/eval.js";
import { policyHash, readSetHash, type Policy } from "../../src/policy/dsl.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const L2_DIR = join(__dirname, "..", "..", "..", "conformance", "l2");
// Every committed L2 vector file is loaded (refund-guard = baseline; utf16-edge = the UTF-16
// interop-landmine corpus). Any new file dropped here is conformance-checked automatically.
const VEC_FILES = ["refund-guard.vectors.json", "utf16-edge.vectors.json"];

interface L2Vectors {
  policies: Array<{
    policy: Policy;
    // null ⇒ the policy is over-depth/invalid and UNHASHABLE; a conforming impl must ALSO refuse to hash it.
    policyHash: string | null;
    readSetHash: string | null;
    cases: Array<{ name: string; inputs: Record<string, unknown>; verdict: string; ruleFired: string | null }>;
  }>;
}

function loadAll(): Array<{ file: string; v: L2Vectors }> {
  return VEC_FILES.map((file) => ({ file, v: JSON.parse(readFileSync(join(L2_DIR, file), "utf8")) as L2Vectors }));
}

/** Reproduce a hash, OR null if the policy is unhashable (over-depth) — both impls must agree on which. */
function tryHash(fn: (p: Policy) => string, p: Policy): string | null {
  try {
    return fn(p);
  } catch {
    return null;
  }
}

test("L2 conformance: re-evaluating every committed vector reproduces verdict + ruleFired + hashes", () => {
  for (const { file, v } of loadAll()) {
    assert.ok(v.policies.length > 0, `${file}: must have at least one policy block`);
    for (const block of v.policies) {
      // hashes must reproduce (any re-implementer must compute the same — incl. "null = refuses to hash")
      assert.equal(tryHash(policyHash, block.policy), block.policyHash, `${file}: policyHash mismatch (${block.policy.id})`);
      assert.equal(tryHash(readSetHash, block.policy), block.readSetHash, `${file}: readSetHash mismatch (${block.policy.id})`);
      for (const c of block.cases) {
        const r = evaluate(block.policy, c.inputs as never);
        assert.equal(r.verdict, c.verdict, `${file}: verdict mismatch for case "${c.name}"`);
        assert.equal(r.ruleFired, c.ruleFired, `${file}: ruleFired mismatch for case "${c.name}"`);
      }
    }
  }
});

test("L2 conformance: the corpus actually exercises allow + block + default-deny + fail-closed", () => {
  const all = loadAll().flatMap(({ v }) => v.policies);
  const verdicts = new Set(all.flatMap((p) => p.cases.map((c) => c.verdict)));
  const rules = new Set(all.flatMap((p) => p.cases.map((c) => c.ruleFired)));
  assert.ok(verdicts.has("ALLOW") && verdicts.has("DENY"), "must cover both ALLOW and DENY");
  assert.ok([...rules].some((r) => r === null), "must cover default-deny (ruleFired null)");
  assert.ok([...rules].some((r) => (r ?? "").startsWith("required-input-absent")), "must cover required-absent");
  assert.ok([...rules].some((r) => r === "eval-error"), "must cover fail-closed eval-error");
});

test("L2 conformance: the utf16-edge corpus pins UTF-16 code-unit ordering divergences", () => {
  const utf16 = loadAll().find(({ file }) => file === "utf16-edge.vectors.json");
  assert.ok(utf16, "utf16-edge.vectors.json must be present");
  const cases = utf16!.v.policies.flatMap((p) => p.cases);
  // the engineered divergence cases must be present AND pin the UTF-16 (not code-point) verdict
  const byName = (n: string) => cases.find((c) => c.name === n);
  assert.equal(byName("A-astral-lt-divergence-ALLOW")?.verdict, "ALLOW", "astral lt must pin ALLOW (UTF-16), where code-point would DENY");
  assert.equal(byName("F1-cjk-gt-ff00-DENY-divergence")?.verdict, "DENY", "CJK gt FF00 must pin DENY (UTF-16), where code-point would ALLOW");
  assert.equal(byName("F2-cjk-gt-fffd-DENY-divergence")?.verdict, "DENY", "CJK gt FFFD must pin DENY (UTF-16), where code-point would ALLOW");
  // BMP/astral boundary: flip at U+E000 (diverge), agree at U+D7FF (lower edge), shared-prefix multi-position
  assert.equal(byName("G1-boundary-flip-e000-divergence-ALLOW")?.verdict, "ALLOW", "U+E000 boundary must pin ALLOW (UTF-16), where code-point would DENY");
  assert.equal(byName("G2-boundary-agree-d7ff-DENY")?.verdict, "DENY", "U+D7FF boundary must be DENY in BOTH orderings (no divergence — lower edge)");
  assert.equal(byName("G3-shared-prefix-divergence-ALLOW")?.verdict, "ALLOW", "shared-prefix divergence at position 2 must pin ALLOW (UTF-16)");
  // depth-cap fail-closed + boolean-compare findings are recorded as ground truth
  assert.equal(byName("E-deep-62-fail-closed")?.ruleFired, "policy-invalid", "depth-62 must fail-closed policy-invalid");
  assert.equal(byName("E-deep-500-fail-closed")?.ruleFired, "policy-invalid", "depth-500 must fail-closed policy-invalid");
  assert.equal(byName("E-deep-50-evaluates")?.verdict, "ALLOW", "depth-50 evaluates (below the depth-64 cap)");
});
