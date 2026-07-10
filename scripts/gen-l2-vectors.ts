/**
 * Deterministic L2 conformance-vector generator — the PRIMARY L2 deliverable: the
 * conformance corpus matters more than the evaluator code; it pins behaviour for any re-implementer.
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

// inputs cover allow / block-rule / default-deny / required-absent / fail-closed. NB the two fail-closed
// cases trip DIFFERENT guards: the float 1.5 fails the input-scalar well-formedness pass (assertScalar's
// Number.isSafeInteger check, eval.ts:126) BEFORE any rule runs; the string "lots" passes that pass and
// fail-closes later inside cmp() on a string-vs-number type mismatch. Both => DENY ruleFired "eval-error".
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

// ─────────────────────────────────────────────────────────────────────────────
// UTF-16 / edge-case interop-landmine corpus. Pins the #1
// cross-impl divergence: NOA orders strings by raw UTF-16 CODE-UNIT value
// (eval.ts cmp, RFC-8785/JCS-aligned). A 2nd impl that orders by Unicode
// code-point (or by naive UTF-8 byte) DIVERGES on astral-plane chars (U+10000+),
// because an astral char's first UTF-16 code unit is a HIGH SURROGATE in 0xD800..
// 0xDBFF (55296..56319) — LOWER than the BMP block 0xE000..0xFFFF. So an astral
// char sorts BELOW every char in 0xD800..0xFFFF under UTF-16, but ABOVE all of
// them under code-point. Every "*-divergence" case below is engineered so the
// pinned (UTF-16) verdict is the OPPOSITE of a code-point/UTF-8 evaluator's —
// a non-conforming evaluator FAILS these vectors. All verdicts/ruleFired/hashes are
// produced by RUNNING the real evaluator + real hash fns (never hand-written).
type PolicyCase = { name: string; inputs: Record<string, unknown>; note?: string };
type PolicyBlock = { policy: Policy; cases: PolicyCase[] };

// helper: nest `not` `depth` times around a leaf (Case E deep-nesting policies)
function nestNot(depth: number, inner: object): object {
  let c: object = inner;
  for (let i = 0; i < depth; i++) c = { op: "not", clause: c };
  return c;
}

const ASTRAL_LT: Policy = {
  // A. rule "lt ￿(U+FFFF)" then ALLOW; default DENY. Input 𐀀(U+10000).
  spec: "noa.policy/0.2",
  id: "utf16-astral-lt-v1",
  requiredPaths: ["label"],
  rules: [{ id: "allow-below-ffff", when: { op: "lt", path: "label", value: "￿" }, then: "ALLOW" }],
};
const IN_ASTRAL: Policy = {
  // B. `in` set with an astral emoji (😀 U+1F600, surrogate pair) + an é string.
  spec: "noa.policy/0.2",
  id: "utf16-in-astral-v1",
  requiredPaths: ["tag"],
  rules: [{ id: "allow-in-set", when: { op: "in", path: "tag", values: ["a", "\u{1F600}", "café"] }, then: "ALLOW" }],
};
const NEG_INT: Policy = {
  // C. negative-integer ordering.
  spec: "noa.policy/0.2",
  id: "utf16-neg-int-v1",
  requiredPaths: ["balance"],
  rules: [{ id: "allow-below-neg100", when: { op: "lt", path: "balance", value: -100 }, then: "ALLOW" }],
};
const BOOL_EQ: Policy = {
  // D. boolean eq.
  spec: "noa.policy/0.2",
  id: "utf16-bool-eq-v1",
  requiredPaths: ["flag"],
  rules: [{ id: "allow-flag-true", when: { op: "eq", path: "flag", value: true }, then: "ALLOW" }],
};
const BOOL_LT: Policy = {
  // D. lt on a boolean — REAL behavior recorded (the evaluator compares false<true as 0<1, it does NOT throw).
  spec: "noa.policy/0.2",
  id: "utf16-bool-lt-v1",
  requiredPaths: ["flag"],
  rules: [{ id: "allow-flag-lt-true", when: { op: "lt", path: "flag", value: true }, then: "ALLOW" }],
};
const BOOL_GT: Policy = {
  // D. gt on a boolean — REAL behavior recorded (true>false as 1>0, does NOT throw).
  spec: "noa.policy/0.2",
  id: "utf16-bool-gt-v1",
  requiredPaths: ["flag"],
  rules: [{ id: "allow-flag-gt-false", when: { op: "gt", path: "flag", value: false }, then: "ALLOW" }],
};
const DEEP_50: Policy = {
  // E. depth-50 not-nesting — RUN it: the depth guard does NOT bite here, it evaluates fine.
  spec: "noa.policy/0.2",
  id: "utf16-deep-50-v1",
  requiredPaths: ["x"],
  rules: [{ id: "deep-ok", when: nestNot(50, { op: "eq", path: "x", value: 1 }) as never, then: "ALLOW" }],
};
const DEEP_62: Policy = {
  // E. depth-62 not-nesting — the validator/canonicalize depth-64 limit BITES here (policy-invalid, fail-closed DENY).
  spec: "noa.policy/0.2",
  id: "utf16-deep-62-v1",
  requiredPaths: ["x"],
  rules: [{ id: "deep-overcap", when: nestNot(62, { op: "eq", path: "x", value: 1 }) as never, then: "ALLOW" }],
};
const DEEP_500: Policy = {
  // E. depth-500 not-nesting — far past the cap, fail-closed DENY policy-invalid.
  spec: "noa.policy/0.2",
  id: "utf16-deep-500-v1",
  requiredPaths: ["x"],
  rules: [{ id: "deep-way-overcap", when: nestNot(500, { op: "eq", path: "x", value: 1 }) as never, then: "ALLOW" }],
};
const CJK_GT_FF00: Policy = {
  // F1. gt ＀(U+FF00, BMP). Input 𠀀(U+20000, CJK-ext-B).
  spec: "noa.policy/0.2",
  id: "utf16-cjk-gt-ff00-v1",
  requiredPaths: ["name"],
  rules: [{ id: "allow-above-ff00", when: { op: "gt", path: "name", value: "＀" }, then: "ALLOW" }],
};
const CJK_GT_FFFD: Policy = {
  // F2. gt �(U+FFFD, BMP replacement char). Input 𠀀(U+20000).
  spec: "noa.policy/0.2",
  id: "utf16-cjk-gt-fffd-v1",
  requiredPaths: ["name"],
  rules: [{ id: "allow-above-fffd", when: { op: "gt", path: "name", value: "�" }, then: "ALLOW" }],
};
// Boundary chars built with EXPLICIT escapes (never pasted literals): a Private-Use / special-range
// char can be silently stripped or substituted in transit, which would change the policy value and the
// hash.  = smallest BMP code point ABOVE the surrogate range; ퟿ = largest BMP code point
// BELOW it; these two bracket the surrogate block 0xD800..0xDFFF where UTF-16-vs-code-point ordering of
// astral chars flips.
const BNDRY_FLIP_E000: Policy = {
  // G1. lt  (smallest BMP above surrogates). Input 𐀀(U+10000) — DIVERGES.
  spec: "noa.policy/0.2",
  id: "utf16-bndry-flip-e000-v1",
  requiredPaths: ["label"],
  rules: [{ id: "allow-below-e000", when: { op: "lt", path: "label", value: "" }, then: "ALLOW" }],
};
const BNDRY_AGREE_D7FF: Policy = {
  // G2. lt ퟿ (largest BMP below surrogates). Input 𐀀 — AGREES (lower edge where divergence stops).
  spec: "noa.policy/0.2",
  id: "utf16-bndry-agree-d7ff-v1",
  requiredPaths: ["label2"],
  rules: [{ id: "allow-below-d7ff", when: { op: "lt", path: "label2", value: "퟿" }, then: "ALLOW" }],
};
const SHARED_PREFIX_FFFF: Policy = {
  // G3. lt "x￿" — shared prefix "x", diverges at position 2. Input "x𐀀".
  spec: "noa.policy/0.2",
  id: "utf16-shared-prefix-v1",
  requiredPaths: ["name3"],
  rules: [{ id: "allow-below-xffff", when: { op: "lt", path: "name3", value: "x￿" }, then: "ALLOW" }],
};

const UTF16_BLOCKS: PolicyBlock[] = [
  {
    policy: ASTRAL_LT,
    cases: [
      {
        name: "A-astral-lt-divergence-ALLOW",
        inputs: { label: "\u{10000}" }, // 𐀀, first code unit 0xD800
        note: "DIVERGES: UTF-16 firstCU 0xD800 < 0xFFFF => lt TRUE => ALLOW (pinned). A code-point/UTF-8 evaluator computes U+10000 > U+FFFF => lt FALSE => would WRONGLY DENY.",
      },
      {
        name: "A2-astral-lt-boundary-DENY",
        inputs: { label: "￿" }, // ￿ equals the bound => lt FALSE
        note: "Boundary: label == value (U+FFFF) => lt FALSE => default DENY (no divergence).",
      },
    ],
  },
  {
    policy: IN_ASTRAL,
    cases: [
      { name: "B-in-astral-emoji-match", inputs: { tag: "\u{1F600}" }, note: "Full surrogate-pair (U+1F600 😀) string equality inside `in` => match." },
      { name: "B-in-cafe-no-accent-no-match", inputs: { tag: "cafe" }, note: "'cafe' != 'café' (no é U+00E9) => not in set => default DENY." },
    ],
  },
  {
    policy: NEG_INT,
    cases: [
      { name: "C-neg-below", inputs: { balance: -200 } },
      { name: "C-neg-at-bound", inputs: { balance: -100 } },
      { name: "C-neg-above", inputs: { balance: -99 } },
    ],
  },
  {
    policy: BOOL_EQ,
    cases: [
      { name: "D-bool-eq-true-match", inputs: { flag: true } },
      { name: "D-bool-eq-false-no-match", inputs: { flag: false } },
    ],
  },
  {
    policy: BOOL_LT,
    cases: [
      { name: "D-bool-lt-false-lt-true", inputs: { flag: false }, note: "REAL behavior: evaluator compares booleans numerically (false=0 < true=1) => lt TRUE => ALLOW. lt/gt on a boolean does NOT throw/fail-close." },
      { name: "D-bool-lt-true-not-lt-true", inputs: { flag: true }, note: "true(1) < true(1) => FALSE => default DENY." },
    ],
  },
  {
    policy: BOOL_GT,
    cases: [
      { name: "D-bool-gt-true-gt-false", inputs: { flag: true }, note: "REAL behavior: true(1) > false(0) => gt TRUE => ALLOW (boolean comparison, no eval-error)." },
    ],
  },
  {
    policy: DEEP_50,
    cases: [
      { name: "E-deep-50-evaluates", inputs: { x: 1 }, note: "depth-50 not-nesting: the depth-64 guard does NOT bite; evaluator deep-recurses and ALLOWs. FINDING: recursion is bounded only by the depth-64 structural cap (validator + canonicalize), NOT by an engine stack limit — a conforming 2nd impl MUST enforce the same depth-64 cap (see deep-62) so stack-limit differences cannot cause divergence." },
    ],
  },
  {
    policy: DEEP_62,
    cases: [
      { name: "E-deep-62-fail-closed", inputs: { x: 1 }, note: "Fail-closed DENY policy-invalid. The cap is MAX_DEPTH=64, enforced by canonicalize (jcs.ts:32) and asserted by validatePolicy (validate.ts). AUTHOR not-nesting depth is NOT the canonicalize depth: each `not` wrapper is one OBJECT level, and canonicalize also counts the policy->rules->[array]->rule->when wrappers (and an extra array level inside every and/or), so the first not-nesting that canonicalize rejects is ~depth-61 (62 is safely past it). The load-bearing interop point: a conforming 2nd impl MUST count EVERY object AND array nesting level identically and enforce MAX_DEPTH=64 — miscounting (e.g. ignoring array levels) makes it accept/reject at a different author-depth and diverge at the boundary." },
    ],
  },
  {
    policy: DEEP_500,
    cases: [
      { name: "E-deep-500-fail-closed", inputs: { x: 1 }, note: "depth-500 not-nesting => policy-invalid => fail-closed DENY (far past the depth-64 cap)." },
    ],
  },
  {
    policy: CJK_GT_FF00,
    cases: [
      {
        name: "F1-cjk-gt-ff00-DENY-divergence",
        inputs: { name: "\u{20000}" }, // 𠀀 first code unit 0xD840
        note: "DIVERGES: UTF-16 firstCU 0xD840 < 0xFF00 => gt FALSE => default DENY (pinned). A code-point evaluator computes U+20000 > U+FF00 => gt TRUE => would WRONGLY ALLOW.",
      },
    ],
  },
  {
    policy: CJK_GT_FFFD,
    cases: [
      {
        name: "F2-cjk-gt-fffd-DENY-divergence",
        inputs: { name: "\u{20000}" }, // 𠀀
        note: "DIVERGES: UTF-16 firstCU 0xD840 < 0xFFFD => gt FALSE => default DENY (pinned). A code-point evaluator computes U+20000 > U+FFFD => gt TRUE => would WRONGLY ALLOW.",
      },
    ],
  },
  {
    // G1. BMP/astral boundary FLIP — the smallest BMP char ABOVE the surrogate range (U+E000) that still
    // diverges. An impl that only passes the U+FFFF cases could still mishandle the U+E000 boundary; this
    // locks it. (Built with explicit code points; the U+E000 literal can be stripped in transit.)
    policy: BNDRY_FLIP_E000,
    cases: [
      {
        name: "G1-boundary-flip-e000-divergence-ALLOW",
        inputs: { label: "\u{10000}" }, // 𐀀, first code unit 0xD800
        note: "DIVERGES: value = U+E000 (smallest BMP above surrogates). UTF-16 firstCU 0xD800 < 0xE000 => lt TRUE => ALLOW (pinned). A code-point evaluator computes U+10000 (65536) NOT < U+E000 (57344) => lt FALSE => would WRONGLY DENY.",
      },
    ],
  },
  {
    // G2. BMP/astral boundary AGREE — the largest BMP char BELOW the surrogate range (U+D7FF). This is the
    // lower edge where divergence STOPS: both orderings put the astral char ABOVE U+D7FF, so both => DENY.
    policy: BNDRY_AGREE_D7FF,
    cases: [
      {
        name: "G2-boundary-agree-d7ff-DENY",
        inputs: { label2: "\u{10000}" }, // 𐀀
        note: "NO DIVERGENCE (locks the lower edge): value = U+D7FF (largest BMP below surrogates). UTF-16 firstCU 0xD800 > 0xD7FF => lt FALSE => DENY (pinned). A code-point evaluator computes U+10000 > U+D7FF => lt FALSE => ALSO DENY. Both AGREE.",
      },
    ],
  },
  {
    // G3. Shared-prefix / multi-position: the strings share "x" then diverge at position 2 — proves the
    // UTF-16-vs-code-point divergence is NOT only a first-character phenomenon.
    policy: SHARED_PREFIX_FFFF,
    cases: [
      {
        name: "G3-shared-prefix-divergence-ALLOW",
        inputs: { name3: "x\u{10000}" }, // "x𐀀"
        note: "DIVERGES at position 2: both strings share prefix 'x', then compare 𐀀 vs U+FFFF. UTF-16 firstCU-of-tail 0xD800 < 0xFFFF => lt TRUE => ALLOW (pinned). A code-point evaluator computes U+10000 > U+FFFF => lt FALSE => would WRONGLY DENY. Proves the divergence isn't first-position-only.",
      },
    ],
  },
];

const utf16Vectors = {
  spec: "noa.l2-conformance/0.2",
  engine: "noa-refeval/0.2",
  note:
    "UTF-16 / edge-case interop-landmine corpus. NOA orders strings by RAW UTF-16 CODE-UNIT value (eval.ts cmp, RFC-8785/JCS-aligned), NOT by Unicode code-point or UTF-8 byte. On astral-plane chars (U+10000+) the first UTF-16 code unit is a HIGH SURROGATE 0xD800..0xDBFF — LOWER than BMP 0xE000..0xFFFF — so an astral char sorts BELOW the U+D800..U+FFFF range under UTF-16 but ABOVE it under code-point. Cases tagged '*-divergence' are engineered so the pinned (UTF-16) verdict is the OPPOSITE of a code-point/UTF-8-order evaluator's: A pins ALLOW where code-point gives DENY (U+10000 vs U+FFFF); F1/F2 pin DENY where code-point gives ALLOW (U+20000 vs U+FF00 / U+FFFD). BMP/astral BOUNDARY coverage (G): G1 pins ALLOW vs U+E000 (smallest BMP above surrogates — code-point would DENY); G2 pins DENY vs U+D7FF (largest BMP below surrogates — the lower edge where BOTH orderings AGREE, divergence STOPS); G3 pins ALLOW with a SHARED 'x' prefix that diverges at position 2 (proves it isn't first-position-only). A non-conforming (code-point/byte-order) evaluator FAILS the divergence cases. Booleans: lt/gt compare numerically (false<true), they do NOT fail-close. Depth: MAX_DEPTH=64 enforced by canonicalize (jcs.ts:32) + validatePolicy bounds recursion — a conforming impl MUST count every object AND array nesting level identically; deep-50 evaluates, deep-62/deep-500 fail-close policy-invalid (and are UNHASHABLE → policyHash:null, which a conforming impl must reproduce). Every verdict/ruleFired/policyHash/readSetHash below was produced by RUNNING the real evaluator + real hash fns.",
  policies: UTF16_BLOCKS.map((b) => {
    // An over-depth policy (deep-62 / deep-500) is INVALID and therefore UNHASHABLE: canonicalize()
    // throws past the depth-64 cap, so policyHash/readSetHash have no value (null). A conforming 2nd
    // impl MUST also refuse to hash it — recording null pins "both sides refuse", never a fake hash.
    const tryHash = (fn: (p: Policy) => string): string | null => {
      try {
        return fn(b.policy);
      } catch {
        return null;
      }
    };
    return {
      policy: b.policy,
      policyHash: tryHash(policyHash),
      readSetHash: tryHash(readSetHash),
      cases: b.cases.map((c) => {
        const r = evaluate(b.policy, c.inputs as never);
        return { name: c.name, inputs: c.inputs, verdict: r.verdict, ruleFired: r.ruleFired, ...(c.note ? { note: c.note } : {}) };
      }),
    };
  }),
};

rmSync(OUT, { recursive: true, force: true });
mkdirSync(OUT, { recursive: true });
writeFileSync(join(OUT, "refund-guard.vectors.json"), JSON.stringify(vectors, null, 2) + "\n");
writeFileSync(join(OUT, "utf16-edge.vectors.json"), JSON.stringify(utf16Vectors, null, 2) + "\n");
const utf16Cases = UTF16_BLOCKS.reduce((n, b) => n + b.cases.length, 0);
process.stdout.write(`generated L2 conformance vectors (refund-guard: ${CASES.length} cases, utf16-edge: ${utf16Cases} cases) -> ${OUT}\n`);
