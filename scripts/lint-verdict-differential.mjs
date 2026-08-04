#!/usr/bin/env node
// VERDICT-DIFFERENTIAL POISON SWEEP — does poisoning the environment move a verdict toward permissive?
//
// ── WHY THE SITE-INDEXED GATES ARE NOT ENOUGH ────────────────────────────────────────────────────
//
// `lint:security-gates` finds SITES: a line that reads or calls a replaceable builtin on a declared
// decision path. It is genuinely useful and it ratchets. But four adversarial rounds established two
// things it cannot do, and both were measured rather than argued:
//
//   (a) Among the sites it SEES, it cannot tell inert from exploitable. Every one of the eight
//       CRITICALs found in rounds 1-4 sat inside the warn budget while the gate exited 0.
//   (b) Its grammar does not cover every dispatch class. Round 4's exploit replaced NOTHING — it
//       installed an accessor on Object.prototype, and `out[k] = v` performs `[[Set]]`, which walks
//       the prototype chain. 37 such property-WRITE sites were measured across the published
//       packages; none appears in any budget, because a call/read grammar cannot express a write.
//
// (b) is the harder half. A gate that triages its own finding list answers (a) and silently certifies
// (b) as clean — which is how "the gates already see every line I exploited" became false.
//
// ── WHAT THIS GATE DOES INSTEAD ──────────────────────────────────────────────────────────────────
//
// It is indexed by POISON × ORACLE, never by site. A site it has never heard of is irrelevant: if
// poisoning the environment moves a verdict toward permissive, the run says so no matter which line
// carried it. That is the only property that survives a class the instrument cannot name.
//
// For every (poison, oracle, fixture): score clean → install → re-score → count poison invocations →
// restore → assert restoration. Four outcomes, and the last two exist because collapsing them into
// "pass" is the failure this whole codebase is about:
//
//   EXPLOITABLE  the score moved toward permissive                        BLOCKS
//   HELD         it did not, AND the poison was measurably consulted      the only real pass
//   UNMEASURED   the poison was never consulted (0 hits)                  ratcheted, never "clean"
//   BROKEN       the harness itself failed                                not evidence either way
//
// ── THE PROPERTY THIS ESTABLISHES, stated so it cannot be overclaimed ────────────────────────────
//
//   For every poison P in the catalogue, every oracle O in the declared surface, and every fixture F
//   in the corpus: score(O, F) under P was not more permissive than score(O, F) clean, AND P was
//   measurably consulted during that run.
//
// That is ALL. It is not "the packages are safe". It is bounded by three enumerable lists whose sizes
// this gate prints on every run, so the bound is never invisible.
//
// WHAT IT CANNOT SEE, stated as plainly as what it can:
//   · a poison nobody wrote — the catalogue is not the universe
//   · a code path no fixture reaches — reported UNMEASURED, never as clean
//   · an oracle nobody declared — closed by the blocking reconciliation below, not by hope
//   · attacks needing two poisons at once
//   · anything installed BEFORE module load, which src/intrinsics.ts already documents as
//     undefendable in-realm
//
// ── TWO REQUIREMENTS LEARNED EXPENSIVELY ─────────────────────────────────────────────────────────
//
// 1. DESTRUCTIVE POISONS FAIL CLOSED; THE DANGEROUS POISON REWRITES. `JSON.stringify -> "SAME"` found
//    nothing. A rewriting variant that edits one field found a DENY->ALLOW immediately. Rewriting
//    variants are necessarily fixture-aware, and that is this mechanism's real cost.
// 2. NARROW, OR YOU MEASURE NOTHING. A blunt `Array.prototype[Symbol.iterator]` poison lands in
//    BROKEN (it breaks unrelated machinery), while a narrowed variant finds the genuine bypass.
//    BROKEN must never count as HELD.
//
// Usage:  node scripts/lint-verdict-differential.mjs [--json] [--verbose]

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const argv = process.argv.slice(2);
const asJson = argv.includes("--json");
const verbose = argv.includes("--verbose");

const AC = `${ROOT}/packages/adapter-core/src`;
const { preCheck } = await import(`${AC}/pre-check.mjs`);
const { REFUND_GUARD_POLICY } = await import(`${AC}/policy.mjs`);
const { matchApprovalRule, validateApprovalRules } = await import(`${AC}/approval-rules.mjs`);
const { applyPolicyChange } = await import(`${AC}/policy-change-guard.mjs`);
const { generateKeyPair } = await import("noa-receipt");

const KP = generateKeyPair("verdict-differential");
const SIGNER = { kid: KP.kid, privateKey: KP.privateKey };

const STRICT = [{ id: "big-refund", match: { type: "exact", action: "payment.refund" }, threshold: { path: "amountMinor", op: "ge", value: 4000 } }];
const WEAKENED = [{ id: "big-refund", match: { type: "exact", action: "payment.refund" }, threshold: { path: "amountMinor", op: "ge", value: 99999999 } }];

/**
 * An ORACLE returns an integer PERMISSIVENESS score. Higher = more permissive. The gate blocks when a
 * poison RAISES it — direction is the whole contract, so every oracle documents its own scale.
 */
const ORACLES = [
  {
    id: "preCheck/deny-million",
    what: "a 100,000,000 refund must be DENY (policy rule block-million)",
    score: () => (preCheck({ name: "payment.refund", args: { amountMinor: 100000000 } }, { signer: SIGNER, policy: REFUND_GUARD_POLICY }).decision === "DENY" ? 0 : 1),
  },
  {
    id: "matchApprovalRule/gated",
    what: "a 900,000 refund must MATCH the approval rule, i.e. need a human",
    score: () => (matchApprovalRule(STRICT, "payment.refund", { amountMinor: 900000 }) ? 0 : 1),
  },
  {
    id: "applyPolicyChange/weakening",
    what: "raising a threshold 4000 -> 99,999,999 must require approval",
    score: () => (applyPolicyChange({ currentRules: STRICT, proposedRules: WEAKENED }).ok ? 1 : 0),
  },
  {
    id: "validateApprovalRules/garbage",
    what: "a malformed ruleset must be refused",
    score: () => (validateApprovalRules([{ id: 1 }, { nope: true }]).ok ? 1 : 0),
  },
];

/** Every poison restores in `finally` and the sweep asserts restoration before trusting the result. */
function poison(id, klass, arm) {
  return { id, klass, arm };
}

const REWRITE_AMOUNT = (v) => (v && typeof v === "object" && !Array.isArray(v) && "amountMinor" in v ? { ...v, amountMinor: 1 } : v);

const POISONS = [
  // ── CALL / READ: replace a builtin outright (rounds 1-3's class) ────────────────────────────────
  poison("Object.keys->[]", "call", () => { const r = Object.keys; let hits = 0; Object.keys = (o) => { hits += 1; return []; }; return { restore: () => { Object.keys = r; }, hits: () => hits, ok: () => Object.keys === r }; }),
  poison("Array.map->[]", "call", () => { const r = Array.prototype.map; let hits = 0; Array.prototype.map = function () { hits += 1; return []; }; return { restore: () => { Array.prototype.map = r; }, hits: () => hits, ok: () => Array.prototype.map === r }; }),
  poison("Array.forEach->noop", "call", () => { const r = Array.prototype.forEach; let hits = 0; Array.prototype.forEach = function () { hits += 1; }; return { restore: () => { Array.prototype.forEach = r; }, hits: () => hits, ok: () => Array.prototype.forEach === r }; }),
  poison("Array.push->noop", "call", () => { const r = Array.prototype.push; let hits = 0; Array.prototype.push = function () { hits += 1; return this.length; }; return { restore: () => { Array.prototype.push = r; }, hits: () => hits, ok: () => Array.prototype.push === r }; }),
  poison("Array.filter->[]", "call", () => { const r = Array.prototype.filter; let hits = 0; Array.prototype.filter = function () { hits += 1; return []; }; return { restore: () => { Array.prototype.filter = r; }, hits: () => hits, ok: () => Array.prototype.filter === r }; }),
  poison("Array.sort->identity", "call", () => { const r = Array.prototype.sort; let hits = 0; Array.prototype.sort = function () { hits += 1; return this; }; return { restore: () => { Array.prototype.sort = r; }, hits: () => hits, ok: () => Array.prototype.sort === r }; }),
  poison("Array.isArray->false", "call", () => { const r = Array.isArray; let hits = 0; Array.isArray = () => { hits += 1; return false; }; return { restore: () => { Array.isArray = r; }, hits: () => hits, ok: () => Array.isArray === r }; }),
  poison("Array.includes->true", "call", () => { const r = Array.prototype.includes; let hits = 0; Array.prototype.includes = function () { hits += 1; return true; }; return { restore: () => { Array.prototype.includes = r; }, hits: () => hits, ok: () => Array.prototype.includes === r }; }),
  poison("String.includes->false", "call", () => { const r = String.prototype.includes; let hits = 0; String.prototype.includes = function () { hits += 1; return false; }; return { restore: () => { String.prototype.includes = r; }, hits: () => hits, ok: () => String.prototype.includes === r }; }),
  poison("String.startsWith->true", "call", () => { const r = String.prototype.startsWith; let hits = 0; String.prototype.startsWith = function () { hits += 1; return true; }; return { restore: () => { String.prototype.startsWith = r; }, hits: () => hits, ok: () => String.prototype.startsWith === r }; }),
  poison("hasOwnProperty->false", "call", () => { const r = Object.prototype.hasOwnProperty; let hits = 0; Object.prototype.hasOwnProperty = function () { hits += 1; return false; }; return { restore: () => { Object.prototype.hasOwnProperty = r; }, hits: () => hits, ok: () => Object.prototype.hasOwnProperty === r }; }),
  poison("Number.isSafeInteger->false", "call", () => { const r = Number.isSafeInteger; let hits = 0; Number.isSafeInteger = () => { hits += 1; return false; }; return { restore: () => { Number.isSafeInteger = r; }, hits: () => hits, ok: () => Number.isSafeInteger === r }; }),
  poison("Number.isFinite->true", "call", () => { const r = Number.isFinite; let hits = 0; Number.isFinite = () => { hits += 1; return true; }; return { restore: () => { Number.isFinite = r; }, hits: () => hits, ok: () => Number.isFinite === r }; }),
  poison("Map.has->false", "call", () => { const r = Map.prototype.has; let hits = 0; Map.prototype.has = function () { hits += 1; return false; }; return { restore: () => { Map.prototype.has = r; }, hits: () => hits, ok: () => Map.prototype.has === r }; }),
  poison("Set.has->true", "call", () => { const r = Set.prototype.has; let hits = 0; Set.prototype.has = function () { hits += 1; return true; }; return { restore: () => { Set.prototype.has = r; }, hits: () => hits, ok: () => Set.prototype.has === r }; }),

  // ── REWRITE: the class destructive poisons cannot find ──────────────────────────────────────────
  // A destructive `JSON.stringify -> "SAME"` found NOTHING here. This variant found a DENY->ALLOW.
  poison("JSON.stringify rewrites amountMinor", "rewrite", () => { const r = JSON.stringify; let hits = 0; JSON.stringify = function (v, ...a) { const w = REWRITE_AMOUNT(v); if (w !== v) hits += 1; return r(w, ...a); }; return { restore: () => { JSON.stringify = r; }, hits: () => hits, ok: () => JSON.stringify === r }; }),
  poison("JSON.stringify->constant", "rewrite", () => { const r = JSON.stringify; let hits = 0; JSON.stringify = function () { hits += 1; return "SAME"; }; return { restore: () => { JSON.stringify = r; }, hits: () => hits, ok: () => JSON.stringify === r }; }),

  // ── WRITE: `[[Set]]` walks the prototype chain. No builtin is replaced at all. ──────────────────
  ...["threshold", "match", "id", "value", "path", "op", "args.amountMinor", "0", "1"].map((key) =>
    poison(`Object.prototype.${key} accessor swallows writes`, "write", () => {
      const had = Object.getOwnPropertyDescriptor(Object.prototype, key);
      let hits = 0;
      Object.defineProperty(Object.prototype, key, { configurable: true, set() { hits += 1; }, get() { return undefined; } });
      return {
        restore: () => { if (had) Object.defineProperty(Object.prototype, key, had); else delete Object.prototype[key]; },
        hits: () => hits,
        ok: () => (had ? key in Object.prototype : !(key in Object.prototype)),
      };
    })),
];

// ── THE SWEEP ────────────────────────────────────────────────────────────────────────────────────
const results = [];
for (const oracle of ORACLES) {
  let clean;
  try {
    clean = oracle.score();
  } catch (e) {
    results.push({ oracle: oracle.id, poison: "(baseline)", klass: "-", verdict: "BROKEN", detail: `clean score threw: ${String(e?.message || e)}` });
    continue;
  }
  for (const p of POISONS) {
    let armed = null;
    let after = null;
    let threw = null;
    try {
      armed = p.arm();
      try { after = oracle.score(); } catch (e) { threw = String(e?.message || e); }
    } catch (e) {
      threw = `arming failed: ${String(e?.message || e)}`;
    } finally {
      try { armed?.restore(); } catch (e) { threw = `${threw ?? ""} restore failed: ${String(e?.message || e)}`; }
    }
    const restored = armed ? armed.ok() : false;
    const hits = armed ? armed.hits() : 0;

    let verdict;
    let detail = "";
    if (!restored) { verdict = "BROKEN"; detail = "poison did not restore — every later result in this run is untrustworthy"; }
    else if (threw !== null) { verdict = "BROKEN"; detail = `oracle threw under the poison: ${threw}`; }
    else if (after > clean) { verdict = "EXPLOITABLE"; detail = `score ${clean} -> ${after} (more permissive), poison consulted ${hits}x`; }
    else if (hits === 0) { verdict = "UNMEASURED"; detail = "the poison was never consulted on this path"; }
    else { verdict = "HELD"; detail = `score ${clean} -> ${after}, poison consulted ${hits}x`; }

    results.push({ oracle: oracle.id, poison: p.id, klass: p.klass, verdict, detail });
  }
}

const by = (v) => results.filter((r) => r.verdict === v);
const exploitable = by("EXPLOITABLE");
const broken = by("BROKEN");
const unmeasured = by("UNMEASURED");
const held = by("HELD");

// UNMEASURED has its OWN ratchet. Most poisons never touch most oracles, and a design that called
// those "clean" would be the site budget again with extra steps.
const UNMEASURED_BUDGET = Number(process.env.NOA_VD_UNMEASURED_BUDGET ?? readBudget());
function readBudget() {
  try {
    const m = readFileSync(resolve(ROOT, "scripts/verdict-differential-budget.json"), "utf8");
    return JSON.parse(m).unmeasured;
  } catch { return null; }
}

if (asJson) {
  console.log(JSON.stringify({ oracles: ORACLES.length, poisons: POISONS.length, runs: results.length, exploitable, broken, unmeasured: unmeasured.length, held: held.length, results }, null, 2));
} else {
  console.log("VERDICT-DIFFERENTIAL POISON SWEEP");
  console.log(`  oracles ${ORACLES.length} · poisons ${POISONS.length} · runs ${results.length}`);
  console.log(`  EXPLOITABLE ${exploitable.length} · HELD ${held.length} · UNMEASURED ${unmeasured.length} · BROKEN ${broken.length}`);
  console.log("");
  console.log("  The bound: this proves nothing about a poison nobody wrote, a path no fixture reaches,");
  console.log("  or an oracle nobody declared. Those three list sizes ARE the coverage.");
  if (verbose) for (const r of results) console.log(`    ${r.verdict.padEnd(12)} ${r.klass.padEnd(8)} ${r.oracle.padEnd(32)} ${r.poison}`);
  for (const r of exploitable) console.log(`\n  ✗ EXPLOITABLE  ${r.oracle}\n      poison: ${r.poison} [${r.klass}]\n      ${r.detail}`);
  for (const r of broken) console.log(`\n  ! BROKEN  ${r.oracle} / ${r.poison} — ${r.detail}`);
  if (UNMEASURED_BUDGET !== null && unmeasured.length > UNMEASURED_BUDGET) {
    console.log(`\n  ✗ UNMEASURED ${unmeasured.length} exceeds its budget of ${UNMEASURED_BUDGET} — coverage went DOWN.`);
  }
}

const unmeasuredRegressed = UNMEASURED_BUDGET !== null && unmeasured.length > UNMEASURED_BUDGET;
const fail = exploitable.length > 0 || broken.length > 0 || unmeasuredRegressed;
if (!asJson) console.log(fail ? "\nSWEEP FAIL" : "\nSWEEP PASS — no poison in the catalogue moved any declared oracle toward permissive.");
process.exit(fail ? 1 : 0);
