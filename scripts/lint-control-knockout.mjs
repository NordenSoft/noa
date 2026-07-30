#!/usr/bin/env node
/**
 * L4 — CONTROL KNOCKOUT: every security control must have a test that fails when the control is
 * REMOVED (ADR §8.2). A control nothing measures is deleted or fixed.
 *
 * WHY KNOCKOUT AND NOT MUTATION TOOLING. A blanket mutation runner over the TCB would spend hours
 * flipping arithmetic operators in a canonicalizer and produce a survival percentage — a number
 * that answers a question nobody asked. The question here is exact and small: *for this specific
 * security control, is there a test that goes red without it?* That is answered by deleting the
 * control and running the suite. Twelve targeted knockouts that each name a real defensive
 * mechanism are worth more than a 90%-mutation-score badge, and they can be read in a minute.
 *
 * WHY THIS EXISTS AT ALL. `packages/gate/test/grant-atomic.test.ts:66` asserted the C-04 defect as
 * correct behaviour and passed for months. Nothing in the repository disagreed with it, because the
 * suite's only opinion on the matter WAS that test. Knockout is the mechanical form of the question
 * "and what, exactly, would have caught this?"
 *
 * THE RULE: a knockout that leaves the suite GREEN is a finding. It means either the control is not
 * load-bearing (delete it) or nothing tests it (write the test). The runner never edits anything
 * permanently — each knockout is applied to a scratch copy, the suite is run, and the file is
 * restored from the pristine copy taken before the run, in a `finally`.
 *
 * Run:  node scripts/lint-control-knockout.mjs [--warn] [--only <id>]
 */
import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const WARN_ONLY = process.argv.includes("--warn");
const onlyIdx = process.argv.indexOf("--only");
const ONLY = onlyIdx > -1 ? process.argv[onlyIdx + 1] : null;

/**
 * Each entry names ONE defensive mechanism, the exact source edit that removes it, and the suite
 * that must go red. `find` must match EXACTLY ONCE — an ambiguous knockout is not a knockout, and
 * a `find` that stops matching means the control moved and this entry has rotted (which is itself
 * reported, so the registry cannot silently stop describing the code).
 */
const KNOCKOUTS = [
  // ── ADR-0005 (2026-07-30) ───────────────────────────────────────────────────────────────────────
  // This registry carried 28 entries and NOT ONE covered ADR-0005, while its own header says a fix
  // without a knockout is a claim. Seven controls were built or repaired in that work and every one
  // of them was knocked out by hand at the time; these entries make that permanent, so the next
  // refactor cannot quietly restore a defect the tests would then pass over.
  //
  // Every find/replace below is BEHAVIOURAL and COMPILES. Three of my first attempts were compile
  // errors, which this file already refuses (see the header): a compile error proves the identifier
  // exists, not that the check runs.
  {
    id: "adr5-relay-cross-agent-ownership",
    control: "E-3 — a foreign agent cannot read another agent's hold, receipt or decisionArtifact (F29-authz, ported)",
    file: "packages/relay/src/engine.ts",
    find: 'if (!this.ownsHold(hold, agent, "getHold")) return err(404, "UNKNOWN_HOLD");',
    replace: 'if (!hold) return err(404, "UNKNOWN_HOLD");',
    suite: ["packages/relay", "npm", ["test"]],
  },
  {
    id: "adr5-relay-inert-receipt-snapshot",
    control: "R-ING-01 — one accessor-free snapshot, so a two-faced verdict cannot sign a DENIAL and record an approval",
    file: "packages/relay/src/engine.ts",
    find: "    const inertReceipt = inertSnapshot(rawReceipt);",
    replace: "    const inertReceipt: unknown = rawReceipt;",
    suite: ["packages/relay", "npm", ["test"]],
  },
  {
    id: "adr5-relay-exposure-from-real-socket",
    control: "R-1 shape (A) — exposure is classified from the OS-bound address, not from config.bindAddress",
    file: "packages/relay/src/server.ts",
    find: "    handle(req, res, engine, effectiveConfig(), limiter).catch(() => {",
    replace: "    handle(req, res, engine, config, limiter).catch(() => {",
    suite: ["packages/relay", "npm", ["test"]],
  },
  {
    id: "adr5-relay-declared-exposure",
    control: "R-1 shape (B) — tlsTerminated or unsafeListen means EXPOSED, whatever the bind address says",
    file: "packages/relay/src/config.ts",
    find: "    const declaredExposed = config.tlsTerminated || config.unsafeListen;",
    replace: "    const declaredExposed = false;",
    suite: ["packages/relay", "npm", ["test"]],
  },
  {
    id: "adr5-signer-producer-inert-copy",
    control: "C-01 sibling (producer) — what is signed is what is returned; no writable global between them",
    file: "packages/signer-core/src/sign.ts",
    find: "  const signed = inertDeepCopy(core);",
    replace: "  const signed = structuredClone(core);",
    suite: ["packages/signer-core", "npm", ["test"]],
  },
  {
    id: "adr5-gate-b1-fail-closed-floor",
    control: "B-1 — an unmatched action classifies to the highest tier and fails closed, whatever tier the caller names",
    file: "packages/gate/src/engine.ts",
    find: '    if (mode === "RAW") {',
    replace: '    if (mode === "RAW" && (riskClass === "CRITICAL" || riskClass === "IRREVERSIBLE")) {',
    suite: ["packages/gate", "npm", ["test"]],
  },
  {
    id: "c04-gate-observation",
    control: "C-04 — report() signs no determinate negative in ANY state (the UNUSED 409 and the attributed-claim 202)",
    file: "packages/gate/src/engine.ts",
    find: 'if (result === "FAILED_BEFORE_DISPATCH") {',
    replace: 'if (false as boolean) {',
    suite: ["packages/gate", "npm", ["test"]],
  },
  {
    id: "h02c-read-before-transition",
    control: "H-02c — the tool's self-report is read BEFORE any reducer transition",
    file: "packages/gate/src/wrapper.ts",
    find: "    const ok = r.ok;\n    const detail = r.detail;\n    if (ok) {",
    replace: "    const ok = r.ok;\n    if (ok) {",
    also: [{ find: "    execDetail = detail;\n  } catch (e) {", replace: "    execDetail = r.detail;\n  } catch (e) {" }],
    suite: ["packages/gate", "npm", ["test"]],
  },
  {
    id: "h02a-reducer-routed-outcome",
    control: "H-02a — the framework adapter's terminal outcome comes from the reducer, not from `threw`",
    file: "packages/framework-adapters/src/wrap-tool.mjs",
    find: "      if (recordedState === null) {",
    replace: "      if (false) {",
    suite: ["packages/framework-adapters", "npm", ["test"]],
  },
  {
    id: "h02b-host-discriminator",
    control: "H-02b — the host-visible McpError carries the anti-retry discriminator",
    file: "packages/mcp-proxy/src/create-proxy-server.mjs",
    find: `        {
          executionHappened: true,
          sideEffectState: dispatchState,
          evidenceOutcome: EVIDENCE_OUTCOME_FOR[dispatchState],
          safeToRetry: isSafeToRetry(dispatchState),
        },`,
    replace: "        undefined,",
    suite: ["packages/mcp-proxy", "npm", ["test"]],
  },
  {
    id: "reducer-no-retry-safe-exit",
    control: "the reducer has NO exit from DISPATCHED to a retry-safe state without a RECONCILED_* event",
    file: "packages/adapter-core/src/side-effect-state.mjs",
    find: '    TOOL_REPORTED_NO_DISPATCH: "SIDE_EFFECT_UNCONFIRMED",',
    replace: '    TOOL_REPORTED_NO_DISPATCH: "FAILED_NO_SIDE_EFFECT",',
    suite: ["packages/adapter-core", "npm", ["test"]],
  },
  {
    id: "reducer-immutability",
    control: "the side-effect state table is deep-frozen so safeToRetry cannot be flipped at runtime",
    file: "packages/adapter-core/src/side-effect-state.mjs",
    find: "export const SIDE_EFFECT_STATES = deepFreeze({",
    replace: "export const SIDE_EFFECT_STATES = ({",
    suite: ["packages/adapter-core", "npm", ["test"]],
  },
  {
    id: "grant-single-use-cas",
    control: "F8a — the atomic CAS UNUSED→RESERVED makes a grant single-use",
    file: "packages/gate/src/engine.ts",
    find: 'if (rec.status !== "UNUSED") return err(409, "GRANT_ALREADY_RESERVED", { status: rec.status });',
    replace: 'if (false as boolean) return err(409, "GRANT_ALREADY_RESERVED", { status: rec.status });',
    suite: ["packages/gate", "npm", ["test"]],
  },
  {
    id: "grant-ownership-before-cas",
    control: "F29-authz — hold ownership is checked BEFORE any state transition or signature",
    file: "packages/gate/src/engine.ts",
    find: 'if (!this.ownsHold(this.store.getHold(rec.holdId), agent, "report")) return err(404, "UNKNOWN_GRANT");',
    replace: 'if (false as boolean) return err(404, "UNKNOWN_GRANT");',
    suite: ["packages/gate", "npm", ["test"]],
  },
  {
    id: "uncertainty-requires-corroboration",
    control: "F8c — an Execution Uncertainty is signed only after the gate's own sweep window elapsed",
    file: "packages/gate/src/engine.ts",
    find: "if (this.now() - rec.reservedAt < this.cfg.uncertaintySweepWindowMs) return false;",
    replace: "if (false as boolean) return false;",
    suite: ["packages/gate", "npm", ["test"]],
  },
  {
    id: "safe-json-proto-rejection",
    control: "the strict parser rejects __proto__ / prototype / constructor keys",
    file: "src/safe-json.ts",
    // RE-AIMED 2026-07-28. The control moved from a module-level `const FORBIDDEN_KEYS = new Set(…)`
    // to a `isForbiddenKey()` comparing against literals, because `Set.prototype.has` is a writable
    // global slot and the parse boundary cannot decide anything by calling a method it does not own
    // (ADR §5.5). This gate FOUND the move — it reported ROTTED rather than passing, which is exactly
    // what a knockout is for: an entry that silently stops matching measures nothing.
    //
    // The knockout is now a BEHAVIOURAL one rather than a rename. Renaming the function would only
    // fail to compile, which proves the identifier exists, not that the check runs. Inverting the
    // predicate's body makes the parser ACCEPT `__proto__` and the suite must go red.
    find: "return key === \"__proto__\"",
    replace: "return false && key === \"__proto__\"",
    suite: [".", "npm", ["test"]],
  },
  // ── ADDED 2026-07-29 (round-3). One entry per finding, because the previous rounds' fixes shipped
  // with NO knockout at all: nothing in the repository would have gone red if any of them had been
  // reverted, which is why the same class kept reappearing one call deeper and kept being reported as
  // "new". A fix without a knockout is a claim.
  {
    id: "t17-crypto-verify-capture",
    control: "T17 — the Ed25519 signature verdict goes through the LOAD-TIME snapshot of crypto.verify, not a live ESM binding",
    file: "src/keys.ts",
    // Restores the vulnerability exactly: a live `node:crypto` import binding used as the verdict.
    find: "    return ed25519Verify(message, key, sigBytes);",
    replace: "    return _liveVerify(null, message, key as never, sigBytes);",
    also: [{
      find: "import {\n  bufferFrom, bufToString, bufEquals, bufSubarray, byteLength,",
      replace: "import { verify as _liveVerify } from \"node:crypto\";\nimport {\n  bufferFrom, bufToString, bufEquals, bufSubarray, byteLength,",
    }],
    suite: [".", "npm", ["test"]],
  },
  {
    id: "t18-bigint-capture",
    control: "T18 — the y<q canonicality gate builds its comparand with the CAPTURED BigInt, not the bare global",
    file: "src/keys.ts",
    find: "toBigInt(yBytes[i]!)",
    replace: "BigInt(yBytes[i]!)",
    suite: [".", "npm", ["test"]],
  },
  {
    id: "t18-curve-pin-accessor",
    control: "T18b — the Ed25519 curve pin reads asymmetricKeyType through the CAPTURED accessor",
    file: "src/keys.ts",
    find: "    if (asymmetricKeyType(key) !== \"ed25519\") return false;",
    replace: "    if ((key as { asymmetricKeyType?: string }).asymmetricKeyType !== \"ed25519\") return false;",
    suite: [".", "npm", ["test"]],
  },
  {
    id: "t19-parser-inert-arrays",
    control: "T19 — safeParse re-roots every array it emits onto INERT_ARRAY_PROTOTYPE (the ROOT of the iterator/HOF class)",
    file: "src/safe-json.ts",
    find: "        return inertArray(arr);",
    replace: "        return arr;",
    suite: [".", "npm", ["test"]],
  },
  {
    id: "t19-validator-index-walk",
    control: "T19 — the policy validator walks `rules` by INDEX, so a no-op forEach cannot skip every rule",
    file: "src/policy/validate.ts",
    find: "    for (let i = 0; i < pol.rules.length; i++) {\n      const r = pol.rules[i];",
    replace: "    (pol.rules as unknown[]).forEach((r, i) => {",
    also: [{
      find: "      validateCondition(rule.when, `policy.rules[${i}].when`, errors, 0);\n    }",
      replace: "      validateCondition(rule.when, `policy.rules[${i}].when`, errors, 0);\n    });",
    }, { find: "        continue;\n      }\n      const rule = r as Record<string, unknown>;", replace: "        return;\n      }\n      const rule = r as Record<string, unknown>;" }],
    // The parser's re-rooting independently defeats this poison, so knocking out ONE layer leaves the
    // other measuring it and the run would report a false "nothing measures this". Both come out
    // together — which is also the honest statement of the design: two layers, each load-bearing.
    andAlso: "t19-parser-inert-arrays",
    suite: [".", "npm", ["test"]],
  },
  {
    id: "t19b-cbor-inert-arrays",
    control: "T19b — the CBOR decoder re-roots decoded arrays AND each map pair (destructuring dispatches through the pair's own iterator)",
    file: "src/cose/cbor.ts",
    find: "      return { t: \"map\", v: inertArray(m) };",
    replace: "      return { t: \"map\", v: m };",
    also: [{
      find: "        arrayPush(m, inertArray([key, val]) as [CborValue, CborValue]);",
      replace: "        arrayPush(m, [key, val] as [CborValue, CborValue]);",
    }],
    suite: [".", "npm", ["test"]],
  },
  {
    id: "inert-proto-refuses-accessors",
    control: "INERT_ARRAY_PROTOTYPE copies DATA descriptors only — a pre-load accessor is refused (absent), never copied",
    // RE-AIMED 2026-07-29 (round-4, A1). The construction MOVED from `src/inert.ts` to
    // `src/intrinsics.ts` so the captured wrappers could re-root the arrays they manufacture through
    // it without an import cycle. This entry reported ROTTED on the first run after the move, which
    // is exactly what a knockout registry is for: an entry that silently stops matching measures
    // nothing, and the runner says so instead of passing.
    file: "src/intrinsics.ts",
    find: "    if (!(_apply(_hasOwnProperty, d as never, [\"value\"] as never) as boolean)) continue;",
    replace: "    if (!(_apply(_hasOwnProperty, d as never, [\"value\"] as never) as boolean)) { _apply(_objectDefineProperty, undefined as never, [proto, key, { get: d.get, set: d.set, enumerable: false, configurable: false }] as never); continue; }",
    suite: [".", "npm", ["test"]],
  },
  {
    id: "t20-l8-selftest",
    control: "T20/A5 — every AST-gate rule is proven to BITE against a known-positive sample (a gate reading 0 because it matches nothing is the false-green pathology)",
    // RE-AIMED 2026-07-29 (round-4, A5): L8 is no longer a set of regexes, so the string this entry
    // used to defang does not exist. It now defangs a NODE-KIND test in the analyser itself. The
    // evasion matrix's `for-of` positive sample must go unflagged and L8-selftest must go red.
    file: "scripts/lib/dispatch-ast.mjs",
    find: "      if (ts.isForOfStatement(node) && deferred) {",
    replace: "      if (false && ts.isForOfStatement(node) && deferred) {",
    suite: [".", "npm", ["run", "lint:security-gates"]],
  },
  {
    id: "t20-source-lock-scope",
    control: "T20 — the source lock's subject is the WHOLE derived TCB, not a hand-picked five",
    file: "test/security/intrinsic-poisoning.test.ts",
    // Aimed at the DERIVATION, not at the scan loop. Narrowing the loop alone is unmeasurable once
    // the tree is clean — nothing is found either way — which is precisely the trap: a scope
    // regression is invisible until an offender exists, so the SCOPE ITSELF has to be the assertion.
    // Replacing the derived list with the hand-picked five this lock used to carry is the exact
    // regression that left src/keys.ts unlocked while it held a live `verify` binding on the
    // signature verdict, and it turns the coverage test red immediately.
    find: "  return (block![1]!.match(/\"([^\"]+)\"/g) ?? []).map((s) => s.slice(1, -1));",
    replace: "  return [\"src/hash.ts\", \"src/signing.ts\", \"src/cose/cbor.ts\", \"src/nfc.ts\", \"src/verify.ts\"];",
    suite: [".", "npm", ["test"]],
  },
  // ── ADDED 2026-07-29 (round-4). One entry per control this pass introduced. The previous three
  // rounds' fixes shipped with NO knockout, which is why the same class kept reappearing one call
  // deeper and kept being reported as "new". A fix without a knockout is a claim.
  {
    id: "r4-a1-inert-wrappers",
    control: "A1 — the captured wrappers that MANUFACTURE arrays (objectKeys/ownNames/ownKeys/slice/split/…) return INERT-rooted arrays, so a fresh array is never rooted on the live Array.prototype",
    file: "src/intrinsics.ts",
    // The root of the whole round-4 class, in one edit: make the re-rooting a no-op.
    find: "function _inert<T>(a: T[]): T[] {\n  _apply(_objectSetPrototypeOf, undefined as never, [a, INERT_ARRAY_PROTOTYPE] as never);\n  return a;\n}",
    replace: "function _inert<T>(a: T[]): T[] {\n  return a;\n}",
    suite: [".", "npm", ["test"]],
  },
  {
    id: "r4-a2-noextrakeys-index-walk",
    control: "A2 — the policy closed-grammar check walks keys by INDEX, so a skipping iterator cannot hide an unknown key (DENY/policy-invalid -> ALLOW/allow-x, measured)",
    file: "src/policy/validate.ts",
    find: "  const keys = objectKeys(obj);\n  for (let i = 0; i < keys.length; i++) {\n    const k = keys[i] as string;",
    replace: "  for (const k of objectKeys(obj)) {",
    // A1 independently defeats this poison, so knocking out ONE layer leaves the other measuring it
    // and the run would report a false "nothing measures this". Both come out together — which is
    // also the honest statement of the design: two layers, each load-bearing.
    andAlso: "r4-a1-inert-wrappers",
    suite: [".", "npm", ["test"]],
  },
  {
    id: "r4-a2-checkpoint-index-walk",
    control: "A2 — the checkpoint closed-schema walk is an INDEX walk, so a skipping iterator cannot hide a smuggled (and honestly re-signed) field (TAMPERED -> VALID/tailChecked, measured)",
    file: "src/verify.ts",
    find: "  const cKeys = objectKeys(c);\n  for (let i = 0; i < cKeys.length; i++) {\n    if (!arrayIncludes(CHECKPOINT_KEYS, cKeys[i] as string)) return \"malformed checkpoint\";\n  }",
    replace: "  for (const k of objectKeys(c)) {\n    if (!arrayIncludes(CHECKPOINT_KEYS, k)) return \"malformed checkpoint\";\n  }",
    andAlso: "r4-a1-inert-wrappers",
    suite: [".", "npm", ["test"]],
  },
  {
    id: "r4-a2-manifest-index-walk",
    control: "A2 — the identity-manifest walk is an INDEX walk, so a skipping iterator cannot hide a malformed entry from validation (MALFORMED -> VALID, measured)",
    file: "src/verify.ts",
    find: "      const aids = objectGetOwnPropertyNames(live);\n      for (let ai = 0; ai < aids.length; ai++) {\n        const aid = aids[ai] as string;",
    replace: "      for (const aid of objectGetOwnPropertyNames(live)) {",
    andAlso: "r4-a1-inert-wrappers",
    suite: [".", "npm", ["test"]],
  },
  {
    id: "r4-t06-newset-captured-add",
    control: "R4-T06 — newSet(init) fills through the CAPTURED Set.prototype.add; `new Set(iterable)` reads `this.add` off the instance and calls it per element, so a no-op add silently empties the committed read-set",
    file: "src/intrinsics.ts",
    find: "  const s = new _Set() as Set<T>;\n  if (init !== undefined) {\n    for (let i = 0; i < (init as { length: number }).length; i++) _apply(_setAdd, s as never, [init[i]] as never);\n  }\n  return s;",
    replace: "  return new _Set(init as never) as Set<T>;",
    suite: [".", "npm", ["test"]],
  },
  {
    id: "r4-t07-audit-captured-weakset",
    control: "R4-T07 — the policy-table audit's cycle guard uses the CAPTURED WeakSet.prototype.has; a live `has -> true` made inertViolations return [] , i.e. the control that hunts mutable policy tables reported CLEAN exactly when an attacker was present",
    file: "src/inert.ts",
    find: "    if (weakSetHas(seen, value as object)) return;\n    weakSetAdd(seen, value as object);",
    replace: "    if (seen.has(value as object)) return;\n    seen.add(value as object);",
    suite: [".", "npm", ["test"]],
  },
  {
    id: "r4-a1c-publication-boundary",
    control: "A1c — a CALLER-OWNED public result (readSet, warnings, inertViolations) is published as an ORDINARY array; shipping the inert internal breaks `instanceof Array` and `deepStrictEqual` for every consumer",
    file: "src/intrinsics.ts",
    find: "export function publishArray<T>(a: readonly T[]): T[] {\n  const out: T[] = [];\n  for (let i = 0; i < (a as { length: number }).length; i++) _apply(_push, out as never, [a[i]]);\n  return out;\n}",
    replace: "export function publishArray<T>(a: readonly T[]): T[] {\n  return a as T[];\n}",
    suite: [".", "npm", ["test"]],
  },
  {
    id: "r4-a5-ast-load-time-exemption",
    control: "A5 — the AST gate's load-time exemption is STRUCTURAL (a parameter default is call-time, an IIFE at module level is load-time); widening it to 'everything is load-time' must not be able to silence the gate",
    file: "scripts/lib/dispatch-ast.mjs",
    find: "function isLoadTime(node) {\n  let n = node;",
    replace: "function isLoadTime(node) {\n  if (node) return true;\n  let n = node;",
    suite: [".", "npm", ["run", "lint:security-gates"]],
  },
  {
    id: "r4-a5-ast-symbol-resolution",
    control: "A5 — the AST gate resolves the leftmost identifier's SYMBOL to decide 'ambient global or ours'; degrading that to 'never a global' is the one-line way to make the gate read 0 forever",
    file: "scripts/lib/dispatch-ast.mjs",
    find: "  if (!BUILTIN_GLOBALS.has(id.text) && !BARE_GLOBAL_CALLS.has(id.text)) return false;",
    replace: "  if (id) return false;\n  if (!BUILTIN_GLOBALS.has(id.text) && !BARE_GLOBAL_CALLS.has(id.text)) return false;",
    suite: [".", "npm", ["run", "lint:security-gates"]],
  },
];

function run(dir, cmd, args) {
  try {
    execFileSync(cmd, args, { cwd: path.join(ROOT, dir), encoding: "utf8", stdio: "pipe", timeout: 900_000 });
    return { green: true };
  } catch (e) {
    return { green: false, out: `${e.stdout ?? ""}${e.stderr ?? ""}`.slice(-400) };
  }
}

const selected = ONLY ? KNOCKOUTS.filter((k) => k.id === ONLY) : KNOCKOUTS;
const results = [];

for (const k of selected) {
  const abs = path.join(ROOT, k.file);
  const pristine = fs.readFileSync(abs, "utf8");
  // A companion control that independently closes the same class must be knocked out together, or
  // the surviving layer masks the result and the run reports a false "nothing measures this".
  const companion = k.andAlso ? KNOCKOUTS.find((x) => x.id === k.andAlso) : null;
  const companionAbs = companion ? path.join(ROOT, companion.file) : null;
  const companionPristine = companionAbs ? fs.readFileSync(companionAbs, "utf8") : null;

  try {
    const edits = [{ find: k.find, replace: k.replace }, ...(k.also ?? [])];
    let src = pristine;
    let rotted = null;
    for (const e of edits) {
      const hits = src.split(e.find).length - 1;
      if (hits !== 1) { rotted = `\`find\` matched ${hits}× (must be exactly 1) — the control moved or the entry rotted`; break; }
      src = src.replace(e.find, e.replace);
    }
    if (!rotted && companion) {
      let csrc = companionAbs === abs ? src : companionPristine;
      const hits = csrc.split(companion.find).length - 1;
      if (hits !== 1) rotted = `companion \`${companion.id}\` find matched ${hits}× (must be exactly 1)`;
      else {
        csrc = csrc.replace(companion.find, companion.replace);
        if (companionAbs === abs) src = csrc;
        else fs.writeFileSync(companionAbs, csrc);
      }
    }
    if (rotted) { results.push({ id: k.id, verdict: "ROTTED", detail: rotted, control: k.control }); continue; }

    fs.writeFileSync(abs, src);
    const r = run(...k.suite);
    results.push({
      id: k.id,
      verdict: r.green ? "SURVIVED" : "KILLED",
      control: k.control,
      detail: r.green ? "the suite stayed GREEN without this control" : "",
    });
  } finally {
    fs.writeFileSync(abs, pristine);
    if (companionAbs && companionPristine !== null) fs.writeFileSync(companionAbs, companionPristine);
  }
}

console.log(`L4 control knockout: ${results.length} controls\n`);
for (const r of results) {
  const mark = r.verdict === "KILLED" ? "ok      " : r.verdict === "ROTTED" ? "ROTTED  " : "SURVIVED";
  console.log(`  ${mark} ${r.id.padEnd(32)} ${r.control}`);
  if (r.detail) console.log(`           ${r.detail}`);
}

const bad = results.filter((r) => r.verdict !== "KILLED");
console.log(`\nkilled ${results.filter((r) => r.verdict === "KILLED").length}/${results.length}`);
if (bad.length) {
  console.error(`\n${bad.length} finding(s):`);
  for (const r of bad) {
    console.error(
      r.verdict === "SURVIVED"
        ? `  UNMEASURED CONTROL  ${r.id} — removing it left the suite green. Either it is not load-bearing (delete it) or nothing tests it (write the test).`
        : `  ROTTED KNOCKOUT     ${r.id} — ${r.detail}. A knockout that no longer matches measures nothing.`,
    );
  }
  if (!WARN_ONLY) process.exit(1);
  console.error("(--warn: reported, not blocking)");
}

// Restore build artefacts to the pristine sources — knockout runs left dist/ built from mutated
// input, and a later step reading dist/ would be reading the mutation.
try {
  execFileSync("npm", ["run", "build"], { cwd: ROOT, stdio: "ignore", timeout: 600_000 });
  for (const p of ["packages/gate", "packages/approval-artifacts", "packages/evidence", "packages/relay", "packages/signer-core"]) {
    try { execFileSync("npm", ["run", "build"], { cwd: path.join(ROOT, p), stdio: "ignore", timeout: 600_000 }); } catch { /* package may have no build */ }
  }
} catch { /* reported by the next CI step if it matters */ }
