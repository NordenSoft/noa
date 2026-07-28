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
