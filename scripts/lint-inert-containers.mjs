#!/usr/bin/env node
/**
 * L11 — INERT-BEFORE-WRITE. Every container that receives a `[[Set]]`-shaped write on a trusted
 * decision path must already be unreachable from `Object.prototype` when it takes that write.
 *
 * ── THE DEFECT CLASS, AND WHY NOTHING IN THIS REPOSITORY COULD SEE IT ────────────────────────────
 * Writing into an ordinary `[]` or `{}` performs `[[Set]]`. `[[Set]]` WALKS THE RECEIVER'S PROTOTYPE
 * CHAIN, and an ordinary container's chain ends at the mutable `Object.prototype`. An accessor
 * installed at `Object.prototype["0"]` SWALLOWS the element write while `push` still bumps `length`.
 * Measured end to end through the public `preCheck`, on an honest, validated rule set:
 *
 *     snapshot: branded=true  length=1  own0=false
 *     preCheck over-threshold transfer -> ALLOW  (ruleFired=allow-all, approvalRuleFired=null)
 *
 * A branded, validated, EMPTY approval rule set, and a 7000-unit transfer forwarded with no human.
 * The realistic gadget is timed: poison at load, hole the container, withdraw the poison, serve.
 *
 * `packages/adapter-core/src/policy-change-guard.mjs:53-63` already wrote this mechanism down, and
 * the same comment states — verbatim — why the existing gates are structurally blind to it:
 *
 *     "L2/L8 model dispatch as a call or a read; they have no grammar for a write, so
 *      `policy-change-guard.mjs:93` appears in NONE of the 298 budgeted findings."
 *
 * That is the gates' own comment about themselves. `approval-rules.mjs` contributes ZERO findings to
 * either budget, so a green L2/L8 is not evidence about this class and never was. Three files got
 * fixed because a human happened to read them. This layer is the grammar for a write.
 *
 * ── THE THREE PROPERTIES THIS LAYER IS BUILT AROUND ──────────────────────────────────────────────
 *  1. CREATION-TIME, NOT FILL-TIME. A container re-rooted AFTER being filled has already taken the
 *     poisoned write. `L11-B` is the separate finding for exactly that ordering, because the fix
 *     that shipped for this class once re-derived the house pattern and got the ordering wrong.
 *  2. NOT-ANALYSABLE MUST FAIL. `L11-D` is raised for a subject that cannot be read or parsed, for a
 *     derivation that comes back empty, and for an inventory that no longer describes the tree. An
 *     unreadable file and a clean file do NOT share an exit code here.
 *  3. IT MUST BE ABLE TO GO RED. `--selftest` drives the SAME analyser the gate calls over violating
 *     and honest fixtures, in memory AND on disk, and fails if any arm stops biting. The disk arm
 *     exists because an in-memory fixture cannot detect that DISCOVERY stopped reaching a file.
 *
 * ── THE WRITE SET, AND WHY IT IS THIS AND NOT LONGER ─────────────────────────────────────────────
 * Only operations that perform `[[Set]]` with a key an attacker can pre-install on `Object.prototype`
 * are writes here:
 *   • assignment to a member expression (`=`, every compound form, `++`/`--`);
 *   • `push`/`unshift`/`splice`/`fill`/`copyWithin`/`sort`/`reverse`/`shift`, each of which the spec
 *     defines in terms of `Set(O, index, value, true)` — including through this repo's captured
 *     `arrayPush`/`arraySort`/… wrappers, which `_apply` the pristine method to the SAME receiver and
 *     therefore inherit the receiver's prototype chain unchanged;
 *   • `Object.assign` / the captured `objectAssign`, defined as `Set(to, key, value, true)`.
 *
 * Deliberately EXCLUDED, with the reason, because a false positive is how a gate earns the right to
 * be ignored:
 *   • `pop` — writes only `length`, an own property of every array, so no chain is walked;
 *   • array/object LITERALS and object SPREAD (`{...src}`) and `Array.prototype.map/filter/slice` —
 *     the spec builds all of them with `CreateDataPropertyOrThrow`, a `[[DefineOwnProperty]]`, which
 *     does not consult the prototype at all. `const a = [x, y]` is not a write in this grammar;
 *   • `Map.prototype.set` / `Set.prototype.add` — internal slots, not properties;
 *   • integer-indexed writes into a TypedArray — `IntegerIndexedElementSet` never walks the chain.
 *
 * Run:  node scripts/lint-inert-containers.mjs             (blocking; exit 1 on any finding)
 *       node scripts/lint-inert-containers.mjs --selftest  (proves the layer goes RED, then GREEN)
 *       node scripts/lint-inert-containers.mjs --sites     (print every classified site, not just findings)
 *       node scripts/lint-inert-containers.mjs --json
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

/* ══════════════════════════════════════════════════════════════════════════════════════════════
 * THE SCOPE, AND THE ARGUMENT FOR IT
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 *
 * The repository already has two TCB inventories for these packages (`ADAPTER_CORE_TCB`,
 * `MCP_PROXY_TCB` in `scripts/lint-security-gates.mjs`). This layer does NOT use them as its
 * subject list, and the reason is the one `lint-trusted-roots.mjs` records about itself: a
 * hand-maintained subject list is only correct on the day it is written. Those two lists are
 * reconciled against the tree by a blocking lint, which is exactly why they are TRUSTWORTHY AS A
 * LOWER BOUND and useless as an upper one — a file legitimately classified OUT of a TCB (a
 * re-export surface, a demo downstream) is still a file where an ordinary container can be filled.
 *
 * So the subject set here is EVERY source file under a gated ROOT, discovered mechanically, and the
 * two TCB lists are read back at runtime and RECONCILED against it: if any TCB entry is not a
 * subject of this layer, that is an `L11-D` finding. The relationship is asserted every run rather
 * than believed. This layer therefore inherits none of the TCBs' membership omissions, and the only
 * judgement left to argue is the ROOT boundary below.
 *
 * WHY THE ROOT BOUNDARY IS WHERE IT IS. The two roots gated below are the two published packages the
 * blindness comment names, and the ones where the defect was reproduced end to end through a public
 * entry point. Every other root is inventoried with a stated reason and its site counts are MEASURED
 * AND PRINTED on every run — an un-gated root is visible here, never silent. That is the difference
 * between "out of scope" and "nobody looked".
 */
const ROOT_INVENTORY = {
  "packages/adapter-core/src": {
    gated: true,
    note: "WHERE THE DEFECT WAS MEASURED. preCheck's policy-input snapshot, the approval-rule " +
      "validator and matcher, the policy-change guard, the receipt-chain session stores. The " +
      "`ALLOW` above came out of this package through its public `preCheck`.",
  },
  "packages/mcp-proxy/src": {
    gated: true,
    note: "The second published package the blindness comment names. It decides whether a tool call " +
      "is forwarded, adopts approvals, and mints outcome receipts; it fills containers from " +
      "caller-owned JSON on that path.",
  },

  // ── INVENTORIED, NOT GATED. Each reason is a claim about THIS class, not a general clearance. ──
  "src": {
    gated: false,
    reason: "the receipt kernel. It is the one root that ALREADY has a structural answer to this " +
      "class — `src/intrinsics.ts` manufactures inert-rooted arrays for every wrapper it exports " +
      "and `src/inert.ts` is the house pattern the two gated packages import. Bringing it under a " +
      "BLOCKING layer in the same commit that introduces the layer would mean either a rushed sweep " +
      "over its measured sites or a budget large enough to hide a regression. Its measured counts " +
      "are printed below every run, so the decision is re-checkable rather than remembered.",
  },
  "packages/tsa-anchor/src": {
    gated: false,
    reason: "a published package with real decision paths (equivocation, DER parsing) that was " +
      "brought under L2/L3/L8 only days ago and still carries an L8 migration budget of 95. " +
      "Enrolling it here in the same commit would stack two migrations; its counts are printed.",
  },
  "packages/gate/src": {
    gated: false,
    reason: "the decision layer, and the strongest candidate for the next enrolment. Held back for " +
      "the same reason as `src`: this commit ships the instrument and fixes what the instrument can " +
      "prove in the two roots it gates. Its counts are printed so the gap is a number, not a guess.",
  },
  "packages/signer-core/src": { gated: false, reason: "signing primitives; counts printed. Same staging reason as packages/gate/src." },
  "packages/approval-artifacts/src": { gated: false, reason: "artifact verification; counts printed. Same staging reason as packages/gate/src." },
  "packages/relay/src": { gated: false, reason: "transport + hold state machine, still on an L10 migration budget of 38; counts printed." },
  "packages/evidence/src": { gated: false, reason: "evidence assembly over already-signed artifacts; counts printed." },
  "packages/signer-sidecar/src": { gated: false, reason: "not currently published (code-ready); counts printed." },
  "packages/framework-adapters/src": { gated: false, reason: "a registered dispatch surface; counts printed. Same staging reason as packages/gate/src." },
  "packages/e2e-demo/src": { gated: false, reason: "demo/harness code, not a shipped decision path (same disposition it carries in lint-trusted-roots.mjs)." },
};

/* ══════════════════════════════════════════════════════════════════════════════════════════════
 * THE L11-C RATCHET — the sites this layer SEES but cannot PROVE
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 *
 * A write whose receiver is a parameter, an import, `this.…`, a member chain or a call result is not
 * a container this layer created, so it cannot say whether it is inert. These are NOT passes. They
 * are printed in full, and the per-file counts are pinned here so a NEW blind write cannot arrive
 * silently: a file above its count fails, a file absent from the table fails, and a count above the
 * measured number fails. The numbers may only fall.
 *
 * This is the honest half of the layer, and it is stated the way `policy-change-guard.mjs` stated
 * L2/L8's blindness: these sites are visible and unproven, not covered.
 */
const UNPROVEN_RATCHET = {
  "packages/adapter-core/src/approval-rules.mjs": { n: 16, why:
    "the rule-set compiler (#56/#58). All 16 are provably inert IN FACT; the single-file layer cannot " +
    "connect the receiver to its construction. Eleven are `arrayPush(errors, …)` inside compileRule / " +
    "requiredOwnField, where `errors` is a PARAMETER — compileApprovalRules and validateApprovalRules " +
    "build it with inertArray() and pass it down, the identical basis as pre-check's `out`/`state` " +
    "below, and a parameter's chain is decided by its caller. Five are `match.*` / `threshold.*` field " +
    "writes on records declared `let match = null` / `let threshold` and then assigned objectCreateNull() " +
    "conditionally before objectFreeze — inert from creation, but this layer classifies a container only " +
    "from its declaration initialiser, so a null-then-assign receiver reads as unprovable. The records " +
    "built directly with objectCreateNull() (UNUSABLE_RULE_SET, `compiled`, `compiledRules`, `errors` at " +
    "its inertArray() creation) are all proven inert." },
  "packages/adapter-core/src/config-artifact.mjs": { n: 1, why:
    "`this.name` in the ConfigArtifactError constructor. Error.prototype.name is a writable DATA " +
    "property, so the [[Set]] walk terminates there and never reaches Object.prototype — visible " +
    "to the grammar, outside the class." },
  "packages/adapter-core/src/pending-store.mjs": { n: 2, why:
    "`this.name` (same basis as config-artifact) and `arrayPush(mapGet(byId, key), ev)`, whose " +
    "receiver comes back out of a Map. The array itself is now built inert a few lines above, but " +
    "this layer resolves receivers, not values, so it cannot connect the two." },
  "packages/adapter-core/src/pre-check.mjs": { n: 5, why:
    "the `out` and `state` PARAMETERS of flattenArgsToPolicyInputs. Both are built inert by the " +
    "single caller (objectCreateNull() and newFlattenState()), but a parameter's chain is decided " +
    "by the caller and this layer does not do interprocedural analysis." },
  "packages/adapter-core/src/session-store.mjs": { n: 6, why:
    "`state.prev` / `state.seq` / `state.lastAccessedAt` on state objects fetched back out of a " +
    "tenant bucket Map. Both construction sites are now null-rooted at creation; the WRITE sites " +
    "resolve to a Map get, which this layer cannot follow." },
  "packages/adapter-core/src/side-effect-state.mjs": { n: 1, why: "`this.name` — same basis as config-artifact." },
  "packages/adapter-core/src/tool-outcome-not-recorded.mjs": { n: 1, why: "`this.name` — same basis as config-artifact." },
  "packages/mcp-proxy/src/create-proxy-server.mjs": { n: 1, why:
    "`server.onclose = …` where `server` is the MCP SDK's own Server instance. The receiver is not " +
    "ours to re-root; the SDK owns its prototype." },
  "packages/mcp-proxy/src/http-server.mjs": { n: 2, why:
    "`transport.onclose = …` on the SDK's StreamableHTTPServerTransport — the SDK owns that receiver's " +
    "prototype (same basis as above). AND `proxyConfig.approvalRules = requireValidApprovalRules(…)` " +
    "(#56/#58): `proxyConfig` is this function's own rest-destructured config object, and the write " +
    "stores the trusted, FROZEN compiled snapshot back under a fixed string key so every session " +
    "receives it — a decision-path hardening line, not a caller-indexed write, whose receiver this " +
    "layer still cannot prove inert." },
  "packages/mcp-proxy/src/proxy.mjs": { n: 1, why:
    "`PROCESS.exitCode = …` on the captured `process` object. Node owns that object; re-rooting it " +
    "would be a change to the host environment, not to this package." },
};

/* ── the write set (see the docstring for what is deliberately absent, and why) ─────────────────── */

/** Methods the spec defines in terms of `Set(O, …)` on the RECEIVER. */
const WRITE_METHODS = new Set(["push", "unshift", "splice", "fill", "copyWithin", "sort", "reverse", "shift"]);

/**
 * The captured wrappers for those same methods. `arrayPush(a, v)` is `_apply(_push, a, [v])` — the
 * method is pristine, the RECEIVER is still `a`, and `[[Set]]` walks `a`'s chain either way. A gate
 * that watched only `.push(` would read the hardened spelling as clean, which is the precise shape
 * of the mistake this repository keeps recording about itself.
 */
const WRITE_WRAPPERS = new Set([
  "arrayPush", "arrayUnshift", "arraySplice", "arrayFill", "arrayCopyWithin", "arraySort",
  "arrayReverse", "arrayShift", "objectAssign", "reflectSet",
]);

/** Re-rooting calls: the operations that make an already-created container inert. */
const REROOT_FNS = new Set(["objectSetPrototypeOf", "setPrototypeOf", "makeInertArray", "inertArray"]);

/** TypedArray constructors — integer-indexed writes never walk a prototype chain. */
const TYPED_ARRAYS = new Set([
  "Uint8Array", "Int8Array", "Uint8ClampedArray", "Uint16Array", "Int16Array", "Uint32Array",
  "Int32Array", "Float32Array", "Float64Array", "BigInt64Array", "BigUint64Array", "Buffer",
]);

/** Constructors that build a container with a live `Object.prototype` at the end of its chain. */
const ORDINARY_CTORS = new Set(["Array", "Object"]);

const findings = [];
const add = (id, file, line, msg) => findings.push({ id, file, line, msg });

/* ══════════════════════════════════════════════════════════════════════════════════════════════
 * DERIVED AUTHORITIES — never a hand-written list of "functions that return something safe"
 * ══════════════════════════════════════════════════════════════════════════════════════════════ */

/**
 * The names of `src/intrinsics.ts` exports that hand back an ALREADY-INERT container, derived from
 * the source rather than transcribed: a wrapper qualifies when its body returns `_inert(…)` (the
 * module's own re-rooting helper) or `_objectCreate(…, null)`.
 *
 * DERIVED, because a transcribed list is a second authority that drifts the first time somebody adds
 * a wrapper — and this file would then report a correct call site as unproven forever, which is the
 * false-positive failure mode. An empty derivation is a FINDING, not an empty allowlist: that is the
 * "a zero result means the instrument is wrong until proven otherwise" rule applied to this layer's
 * own inputs.
 */
function deriveInertFactories() {
  const rel = "src/intrinsics.ts";
  const abs = path.join(ROOT, rel);
  const names = new Set();
  let text;
  try {
    text = fs.readFileSync(abs, "utf8");
  } catch (e) {
    add("L11-D", rel, 0, `the inert-factory derivation could not READ its source (${e.message}). ` +
      "Without it every correct call site reads as unproven, so this layer refuses to run rather " +
      "than report a number produced by not looking.");
    return names;
  }
  const sf = ts.createSourceFile(`${rel}.l11.ts`, text, ts.ScriptTarget.ES2022, true, ts.ScriptKind.TS);
  const visit = (n) => {
    if (ts.isFunctionDeclaration(n) && n.name && n.body &&
        n.modifiers?.some((m) => m.kind === ts.SyntaxKind.ExportKeyword)) {
      const body = n.body.getText(sf);
      if (/\breturn\s+_inert\s*\(/.test(body)) names.add(n.name.text);
      else if (/_objectCreate\b[\s\S]*\[\s*null\s*\]/.test(body)) names.add(n.name.text);
    }
    ts.forEachChild(n, visit);
  };
  visit(sf);
  // ANTI-VACUITY. These two are the load-bearing members: `objectCreateNull` is how every
  // null-prototype object in the two gated packages is built, and `objectKeys` is the array wrapper
  // whose inertness the key walks depend on. If the derivation stops finding them it has stopped
  // working, and a silently-empty allowlist would turn this whole layer into noise.
  for (const required of ["objectCreateNull", "objectKeys"]) {
    if (!names.has(required)) {
      add("L11-D", rel, 0,
        `the inert-factory derivation did not find \`${required}\`. The derivation reads ` +
        "src/intrinsics.ts for exports that return `_inert(…)` or `Object.create(null)`; losing a " +
        "known member means the shape it reads for has changed and every result below is suspect.");
    }
  }
  return names;
}

/**
 * Re-read the two published packages' TCB inventories out of `scripts/lint-security-gates.mjs` —
 * PARSED, never transcribed. Two things come back:
 *
 *   • the TCB arrays. This layer does not use them as its SUBJECT list (see the scope note above);
 *     it reconciles against them, so "L11 covers strictly more than the existing TCBs" is a fact
 *     re-derived on every run instead of a sentence in a report that was true once.
 *   • the OUT_OF_TCB tables, WITH their reasons, which decide SEVERITY and nothing else.
 *
 * THE SEVERITY BORROW, ARGUED RATHER THAN ASSUMED. Using a TCB to decide what a gate can SEE is the
 * failure this repository has recorded against itself three times. Using one to decide whether a
 * finding BLOCKS is a different act, and the difference is the whole reason it is acceptable here:
 * every file under a gated root is still analysed, still counted, and still printed. What the
 * borrowed table changes is only whether a finding stops the build — and that boundary has already
 * been argued file by file, carries a written reason per exclusion, and is itself kept honest by a
 * BLOCKING reconciliation (`adapter-core-reconcile` / `mcp-proxy-reconcile`) that refuses an empty
 * reason. Inventing a second severity boundary here would create exactly the rival authority
 * `lint-trusted-roots.mjs` warns about, and it would drift.
 *
 * A subject under a gated root that appears in NEITHER table is a finding, not a default-pass.
 */
function readSecurityGateTcbs() {
  const rel = "scripts/lint-security-gates.mjs";
  const out = new Map();
  const exempt = new Map();
  let text;
  try {
    text = fs.readFileSync(path.join(ROOT, rel), "utf8");
  } catch (e) {
    add("L11-D", rel, 0, `could not read the existing TCB inventories to reconcile against (${e.message}).`);
    return { tcbs: out, exempt };
  }
  const sf = ts.createSourceFile(`${rel}.l11.ts`, text, ts.ScriptTarget.ES2022, true, ts.ScriptKind.TS);
  const literalText = (node) => {
    // A reason is frequently a `"…" + "…"` concatenation; take the whole thing rather than the head.
    if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) return node.text;
    if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.PlusToken) {
      return literalText(node.left) + literalText(node.right);
    }
    return "";
  };
  const visit = (n) => {
    if (ts.isVariableDeclaration(n) && ts.isIdentifier(n.name) && n.initializer) {
      const name = n.name.text;
      if ((name === "ADAPTER_CORE_TCB" || name === "MCP_PROXY_TCB") &&
          ts.isArrayLiteralExpression(n.initializer)) {
        out.set(name, n.initializer.elements.filter((e) => ts.isStringLiteral(e)).map((e) => e.text));
      }
      if ((name === "ADAPTER_CORE_OUT_OF_TCB" || name === "MCP_PROXY_OUT_OF_TCB") &&
          ts.isObjectLiteralExpression(n.initializer)) {
        for (const p of n.initializer.properties) {
          if (!ts.isPropertyAssignment(p)) continue;
          const key = ts.isStringLiteral(p.name) ? p.name.text : null;
          if (key === null) continue;
          exempt.set(key, literalText(p.initializer));
        }
      }
    }
    ts.forEachChild(n, visit);
  };
  visit(sf);
  for (const name of ["ADAPTER_CORE_TCB", "MCP_PROXY_TCB"]) {
    if (!out.has(name) || out.get(name).length === 0) {
      add("L11-D", rel, 0,
        `\`${name}\` could not be extracted, or extracted EMPTY. The reconciliation that proves this ` +
        "layer covers at least the existing TCB did not happen, so its coverage claim is unbacked.");
    }
  }
  // An exemption with an empty reason must not silently downgrade a finding here either. The other
  // gate blocks on this too; duplicating the check costs nothing and removes the dependency on that
  // gate still existing tomorrow.
  for (const [f, why] of exempt) {
    if (why.trim() === "") {
      add("L11-D", f, 0,
        "the published-package TCB exempts this file with an EMPTY reason, and this layer would " +
        "otherwise downgrade its findings on that basis. An unjustified exemption does not get to " +
        "decide severity.");
    }
  }
  return { tcbs: out, exempt };
}

/* ══════════════════════════════════════════════════════════════════════════════════════════════
 * DISCOVERY
 * ══════════════════════════════════════════════════════════════════════════════════════════════ */

const SRC_RE = /\.(ts|tsx|mts|cts|mjs|cjs|js|jsx)$/;

/**
 * Every source file under a root. `statSync` rather than `Dirent.isDirectory()` so a symlinked
 * DIRECTORY is followed — `lint-trusted-roots.mjs` records an entire subtree leaving that gate's
 * world through exactly that hole, and copying the walk without copying the fix would reproduce it.
 * `.d.ts` stays excluded: a declaration writes nothing at runtime.
 */
function listSources(dir) {
  const out = [];
  const walk = (d) => {
    let entries;
    try {
      entries = fs.readdirSync(path.join(ROOT, d), { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      if (e.name === "node_modules" || e.name === "dist") continue;
      const rp = `${d}/${e.name}`;
      let st;
      try {
        st = fs.statSync(path.join(ROOT, rp));
      } catch {
        continue; // dangling symlink — nothing to read
      }
      if (st.isDirectory()) walk(rp);
      else if (st.isFile() && SRC_RE.test(e.name) && !/\.d\.(ts|mts|cts)$/.test(e.name)) out.push(rp);
    }
  };
  if (fs.existsSync(path.join(ROOT, dir))) walk(dir);
  return out.sort();
}

/** Every `src` root in the tree, so a NEW package cannot be silently outside the inventory. */
function discoverRoots() {
  const roots = [];
  if (fs.existsSync(path.join(ROOT, "src"))) roots.push("src");
  const pkgDir = path.join(ROOT, "packages");
  if (fs.existsSync(pkgDir)) {
    for (const e of fs.readdirSync(pkgDir, { withFileTypes: true })) {
      if (!e.isDirectory()) continue;
      const r = `packages/${e.name}/src`;
      if (fs.existsSync(path.join(ROOT, r))) roots.push(r);
    }
  }
  return roots.sort();
}

/* ══════════════════════════════════════════════════════════════════════════════════════════════
 * THE ANALYSER
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 *
 * A syntactic, scope-aware AST pass. It is deliberately NOT a dataflow analysis, and the places it
 * gives up are reported as `L11-C` rather than assumed clean — the whole design rests on "unproven"
 * and "proven safe" being different words with different counts.
 *
 * The verdicts a site can receive:
 *   inert   — the receiver is a container this file created, made inert strictly BEFORE this write.
 *   L11-A   — the receiver is a container this file created ORDINARY and never made inert.
 *   L11-B   — the receiver is made inert, but LATER than this write: filled first, re-rooted after.
 *   L11-C   — the receiver is not a container this file created, so nothing here can prove it.
 */

const ASSIGN_OPS = new Set([
  ts.SyntaxKind.EqualsToken, ts.SyntaxKind.PlusEqualsToken, ts.SyntaxKind.MinusEqualsToken,
  ts.SyntaxKind.AsteriskEqualsToken, ts.SyntaxKind.AsteriskAsteriskEqualsToken,
  ts.SyntaxKind.SlashEqualsToken, ts.SyntaxKind.PercentEqualsToken,
  ts.SyntaxKind.LessThanLessThanEqualsToken, ts.SyntaxKind.GreaterThanGreaterThanEqualsToken,
  ts.SyntaxKind.GreaterThanGreaterThanGreaterThanEqualsToken, ts.SyntaxKind.AmpersandEqualsToken,
  ts.SyntaxKind.BarEqualsToken, ts.SyntaxKind.CaretEqualsToken,
  ts.SyntaxKind.BarBarEqualsToken, ts.SyntaxKind.AmpersandAmpersandEqualsToken,
  ts.SyntaxKind.QuestionQuestionEqualsToken,
]);

const unwrap = (e) => {
  let x = e;
  for (;;) {
    if (ts.isParenthesizedExpression(x) || ts.isNonNullExpression(x) ||
        ts.isAsExpression(x) || ts.isTypeAssertionExpression(x) || ts.isSatisfiesExpression(x)) {
      x = x.expression;
      continue;
    }
    return x;
  }
};

/**
 * Does this identifier READ the binding of that name, or is it merely spelled the same?
 *
 * ⚠ THIS EXISTS BECAUSE ITS ABSENCE PRODUCED A FALSE POSITIVE ON THE FIRST CORRECT FIX. The ordering
 * rule below asks "is the re-rooting call the FIRST thing that touches this binding?", so anything
 * mistaken for a touch moves the answer to no. `return { ok: true, errors: [] }` earlier in the same
 * function contains the identifier `errors` as a PROPERTY NAME — it reads nothing — and counting it
 * reported `approval-rules.mjs` as re-rooted-after-fill when the re-root is on the line after the
 * declaration. A gate that fires on the shape of the fix teaches maintainers to ignore it.
 */
function isReferencePosition(id) {
  const p = id.parent;
  if (!p) return true;
  if (ts.isPropertyAccessExpression(p) && p.name === id) return false;  // `x.errors`
  if (ts.isPropertyAssignment(p) && p.name === id) return false;        // `{ errors: … }`
  if (ts.isBindingElement(p) && (p.name === id || p.propertyName === id)) return false;
  if (ts.isVariableDeclaration(p) && p.name === id) return false;
  if (ts.isParameter(p) && p.name === id) return false;
  if (ts.isImportSpecifier(p) || ts.isExportSpecifier(p) || ts.isImportClause(p) ||
      ts.isNamespaceImport(p)) return false;
  if (ts.isQualifiedName(p) && p.right === id) return false;
  if (ts.isLabeledStatement(p) || ts.isBreakStatement(p) || ts.isContinueStatement(p)) return false;
  if (ts.isEnumMember(p) && p.name === id) return false;
  if ((ts.isFunctionDeclaration(p) || ts.isFunctionExpression(p) || ts.isClassDeclaration(p) ||
       ts.isClassExpression(p) || ts.isMethodDeclaration(p) || ts.isMethodSignature(p) ||
       ts.isPropertyDeclaration(p) || ts.isPropertySignature(p) || ts.isGetAccessorDeclaration(p) ||
       ts.isSetAccessorDeclaration(p) || ts.isTypeAliasDeclaration(p) ||
       ts.isInterfaceDeclaration(p)) && p.name === id) return false;
  // A shorthand `{ errors }` IS a read, and is deliberately not excluded above.
  return true;
}

/** The scope a `let`/`const` binding belongs to: the nearest block-like ancestor. */
function blockScopeOf(node) {
  let p = node.parent;
  while (p) {
    if (ts.isBlock(p) || ts.isSourceFile(p) || ts.isModuleBlock(p) || ts.isCaseBlock(p) ||
        ts.isForStatement(p) || ts.isForOfStatement(p) || ts.isForInStatement(p) ||
        ts.isCatchClause(p) || ts.isClassStaticBlockDeclaration(p)) return p;
    p = p.parent;
  }
  return null;
}

/** The scope a `var`/parameter/function-name binding belongs to: the nearest function-like ancestor. */
function functionScopeOf(node) {
  let p = node.parent;
  while (p) {
    if (ts.isSourceFile(p) || ts.isFunctionDeclaration(p) || ts.isFunctionExpression(p) ||
        ts.isArrowFunction(p) || ts.isMethodDeclaration(p) || ts.isConstructorDeclaration(p) ||
        ts.isGetAccessorDeclaration(p) || ts.isSetAccessorDeclaration(p) ||
        ts.isClassStaticBlockDeclaration(p)) return p;
    p = p.parent;
  }
  return null;
}

/**
 * Classify a declaration's initialiser.
 *   { container: "array"|"object", inert: false }  an ordinary container this file created
 *   { container: "safe" }                          inert (or unpoisonable) from creation
 *   null                                           not a container this layer tracks
 */
function classifyInitializer(init, inertFactories, isIntrinsicBinding, aliases) {
  if (init === undefined) return null;
  const e = unwrap(init);

  if (ts.isArrayLiteralExpression(e)) return { container: "array", inert: false };
  if (ts.isObjectLiteralExpression(e)) return { container: "object", inert: false };

  if (ts.isNewExpression(e) && ts.isIdentifier(e.expression)) {
    const ctor = e.expression.text;
    if (TYPED_ARRAYS.has(ctor)) return { container: "safe" };   // integer-indexed set: no chain walk
    if (ORDINARY_CTORS.has(ctor)) return { container: ctor === "Array" ? "array" : "object", inert: false };
    return null;
  }

  if (ts.isCallExpression(e)) {
    const callee = unwrap(e.expression);
    // `Object.create(null)` — the spelling that does not go through the captured wrapper — and the
    // SAME operation under a locally-captured name. `packages/mcp-proxy/src/rotatable-signer.mjs`
    // writes `const createCaptured = Object.create;` at module load and builds every key snapshot
    // with `createCaptured(null)`; that is already correct, and a gate that could not see it would
    // report the hardened idiom as unproven forever. The alias set is derived per file from the
    // declarations themselves, never from a name list.
    const nullArg = e.arguments.length >= 1 && unwrap(e.arguments[0]).kind === ts.SyntaxKind.NullKeyword;
    if (nullArg && ts.isPropertyAccessExpression(callee) && callee.name.text === "create" &&
        ts.isIdentifier(callee.expression) && callee.expression.text === "Object") {
      return { container: "safe" };
    }
    if (nullArg && ts.isIdentifier(callee) && aliases.objectCreate.has(callee.text)) {
      return { container: "safe" };
    }
    // A derived inert factory, but ONLY when the callee name is bound from the kernel's capture
    // module. A local function that happens to be called `objectCreateNull` earns nothing.
    const name = ts.isIdentifier(callee) ? callee.text
      : ts.isPropertyAccessExpression(callee) && ts.isIdentifier(callee.expression) &&
        callee.expression.text === "intrinsics" ? callee.name.text : null;
    if (name !== null && inertFactories.has(name) && isIntrinsicBinding(name, callee)) {
      return { container: "safe" };
    }
    // `inertArray([…])` / `makeInertArray([…])` — the literal fill is CreateDataProperty, which does
    // not consult the prototype, and the re-root happens before the value is ever visible.
    if (name !== null && (name === "inertArray" || name === "makeInertArray")) return { container: "safe" };
    return null;
  }

  return null;
}

/**
 * The NAME a call dispatches to, for the two spellings this repository uses: a destructured wrapper
 * (`objectKeys(o)`) and a namespace member (`intrinsics.objectKeys(o)`). Anything else returns null,
 * which lands the site in the unproven bucket rather than in a guess.
 */
function calleeName(call) {
  const callee = unwrap(call.expression);
  if (ts.isIdentifier(callee)) return callee.text;
  if (ts.isPropertyAccessExpression(callee) && ts.isIdentifier(callee.expression) &&
      callee.expression.text === "intrinsics") return callee.name.text;
  return null;
}

/**
 * Is this call a re-rooting of `binding`, i.e. does it make the container inert in place?
 *
 * THE SECOND ARGUMENT IS CHECKED, and that is not pedantry: `objectSetPrototypeOf(x, somethingLive)`
 * has the exact shape of the fix and none of its effect. A gate that accepted the shape would hand a
 * clean verdict to a container re-rooted onto a prototype the attacker still owns — a defence that
 * reads correct and measures nothing, which is the class this whole layer exists to end.
 */
function isRerootOf(call, nameNode, aliases) {
  const callee = unwrap(call.expression);
  const fname = ts.isIdentifier(callee) ? callee.text
    : ts.isPropertyAccessExpression(callee) ? callee.name.text : null;
  if (fname === null) return false;
  if (!REROOT_FNS.has(fname) && !(ts.isIdentifier(callee) && aliases.setPrototypeOf.has(fname))) return false;
  if (call.arguments.length < 1 || unwrap(call.arguments[0]) !== nameNode) return false;
  // `inertArray(x)` / `makeInertArray(x)` name their target prototype themselves.
  if (fname === "inertArray" || fname === "makeInertArray") return true;
  if (call.arguments.length < 2) return false;
  const proto = unwrap(call.arguments[1]);
  if (proto.kind === ts.SyntaxKind.NullKeyword) return true;
  // The named prototype must be the KERNEL'S — bound from `noa-receipt` / the `intrinsics` capture in
  // this file. Accepting the NAME alone would let `const INERT_ARRAY_PROTOTYPE = Object.prototype;`
  // buy a clean verdict for a container re-rooted onto the very object the attacker owns.
  return ts.isIdentifier(proto) && proto.text === "INERT_ARRAY_PROTOTYPE" &&
    aliases.intrinsicNames.has("INERT_ARRAY_PROTOTYPE");
}

/**
 * Every `[[Set]]`-shaped write AT `node`, as a list of `{ receiver, what }`. `receiver` is the
 * expression whose prototype chain the write walks. A list rather than a single value because ONE
 * destructuring assignment can carry several member targets — `({ a: o.x, b: o.y } = src)` is two
 * [[Set]] operations in one node, and returning only the first would silently drop the second.
 */
function writeAt(node) {
  if (ts.isBinaryExpression(node) && ASSIGN_OPS.has(node.operatorToken.kind)) {
    const lhs = unwrap(node.left);
    if (ts.isPropertyAccessExpression(lhs) || ts.isElementAccessExpression(lhs)) {
      return [{ receiver: unwrap(lhs.expression), what: "property assignment" }];
    }
    // DESTRUCTURING ASSIGNMENT (not a declaration): `[o.x] = xs` and `({ k: o.x } = src)` both
    // perform `PutValue` on a member expression, which is a [[Set]]. The pattern is parsed as an
    // array/object LITERAL in assignment position, so it has to be walked explicitly — a grammar
    // that only knew `lhs is a member expression` would read these as no write at all.
    if (ts.isArrayLiteralExpression(lhs) || ts.isObjectLiteralExpression(lhs)) {
      const out = [];
      const walkTarget = (n) => {
        const e = unwrap(n);
        if (ts.isPropertyAccessExpression(e) || ts.isElementAccessExpression(e)) {
          out.push({ receiver: unwrap(e.expression), what: "destructuring assignment target" });
          return;
        }
        if (ts.isArrayLiteralExpression(e)) { e.elements.forEach(walkTarget); return; }
        if (ts.isObjectLiteralExpression(e)) {
          for (const p of e.properties) {
            if (ts.isPropertyAssignment(p)) walkTarget(p.initializer);
          }
          return;
        }
        if (ts.isSpreadElement(e)) walkTarget(e.expression);
        if (ts.isSpreadAssignment(e)) walkTarget(e.expression);
        if (ts.isBinaryExpression(e) && e.operatorToken.kind === ts.SyntaxKind.EqualsToken) walkTarget(e.left);
      };
      walkTarget(lhs);
      return out;
    }
    return [];
  }
  if ((ts.isPostfixUnaryExpression(node) || ts.isPrefixUnaryExpression(node)) &&
      (node.operator === ts.SyntaxKind.PlusPlusToken || node.operator === ts.SyntaxKind.MinusMinusToken)) {
    const t = unwrap(node.operand);
    if (ts.isPropertyAccessExpression(t) || ts.isElementAccessExpression(t)) {
      return [{ receiver: unwrap(t.expression), what: "increment/decrement of a property" }];
    }
    return [];
  }
  if (ts.isCallExpression(node)) {
    const callee = unwrap(node.expression);
    if (ts.isPropertyAccessExpression(callee) && WRITE_METHODS.has(callee.name.text)) {
      return [{ receiver: unwrap(callee.expression), what: `.${callee.name.text}(…)` }];
    }
    // `Object.assign(target, …)` — `Set(to, key, value, true)` on the FIRST argument — and
    // `Reflect.set(target, k, v)`, which is `[[Set]]` by definition and would otherwise be the
    // cheapest spelling to evade this whole layer with.
    if (ts.isPropertyAccessExpression(callee) && ts.isIdentifier(callee.expression) &&
        node.arguments.length >= 1) {
      const holder = callee.expression.text;
      const method = callee.name.text;
      if (holder === "Object" && method === "assign") {
        return [{ receiver: unwrap(node.arguments[0]), what: "Object.assign(target, …)" }];
      }
      if (holder === "Reflect" && method === "set") {
        return [{ receiver: unwrap(node.arguments[0]), what: "Reflect.set(target, …)" }];
      }
    }
    const wname = ts.isIdentifier(callee) ? callee.text
      : ts.isPropertyAccessExpression(callee) && ts.isIdentifier(callee.expression) &&
        callee.expression.text === "intrinsics" ? callee.name.text : null;
    if (wname !== null && WRITE_WRAPPERS.has(wname) && node.arguments.length >= 1) {
      return [{ receiver: unwrap(node.arguments[0]), what: `${wname}(target, …)` }];
    }
  }
  return [];
}

/**
 * Analyse one source text. Returns `{ sites, parseError }`. `sites` carries EVERY write the grammar
 * recognises, each with a verdict — there is no silently-dropped bucket, which is what makes the
 * totals reconcilable.
 */
export function analyzeSource(relPath, text, inertFactories) {
  const sf = ts.createSourceFile(`${relPath}.l11.ts`, text, ts.ScriptTarget.ES2022, true, ts.ScriptKind.TS);
  const line = (n) => sf.getLineAndCharacterOfPosition(n.getStart(sf)).line + 1;

  // A parse that produced no statements from non-empty text is a parse that did not happen.
  if (sf.statements.length === 0 && text.trim().length > 0) {
    return { sites: [], parseError: "produced ZERO statements from non-empty source" };
  }

  /* ── pass 1: bindings ─────────────────────────────────────────────────────────────────────── */
  // key: scope node -> Map<name, binding>. A name declared twice in one scope is AMBIGUOUS and every
  // write through it degrades to L11-C rather than picking a declaration.
  const scopes = new Map();
  const declare = (scopeNode, name, binding) => {
    if (!scopeNode) return;
    let m = scopes.get(scopeNode);
    if (!m) { m = new Map(); scopes.set(scopeNode, m); }
    if (m.has(name)) m.get(name).ambiguous = true;
    else m.set(name, binding);
  };

  /** Names bound from the kernel's capture module — `import {…} from "noa-receipt"` or
   *  `const { … } = intrinsics`. Only these earn inert-factory treatment. */
  const intrinsicNames = new Set();

  const declPass = (n) => {
    if (ts.isImportDeclaration(n) && n.importClause) {
      const c = n.importClause;
      if (c.name) declare(sf, c.name.text, { kind: "import" });
      const nb = c.namedBindings;
      if (nb && ts.isNamespaceImport(nb)) declare(sf, nb.name.text, { kind: "import" });
      if (nb && ts.isNamedImports(nb)) {
        // Only names imported from the KERNEL (directly, or re-exported through adapter-core) count
        // as the capture module's. A local module could otherwise export something called
        // `INERT_ARRAY_PROTOTYPE` or `objectCreateNull` and buy a clean verdict by naming.
        // The kernel's OWN modules import the capture module by relative path (`./intrinsics.js`),
        // so restricting to the two package names alone would make every kernel call site read as
        // unproven — a survey number produced by the instrument rather than by the code.
        const spec = ts.isStringLiteral(n.moduleSpecifier) ? n.moduleSpecifier.text : "";
        const fromKernel = spec === "noa-receipt" || spec === "noa-mcp-adapter-core" ||
          /(^|\/)(intrinsics|inert)\.(js|ts|mjs)$/.test(spec);
        for (const el of nb.elements) {
          declare(sf, el.name.text, { kind: "import" });
          if (fromKernel) intrinsicNames.add(el.name.text);
        }
      }
    } else if (ts.isVariableDeclaration(n)) {
      const listFlags = n.parent && ts.isVariableDeclarationList(n.parent) ? n.parent.flags : 0;
      const blockScoped = (listFlags & (ts.NodeFlags.Let | ts.NodeFlags.Const)) !== 0;
      const scope = blockScoped ? blockScopeOf(n) : functionScopeOf(n);
      if (ts.isIdentifier(n.name)) {
        declare(scope, n.name.text, {
          kind: "var", decl: n, nameNode: n.name, isConst: (listFlags & ts.NodeFlags.Const) !== 0,
          init: n.initializer,
        });
      } else {
        // A destructuring pattern. Record the names so resolution does not walk past them into an
        // outer container binding of the same name, but never treat them as containers.
        const names = [];
        const collect = (p) => {
          if (ts.isIdentifier(p)) names.push(p.text);
          else if (ts.isBindingElement(p)) collect(p.name);
          else if (ts.isObjectBindingPattern(p) || ts.isArrayBindingPattern(p)) p.elements.forEach((el) => { if (!ts.isOmittedExpression(el)) collect(el); });
        };
        collect(n.name);
        const fromIntrinsics = n.initializer !== undefined && /\bintrinsics\b/.test(n.initializer.getText(sf));
        for (const nm of names) {
          declare(scope, nm, { kind: "destructured" });
          if (fromIntrinsics) intrinsicNames.add(nm);
        }
      }
    } else if (ts.isParameter(n) && ts.isIdentifier(n.name)) {
      declare(functionScopeOf(n), n.name.text, { kind: "param" });
    } else if (ts.isFunctionDeclaration(n) && n.name) {
      declare(blockScopeOf(n), n.name.text, { kind: "function" });
    } else if (ts.isClassDeclaration(n) && n.name) {
      declare(blockScopeOf(n), n.name.text, { kind: "class" });
    } else if (ts.isCatchClause(n) && n.variableDeclaration && ts.isIdentifier(n.variableDeclaration.name)) {
      declare(n, n.variableDeclaration.name.text, { kind: "catch" });
    }
    ts.forEachChild(n, declPass);
  };
  declPass(sf);

  const isIntrinsicBinding = (name) => intrinsicNames.has(name);

  // ── DERIVED PER-FILE ALIASES for the two operations that make a container inert ──────────────
  // A module-load capture (`const createCaptured = Object.create;`) is this repository's standard
  // idiom, and the SAME operation under a local name must read the same way here — otherwise the
  // gate reports already-hardened code as unproven, which is how a gate earns the right to be
  // ignored. Derived from the declarations in this file, never from a name list.
  const aliases = { objectCreate: new Set(), setPrototypeOf: new Set(), intrinsicNames };
  for (const m of scopes.values()) {
    for (const [name, b] of m) {
      if (b.kind !== "var" || b.init === undefined) continue;
      const init = unwrap(b.init);
      if (!ts.isPropertyAccessExpression(init) || !ts.isIdentifier(init.expression)) continue;
      const holder = init.expression.text;
      if (init.name.text === "create" && holder === "Object") aliases.objectCreate.add(name);
      if (init.name.text === "setPrototypeOf" && (holder === "Object" || holder === "Reflect")) {
        aliases.setPrototypeOf.add(name);
      }
    }
  }

  // Classify every `var` binding's initialiser now that `intrinsicNames` is complete.
  for (const m of scopes.values()) {
    for (const b of m.values()) {
      if (b.kind !== "var") continue;
      b.container = classifyInitializer(b.init, inertFactories, isIntrinsicBinding, aliases);
      b.inertFrom = b.container?.container === "safe" ? -1 : null;
      b.reassigned = false;
      b.refs = [];
    }
  }

  /** Resolve an identifier NODE to its binding by walking its own ancestor chain. */
  const resolve = (idNode) => {
    let p = idNode.parent;
    let node = idNode;
    // Include the identifier's own scope chain starting at the innermost enclosing scope.
    while (node) {
      const m = scopes.get(node);
      if (m && m.has(idNode.text)) return m.get(idNode.text);
      node = node.parent;
    }
    void p;
    return null;
  };

  /* ── pass 2: references, reassignment, re-rooting ─────────────────────────────────────────── */
  const refPass = (n) => {
    if (ts.isIdentifier(n) && isReferencePosition(n)) {
      const b = resolve(n);
      if (b && b.kind === "var" && b.container) {
        if (b.nameNode !== n) b.refs.push(n);
      }
    }
    // Reassignment of the binding itself makes every later verdict about it a guess.
    if (ts.isBinaryExpression(n) && n.operatorToken.kind === ts.SyntaxKind.EqualsToken) {
      const lhs = unwrap(n.left);
      if (ts.isIdentifier(lhs)) {
        const b = resolve(lhs);
        if (b && b.kind === "var" && b.container) b.reassigned = true;
      }
    }
    ts.forEachChild(n, refPass);
  };
  refPass(sf);

  // ── THE ORDERING RULE, WHICH IS THE WHOLE POINT OF THE LAYER ────────────────────────────────
  // A container created ordinary becomes inert at the position of the re-rooting call — and only if
  // that call is the FIRST thing that touches the binding. Anything else touching it first means a
  // write could already have landed, so the layer refuses to call it creation-time inert and reports
  // every earlier write as L11-B. Positional order is used as the ordering witness; where positional
  // and execution order can differ (a closure written before the re-root), the verdict lands on the
  // conservative side. That is a stated approximation, not an unexamined one.
  for (const m of scopes.values()) {
    for (const b of m.values()) {
      if (b.kind !== "var" || !b.container || b.container.container === "safe") continue;
      b.refs.sort((x, y) => x.getStart(sf) - y.getStart(sf));
      const first = b.refs[0];
      if (first && ts.isCallExpression(first.parent) && isRerootOf(first.parent, first, aliases)) {
        b.inertFrom = first.parent.getEnd();
        b.rerootedAtCreation = true;
        continue;
      }
      // A re-root that is not first: record WHERE, so earlier writes can be named L11-B.
      for (const r of b.refs) {
        if (ts.isCallExpression(r.parent) && isRerootOf(r.parent, r, aliases)) {
          b.inertFrom = r.parent.getEnd();
          b.rerootedAtCreation = false;
          break;
        }
      }
    }
  }

  /* ── pass 3: writes ──────────────────────────────────────────────────────────────────────── */
  const sites = [];
  const writePass = (n) => {
    for (const w of writeAt(n)) {
      const pos = n.getStart(sf);
      const recv = w.receiver;
      let verdict;
      let detail;
      // A receiver that IS a call to a derived inert factory — `arraySort(objectKeys(o), …)`. The
      // container never exists in an ordinary form at all, so there is no window to poison. Handled
      // before the identifier case because it is a stronger fact than any binding-based one.
      const factoryCall = ts.isCallExpression(recv) ? calleeName(recv) : null;
      if (factoryCall !== null && inertFactories.has(factoryCall) && isIntrinsicBinding(factoryCall)) {
        verdict = "inert";
        detail = `the receiver is the result of \`${factoryCall}(…)\`, which hands back an inert-rooted container`;
      } else if (ts.isIdentifier(recv)) {
        const b = resolve(recv);
        if (b && b.kind === "var" && b.container && !b.ambiguous && !b.reassigned) {
          if (b.container.container === "safe") {
            verdict = "inert";
            detail = "created inert";
          } else if (b.inertFrom !== null && pos > b.inertFrom && b.rerootedAtCreation) {
            verdict = "inert";
            detail = "re-rooted before its first write";
          } else if (b.inertFrom !== null) {
            verdict = "L11-B";
            detail = `\`${recv.text}\` is created as an ordinary ${b.container.container} and re-rooted at ` +
              `line ${sf.getLineAndCharacterOfPosition(b.inertFrom).line + 1}, which is NOT before this write. ` +
              "A container re-rooted after it is filled has already taken the poisoned write: the " +
              "accessor on Object.prototype swallowed the element and `length` still moved. Re-root " +
              "at creation, or build it with objectCreateNull().";
          } else {
            verdict = "L11-A";
            detail = `\`${recv.text}\` is an ordinary ${b.container.container} (declared line ` +
              `${line(b.nameNode)}) and is never made inert. This write performs [[Set]], which walks ` +
              "the receiver's prototype chain to the mutable Object.prototype; an accessor planted " +
              "there swallows it. Build it with objectCreateNull(), or re-root it onto " +
              "INERT_ARRAY_PROTOTYPE immediately after the declaration and before any write.";
          }
        } else if (b && b.ambiguous) {
          verdict = "L11-C";
          detail = `\`${recv.text}\` is declared more than once in one scope; this layer refuses to pick a declaration.`;
        } else if (b && b.kind === "var" && b.container && b.reassigned) {
          verdict = "L11-C";
          detail = `\`${recv.text}\` is REASSIGNED elsewhere, so the container reaching this write is not the one declared.`;
        } else {
          verdict = "L11-C";
          detail = `\`${recv.text}\` is ${b ? `a ${b.kind}` : "not declared in this file"}; its prototype chain is decided by its caller.`;
        }
      } else if (recv.kind === ts.SyntaxKind.ThisKeyword) {
        verdict = "L11-C";
        detail = "the receiver is `this` — an ordinary class instance whose chain ends at Object.prototype, " +
          "but the instance is not a container this file created, so inertness cannot be decided here.";
      } else {
        verdict = "L11-C";
        detail = `the receiver is a ${ts.SyntaxKind[recv.kind]} (\`${recv.getText(sf).slice(0, 48).replace(/\s+/g, " ")}\`), not a container this file created.`;
      }
      sites.push({ file: relPath, line: line(n), what: w.what, verdict, detail,
        text: n.getText(sf).slice(0, 96).replace(/\s+/g, " ") });
    }
    ts.forEachChild(n, writePass);
  };
  writePass(sf);

  return { sites, parseError: null };
}

/* ══════════════════════════════════════════════════════════════════════════════════════════════
 * SELF-TEST — the layer must be OBSERVED to fail
 * ══════════════════════════════════════════════════════════════════════════════════════════════ */

const FIXTURE_VIOLATING = `
import { intrinsics, INERT_ARRAY_PROTOTYPE } from "noa-receipt";
const { objectCreateNull, objectSetPrototypeOf, arrayPush } = intrinsics;

// A1 — an ordinary array filled through the CAPTURED wrapper. The wrapper is pristine; the RECEIVER
// is still rooted on the live Array.prototype -> Object.prototype.
export function selftestOrdinaryArray(rules) {
  const out = [];
  for (let i = 0; i < rules.length; i += 1) arrayPush(out, rules[i]);
  return out;
}

// A2 — an ordinary object filled by index assignment.
export function selftestOrdinaryObject(keys, src) {
  const out = {};
  for (let i = 0; i < keys.length; i += 1) out[keys[i]] = src[keys[i]];
  return out;
}

// B — THE ORDERING DEFECT: filled first, re-rooted after. Every element write above the re-root has
// already gone through Object.prototype.
export function selftestRerootedAfterFill(rules) {
  const canon = [];
  for (let i = 0; i < rules.length; i += 1) arrayPush(canon, rules[i]);
  objectSetPrototypeOf(canon, INERT_ARRAY_PROTOTYPE);
  return canon;
}

// A3 — Object.assign onto an ordinary target is Set(to, key, value, true).
export function selftestAssignOntoOrdinary(src) {
  const merged = {};
  Object.assign(merged, src);
  return merged;
}

// A4 — Reflect.set IS [[Set]] by definition, and would be the cheapest spelling to evade a grammar
// that only knew about plain assignment and dot-push.
export function selftestReflectSet(src) {
  const bag = {};
  Reflect.set(bag, "k", src);
  return bag;
}

// A5 — a DESTRUCTURING ASSIGNMENT (not a declaration) performs PutValue on each member target, which
// is a [[Set]] each. Two targets here, so a grammar that reported only the first would lose one.
export function selftestDestructuringTargets(src) {
  const bag = {};
  ({ a: bag.a, b: bag.b } = src);
  return bag;
}

void objectCreateNull;
`;

/**
 * A5b — THE NAME IS NOT THE PROTOTYPE. `objectSetPrototypeOf(x, INERT_ARRAY_PROTOTYPE)` has the exact
 * shape of the fix; if the identifier is a local binding for `Object.prototype`, it has none of the
 * effect. A gate that matched the spelling would hand a clean verdict to a container re-rooted onto
 * the object the attacker owns.
 */
const FIXTURE_FORGED_PROTOTYPE = `
import { intrinsics } from "noa-receipt";
const { objectSetPrototypeOf, arrayPush } = intrinsics;
const INERT_ARRAY_PROTOTYPE = Object.prototype;
export function selftestForgedPrototype(xs) {
  const a = [];
  objectSetPrototypeOf(a, INERT_ARRAY_PROTOTYPE);
  for (let i = 0; i < xs.length; i += 1) arrayPush(a, xs[i]);
  return a;
}
`;

const FIXTURE_HONEST = `
import { intrinsics, INERT_ARRAY_PROTOTYPE } from "noa-receipt";
const { objectCreateNull, objectSetPrototypeOf, arrayPush, objectAssign, objectKeys, arraySort } = intrinsics;

// Null-prototype from creation: [[Set]] has no chain to walk.
export function honestNullProtoObject(keys, src) {
  const out = objectCreateNull();
  for (let i = 0; i < keys.length; i += 1) out[keys[i]] = src[keys[i]];
  return out;
}

// Re-rooted BEFORE the first write — the house pattern, in the correct order.
export function honestRerootedAtCreation(rules) {
  const canon = [];
  objectSetPrototypeOf(canon, INERT_ARRAY_PROTOTYPE);
  for (let i = 0; i < rules.length; i += 1) arrayPush(canon, rules[i]);
  return canon;
}

// objectAssign onto a null-prototype target.
export function honestAssign(src) {
  const merged = objectCreateNull();
  objectAssign(merged, src);
  return merged;
}

// A literal is built with CreateDataPropertyOrThrow, which never consults the prototype, so it is
// not a write in this grammar and must NOT be reported.
export function honestLiteral(a, b) {
  const pair = [a, b];
  const rec = { a, b };
  return [pair, rec, objectKeys(rec)];
}

// A TypedArray: integer-indexed writes never walk a prototype chain.
export function honestTypedArray(n) {
  const der = new Uint8Array(n);
  for (let i = 0; i < n; i += 1) der[i] = i & 255;
  return der;
}

// THE SAME TWO OPERATIONS UNDER MODULE-LOAD CAPTURE NAMES — the idiom rotatable-signer.mjs uses.
// Without the derived alias set these read as unproven, and a gate that cannot recognise the
// hardened form of its own rule reports correct code as a finding forever.
const createCaptured = Object.create;
const setProtoCaptured = Object.setPrototypeOf;
export function honestCapturedAliases(entries) {
  const keys = createCaptured(null);
  keys.first = entries[0];
  const list = [];
  setProtoCaptured(list, null);
  list[list.length] = entries[0];
  return [keys, list];
}

// FALSE-POSITIVE GUARD, and it is here because its absence fired on the first correct fix: the
// identifier "errors" appears as a PROPERTY NAME on the early-return line, before the re-root. It
// reads nothing, so it must not count as "something touched this binding before it was made inert".
export function honestPropertyNameIsNotAReference(rules) {
  if (!rules) return { ok: true, errors: [] };
  const errors = [];
  objectSetPrototypeOf(errors, INERT_ARRAY_PROTOTYPE);
  for (let i = 0; i < rules.length; i += 1) arrayPush(errors, rules[i]);
  return { ok: errors.length === 0, errors };
}

// A container handed back by a DERIVED inert factory: objectKeys returns an inert-rooted array, so
// sorting it in place — which is Set(O, index, value, true) on that receiver — walks no live chain.
export function honestSortOfFactoryArray(rec) {
  const ks = objectKeys(rec);
  return arraySort(ks, undefined);
}
`;

function runSelfTest(inertFactories) {
  let ok = true;
  const say = (label, pass, extra = "") => {
    console.log(`  ${pass ? "OK  " : "FAIL"}  ${label}${extra ? `  ${extra}` : ""}`);
    if (!pass) ok = false;
  };

  console.log("L11 selftest — the layer must go RED on violating fixtures and GREEN on honest ones\n");

  // ── ARM 1: in-memory, through the SAME analyser the gate calls ──────────────────────────────
  const red = analyzeSource("__l11_selftest_violating.mjs", FIXTURE_VIOLATING, inertFactories);
  const green = analyzeSource("__l11_selftest_honest.mjs", FIXTURE_HONEST, inertFactories);
  const redA = red.sites.filter((s) => s.verdict === "L11-A");
  const redB = red.sites.filter((s) => s.verdict === "L11-B");
  const greenBad = green.sites.filter((s) => s.verdict !== "inert");

  say("L11-A fires on an ordinary container that takes a write", redA.length >= 3, `(${redA.length} site(s))`);
  for (const s of redA) console.log(`          ${s.file}:${s.line}  ${s.what}  ${s.text}`);
  // The ordering arm is the reason this layer exists: a gate that reported both orderings the same
  // way would pass the exact code that shipped the defect.
  say("L11-B fires on a container re-rooted AFTER its fill", redB.length >= 1, `(${redB.length} site(s))`);
  for (const s of redB) console.log(`          ${s.file}:${s.line}  ${s.what}  ${s.text}`);
  say("the honest fixture is CLEAN", greenBad.length === 0,
    greenBad.length ? `(${greenBad.map((s) => `${s.line}:${s.verdict}`).join(", ")})` : `(${green.sites.length} write(s), all proven inert)`);
  // A green fixture with no writes in it would pass vacuously.
  say("the honest fixture actually CONTAINS writes to prove", green.sites.length >= 5, `(${green.sites.length} write(s))`);

  // Each write SPELLING must be observed to bite on its own. A total count would let one spelling
  // die silently behind another's findings — the failure mode `lint-trusted-roots.mjs` records about
  // per-layer counts, applied to the write grammar.
  const firedOn = (what) => red.sites.some((s) => s.what === what && s.verdict === "L11-A");
  for (const what of ["arrayPush(target, …)", "property assignment", "Object.assign(target, …)",
    "Reflect.set(target, …)", "destructuring assignment target"]) {
    say(`the write grammar bites on: ${what}`, firedOn(what));
  }
  const destructuringSites = red.sites.filter((s) => s.what === "destructuring assignment target");
  say("BOTH targets of a two-target destructuring assignment are reported, not just the first",
    destructuringSites.length === 2, `(${destructuringSites.length} target(s))`);

  // A re-root onto a locally-forged `INERT_ARRAY_PROTOTYPE` must NOT buy a clean verdict.
  const forged = analyzeSource("__l11_forged_proto.mjs", FIXTURE_FORGED_PROTOTYPE, inertFactories);
  say("a re-root onto a locally-forged INERT_ARRAY_PROTOTYPE is still a finding",
    forged.sites.length === 1 && forged.sites[0].verdict !== "inert",
    `(${forged.sites.map((s) => s.verdict).join(",") || "no site at all"})`);

  // ── ARM 2: the ORDERING DISTINCTION, measured as a difference on one construct ───────────────
  // Same body, two orderings. If the layer ever stops distinguishing them, both arms below go equal
  // and this fails — which is stricter than asserting each side alone.
  const beforeText = `
import { intrinsics, INERT_ARRAY_PROTOTYPE } from "noa-receipt";
const { objectSetPrototypeOf, arrayPush } = intrinsics;
export function f(xs) { const a = []; objectSetPrototypeOf(a, INERT_ARRAY_PROTOTYPE); for (let i = 0; i < xs.length; i += 1) arrayPush(a, xs[i]); return a; }
`;
  const afterText = `
import { intrinsics, INERT_ARRAY_PROTOTYPE } from "noa-receipt";
const { objectSetPrototypeOf, arrayPush } = intrinsics;
export function f(xs) { const a = []; for (let i = 0; i < xs.length; i += 1) arrayPush(a, xs[i]); objectSetPrototypeOf(a, INERT_ARRAY_PROTOTYPE); return a; }
`;
  const beforeSites = analyzeSource("__l11_order_before.mjs", beforeText, inertFactories).sites;
  const afterSites = analyzeSource("__l11_order_after.mjs", afterText, inertFactories).sites;
  const beforeClean = beforeSites.length === 1 && beforeSites[0].verdict === "inert";
  const afterRed = afterSites.length === 1 && afterSites[0].verdict === "L11-B";
  say("re-root BEFORE the fill is clean and re-root AFTER the fill is a finding",
    beforeClean && afterRed,
    `(before=${beforeSites.map((s) => s.verdict).join(",")}  after=${afterSites.map((s) => s.verdict).join(",")})`);

  // ── ARM 3: ON DISK, so DISCOVERY is exercised ───────────────────────────────────────────────
  // An in-memory fixture cannot detect that the walk stopped reaching a file — which is the exact
  // blindness `lint-trusted-roots.mjs` records twice about itself. This arm plants a real violating
  // file inside a GATED root and requires the gate's own discovery to find it.
  const gatedRoot = Object.entries(ROOT_INVENTORY).find(([, v]) => v.gated)?.[0];
  let diskOk = false;
  let diskCount = 0;
  const fixturePath = gatedRoot ? path.join(ROOT, gatedRoot, "__l11_selftest_fixture.mjs") : null;
  if (fixturePath) {
    try {
      fs.writeFileSync(fixturePath, FIXTURE_VIOLATING);
      const discovered = gatedRoots().flatMap((r) => listSources(r));
      const rel = path.relative(ROOT, fixturePath);
      if (discovered.includes(rel)) {
        const res = analyzeSource(rel, fs.readFileSync(fixturePath, "utf8"), inertFactories);
        diskCount = res.sites.filter((s) => s.verdict === "L11-A" || s.verdict === "L11-B").length;
        diskOk = diskCount >= 4;
      }
    } finally {
      try { fs.unlinkSync(fixturePath); } catch { /* already gone */ }
    }
  }
  say("discovery reaches a NEW file planted in a gated root", diskOk, `(${diskCount} finding(s) in the planted file)`);
  const stillThere = fixturePath !== null && fs.existsSync(fixturePath);
  say("the planted fixture is removed again", !stillThere);

  // ── ARM 4: the derived authorities are non-empty ────────────────────────────────────────────
  say("the inert-factory derivation is non-empty", inertFactories.size >= 5, `(${inertFactories.size} factories)`);
  const { tcbs, exempt } = readSecurityGateTcbs();
  say("the existing TCB inventories are readable for reconciliation",
    (tcbs.get("ADAPTER_CORE_TCB")?.length ?? 0) > 0 && (tcbs.get("MCP_PROXY_TCB")?.length ?? 0) > 0,
    `(adapter-core ${tcbs.get("ADAPTER_CORE_TCB")?.length ?? 0}, mcp-proxy ${tcbs.get("MCP_PROXY_TCB")?.length ?? 0})`);
  // The severity borrow is only legitimate while the exemption table it borrows carries reasons.
  say("the OUT_OF_TCB exemption table is readable and every reason is non-empty",
    exempt.size > 0 && [...exempt.values()].every((v) => v.trim().length > 0),
    `(${exempt.size} exemption(s))`);

  // ── ARM 5: a subject that cannot be parsed must FAIL, not read as clean ─────────────────────
  const broken = analyzeSource("__l11_broken.mjs", "", inertFactories);
  const brokenNonEmpty = analyzeSource("__l11_broken2.mjs", "   ", inertFactories);
  say("an EMPTY analysis of non-empty text is reported as a parse failure, not as clean",
    broken.parseError === null && brokenNonEmpty.parseError !== null,
    `(empty-file: ${broken.parseError ?? "no error, correct"}; garbage: ${brokenNonEmpty.parseError ?? "NO ERROR — wrong"})`);

  console.log(ok
    ? "\nSELFTEST PASS -- this layer is observed to fail, so it is known to be a gate."
    : "\nSELFTEST FAIL -- a layer never observed to fail is not known to be a gate.");
  return ok;
}

const gatedRoots = () => Object.entries(ROOT_INVENTORY).filter(([, v]) => v.gated).map(([r]) => r);

/* ══════════════════════════════════════════════════════════════════════════════════════════════
 * RUN
 * ══════════════════════════════════════════════════════════════════════════════════════════════ */

const INERT_FACTORIES = deriveInertFactories();

if (process.argv.includes("--selftest")) {
  const derivationBroke = findings.some((f) => f.id === "L11-D");
  const ok = runSelfTest(INERT_FACTORIES) && !derivationBroke;
  for (const f of findings) console.log(`  ${f.id} ${f.file}:${f.line} ${f.msg}`);
  process.exit(ok ? 0 : 1);
}

// ── inventory reconciliation: no root may be silently outside the inventory ─────────────────────
for (const r of discoverRoots()) {
  if (!(r in ROOT_INVENTORY)) {
    add("L11-D", r, 0,
      "source root is NOT in this layer's inventory. It may contain containers filled on a decision " +
      "path and no verdict here covers it. Classify it in scripts/lint-inert-containers.mjs — " +
      "`gated: true`, or `gated: false` with a stated reason.");
  }
}
for (const r of Object.keys(ROOT_INVENTORY)) {
  if (!fs.existsSync(path.join(ROOT, r))) {
    add("L11-D", r, 0, "the inventory names a root that does not exist — stale entry, remove it.");
  }
  const inv = ROOT_INVENTORY[r];
  if (inv.gated === false && (typeof inv.reason !== "string" || inv.reason.trim() === "")) {
    add("L11-D", r, 0,
      "inventoried as NOT GATED with no auditable reason. An un-gated root without a stated reason is " +
      "indistinguishable from a root somebody quietly removed from coverage.");
  }
}

// ── the subject set, and the proof that it covers at least the existing TCBs ────────────────────
const subjects = gatedRoots().flatMap((r) => listSources(r));
const subjectSet = new Set(subjects);
if (subjects.length === 0) {
  add("L11-D", "-", 0,
    "ZERO subject files were discovered under the gated roots. An empty subject set produces a clean " +
    "report from an experiment that did not happen.");
}
const { tcbs: TCBS, exempt: TCB_EXEMPT } = readSecurityGateTcbs();
const inTcb = new Set([...TCBS.values()].flat());
for (const [name, files] of TCBS) {
  for (const f of files) {
    if (!subjectSet.has(f)) {
      add("L11-D", f, 0,
        `${name} classifies this file as a decision path, and this layer does NOT cover it. The ` +
        "coverage relationship this layer claims (a strict superset of the published TCBs) is broken.");
    }
  }
}
// FAIL CLOSED ON UNCLASSIFIED. A subject under a gated root that neither table mentions gets the
// BLOCKING treatment, never the exempt one — "nobody classified it" must not be the cheap way to
// make a finding stop mattering.
for (const f of subjects) {
  if (!inTcb.has(f) && !TCB_EXEMPT.has(f)) {
    add("L11-D", f, 0,
      "a subject under a gated root appears in neither the published package TCB nor its OUT_OF_TCB " +
      "table. Classify it in scripts/lint-security-gates.mjs; until then its findings BLOCK.");
  }
}

// ── analyse ────────────────────────────────────────────────────────────────────────────────────
const allSites = [];
for (const f of subjects) {
  let text;
  try {
    text = fs.readFileSync(path.join(ROOT, f), "utf8");
  } catch (e) {
    add("L11-D", f, 0, `subject could not be READ (${e.message}). Not-analysable is a failure here, never a pass.`);
    continue;
  }
  let res;
  try {
    res = analyzeSource(f, text, INERT_FACTORIES);
  } catch (e) {
    add("L11-D", f, 0, `the analyser THREW on this subject (${e.message}). A subject this layer cannot analyse fails it.`);
    continue;
  }
  if (res.parseError) {
    add("L11-D", f, 0, `subject could not be analysed: ${res.parseError}.`);
    continue;
  }
  for (const s of res.sites) allSites.push(s);
}

const exemptSites = [];
for (const s of allSites) {
  if (s.verdict !== "L11-A" && s.verdict !== "L11-B") continue;
  if (TCB_EXEMPT.has(s.file) && !inTcb.has(s.file)) { exemptSites.push(s); continue; }
  add(s.verdict, s.file, s.line, `${s.what} — ${s.detail}`);
}

// ── the L11-C ratchet ──────────────────────────────────────────────────────────────────────────
const unprovenByFile = new Map();
for (const s of allSites) {
  if (s.verdict !== "L11-C") continue;
  unprovenByFile.set(s.file, (unprovenByFile.get(s.file) ?? 0) + 1);
}
for (const [f, n] of unprovenByFile) {
  const pinned = UNPROVEN_RATCHET[f];
  if (pinned === undefined) {
    add("L11-C", f, 0,
      `${n} write site(s) here have a receiver this layer cannot prove inert, and this file is not in ` +
      "the ratchet. A new unprovable write must be seen, not absorbed: either make the receiver a " +
      "container created inert in this file, or pin the count in UNPROVEN_RATCHET — WITH A REASON.");
  } else if (typeof pinned.why !== "string" || pinned.why.trim() === "") {
    // A bare number is a scoreboard. The reason is what makes an unproven site auditable instead of
    // merely tolerated, so an empty one is a finding on the same principle the OUT_OF_TCB table uses.
    add("L11-C", f, 0, `pinned at ${pinned.n} with no stated reason. An unproven site without a reason is indistinguishable from one nobody looked at.`);
  } else if (n > pinned.n) {
    add("L11-C", f, 0,
      `${n} unprovable write site(s) against a pinned ${pinned.n}. This ratchet only ever falls.`);
  }
}
const ratchetSlack = [];
for (const f of Object.keys(UNPROVEN_RATCHET)) {
  if (!subjectSet.has(f)) {
    add("L11-D", f, 0, "the L11-C ratchet pins a file that is no longer a subject — stale entry.");
  } else if ((unprovenByFile.get(f) ?? 0) < UNPROVEN_RATCHET[f].n) {
    // Not a failure — a ratchet that must be written DOWN. Collected so the number cannot rot upward
    // by being forgotten, and printed with the report rather than ahead of it (a line on stdout
    // before `--json` would make the machine-readable output unparseable).
    ratchetSlack.push(`${f} is pinned at ${UNPROVEN_RATCHET[f].n} and measures ${unprovenByFile.get(f) ?? 0} — lower the pin.`);
  }
}

/* ── report ─────────────────────────────────────────────────────────────────────────────────── */

const count = (v) => allSites.filter((s) => s.verdict === v).length;

if (process.argv.includes("--json")) {
  console.log(JSON.stringify({
    subjects: subjects.length,
    sites: allSites.length,
    proven: count("inert"), violations: count("L11-A") + count("L11-B"), unprovable: count("L11-C"),
    allSites, findings,
  }, null, 2));
  process.exit(findings.length === 0 ? 0 : 1);
}

console.log("L11 — inert-before-write on trusted decision paths\n");
for (const s of ratchetSlack) console.log(`  ratchet slack: ${s}`);
if (ratchetSlack.length) console.log();
for (const r of discoverRoots()) {
  const inv = ROOT_INVENTORY[r];
  const files = listSources(r);
  // Un-gated roots are MEASURED anyway. A root nobody counted is how "out of scope" becomes
  // "nobody looked", and this layer's whole claim is that it says which is which.
  let a = 0, b = 0, c = 0, ok = 0, err = 0;
  for (const f of files) {
    try {
      const res = analyzeSource(f, fs.readFileSync(path.join(ROOT, f), "utf8"), INERT_FACTORIES);
      if (res.parseError) { err++; continue; }
      for (const s of res.sites) {
        if (s.verdict === "L11-A") a++;
        else if (s.verdict === "L11-B") b++;
        else if (s.verdict === "L11-C") c++;
        else ok++;
      }
    } catch { err++; }
  }
  const state = !inv ? "*** UNCLASSIFIED ***" : inv.gated ? "GATED" : "inventoried, not gated";
  console.log(`  ${r.padEnd(34)} ${state.padEnd(24)} ${String(files.length).padStart(3)} file(s)  ` +
    `writes: ${String(ok + a + b + c).padStart(3)}  proven-inert ${String(ok).padStart(3)}  ` +
    `A ${String(a).padStart(3)}  B ${String(b).padStart(2)}  unprovable ${String(c).padStart(3)}` +
    (err ? `  unanalysable ${err}` : ""));
}

console.log(`\n  gated subjects: ${subjects.length} file(s), ${allSites.length} write site(s) — ` +
  `${count("inert")} proven inert, ${count("L11-A") + count("L11-B")} violation(s) ` +
  `(${exemptSites.length} of them in a file the published-package TCB excludes, reported below and ` +
  `NOT blocking), ${count("L11-C")} that this layer SEES but cannot prove.`);

// A downgraded finding that is not printed is a deleted finding.
if (exemptSites.length) {
  console.log("\n  L11-X — findings in files the published package TCB puts OUT of its decision paths:");
  for (const s of exemptSites) {
    console.log(`    ${s.verdict} ${s.file}:${s.line}  ${s.what}  ${s.text}`);
  }
  for (const f of new Set(exemptSites.map((s) => s.file))) {
    console.log(`    reason on record for ${f}: ${TCB_EXEMPT.get(f)}`);
  }
}

if (process.argv.includes("--sites")) {
  console.log("\n  every classified write site under a gated root:");
  for (const s of allSites) console.log(`    ${s.verdict.padEnd(6)} ${s.file}:${s.line}  ${s.what.padEnd(22)} ${s.text}`);
}

console.log();
const byId = {};
for (const f of findings) (byId[f.id] ||= []).push(f);
for (const [id, list] of Object.entries(byId)) {
  console.log(`${id} -- ${list.length} finding(s)`);
  for (const f of list) console.log(`   ${f.file}${f.line ? `:${f.line}` : ""}  ${f.msg}`);
  console.log();
}
// THE COVERAGE SENTENCE, PRINTED EVERY RUN. A gate that honestly reports what it cannot see is worth
// more than one that claims coverage it does not have, and a claim that is not printed is not made.
console.log(
  `L11: ${findings.length === 0 ? "0 findings" : `${findings.length} finding(s) -- BLOCKING`}. ` +
  `Coverage: ${count("inert")} write site(s) PROVEN inert before the write; ${count("L11-C")} site(s) ` +
  "whose receiver is a parameter, an import, `this`, or a call result — visible, listed, and NOT proven.");
process.exit(findings.length === 0 ? 0 : 1);
