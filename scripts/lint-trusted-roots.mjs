#!/usr/bin/env node
/**
 * L9 — TRUSTED SOURCE ROOT INVENTORY, and the forbidden trust-input patterns.
 *
 * WHY THIS FILE EXISTS. `scripts/lint-security-gates.mjs:275` is `walk("src")`, and that file contains
 * ZERO `packages/` paths. So all nine classifying layers L0-L8 are structurally blind to every source
 * root except the receipt kernel -- including `packages/gate/src`, where ALLOW/DENY is actually decided.
 * Eight measured defects lived there while the gate suite reported a blocking zero
 * (`docs/GATE-PROVENANCE-FINDINGS-2026-07-30.md`).
 *
 * The existing gate predicted this failure about itself, in the comment above its own `OUT_OF_TCB`:
 *
 *     "A hardcoded subject list that nothing reconciles is the poison matrix again, wearing a
 *      different hat: correct on the day it was written, silent thereafter."
 *
 * That list reconciles `src/` only. It described its own defect and could not see it, because nothing
 * reconciled the set of ROOTS. This layer reconciles the roots.
 *
 * Run:  node scripts/lint-trusted-roots.mjs             (blocking; exit 1 on any finding)
 *       node scripts/lint-trusted-roots.mjs --selftest  (proves the layer goes RED, then GREEN)
 */

import fs from "node:fs";
import path from "node:path";

const ROOT = path.resolve(import.meta.dirname, "..");

/** Markers that make a source root security-critical -- the owner's list (parsing, verification,
 *  policy, approval, projection, grant, signing, execution, receipt, trust decisions) expressed as
 *  things that appear in code rather than as prose. */
const CRITICAL_MARKERS = [
  "verifyArtifact", "paramsHash", "riskClass", "decisionArtifact", "registerProjection",
  "signArtifact", "createHold", "buildReceipt", "canonicalize", "encodeDocument",
  "issueGrant", "HUMAN_APPROVED", "encryptedDisplay",
];

/**
 * THE INVENTORY. Every root that mechanical discovery finds security-critical must appear here with an
 * explicit disposition. `gated: false` requires an auditable reason -- never a silent omission.
 *
 * Adding a root here does NOT make it safe. It makes it VISIBLE. Roots below are gated while carrying
 * known-open findings; that is intentional and the findings are named.
 */
const INVENTORY = {
  "src": { gated: true, note: "receipt kernel -- already covered by L0-L8" },
  "packages/gate/src": {
    gated: true,
    note: "THE DECISION LAYER: holds, approvals, projections, grants, HUMAN_APPROVED. Eight measured " +
      "defects live here and were invisible to L0-L8 for the entire hardening effort.",
  },
  "packages/approval-artifacts/src": {
    gated: true,
    note: "artifact verification + the F15 approver-role lattice; derives the required approver role",
  },
  "packages/signer-core/src": { gated: true, note: "display sealing, AAD binding, signing primitives" },
  "packages/relay/src": {
    gated: true,
    note: "757 lines, NEVER adversarially reviewed, 0 of 28 knockout controls (Fable R-1/R-2)",
  },
  "packages/evidence/src": { gated: true, note: "evidence assembly over signed artifacts" },

  // ── THE FIVE `.mjs`-ONLY ROOTS (added 2026-07-30, ADR-0005 Slice 5) ─────────────────────────────
  // Every one of these was previously printed by this gate as "not security-critical". That was not a
  // judgement — `listSources` was `.ts`-only (see its docstring), these packages ship ZERO `.ts` files,
  // so `isCritical()` read nothing and returned false. An affirmative clearance produced by not looking.
  // The marker each one actually hits is named below, measured rather than assumed. Gating all five adds
  // ZERO findings, so making them visible costs nothing and the previous silence bought nothing.
  "packages/adapter-core/src": {
    gated: true,
    note: "BOUNDARY 2 + the side-effect state machine. `gate`, `mcp-proxy` and `framework-adapters` ALL " +
      "import it (safe-throw, side-effect-state, tool-outcome-not-recorded), so it decides `ran` / " +
      "`safeToRetry` for every dispatch surface in the repo — the C-04 class. Markers: buildReceipt, " +
      "canonicalize, encodeDocument, paramsHash, riskClass.",
  },
  "packages/framework-adapters/src": {
    gated: true,
    note: "a REGISTERED DISPATCH SURFACE (`framework-adapter-fn`, CLOSED, in lint-dispatch-surfaces) — it " +
      "invokes caller tools and signs the outcome. Markers: buildReceipt, paramsHash, riskClass.",
  },
  "packages/mcp-proxy/src": {
    gated: true,
    note: "a REGISTERED DISPATCH SURFACE (`mcp-proxy-calltool`, MITIGATED) plus a rotatable SIGNER and " +
      "outcome-receipt minting. Markers: buildReceipt, canonicalize, paramsHash.",
  },
  "packages/signer-sidecar/src": {
    gated: true,
    note: "SIGNING. The starkest case: a gate whose job is to inventory security-critical roots cleared " +
      "the signer sidecar because its two files are `.mjs`. Not currently published (code-ready), which " +
      "is a release fact and not a reason to leave it unscanned. Marker: buildReceipt.",
  },
  "packages/tsa-anchor/src": {
    gated: true,
    note: "RFC-3161 timestamp anchoring — it canonicalizes the value that gets externally timestamped, so " +
      "a split read there is a split anchor. Marker: canonicalize.",
  },

  "packages/e2e-demo/src": {
    gated: false,
    reason: "demo/harness code, not a shipped decision path -- but it CONSTRUCTS security artifacts, " +
      "so it is inventoried rather than ignored. If it gains a verdict path, flip gated to true.",
  },
};

const findings = [];
const add = (id, file, line, msg) => findings.push({ id, file, line, msg });

/**
 * Every SOURCE file in a root.
 *
 * ⚠ THIS WAS `.ts`-ONLY UNTIL 2026-07-30, AND IT IS THE SECOND TIME THIS LAYER WAS BLIND IN EXACTLY THE
 * WAY IT EXISTS TO PREVENT. `isCritical()` decides whether a root is security-critical by scanning this
 * list for CRITICAL_MARKERS. Five packages ship ZERO `.ts` files and only `.mjs`:
 *
 *     packages/signer-sidecar/src        0 .ts   2 .mjs     <- SIGNING
 *     packages/adapter-core/src          0 .ts  16 .mjs
 *     packages/tsa-anchor/src            0 .ts   7 .mjs
 *     packages/mcp-proxy/src             0 .ts   7 .mjs
 *     packages/framework-adapters/src    0 .ts   4 .mjs
 *
 * So `isCritical()` read ZERO files for each, found no markers, and this gate PRINTED them as
 * "not security-critical" — an AFFIRMATIVE clearance produced by not looking. That is worse than an
 * omission: an omission reads as a gap, a printed "not security-critical" reads as evidence. The
 * docstring at the top of this file quotes the PREVIOUS gate predicting this about itself ("correct on
 * the day it was written, silent thereafter") — and then this function did it again one layer down,
 * because "source file" was silently defined as "TypeScript file".
 *
 * `.d.ts` stays excluded: a declaration decides nothing.
 */
const listSources = (dir) => {
  const out = [];
  // ── THIRD TIME, 2026-07-30. `.tsx`/`.jsx` were missing and a symlinked DIRECTORY was skipped. ──
  // The paragraph above records this layer going blind twice by defining "source file" too narrowly.
  // It was still too narrow. Both holes were reproduced with a CONTROL — the identical violating
  // construct from `wrapper.ts:135`, planted twice under `packages/gate/src`:
  //
  //     __probe.tsx                L9: 1 finding   <- invisible
  //     __probe.ts  (same bytes)   L9: 2 findings  <- caught
  //     __evildir -> /tmp/evilsrc  L9: 1 finding   <- invisible (contains hidden.ts, violating)
  //
  // A `.tsx` under a gated root is not hypothetical the moment any package grows a rendered surface,
  // and the symlink hole needs no exotic attacker: `Dirent.isDirectory()` is FALSE for a link to a
  // directory, so the walk fell through to the file branch, the name did not match SRC, and an
  // entire subtree left the gate's world silently.
  //
  // `statSync` FOLLOWS the link and answers about the target, which is the question that matters.
  // A dangling link is skipped — there is nothing to read — rather than crashing the gate.
  //
  // `.d.ts`/`.d.mts`/`.d.cts` stay excluded: a declaration decides nothing.
  const SRC = /\.(ts|tsx|mts|cts|mjs|cjs|js|jsx)$/;
  const walk = (d) => {
    for (const e of fs.readdirSync(path.join(ROOT, d), { withFileTypes: true })) {
      if (e.name === "node_modules" || e.name === "dist") continue;
      const rp = `${d}/${e.name}`;
      let st;
      try {
        st = fs.statSync(path.join(ROOT, rp));
      } catch {
        continue; // dangling symlink
      }
      if (st.isDirectory()) walk(rp);
      else if (st.isFile() && SRC.test(e.name) && !/\.d\.(ts|mts|cts)$/.test(e.name)) out.push(rp);
    }
  };
  if (fs.existsSync(path.join(ROOT, dir))) walk(dir);
  return out;
};

/** Every `*​/src` directory. Discovery is mechanical so a NEW package cannot be silently unguarded. */
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
  return roots;
}

function isCritical(root) {
  for (const f of listSources(root)) {
    const src = fs.readFileSync(path.join(ROOT, f), "utf8");
    if (CRITICAL_MARKERS.some((m) => src.includes(m))) return true;
  }
  return false;
}

/**
 * Identifiers that provably hold a PARSE SNAPSHOT rather than a live caller object.
 *
 * ⚠ WHY THIS EXISTS — L9-D FIRED ON THE FIX (ADR-0005 Slice 1, 2026-07-30). L9-D watches for
 * "serialized for authentication, then RE-READ", because `encodeDocument` is `JSON.stringify` and
 * invokes accessors. That is the right thing to watch while the serialized value is CALLER-OWNED.
 *
 * But the CORRECT post-Slice-1 shape is, necessarily, that exact textual pattern:
 *
 *     const daBytes = encodeDocument(daDoc);      // daDoc is the PARSE of the request bytes
 *     verifyArtifact(daBytes, …);
 *     const decisionVal = daDoc["decision"];      // read the snapshot — the whole point
 *
 * `daDoc` came out of `parseDocument`, so it is frozen, null-prototype and accessor-free: re-reading
 * it cannot disagree with the serialization, by construction. Left unfixed, L9-D would report a
 * finding against every correct call site forever — and this file's own docstring already names why
 * that is worse than no gate at all: "a gate that cannot tell code from a string produces findings a
 * maintainer learns to dismiss, and a dismissed gate is worse than no gate."
 *
 * SEED + TRANSITIVE CLOSURE: an identifier bound from `parseDocument`/`parseBody`, plus anything bound
 * from an expression mentioning such an identifier, to a fixed point. The two-hop case is real and had
 * to be handled — `engine.ts` binds `parsedBody` → `daDocRaw` → `daDoc`.
 *
 * KNOWN BLIND SPOT, STATED RATHER THAN GLOSSED: this is a textual approximation of provenance, not
 * dataflow. An expression that MIXES a snapshot with a live object (`{ ...daDoc, ...liveObj }`) taints
 * as a snapshot and would be skipped. That is a narrow hole and a deliberate trade against firing on
 * all correct code; closing it properly needs the AST pass L8 already does for dispatch surfaces. The
 * `--selftest` below pins that L9-D still FIRES on a plainly live object, so this relaxation cannot
 * silently turn the layer off — which is the failure mode that would actually matter.
 */
function parseSnapshotIds(lines) {
  const ids = new Set();
  const bind = /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=]+?)?=\s*([^;]*)/;
  // `signArtifact` belongs here on the same principle, not as a convenience: it TAKES BYTES and
  // `approval-artifacts/src/sign.ts:40` calls `parseDocument(docBytes, "document")`, so its result is a
  // parse snapshot by construction. Without it, L9-D reports `trust.ts:162` — `refHash(keyManifest)`
  // followed by `keyManifest.version` — where `keyManifest` is the gate's own signed artifact built from
  // its own bytes and cannot possibly answer two reads differently.
  const seed = /\b(?:parseDocument|parseBody|signArtifact)\s*\(/;
  for (const ln of lines) {
    const m = bind.exec(ln);
    if (m && seed.test(m[2])) ids.add(m[1]);
  }
  for (let pass = 0; pass < 10; pass++) {
    let grew = false;
    for (const ln of lines) {
      const m = bind.exec(ln);
      if (!m || ids.has(m[1])) continue;
      for (const id of ids) {
        if (new RegExp(`\\b${id}\\b`).test(m[2])) { ids.add(m[1]); grew = true; break; }
      }
    }
    if (!grew) break;
  }
  return ids;
}

function scanPatterns(files) {
  const out = [];
  for (const f of files) {
    const lines = fs.readFileSync(path.join(ROOT, f), "utf8").split("\n");
    const snapshots = parseSnapshotIds(lines);
    lines.forEach((ln, i) => {
      if (/^export\s+(async\s+)?function\s+\w+/.test(ln)) {
        const body = lines.slice(i, i + 6).join("\n");
        if (/\b[A-Z_][A-Z0-9_]*\.(set|delete|clear|push)\s*\(/.test(body)) {
          out.push({ id: "L9-B", file: f, line: i + 1,
            msg: "exported function mutates a module-level collection -- a public mutable trust " +
              "registry. Trusted state must be sealed after construction or installed through an " +
              "authenticated administrative path, never via a function any dependency can call." });
        }
      }
      if (/\bexecute\s*\??\s*:\s*\(\s*\)\s*=>/.test(ln)) {
        out.push({ id: "L9-C", file: f, line: i + 1,
          msg: "trusted interface accepts a ZERO-ARGUMENT caller-supplied execution callback. The " +
            "boundary cannot bind what executed to what was granted. It must accept a typed " +
            "execution command it constructs itself." });
      }
      // ⚠ SINK SCAN RUNS ON CODE, NOT ON PROSE. Widening the sink list immediately produced THREE false
      // positives in `packages/evidence/src/steps.ts`, and all three were this gate reading its own
      // English: `refHash(grant)` appears inside the ERROR MESSAGE
      // `"consumption.grantHash != refHash(grant)"` and inside a comment quoting the check. This file
      // already learned that lesson and fixed it for the RE-READ side only (see the note below about
      // `getPath(head, "chain.hash")`); the SINK side was never blanked, so the bug was latent until a
      // sink appeared in a message. Blank strings and line comments first — the code structure is
      // unchanged, only literals are erased.
      const code = ln
        .replace(/"(?:[^"\\]|\\.)*"/g, '""')
        .replace(/'(?:[^'\\]|\\.)*'/g, "''")
        .replace(/`(?:[^`\\]|\\.)*`/g, "``")
        .replace(/\/\/.*$/, "")
        .replace(/^\s*\*.*$/, "");
      // ⚠ THE SINK LIST WAS `encodeDocument` ALONE, WHICH IS WHY L9-D MISSED THE HEADLINE DEFECT.
      // `engine.ts:635` passed the LIVE `decisionArtifact` to `buildHoldResolution`, which hands it to
      // `refHash` (`resolution.ts:32`) — and `refHash` CANONICALIZES, which invokes accessors exactly as
      // `JSON.stringify` does. The gate signed a `decisionArtifactHash` over bytes it never verified while
      // this layer reported zero findings, because it watched one of the SEVERAL functions that serialize.
      // A sink list is a hardcoded subject list, and this file's own opening docstring names that as the
      // failure mode it was written to fix.
      const m = /(?:encodeDocument|refHash|receiptRefHash|virtualHash)\(\s*([A-Za-z_$][\w$]*)\s*\)/.exec(code);
      // A parse snapshot is not a caller-owned object: re-reading it cannot disagree with the
      // serialization, so the re-read L9-D exists to forbid is not a defect here. See parseSnapshotIds.
      if (m && !snapshots.has(m[1])) {
        const v = m[1];
        // ⚠ FALSE-POSITIVE FIX 2026-07-30. This scan previously matched inside STRING LITERALS:
        // `getPath(head, "chain.hash")` was reported as a re-read of a variable named `chain`
        // (`packages/evidence/src/steps.ts:952`). A gate that cannot tell code from a string produces
        // findings a maintainer learns to dismiss, and a dismissed gate is worse than no gate.
        // Strings are blanked before the re-read scan; the code structure is unchanged.
        const after = lines.slice(i + 1, i + 41).map((l) =>
          l.replace(/"(?:[^"\\]|\\.)*"/g, '""').replace(/'(?:[^'\\]|\\.)*'/g, "''").replace(/`(?:[^`\\]|\\.)*`/g, "``"));
        const k = after.findIndex((l) => new RegExp(`\\b${v}\\s*\\[`).test(l) || new RegExp(`\\b${v}\\.[a-z]`).test(l));
        if (k >= 0) {
          out.push({ id: "L9-D", file: f, line: i + 1,
            msg: `\`${v}\` is serialized for authentication/commitment here and RE-READ at line ${i + 2 + k}. ` +
              "encodeDocument is JSON.stringify and refHash/receiptRefHash/virtualHash canonicalize; ALL of " +
              "them invoke accessors, so the committed bytes and the authorizing read can disagree. " +
              "Authorize from a parsed immutable snapshot." });
        }
      }
    });
  }
  return out;
}

const gatedFiles = () => Object.entries(INVENTORY).filter(([, v]) => v.gated).flatMap(([r]) => listSources(r));

// ── self-test: prove the layer goes RED with a forbidden fixture, and GREEN without it ───────────
if (process.argv.includes("--selftest")) {
  const fixture = path.join(ROOT, "packages/gate/src/__l9_selftest_fixture.ts");
  fs.writeFileSync(fixture, [
    "export const SELFTEST_REGISTRY = new Map<string, unknown>();",
    "export function selftestRegister(k: string, v: unknown): void { SELFTEST_REGISTRY.set(k, v); }",
    "export interface SelftestOpaque { execute: () => Promise<{ ok: boolean }>; }",
    // ── L9-D POSITIVE SAMPLE (added 2026-07-30 with the parse-provenance relaxation). ──────────────
    // `live` is a CALLER-OWNED parameter: serialized for authentication, then re-read. L9-D must fire.
    // Without this sample the provenance skip could suppress L9-D entirely and the selftest would
    // still pass on L9-B + L9-C alone — a relaxation that silently turns a layer off is the exact
    // failure this file was written to prevent.
    "export function selftestLiveReread(live: Record<string, unknown>): string {",
    "  const bytes = encodeDocument(live);",
    "  void bytes;",
    "  return String(live[\"decision\"]);",
    "}",
    // ── L9-D NEGATIVE SAMPLE: the CORRECT shape must NOT fire. `snap` is a parse snapshot. ─────────
    "export function selftestSnapshotReread(raw: unknown): string {",
    "  const parsed = parseDocument(raw, \"doc\");",
    "  const snap = parsed as Record<string, unknown>;",
    "  const snapBytes = encodeDocument(snap);",
    "  void snapBytes;",
    "  return String(snap[\"decision\"]);",
    "}",
    "",
  ].join("\n"));
  // ── .mjs FIXTURE (added 2026-07-30). `listSources` was `.ts`-only and this selftest planted a `.ts`
  // fixture, so the selftest PASSED while five `.mjs`-only roots were being cleared without being read.
  // A selftest that only exercises the extension the scanner already handled cannot detect that the
  // scanner ignores another one. This fixture is `.mjs` and lives in a root that is `.mjs`-only in
  // reality, so if discovery ever narrows back to `.ts` this arm goes silent and the run FAILS.
  const mjsFixture = path.join(ROOT, "packages/signer-sidecar/src/__l9_selftest_fixture.mjs");
  fs.writeFileSync(mjsFixture, [
    "export const SELFTEST_MJS_REGISTRY = new Map();",
    "export function selftestMjsRegister(k, v) { SELFTEST_MJS_REGISTRY.set(k, v); }",
    "export function selftestMjsLiveReread(live) {",
    "  const bytes = encodeDocument(live);",
    "  void bytes;",
    "  return String(live[\"decision\"]);",
    "}",
    "",
  ].join("\n"));

  // ── .tsx FIXTURE (added 2026-07-30, THIRD blindness). `SRC` covered ts|mts|cts|mjs|cjs|js and not
  // `.tsx`/`.jsx`. Measured with a control: the identical violating interface as `__probe.tsx` left
  // L9 at 1 finding, and as `__probe.ts` took it to 2. Same reasoning as the `.mjs` arm — an
  // extension the scanner already handled cannot detect an extension it does not.
  const tsxFixture = path.join(ROOT, "packages/gate/src/__l9_selftest_fixture.tsx");
  fs.writeFileSync(tsxFixture, [
    "export interface SelftestTsxOpaque { execute: () => Promise<{ ok: boolean }>; }",
    "",
  ].join("\n"));

  // ── SYMLINKED-DIRECTORY FIXTURE (added 2026-07-30, alongside the .tsx arm). `Dirent.isDirectory()`
  // is FALSE for a link to a directory, so the walk fell through to the file branch, the link's own
  // name did not match SRC, and the entire subtree left the gate's world with no diagnostic. The
  // fixture plants a REAL directory outside every gated root and links it inside one, so the arm can
  // only go green if the walk follows the link.
  const linkTargetDir = path.join(ROOT, ".l9-selftest-linktarget");
  const linkPath = path.join(ROOT, "packages/gate/src/__l9_selftest_fixture_link");
  fs.mkdirSync(linkTargetDir, { recursive: true });
  fs.writeFileSync(path.join(linkTargetDir, "__l9_selftest_fixture_linked.ts"), [
    "export interface SelftestLinkedOpaque { execute: () => Promise<{ ok: boolean }>; }",
    "",
  ].join("\n"));
  try { fs.unlinkSync(linkPath); } catch { /* not present */ }
  fs.symlinkSync(linkTargetDir, linkPath, "dir");

  const red = scanPatterns(gatedFiles()).filter((x) => x.file.includes("__l9_selftest_fixture"));
  const redMjs = red.filter((x) => x.file.endsWith(".mjs"));
  const redTsx = red.filter((x) => x.file.endsWith(".tsx"));
  const redLinked = red.filter((x) => x.file.includes("__l9_selftest_fixture_link/"));
  fs.unlinkSync(fixture);
  fs.unlinkSync(mjsFixture);
  fs.unlinkSync(tsxFixture);
  fs.unlinkSync(linkPath);
  fs.rmSync(linkTargetDir, { recursive: true, force: true });
  const green = scanPatterns(gatedFiles()).filter((x) => x.file.includes("__l9_selftest_fixture"));

  console.log(`selftest RED  (fixture present): ${red.length} finding(s) ${red.length >= 3 ? "OK" : "FAIL"}`);
  for (const h of red) console.log(`   ${h.id} ${h.file}:${h.line}`);
  console.log(`selftest GREEN (fixture gone)  : ${green.length} finding(s) ${green.length === 0 ? "OK" : "FAIL"}`);

  // Each layer must be observed to fire INDIVIDUALLY. A total count alone would let one layer's
  // findings mask another layer being dead — which is how a relaxation disables a gate unnoticed.
  const byLayer = (id) => red.filter((x) => x.id === id).length;
  const dPositive = byLayer("L9-D");
  // The negative sample lives at a known offset; assert L9-D did NOT fire on the snapshot function.
  const dOnSnapshot = red.filter((x) => x.id === "L9-D" && x.line >= 12).length;
  console.log(`  .mjs reached by discovery: ${redMjs.length >= 2 ? "OK" : "FAIL"} (${redMjs.length} finding(s) in a .mjs fixture)`);
  console.log(`  .tsx reached by discovery: ${redTsx.length >= 1 ? "OK" : "FAIL"} (${redTsx.length} finding(s) in a .tsx fixture)`);
  console.log(`  symlinked DIR followed:    ${redLinked.length >= 1 ? "OK" : "FAIL"} (${redLinked.length} finding(s) behind a directory symlink)`);
  console.log(`  L9-B fires: ${byLayer("L9-B") >= 1 ? "OK" : "FAIL"}   ` +
    `L9-C fires: ${byLayer("L9-C") >= 1 ? "OK" : "FAIL"}   ` +
    `L9-D fires on a LIVE re-read: ${dPositive >= 1 ? "OK" : "FAIL"}   ` +
    `L9-D silent on a SNAPSHOT re-read: ${dOnSnapshot === 0 ? "OK" : "FAIL"}`);

  const ok = red.length >= 3 && green.length === 0 && redMjs.length >= 2 &&
    redTsx.length >= 1 && redLinked.length >= 1 &&
    byLayer("L9-B") >= 1 && byLayer("L9-C") >= 1 && dPositive >= 1 && dOnSnapshot === 0;
  console.log(ok
    ? "SELFTEST PASS -- this layer is observed to fail, so it is known to be a gate."
    : "SELFTEST FAIL -- a layer never observed to fail is not known to be a gate.");
  process.exit(ok ? 0 : 1);
}

// ── L9-A: no security-critical root may be unclassified ─────────────────────────────────────────
for (const root of discoverRoots()) {
  if (!isCritical(root)) continue;
  if (!(root in INVENTORY)) {
    add("L9-A", root, 0,
      "security-critical source root is NOT in the trusted-root inventory. It contains code that " +
      "parses, verifies, decides policy, approves, projects, grants, signs, executes or builds " +
      "receipts, and no gate layer can see it. Classify it in scripts/lint-trusted-roots.mjs.");
  }
}
for (const root of Object.keys(INVENTORY)) {
  if (!fs.existsSync(path.join(ROOT, root))) {
    add("L9-A", root, 0, "inventory names a source root that does not exist -- stale entry, remove it.");
  }
  // ── R8-29 (2026-07-31): THE REASON THE DOCSTRING DEMANDS WAS NEVER READ ──────────────────────
  // Line 39 of this file states: "`gated: false` requires an auditable reason -- never a silent
  // omission." Measured: `grep -c "\.reason"` over this file returned ZERO. The requirement was
  // asserted in prose and enforced nowhere, which is the exact class this gate exists to catch,
  // committed by the gate itself.
  //
  // MEASURED in an isolated copy, un-gating the component that MINTS GRANTS:
  //     "packages/gate/src": { gated: false, reason: "" }  ->  L9: 0 findings, exit 0
  //     (baseline: 1 finding, exit 1)
  // An empty string removed the decision layer from the gate's world and the report read complete.
  const inv = INVENTORY[root];
  if (inv && inv.gated === false) {
    const why = typeof inv.reason === "string" ? inv.reason.trim() : "";
    if (why === "") {
      add("L9-A", root, 0,
        "inventoried as NOT GATED with no auditable reason. This file's own docstring requires one. " +
        "An un-gated root without a stated reason is indistinguishable from a root somebody quietly " +
        "removed from coverage -- state why it is not security-critical, or gate it.");
    }
  }
}
for (const p of scanPatterns(gatedFiles())) add(p.id, p.file, p.line, p.msg);

// ── report ──────────────────────────────────────────────────────────────────────────────────────
console.log("L9 -- trusted source root inventory + forbidden trust-input patterns\n");
for (const root of discoverRoots()) {
  const inv = INVENTORY[root];
  const crit = isCritical(root);
  const state = !crit ? "not security-critical"
    : inv ? (inv.gated ? "GATED" : "inventoried, not gated")
    : "*** UNCLASSIFIED ***";
  console.log(`  ${root.padEnd(38)} ${state}`);
}
console.log();
const byId = {};
for (const f of findings) (byId[f.id] ||= []).push(f);
for (const [id, list] of Object.entries(byId)) {
  console.log(`${id} -- ${list.length} finding(s)`);
  for (const f of list) console.log(`   ${f.file}:${f.line}  ${f.msg}`);
  console.log();
}
console.log(findings.length === 0 ? "L9: 0 findings." : `L9: ${findings.length} finding(s) -- BLOCKING.`);
process.exit(findings.length === 0 ? 0 : 1);
