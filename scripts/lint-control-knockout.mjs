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
 * load-bearing (delete it) or nothing tests it (write the test).
 *
 * ⚠ CORRECTED 2026-07-31 (R8-26/R8-27). This paragraph used to claim "each knockout is applied to a
 * SCRATCH COPY". That was false: `fs.writeFileSync(path.join(ROOT, k.file))` writes into the
 * canonical worktree, and the "pristine copy" is a string in memory. A crash between write and
 * restore left a weakened control on disk, and round 8 observed `git status` rotating through
 * modified `src/cose/cbor.ts`, `src/intrinsics.ts` and `src/verify.ts` mid-run.
 *
 * The mutation still happens in place — a scratch worktree would need a full rebuild per entry —
 * but it is now BOUNDED and PROVEN: baseline sha256 before, a required byte change to prove the
 * mutation applied, restoration verified against that same sha256, and a dirty-tree check at the
 * end. Restoration that cannot be proven is itself a failing verdict.
 *
 * And the verdict is no longer `green ? SURVIVED : KILLED`. That treated a real detection, a
 * pre-existing failure, a compile error, a crash and a timeout as one value. Six of the entries
 * below target `packages/gate`, whose baseline is `exit 1, 200/2` — so they reported KILLED for any
 * mutation. Proven by making one entry's `replace` byte-identical to its `find`: the source did not
 * change at all and the runner still printed `killed 1/1`. Verdicts now come from the closed
 * taxonomy in `lib/knockout-runner.mjs`, and a kill requires a failure the CLEAN baseline did not
 * already have.
 *
 * Run:  node scripts/lint-control-knockout.mjs [--warn] [--only <id>] [--requires <tag>]
 */
import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import {
  runKnockout, observeSuite, validateKnockoutRegistry, VERDICT, PASSING, partitionByDependency,
} from "./lib/knockout-runner.mjs";
import { DEPENDENCY_PROBES } from "./lib/phone-core-probe.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const WARN_ONLY = process.argv.includes("--warn");
const onlyIdx = process.argv.indexOf("--only");
const ONLY = onlyIdx > -1 ? process.argv[onlyIdx + 1] : null;
// --requires <tag>: run exactly the entries that DECLARE the given dependency tag. The set is
// derived from the registry, never hand-listed — a hand-written id list in a workflow is how a
// coverage promise rots (an eleventh phone-core control would silently miss the armed job).
// Used by the golden-path CI job, which is the one environment where `phone-core` is present.
const requiresIdx = process.argv.indexOf("--requires");
const REQUIRES = requiresIdx > -1 ? process.argv[requiresIdx + 1] : null;
const PROOF_INVENTORY = JSON.parse(
  fs.readFileSync(path.join(ROOT, "scripts", "resolver-inventory.json"), "utf8"),
).proofs ?? {};

/** Machine-readable proof bindings carried inside an entry's already-required control string. */
function proofIdsFor(entry) {
  const ids = [];
  for (const match of entry.control.matchAll(/\[proof:\s*([^\]]+)\]/g)) {
    ids.push(...match[1].split(",").map((v) => v.trim()).filter(Boolean));
  }
  return [...new Set(ids)];
}

/**
 * A knockout tagged for a proof is successful only when THAT proof's registered marker is among
 * the new red tests. A different sibling failure is not meaningfulness evidence for this proof.
 */
function requireNamedProofFailures(entry, result) {
  const ids = proofIdsFor(entry);
  if (ids.length === 0) return result;
  const missing = ids.filter((id) => {
    const marker = PROOF_INVENTORY[id]?.marker;
    return typeof marker !== "string" || !result.newFailures?.some((name) => name.includes(marker));
  });
  if (missing.length === 0) {
    result.detail = `${result.detail}; named proof(s) went RED: ${ids.join(", ")}`;
    return result;
  }
  if (result.verdict === VERDICT.DETECTOR_TRIGGERED) {
    result.verdict = VERDICT.ANTI_VACUITY_FAILED;
  }
  result.detail = `${result.detail} Named proof(s) did not go RED: ${missing.join(", ")}. ` +
    `A different new failure cannot certify that these proof bodies measure the mutated control.`;
  return result;
}

/**
 * Each entry names ONE defensive mechanism, the exact source edit that removes it, and the suite
 * that must go red. `find` must match EXACTLY ONCE — an ambiguous knockout is not a knockout, and
 * a `find` that stops matching means the control moved and this entry has rotted (which is itself
 * reported, so the registry cannot silently stop describing the code).
 */
const KNOCKOUTS = [
  // ── R8-32 (2026-07-31): THE GATES ADR-0005 §7 PROMISED AND NEVER SHIPPED ───────────────────────
  // The ADR's table names four knockouts by id — G3 `parse-boundary-strictness`,
  // G4 `render-node-single-input`, G5 `display-aad-egress-check`, G6 `riskclass-derived-not-accepted`
  // — each with "must go red" as its anti-vacuity clause. None existed. G3 and G6 are registered;
  // the G4 registry claim and G5 claim are withdrawn below rather than represented by false-green
  // entries. The canonical ADR/release-status correction is outside this batch's authorized files.
  //
  // G5 WAS FORMALLY WITHDRAWN AND IS NOW REGISTERED (2026-08-03). The withdrawal note read: "Its
  // instruction is 'delete the egress AAD verification', and that verification does not exist… A
  // knockout deletes a control; there is nothing here to delete, so writing a G5 entry would have
  // manufactured the appearance of coverage over a control that was never built."
  //
  // That refusal is why this gap was findable at all — the registry declined to fake coverage, and the
  // hole stayed visible instead of reading as closed. The control now exists
  // (`verifySealedDisplayEgress`, engine.ts), so the condition the withdrawal named is discharged and
  // the entry is registered in the SAME commit that built it. Never the other way round.
  {
    id: "p1-9-key-encoding-index-assembly",
    control:
      "P1-9 — the PKCS8 key encoder assembles by INDEX, never `.set()`. `der.set(seed, 16)` handed the " +
      "RAW 32-BYTE ED25519 PRIVATE SEED to `Uint8Array.prototype.set`, a writable global. Unlike the " +
      "#77-A defect this repeats, a replacement here need not corrupt anything: it can copy the seed, " +
      "call through, and leave the DER byte-identical with every test green. That is EXFILTRATION, and " +
      "an output comparison is structurally blind to it — which is why the test asserts a HIT-COUNT of " +
      "zero on a counting, non-destructive poison rather than comparing bytes.",
    file: "packages/signer-core/src/der.ts",
    find: "  const p = PKCS8_ED25519_PREFIX.length;\n  for (let i = 0; i < p; i++) der[i] = PKCS8_ED25519_PREFIX[i] as number;\n  const s = seed.length;\n  for (let i = 0; i < s; i++) der[p + i] = seed[i] as number;",
    replace: "  der.set(PKCS8_ED25519_PREFIX, 0);\n  der.set(seed, PKCS8_ED25519_PREFIX.length);",
    kind: "tests",
    suite: ["packages/signer-core", "npm", ["test"]],
  },
  {
    id: "g5-display-aad-egress-check",
    control:
      "ADR-0005 §5/§7 G5 (M5 cross-hold display replay) — the gate VERIFIES the sealed display it is " +
      "about to sign: the returned envelope's tenant/holdId/deferredReceiptHash/expiresAt must equal " +
      "what the gate asked for, its aadHash must equal the gate's OWN derivation over those values, " +
      "and every requested recipient — including the always-present AUDIT key — must have survived. " +
      "The sealer is INJECTED, so without this the gate signed whatever a component it does not " +
      "control handed back, and a blob describing a DIFFERENT hold produced a gate-signed envelope " +
      "binding the human's approval to a display they never saw, with every downstream check green.",
    file: "packages/gate/src/engine.ts",
    // Deleting the refusal is the honest mutation: the check still runs, its verdict is discarded.
    // Deleting the CALL instead would leave `egress` unused and fail to compile — a build error scores
    // as MUTATION_DID_NOT_BUILD and tests nothing, which is the trap G3's comment above records.
    find: "      if (egress !== null) {\n        return err(422, \"DISPLAY_EGRESS_AAD_MISMATCH\", { detail: egress });\n      }",
    replace: "      void egress;",
    kind: "tests",
    suite: ["packages/gate", "npm", ["test"]],
  },
  {
    id: "g3-parse-boundary-strictness",
    control: "ADR-0005 §7 G3 — stage 0: every request body enters through parseDocument. PROVEN SCOPE (2026-07-31): replacing it with a LENIENT parser breaks the three bytes-in refusals, so the boundary is load-bearing. NOT yet isolated: whether non-strict JSON specifically is refused — that half needs a mutant that reproduces decodeDocument's exact reason string, and until one exists this entry does not claim it.",
    file: "packages/gate/src/engine.ts",
    find: 'const parsed = parseDocument(body, "request body");',
    // ── FIXED 2026-07-31 (R815-QA-16 found the cause) ──────────────────────────────────────────
    // The old replacement was:
    //     const parsed = { ok: true as const, value: body as unknown };
    // `ok: true as const` narrows `!parsed.ok` to `never`, so the very next line's `parsed.reason`
    // stops type-checking. It NEVER COMPILED, so this entry never tested anything — and the runner
    // scored the build failure as ANTI_VACUITY_FAILED, then (once the taxonomy could say so) as
    // MUTATION_DID_NOT_BUILD. The union annotation keeps both branches reachable, so the mutant
    // compiles and the bypass is BEHAVIOURAL rather than a type error. This is the same
    // narrowing-loss trap that cost three earlier attempts on this branch.
    replace: 'const parsed: { ok: true; value: unknown } | { ok: false; reason: string } = (() => {\n      try {\n        const raw = typeof body === "string" ? body : new TextDecoder().decode(body as Uint8Array);\n        return { ok: true as const, value: JSON.parse(raw) as unknown };\n      } catch {\n        return { ok: false as const, reason: "request body: lenient parse failed" };\n      }\n    })();',
    kind: "tests",
    suite: ["packages/gate", "npm", ["test"]],
  },
  // G4 BATCH-I CORRECTION (2026-08-01): the exact historical mutant IS distinguishable.
  // The exact historical mutation was recovered from commit 4ff3a76:
  //
  //   commandView(canonical)
  //     -> commandView(canonicalize(snapshot as Record<string, unknown>))
  //
  // WITHDRAWN CLAIM (verbatim): "No reachable caller can distinguish the security-relevant return value; the mutant only repeats work."
  // `canonicalize` reads live `Object.keys`. A stateful post-load replacement can return the complete
  // snapshot keys for the first canonicalization and omit `targetEnv` on the next matching call. The
  // shipped path renders the first canonical string and remains accepted; the exact mutant performs
  // the second canonicalization and loses a required field. The public `getProjection().run()` surface
  // reaches this distinction without a caller-owned object surviving the capture-once boundary.
  //
  // NUMBERS, re-measured in Batch F without the two owner-deferred ADR-0006 failures: the source has
  // 2 first-party `.run()` call sites (engine + wrapper) and 1 public direct-call surface. The scoped
  // public-surface Slice-2 run was clean 6/6 GREEN and mutated 6/6 GREEN, including the honest-path
  // anti-vacuity test. A separate clean-vs-mutant differential corpus was 10/10 return-value
  // identical (6 accepted, 4 rejected: honest, destructive and adversarial capture shapes).
  // WITHDRAWN CLAIM (verbatim): "`DETECTOR_DID_NOT_TRIGGER` is therefore the correct result for an observationally equivalent mutant, not evidence that canonical bytes are unimportant."
  // The previous 6/6 and 10/10 corpora did not include a stateful mutable-intrinsic probe. The
  // registered knockout below now applies the exact mutant and runs a test that does.
  //
  // WITHDRAWN CLAIM (verbatim): "ADR-0005 §7 G4 — the render node reads the CANONICAL BYTES, so the display and the paramsHash cannot disagree (M7)"
  //
  // The older claim above remains preserved as history; this entry measures the current correction.
  {
    id: "adr0007-device-token-kid-binding",
    control:
      "ADR-0007 constraint 4 — a device-pairing token names the ONLY key permitted to redeem it. " +
      "The gate sees the phone public key in the CONFIRMATION before it authors ACCEPTED, so the " +
      "token can be issued kid-bound; a leaked paste bundle is then worthless without that phone " +
      "private key. This is the property a shared operator secret cannot have at any price, and it " +
      "is why option A (teach the app one static secret) was rejected: a fleet-wide bearer " +
      "credential is not per-device, not attributable, and unrevocable without rotating every device.",
    file: "packages/relay/src/engine.ts",
    find: "    if (rec.kid !== kid) {",
    replace: "    if (rec.kid !== rec.kid) {",
    kind: "tests",
    suite: ["packages/relay", "npm", ["test"]],
  },
  {
    id: "adr0007-device-token-single-use",
    control:
      "ADR-0007 constraint 8 — a device token is SINGLE-USE, and single-use is the honest word: no " +
      "revoke API exists for these tokens, so one use plus a short TTL is the entire mechanism. " +
      "Accepting a second redemption would turn a replayable paste artifact into a standing " +
      "credential. Recovery for a phone that LOST its response is a SEPARATE path — a fresh token " +
      "re-mints onto the existing device — and its own control pins that this refusal does not " +
      "brick the kid, because revokeSelf needs the very secret that was lost.",
    file: "packages/relay/src/engine.ts",
    find: "    if (rec.usedAt !== null) {",
    replace: "    if (rec.usedAt !== rec.usedAt) {",
    kind: "tests",
    suite: ["packages/relay", "npm", ["test"]],
  },
  {
    id: "adr0007-device-token-hashed-at-rest",
    control:
      "ADR-0007 constraint 6 — the device token is HASHED at rest; the plaintext is returned once " +
      "at issuance and never stored. PairingRecord stores its token raw, unlike apiKeyHash and " +
      "deviceSecretHash — a pre-existing inconsistency the device namespace does not inherit. " +
      "NOTE THE MUTATION SHAPE: it changes BOTH the write and the lookup. Changing only the write " +
      "was tried first and broke FIVE tests on lookup consistency instead of one on secrecy — it " +
      "measured the wrong property, and a knockout that kills for the wrong reason certifies nothing.",
    file: "packages/relay/src/engine.ts",
    find: "      tokenHash: hashSecret(token), tenant, kid, usedAt: null, expiresAt, createdAt: this.now(),",
    replace: "      tokenHash: token, tenant, kid, usedAt: null, expiresAt, createdAt: this.now(),",
    also: [
      {
        find: "    const rec = this.store.getDevicePairingByHash(hashSecret(token));",
        replace: "    const rec = this.store.getDevicePairingByHash(token);",
      },
    ],
    kind: "tests",
    suite: ["packages/relay", "npm", ["test"]],
  },
  {
    id: "adr0007-untenanted-enrolment-dev-only",
    control:
      "ADR-0007 — a VALID enrolment secret must NOT open the untenanted device route. Constraint 3 " +
      "gave DeviceRecord a tenant and made claimDevice match on it, but that match only fires when " +
      "device.tenant !== null (engine.ts:254) and anonymous POST /v1/devices records tenant: null " +
      "(engine.ts:212). So a correctly-authenticated PRODUCTION operator could still mint devices " +
      "claimable by any tenant — the first-claimer-wins race constraint 3 closed, reopened through " +
      "the side door by the same change that closed it. The route survives, confined to the loopback " +
      "development opt-in where the demo, e2e and simulator flows live; production gets exactly one " +
      "device-minting path, the one that stamps a tenant.",
    file: "packages/relay/src/config.ts",
    find: "  if (opts.untenanted === true) {",
    replace: "  if (false) {",
    kind: "tests",
    suite: ["packages/relay", "npm", ["test"]],
  },
  {
    id: "adr0007-device-tenant-claim",
    control:
      "ADR-0007 constraint 3 — a device that DECLARES a tenant is claimable only by that tenant. " +
      "claimDevice refuses an unknown device and someone else's device identically, and that part " +
      "was always right; the gap was the UNCLAIMED device, whose agentId === null satisfies the " +
      "ownership check for EVERY authenticated agent. The window between a device enrolling and its " +
      "own operator claiming it is a window in which a different customer on the same relay takes " +
      "it, and from then on sees and decides everything that device is shown — the same consequence " +
      "DeviceRecord.agentId records for an unscoped device, reached through a different door. No " +
      "forgery and no stolen credential: just an unowned object and two parties entitled to ask.",
    file: "packages/relay/src/engine.ts",
    find: "    if (device.tenant !== null && device.tenant !== agent.tenant) {",
    // The mutation KEEPS the `device.tenant !== null` narrowing TypeScript relies on further down.
    // A plain `if (false)` looked like the obvious knockout and came back MUTATION_DID_NOT_BUILD:
    // dropping the narrowing makes `device` possibly-undefined at :257, so the experiment measured
    // the compiler rather than the control. `x !== x` is always false and narrows identically.
    replace: "    if (device.tenant !== null && device.tenant !== device.tenant) {",
    kind: "tests",
    suite: ["packages/relay", "npm", ["test"]],
  },
  {
    id: "stage4-digest-display-disagreement",
    control:
      "ADR-0006 §5 stage 4 — the DIGEST and the DISPLAY must commit to the same bytes. NOA's " +
      "catastrophic failure is a genuine human genuinely approving a DIFFERENT action from the one " +
      "that executes, and that becomes possible the moment a displayed field is derived from a " +
      "caller-controlled value instead of from the canonical bytes. Measured before this control " +
      "existed: bypassing the render node turned ZERO tests red (projections.ts:196-215 records it, " +
      "and this file's oracle re-measured it). SCOPE, stated rather than implied: this mutation is " +
      "the A+B state — the display reads the CALLER's argv. Mutation B alone (the display reads our " +
      "own pre-canonical snapshot) still turns nothing red, because while capture-once holds that " +
      "array is ours and yields the identical string. The oracle closes the CONSEQUENCE a human is " +
      "harmed by, not the render node's redundancy.",
    file: "packages/gate/src/projections.ts",
    find: "      Args: view.argsJoined,",
    replace: '      Args: (argv as unknown as string[]).join(" "),',
    kind: "tests",
    suite: ["packages/gate", "npm", ["test"]],
  },
  {
    id: "g4-render-node-single-input",
    requires: ["phone-core"],
    control: "ADR-0005 §7 G4 — the render node consumes the first canonical byte string. Re-canonicalizing the local snapshot lets a stateful post-load Object.keys replacement supply a different second key set, so the display/risk input can differ from the bytes hashed into paramsHash.",
    file: "packages/gate/src/projections.ts",
    find: "    const view = commandView(canonical);",
    replace: "    const view = commandView(canonicalize(snapshot as Record<string, unknown>));",
    kind: "tests",
    suite: ["packages/e2e-demo", "node", ["--import", "tsx", "--test", "test/keyring-resolver-parity.test.ts"]],
  },
  {
    id: "g6-riskclass-derived-not-accepted",
    control: "ADR-0005 §7 G6 — riskClass is DERIVED inside the boundary; the caller's hint may raise the floor and can never lower it (M2)",
    file: "packages/gate/src/engine.ts",
    find: "effectiveRisk = maxRisk(run.derivedRisk, riskClass);",
    replace: 'effectiveRisk = riskClass ?? run.derivedRisk;',
    kind: "tests",
    suite: ["packages/gate", "npm", ["test"]],
  },
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
    kind: "tests",
    suite: ["packages/relay", "npm", ["test"]],
  },
  {
    id: "adr5-relay-inert-receipt-snapshot",
    control: "R-ING-01 — one accessor-free snapshot, so a two-faced verdict cannot sign a DENIAL and record an approval",
    file: "packages/relay/src/engine.ts",
    find: "    const inertReceipt = inertSnapshot(rawReceipt);",
    replace: "    const inertReceipt: unknown = rawReceipt;",
    kind: "tests",
    suite: ["packages/relay", "npm", ["test"]],
  },
  {
    id: "adr5-relay-exposure-from-real-socket",
    control: "R-1 shape (A) — exposure is classified from the OS-bound address, not from config.bindAddress",
    file: "packages/relay/src/server.ts",
    find: "    handle(req, res, engine, effectiveConfig(), limiter).catch(() => {",
    replace: "    handle(req, res, engine, config, limiter).catch(() => {",
    kind: "tests",
    suite: ["packages/relay", "npm", ["test"]],
  },
  {
    id: "adr5-relay-declared-exposure",
    control: "R-1 shape (B) — tlsTerminated or unsafeListen means EXPOSED, whatever the bind address says",
    file: "packages/relay/src/config.ts",
    find: "    const declaredExposed = config.tlsTerminated || config.unsafeListen;",
    replace: "    const declaredExposed = false;",
    kind: "tests",
    suite: ["packages/relay", "npm", ["test"]],
  },
  {
    id: "adr5-signer-producer-inert-copy",
    control: "C-01 sibling (producer) — what is signed is what is returned; no writable global between them",
    file: "packages/signer-core/src/sign.ts",
    find: "  const signed = inertDeepCopy(core);",
    replace: "  const signed = structuredClone(core);",
    kind: "tests",
    suite: ["packages/signer-core", "npm", ["test"]],
  },
  {
    id: "adr5-gate-b1-fail-closed-floor",
    control: "B-1 — an unmatched action classifies to the highest tier and fails closed, whatever tier the caller names",
    file: "packages/gate/src/engine.ts",
    find: '    if (mode === "RAW") {',
    replace: '    if (mode === "RAW" && (riskClass === "CRITICAL" || riskClass === "IRREVERSIBLE")) {',
    kind: "tests",
    suite: ["packages/gate", "npm", ["test"]],
  },
  {
    id: "c04-gate-observation",
    control: "C-04 — report() signs no determinate negative in ANY state (the UNUSED 409 and the attributed-claim 202)",
    file: "packages/gate/src/engine.ts",
    find: 'if (result === "FAILED_BEFORE_DISPATCH") {',
    replace: 'if (false as boolean) {',
    kind: "tests",
    suite: ["packages/gate", "npm", ["test"]],
  },
  {
    id: "h02c-read-before-transition",
    control: "H-02c — the tool's self-report is read BEFORE any reducer transition",
    file: "packages/gate/src/wrapper.ts",
    find: "    const ok = r.ok;\n    const detail = r.detail;\n    if (ok) {",
    replace: "    const ok = r.ok;\n    if (ok) {",
    also: [{ find: "    execDetail = detail;\n  } catch (e) {", replace: "    execDetail = r.detail;\n  } catch (e) {" }],
    kind: "tests",
    suite: ["packages/gate", "npm", ["test"]],
  },
  {
    id: "h02a-reducer-routed-outcome",
    control: "H-02a — the framework adapter's terminal outcome comes from the reducer, not from `threw`",
    file: "packages/framework-adapters/src/wrap-tool.mjs",
    find: "      if (recordedState === null) {",
    replace: "      if (false) {",
    kind: "tests",
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
    kind: "tests",
    suite: ["packages/mcp-proxy", "npm", ["test"]],
  },
  {
    id: "reducer-no-retry-safe-exit",
    control: "the reducer has NO exit from DISPATCHED to a retry-safe state without a RECONCILED_* event",
    file: "packages/adapter-core/src/side-effect-state.mjs",
    find: '    TOOL_REPORTED_NO_DISPATCH: "SIDE_EFFECT_UNCONFIRMED",',
    replace: '    TOOL_REPORTED_NO_DISPATCH: "FAILED_NO_SIDE_EFFECT",',
    kind: "tests",
    suite: ["packages/adapter-core", "npm", ["test"]],
  },
  {
    id: "reducer-immutability",
    control: "the side-effect state table is deep-frozen so safeToRetry cannot be flipped at runtime",
    file: "packages/adapter-core/src/side-effect-state.mjs",
    find: "export const SIDE_EFFECT_STATES = deepFreeze({",
    replace: "export const SIDE_EFFECT_STATES = ({",
    kind: "tests",
    suite: ["packages/adapter-core", "npm", ["test"]],
  },
  {
    id: "grant-single-use-cas",
    control: "F8a — the atomic CAS UNUSED→RESERVED makes a grant single-use",
    file: "packages/gate/src/engine.ts",
    find: 'if (rec.status !== "UNUSED") return err(409, "GRANT_ALREADY_RESERVED", { status: rec.status });',
    replace: 'if (false as boolean) return err(409, "GRANT_ALREADY_RESERVED", { status: rec.status });',
    kind: "tests",
    suite: ["packages/gate", "npm", ["test"]],
  },
  {
    id: "grant-ownership-before-cas",
    control: "F29-authz — hold ownership is checked BEFORE any state transition or signature",
    file: "packages/gate/src/engine.ts",
    find: 'if (!this.ownsHold(this.store.getHold(rec.holdId), agent, "report")) return err(404, "UNKNOWN_GRANT");',
    replace: 'if (false as boolean) return err(404, "UNKNOWN_GRANT");',
    kind: "tests",
    suite: ["packages/gate", "npm", ["test"]],
  },
  {
    id: "uncertainty-requires-corroboration",
    control: "F8c — an Execution Uncertainty is signed only after the gate's own sweep window elapsed",
    file: "packages/gate/src/engine.ts",
    find: "if (this.now() - rec.reservedAt < this.cfg.uncertaintySweepWindowMs) return false;",
    replace: "if (false as boolean) return false;",
    kind: "tests",
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
    kind: "tests",
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
    kind: "tests",
    suite: [".", "npm", ["test"]],
  },
  {
    id: "t18-bigint-capture",
    control: "T18 — the y<q canonicality gate builds its comparand with the CAPTURED BigInt, not the bare global",
    file: "src/keys.ts",
    find: "toBigInt(yBytes[i]!)",
    replace: "BigInt(yBytes[i]!)",
    kind: "tests",
    suite: [".", "npm", ["test"]],
  },
  {
    id: "t18-curve-pin-accessor",
    control: "T18b — the Ed25519 curve pin reads asymmetricKeyType through the CAPTURED accessor",
    file: "src/keys.ts",
    find: "    if (asymmetricKeyType(key) !== \"ed25519\") return false;",
    replace: "    if ((key as { asymmetricKeyType?: string }).asymmetricKeyType !== \"ed25519\") return false;",
    kind: "tests",
    suite: [".", "npm", ["test"]],
  },
  {
    id: "t19-parser-inert-arrays",
    control: "T19 — safeParse re-roots every array it emits onto INERT_ARRAY_PROTOTYPE (the ROOT of the iterator/HOF class)",
    file: "src/safe-json.ts",
    find: "        return inertArray(arr);",
    replace: "        return arr;",
    kind: "tests",
    suite: [".", "npm", ["test"]],
  },
  {
    id: "t19-validator-index-walk",
    // WITHDRAWN CLAIM (verbatim): "T19 — the policy validator walks `rules` by INDEX, so a no-op forEach cannot skip every rule"
    // That wording implied an independently load-bearing control. Measured at HEAD 3af47d0: the
    // index-walk mutation alone stayed GREEN. The parser mutation alone caused 3 new failures; the
    // pair caused 4, adding the forEach policy regression. The pair therefore proves the index walk
    // as defence-in-depth behind an independently load-bearing inert-array parser.
    control: "T19 PAIR — safeParse inert-array re-rooting is independently load-bearing (3 new failures alone); with it removed, the validator index walk supplies defence-in-depth (paired removal: 4 new failures, including the forEach policy regression). The index walk alone stayed GREEN at HEAD 3af47d0.",
    file: "src/policy/validate.ts",
    find: "    for (let i = 0; i < pol.rules.length; i++) {\n      const r = pol.rules[i];",
    replace: "    (pol.rules as unknown[]).forEach((r, i) => {",
    also: [{
      find: "      validateCondition(rule.when, `policy.rules[${i}].when`, errors, 0);\n    }",
      replace: "      validateCondition(rule.when, `policy.rules[${i}].when`, errors, 0);\n    });",
    }, { find: "        continue;\n      }\n      const rule = r as Record<string, unknown>;", replace: "        return;\n      }\n      const rule = r as Record<string, unknown>;" }],
    // WITHDRAWN CLAIM (verbatim):
    // The parser's re-rooting independently defeats this poison, so knocking out ONE layer leaves the
    // other measuring it and the run would report a false "nothing measures this". Both come out
    // together — which is also the honest statement of the design: two layers, each load-bearing.
    // Correction: only the parser is independently load-bearing; the extra paired failure is the
    // measured basis for calling the index walk defence-in-depth.
    andAlso: "t19-parser-inert-arrays",
    kind: "tests",
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
    kind: "tests",
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
    kind: "tests",
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
    kind: "gate",
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
    kind: "tests",
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
    kind: "tests",
    suite: [".", "npm", ["test"]],
  },
  {
    id: "r4-a2-noextrakeys-index-walk",
    // WITHDRAWN CLAIM (verbatim): "A2 — the policy closed-grammar check walks keys by INDEX, so a skipping iterator cannot hide an unknown key (DENY/policy-invalid -> ALLOW/allow-x, measured)"
    control: "A2 PAIR — inert array-manufacturing wrappers are independently load-bearing (1 new failure alone); with them removed, the policy closed-grammar index walk supplies defence-in-depth (paired removal: 4 new failures, including the hidden-key regression). The index walk alone stayed GREEN at HEAD 3af47d0.",
    file: "src/policy/validate.ts",
    find: "  const keys = objectKeys(obj);\n  for (let i = 0; i < keys.length; i++) {\n    const k = keys[i] as string;",
    replace: "  for (const k of objectKeys(obj)) {",
    // WITHDRAWN CLAIM (verbatim):
    // A1 independently defeats this poison, so knocking out ONE layer leaves the other measuring it
    // and the run would report a false "nothing measures this". Both come out together — which is
    // also the honest statement of the design: two layers, each load-bearing.
    // Correction: only A1 is independently load-bearing; the three additional paired failures are
    // the measured basis for calling this index walk defence-in-depth.
    andAlso: "r4-a1-inert-wrappers",
    kind: "tests",
    suite: [".", "npm", ["test"]],
  },
  {
    id: "r4-a2-checkpoint-index-walk",
    // WITHDRAWN CLAIM (verbatim): "A2 — the checkpoint closed-schema walk is an INDEX walk, so a skipping iterator cannot hide a smuggled (and honestly re-signed) field (TAMPERED -> VALID/tailChecked, measured)"
    control: "A2 PAIR — inert array-manufacturing wrappers are independently load-bearing (1 new failure alone); with them removed, the checkpoint closed-schema index walk supplies defence-in-depth (paired removal: 3 new failures, including chain and standalone checkpoint regressions). The index walk alone stayed GREEN at HEAD 3af47d0.",
    file: "src/verify.ts",
    find: "  const cKeys = objectKeys(c);\n  for (let i = 0; i < cKeys.length; i++) {\n    if (!arrayIncludes(CHECKPOINT_KEYS, cKeys[i] as string)) return \"malformed checkpoint\";\n  }",
    replace: "  for (const k of objectKeys(c)) {\n    if (!arrayIncludes(CHECKPOINT_KEYS, k)) return \"malformed checkpoint\";\n  }",
    andAlso: "r4-a1-inert-wrappers",
    kind: "tests",
    suite: [".", "npm", ["test"]],
  },
  {
    id: "r4-a2-manifest-index-walk",
    // WITHDRAWN CLAIM (verbatim): "A2 — the identity-manifest walk is an INDEX walk, so a skipping iterator cannot hide a malformed entry from validation (MALFORMED -> VALID, measured)"
    control: "A2 PAIR — inert array-manufacturing wrappers are independently load-bearing (1 new failure alone); with them removed, the identity-manifest index walk supplies defence-in-depth (paired removal: 3 new failures, including verifyChain and substituted-key regressions). The index walk alone stayed GREEN at HEAD 3af47d0.",
    file: "src/verify.ts",
    find: "      const aids = objectGetOwnPropertyNames(live);\n      for (let ai = 0; ai < aids.length; ai++) {\n        const aid = aids[ai] as string;",
    replace: "      for (const aid of objectGetOwnPropertyNames(live)) {",
    andAlso: "r4-a1-inert-wrappers",
    kind: "tests",
    suite: [".", "npm", ["test"]],
  },
  {
    id: "r4-t06-newset-captured-add",
    control: "R4-T06 — newSet(init) fills through the CAPTURED Set.prototype.add; `new Set(iterable)` reads `this.add` off the instance and calls it per element, so a no-op add silently empties the committed read-set",
    file: "src/intrinsics.ts",
    find: "  const s = new _Set() as Set<T>;\n  if (init !== undefined) {\n    for (let i = 0; i < (init as { length: number }).length; i++) _apply(_setAdd, s as never, [init[i]] as never);\n  }\n  return s;",
    replace: "  return new _Set(init as never) as Set<T>;",
    kind: "tests",
    suite: [".", "npm", ["test"]],
  },
  {
    id: "r4-t07-audit-captured-weakset",
    control: "R4-T07 — the policy-table audit's cycle guard uses the CAPTURED WeakSet.prototype.has; a live `has -> true` made inertViolations return [] , i.e. the control that hunts mutable policy tables reported CLEAN exactly when an attacker was present",
    file: "src/inert.ts",
    find: "    if (weakSetHas(seen, value as object)) return;\n    weakSetAdd(seen, value as object);",
    replace: "    if (seen.has(value as object)) return;\n    seen.add(value as object);",
    kind: "tests",
    suite: [".", "npm", ["test"]],
  },
  {
    id: "r4-a1c-publication-boundary",
    control: "A1c — a CALLER-OWNED public result (readSet, warnings, inertViolations) is published as an ORDINARY array; shipping the inert internal breaks `instanceof Array` and `deepStrictEqual` for every consumer",
    file: "src/intrinsics.ts",
    find: "export function publishArray<T>(a: readonly T[]): T[] {\n  const out: T[] = [];\n  for (let i = 0; i < (a as { length: number }).length; i++) _apply(_push, out as never, [a[i]]);\n  return out;\n}",
    replace: "export function publishArray<T>(a: readonly T[]): T[] {\n  return a as T[];\n}",
    kind: "tests",
    suite: [".", "npm", ["test"]],
  },
  {
    id: "r4-a5-ast-load-time-exemption",
    control: "A5 — the AST gate's load-time exemption is STRUCTURAL (a parameter default is call-time, an IIFE at module level is load-time); widening it to 'everything is load-time' must not be able to silence the gate",
    file: "scripts/lib/dispatch-ast.mjs",
    find: "function isLoadTime(node) {\n  let n = node;",
    replace: "function isLoadTime(node) {\n  if (node) return true;\n  let n = node;",
    kind: "gate",
    suite: [".", "npm", ["run", "lint:security-gates"]],
  },
  {
    id: "r4-a5-ast-symbol-resolution",
    control: "A5 — the AST gate resolves the leftmost identifier's SYMBOL to decide 'ambient global or ours'; degrading that to 'never a global' is the one-line way to make the gate read 0 forever",
    file: "scripts/lib/dispatch-ast.mjs",
    find: "  if (!BUILTIN_GLOBALS.has(id.text) && !BARE_GLOBAL_CALLS.has(id.text)) return false;",
    replace: "  if (id) return false;\n  if (!BUILTIN_GLOBALS.has(id.text) && !BARE_GLOBAL_CALLS.has(id.text)) return false;",
    kind: "gate",
    suite: [".", "npm", ["run", "lint:security-gates"]],
  },
  {
    id: "r8-15-deep-copy-defineproperty",
    control: "R8-15 \u2014 inertDeepCopy builds its output with defineProperty, NEVER assignment. `out[key] = v` on a plain object consults the prototype chain for a setter, and `Object.prototype.__proto__` is one \u2014 so an own `__proto__` (which JSON.parse produces from ordinary untrusted input) was consumed by the setter instead of copied. The signature covered bytes the returned receipt did not contain, and an injected approval read back as a phantom that is in no wire byte.",
    file: "packages/signer-core/src/deep-copy.ts",
    find: "    objectDefineProperty(out, key, {\n      value: copyValue(d.value, `${path}.${key}`, depth + 1),\n      writable: true,\n      enumerable: true,\n      configurable: true,\n    });",
    replace: "    out[key] = copyValue(d.value, `${path}.${key}`, depth + 1);",
    kind: "tests",
    suite: ["packages/signer-core", "npm", ["test"]],
  },
  {
    id: "r8-15b-deep-copy-array-defineproperty",
    control: "R8-15b \u2014 the ARRAY branch of inertDeepCopy also builds with defineProperty. `out` is a fresh array rooted on the LIVE Array.prototype \u2014 the one prototype this file cannot capture \u2014 so an index accessor defined there OWNED the element write. Measured: a copy of [\"HONEST-FIRST-ELEMENT\",\"second\"] serialised as [\"ATTACKER\",\"second\"]. The source-element accessor guard does not reach it; that guard inspects the SOURCE, the hostile accessor is on the DESTINATION's prototype.",
    file: "packages/signer-core/src/deep-copy.ts",
    find: "      objectDefineProperty(out, i, {\n        value: copyValue(d.value, `${path}[${i}]`, depth + 1),\n        writable: true,\n        enumerable: true,\n        configurable: true,\n      });",
    replace: "      out[i] = copyValue(d.value, `${path}[${i}]`, depth + 1);",
    kind: "tests",
    suite: ["packages/signer-core", "npm", ["test"]],
  },
  {
    id: "p01-root-validfrom-carried",
    control: "P0-1 \u2014 asRootKeyEntryMap carries `validFrom` on ROOT entries. It carried revokedAt but DROPPED validFrom, and verify.ts:234 enforces activation only when the field is non-null \u2014 so a trust-root signature dated BEFORE its own declared activation verified clean. The manifest sibling (trust.ts:156) was fixed for exactly this class and says so; the ROOT resolver 80 lines above was not. [proof: RES-PAR-EVID-ROOT, RES-PAR-ROOT-ENFORCED-E2E]",
    file: "packages/evidence/src/trust.ts",
    find: "validFrom: e.validFrom ?? null, revokedAt: e.revokedAt ?? null };",
    replace: "revokedAt: e.revokedAt ?? null };",
    kind: "tests",
    suite: ["packages/evidence", "npm", ["test"]],
  },
  {
    id: "p05-gate-keyring-validfrom-carried",
    control: "P0-5 — createAlphaTrust carries the generated GATE activation into the live keyring; deleting it makes the registered resolver proof itself fail. [proof: RES-PAR-GATE-KEYRING]",
    file: "packages/gate/src/trust.ts",
    // RE-AIMED 2026-08-12 (S0 authority-root split). The literal role array on this line became
    // `gateRoles` when the execution-signer role moved out of the gate process, so `find` matched
    // 0x and the runner correctly reported MUTATION_NOT_APPLIED — the control was UNMEASURED, not
    // passing. Same control, same mutation (delete the carried activation), re-aimed at the line as
    // it is now written.
    find: '    [gate.kid]: { publicKey: gate.publicKey, type: "GATE", roles: gateRoles, validFrom, revokedAt: null },',
    replace: '    [gate.kid]: { publicKey: gate.publicKey, type: "GATE", roles: gateRoles, revokedAt: null },',
    kind: "tests",
    suite: ["packages/gate", "npm", ["test"]],
  },
  {
    id: "s0-grant-authority-out-of-gate-process",
    control:
      "S0 — the gate process holds NO key the KEY MANIFEST lets sign an Execution Grant. Give the gate " +
      "key back its `execution-signer` role and a compromised gate can mint grants with its own key again, " +
      "which is the defect NON-CLAIMS.md's authority-root corollary recorded.",
    file: "packages/gate/src/trust.ts",
    find: '  const gateRoles: string[] = external ? ["hold-signer"] : ["hold-signer", "execution-signer"];',
    replace: '  const gateRoles: string[] = ["hold-signer", "execution-signer"];',
    kind: "tests",
    suite: ["packages/gate", "npm", ["test"]],
  },
  {
    id: "s0-cross-keyring-kid-agreement",
    control:
      "S0 (adversarial review 2026-08-12, CRITICAL) — the grant signer refuses a trust file in which one kid " +
      "denotes DIFFERENT public keys in the artifact keyring and the receipt keyring. Without it a genuine phone " +
      "Decision and a gate-forged ALLOWED receipt carrying attacker parameters both verify under one kid string, " +
      "and the sidecar signs a grant the shipped verifier then accepts.",
    file: "packages/gate/src/grant-sidecar.ts",
    find: '    if (receiptPub !== entry["publicKey"]) {',
    replace: "    if (false) {",
    kind: "tests",
    suite: ["packages/gate", "npm", ["test"]],
  },
  {
    id: "s0-approver-key-not-co-resident",
    control:
      "S0 (adversarial review 2026-08-12, CRITICAL) — an EXTERNAL execution signer may not be combined with a " +
      "gate-generated approver key. The sidecar authorizes on the one signature an attacker inside the gate cannot " +
      "forge; generating that key in the gate makes the whole boundary decorative, and it was the only shipped wiring.",
    file: "packages/gate/src/trust.ts",
    find: "  if (external && !enrolledApprover) {",
    replace: "  if (false) {",
    kind: "tests",
    suite: ["packages/gate", "npm", ["test"]],
  },
  {
    id: "s0-returned-signature-is-verified",
    control:
      "S0 (adversarial review 2026-08-12, HIGH) — the gate cryptographically verifies every signature the signer " +
      "returns before treating it as its own authority. Without it a response echoing the document with a junk " +
      "sig value made decide() return 200 and persist an APPROVED hold with a grant record.",
    file: "packages/gate/src/exec-signer.ts",
    find: '  if (!verifyEd25519(expectPublicKey, signingMessage(domain, signHashInput(signed)), s["value"] as string)) {',
    replace: "  if (false) {",
    kind: "tests",
    suite: ["packages/gate", "npm", ["test"]],
  },
  {
    id: "s0-grant-params-bound-to-approval",
    control:
      "S0 — the out-of-process grant signer refuses to sign a grant whose paramsHash is not the one a human " +
      "approved. This is the single check that separates a policy gate from a bare signing oracle: without it " +
      "an attacker who can merely REACH the socket has the key in effect.",
    file: "packages/gate/src/grant-sidecar.ts",
    find: '  if (grant["paramsHash"] !== approvedParamsHash) {',
    replace: '  if (grant["paramsHash"] !== approvedParamsHash && false) {',
    kind: "tests",
    suite: ["packages/gate", "npm", ["test"]],
  },
  {
    id: "p06-activation-time-strict",
    control: "P0-6 — a non-canonical declared activation is refused instead of being normalised by Date.parse into a usable instant. [proof: RES-PAR-AA-STRICT]",
    file: "packages/approval-artifacts/src/verify.ts",
    // RE-AIMED 2026-08-01. The previous pair targeted `CANONICAL_INSTANT.test(v)`, a regex guard that
    // batch C deleted when `parseTime` became epoch arithmetic. `find` then matched 0×, the runner
    // reported MUTATION_NOT_APPLIED, and this control went UNMEASURED — its test kept passing and
    // proved nothing, because nothing was mutating the line it was supposed to watch. A knockout whose
    // anchor rots is worse than no knockout: it keeps printing a row in a table people read as coverage.
    //
    // NARROWED 2026-08-03 after a redteam review REFUTED the previous justification. That comment
    // claimed the whole-function wrapper was "the only shape that removes the control without also
    // changing what the parser accepts". It is not. The reviewer built this one and measured it
    // breaking ONLY the named proof, where the wrapper broke three tests:
    //     wrapper (withdrawn)  DETECTOR_TRIGGERED, 3 new failures: Batch N; P0-6 proof; P0-9
    //     this one            DETECTOR_TRIGGERED, 1 new failure:  P0-6 proof
    //
    // The claim was wrong in a specific and instructive way: two narrower mutations HAD failed to
    // kill the control (structural guard alone => the schema refuses first; schema check alone =>
    // the structural guard refuses), and from "these two did not work" I concluded "nothing narrower
    // can". That is an argument, not a measurement, and it is exactly the move this file exists to
    // catch — the strictness IS layered, but a mutation aimed at one INPUT CLASS slips between the
    // layers, which neither of my two attempts did.
    //
    // A knockout that kills three tests still passes anti-vacuity (the runner requires the named
    // proof among the new failures, not that it be alone), so nothing would have flagged this. It
    // would simply have made the next person read a wider blast radius as evidence of a wider control.
    //
    // Its `marker` in resolver-inventory.json was the FULL TEXT OF THE TEST NAME, so tagging the test
    // with [PROOF:RES-PAR-AA-STRICT] unbound it instantly. Changed to the tag form that
    // RES-PAR-ROOT-ENFORCED already used: a marker that is a sentence is one rewording away from
    // silently certifying nothing.
    find: 'function parseTime(v: unknown, timeSchema: Record<string, unknown> | null): bigint | null {',
    replace: 'function parseTime(v: unknown, timeSchema: Record<string, unknown> | null): bigint | null {\n  if (typeof v === "string" && v.length === 1) {\n    const ms = Date.parse(v);\n    if (ms === ms) return toBigInt(ms) * 1_000_000n;\n  }',
    kind: "tests",
    suite: ["packages/approval-artifacts", "npm", ["test"]],
  },
  {
    id: "c77-display-captured-decode",
    control: "#77-C/1 \u2014 openEncryptedDisplay interprets the AUTHENTICATED plaintext through a CAPTURED TextDecoder.prototype.decode and a CAPTURED JSON.parse. Live, the AEAD verified and the human was shown \"Refund EUR 1.00 to Alice\" while the sealed display said \"Wire EUR 2,400,000 to NEW payee GmbH\" \u2014 the product's core failure mode via prototype pollution alone.",
    file: "packages/signer-core/src/encrypted-display.ts",
    find: "  const plaintextText = reflectApply(textDecoderDecode, sharedDecoder, [plaintext]) as string;\n  const parsed = reflectApply(jsonParse, JSON, [plaintextText]) as unknown;",
    replace: "  const parsed = JSON.parse(new TextDecoder().decode(plaintext)) as unknown;",
    kind: "tests",
    suite: ["packages/signer-core", "npm", ["test"]],
  },
  {
    id: "c77-display-recipient-index-walk",
    control: "#77-C/2 \u2014 sealEncryptedDisplay builds the recipient set with an INDEX WALK, not Array.prototype.map. At seal time the CEK is in hand, so a poisoned map chose WHO MAY READ the approval: measured, the sealed list came back [\"attacker-device\"], the attacker opened the display and the intended approver was locked out.",
    file: "packages/signer-core/src/encrypted-display.ts",
    find: "  const src = input.recipients;\n  const n = src.length;",
    replace: "  const src = input.recipients.map((x) => x);\n  const n = src.length;",
    kind: "tests",
    suite: ["packages/signer-core", "npm", ["test"]],
  },
  {
    id: "b77-jcs-captured-sort",
    control: "#77-B/3 \u2014 jcs sorts keys with a CAPTURED Array.prototype.sort. Live, a sort that empties the list made {a:1,b:2} and {x:\"production.delete.all\"} both canonicalize to \"{}\"; a sort that is the identity made the SAME document in two key orders produce TWO canonical forms.",
    file: "packages/signer-core/src/jcs.ts",
    find: "  reflectApply(arraySortRaw, ks, []);",
    replace: "  ks.sort();",
    kind: "tests",
    suite: ["packages/signer-core", "npm", ["test"]],
  },
  {
    id: "b77-jcs-captured-keys",
    control: "#77-B/3 \u2014 jcs enumerates with a CAPTURED Object.keys. Live, `Object.keys -> []` erased every field from the commitment and distinct documents collapsed.",
    file: "packages/signer-core/src/jcs.ts",
    find: "  const ks = objectKeys(o);",
    replace: "  const ks = Object.keys(o);",
    kind: "tests",
    suite: ["packages/signer-core", "npm", ["test"]],
  },
  {
    id: "b77-jcs-captured-iswellformed",
    control: "#77-B/3 \u2014 the unpaired-surrogate refusal reads a CAPTURED String.prototype.isWellFormed. Live and forced true, U+D800 and U+D801 both encoded to 7b2273223a22efbfbd227d \u2014 2048 code points into one hash bucket, the forgery channel serializeString exists to close.",
    file: "packages/signer-core/src/jcs.ts",
    find: "  if (!(reflectApply(strIsWellFormed, s, []) as boolean)) {",
    replace: "  if (!s.isWellFormed()) {",
    kind: "tests",
    suite: ["packages/signer-core", "npm", ["test"]],
  },
  {
    id: "b77-deepcopy-non-enumerable-refusal",
    control: "#77-B/1 \u2014 inertDeepCopy REFUSES an own non-enumerable property. jcs.ts walks Object.keys (own+ENUMERABLE) while deep-copy walks getOwnPropertyNames (own, incl. non-enumerable) and defines everything enumerable:true \u2014 so such a field was invisible to the hash and visible in the returned receipt. Measured end to end: signed governance had no approval, returned governance carried HUMAN:cfo-victim, root verdict TAMPERED.",
    file: "packages/signer-core/src/deep-copy.ts",
    find: "    if (d.enumerable !== true) {",
    replace: "    if (false) {",
    kind: "tests",
    suite: ["packages/signer-core", "npm", ["test"]],
  },
  {
    id: "b77-jcs-named-array-refusal",
    control: "#77-B/2 \u2014 canonicalize() is a PUBLIC EXPORT and must be injective: an array carrying a named property canonicalized to the same bytes as one without it ([1] either way). Not reachable via producer or wire, but reachable directly through the export.",
    file: "packages/signer-core/src/jcs.ts",
    find: "      if (name === \"length\") continue;",
    replace: "      if (name === \"length\") continue;\n      if (name) continue;",
    kind: "tests",
    suite: ["packages/signer-core", "npm", ["test"]],
  },
  {
    id: "a77-signing-index-writes",
    control: "#77-A \u2014 signingMessageBytes assembles the Ed25519 message by INTEGER INDEX, never `.set()`. `Uint8Array.prototype.set` is a writable global; with it a no-op the message became 53 zero bytes, so every receipt was signed over the same constant.",
    file: "packages/signer-core/src/signing.ts",
    find: "  const n = domainBytes.length;\n  for (let i = 0; i < n; i++) out[i] = domainBytes[i] as number;\n  const m = digest.length;\n  for (let i = 0; i < m; i++) out[n + i] = digest[i] as number;",
    replace: "  out.set(domainBytes, 0);\n  out.set(digest, domainBytes.length);",
    kind: "tests",
    suite: ["packages/signer-core", "npm", ["test"]],
  },
  {
    id: "a77-hash-primitive-kat",
    control: "#77-A \u2014 the signing path runs a KNOWN-ANSWER TEST on SHA-256 before signing. `@noble/hashes` builds blocks with `Uint8Array.prototype.set` (_md.js:94), so a poisoned prototype neutralises the hash itself and sha256(A) === sha256(B). Not fixable inside this package; the guarantee is that signing REFUSES rather than emitting a digest that is not a digest.",
    file: "packages/signer-core/src/signing.ts",
    find: "  assertSha256Intact();",
    replace: "  if (Math.abs(1) === 1) { /* KAT removed */ }",
    kind: "tests",
    suite: ["packages/signer-core", "npm", ["test"]],
  },
  {
    id: "a77-hash-captured-encoder",
    control: "#77-A \u2014 hash.ts encodes through a CAPTURED TextEncoder.prototype.encode. It decides WHAT GETS HASHED; live, an attacker returning an empty array made two different receipts share a signature.",
    file: "packages/signer-core/src/hash.ts",
    find: "  const buf = typeof data === \"string\" ? (reflectApply(textEncoderEncode, encoder, [data]) as Uint8Array) : data;",
    replace: "  const buf = typeof data === \"string\" ? encoder.encode(data) : data;",
    kind: "tests",
    suite: ["packages/signer-core", "npm", ["test"]],
  },
  {
    id: "r815-qa17-array-named-property-refusal",
    control: "R815-QA-17 \u2014 a NAMED property on an array is REFUSED, not silently dropped. The index walk copies indices only, so `arr.foo` vanished without a word; JCS emits neither so the wire bytes are unaffected, but silent reshaping on a signing path is exactly what this function refuses to do. Covers the \"4294967295\" boundary, which is a named property rather than an index.",
    file: "packages/signer-core/src/deep-copy.ts",
    find: "      if (name === \"length\") continue;",
    replace: "      if (name === \"length\") continue;\n      if (name) continue;",
    kind: "tests",
    suite: ["packages/signer-core", "npm", ["test"]],
  },
  {
    id: "r815-qa12-forbidden-key-refusal",
    control: "R815-QA-12 \u2014 the producer REFUSES the three keys the strict parser refuses (__proto__/prototype/constructor). What the authoritative verifier will not read, the producer must not write: signing such a document produces an artefact that can never verify. This LAYERS with the defineProperty class closure; it does not replace it.",
    file: "packages/signer-core/src/deep-copy.ts",
    find: "    if (key === \"__proto__\" || key === \"prototype\" || key === \"constructor\") {",
    replace: "    if (false) {",
    kind: "tests",
    suite: ["packages/signer-core", "npm", ["test"]],
  },
  {
    id: "r815-qa14-object-class-not-spelling",
    control: "R815-QA-14 \u2014 the deep copy closes the CLASS of inherited setters, not the `__proto__` SPELLING. A fix that defineProperty'd only the one key the tests named would leave every other inherited setter live, and it passed the whole suite 50/50 before this control existed.",
    file: "packages/signer-core/src/deep-copy.ts",
    find: "    objectDefineProperty(out, key, {\n      value: copyValue(d.value, `${path}.${key}`, depth + 1),\n      writable: true,\n      enumerable: true,\n      configurable: true,\n    });",
    replace: "    if (key === \"__proto__\") {\n      objectDefineProperty(out, key, {\n        value: copyValue(d.value, `${path}.${key}`, depth + 1),\n        writable: true, enumerable: true, configurable: true,\n      });\n    } else {\n      out[key] = copyValue(d.value, `${path}.${key}`, depth + 1);\n    }",
    kind: "tests",
    suite: ["packages/signer-core", "npm", ["test"]],
  },
  {
    id: "r815-qa14-array-class-not-index0",
    control: "R815-QA-14 \u2014 the ARRAY branch closes the class for EVERY index, not index 0. A fix that defineProperty'd only element 0 also passed 50/50; the control is an `Array.prototype` accessor on a NON-ZERO index.",
    file: "packages/signer-core/src/deep-copy.ts",
    find: "      objectDefineProperty(out, i, {\n        value: copyValue(d.value, `${path}[${i}]`, depth + 1),\n        writable: true,\n        enumerable: true,\n        configurable: true,\n      });",
    replace: "      if (i === 0) {\n        objectDefineProperty(out, i, {\n          value: copyValue(d.value, `${path}[${i}]`, depth + 1),\n          writable: true, enumerable: true, configurable: true,\n        });\n      } else {\n        out[i] = copyValue(d.value, `${path}[${i}]`, depth + 1);\n      }",
    kind: "tests",
    suite: ["packages/signer-core", "npm", ["test"]],
  },
  // ── P0-7 / P0-8 (2026-07-31): RESOLVER PARITY + THE CENSUS GATE ────────────────────────────────
  // Three resolvers of one class dropped a declared `validFrom` (P0-1/P0-5/P0-8), the inventory was
  // declared complete twice while a site was missing, and a source comment claimed a parity test
  // that did not exist (P0-7). These three entries make the whole control stack observable failing:
  // the parity TEST (a resolver drops activation), the reconciliation GATE (a resolver leaves the
  // inventory), and the proof-resolution rule (a claimed control stops running).
  {
    id: "p08-e2e-keyring-validfrom-carried",
    requires: ["phone-core"],
    control: "P0-8 — the pairing live keyring carries the manifest-declared validFrom on every entry; dropping ONE entry's activation must fail the parity test [proof: RES-PAR-E2E-KEYRING]",
    file: "packages/e2e-demo/src/pairing.ts",
    find: "    [gate.kid]: { publicKey: gate.publicKey, type: 'GATE', roles: ['hold-signer', 'execution-signer'], validFrom: gateWindow.validFrom, revokedAt: gateWindow.revokedAt },",
    replace: "    [gate.kid]: { publicKey: gate.publicKey, type: 'GATE', roles: ['hold-signer', 'execution-signer'], revokedAt: gateWindow.revokedAt },",
    kind: "tests",
    suite: ["packages/e2e-demo", "npm", ["test"]],
  },
  {
    id: "f2-e2e-keyring-window-from-manifest",
    requires: ["phone-core"],
    control: "F-2 — a present manifest key's per-key activation/revocation wins over auth defaults; restoring the old auth-derived/null behaviour makes only the differing-manifest proof go RED. [proof: RES-PAR-E2E-KEYRING]",
    file: "packages/e2e-demo/src/pairing.ts",
    find: "    return declared === undefined\n      ? { validFrom: auth.validFrom, revokedAt: null }\n      : { validFrom: declared.validFrom, revokedAt: declared.revokedAt };",
    replace: "    return { validFrom: auth.validFrom, revokedAt: null };",
    kind: "tests",
    suite: ["packages/e2e-demo", "npm", ["test"]],
  },
  {
    id: "p08-e2e-tenantroot-validfrom-carried",
    requires: ["phone-core"],
    control: "P0-8 — the pairing resolver carries the ROOT activation into the external tenant-root map; deleting it makes the tenant-root proof itself fail. [proof: RES-PAR-E2E-TENANTROOT]",
    file: "packages/e2e-demo/src/pairing.ts",
    find: "  const tenantRoot: Record<string, KeyEntry> = {\n    // P0-8, same change as the live keyring above: the external anchor carries the ROOT's declared\n    // activation, exactly as `gate/src/trust.ts` and the P0-1 fix do. [proof: RES-PAR-E2E-TENANTROOT]\n    [auth.root.kid]: { publicKey: auth.root.publicKey, type: 'ROOT', roles: [], validFrom: auth.validFrom, revokedAt: null },",
    replace: "  const tenantRoot: Record<string, KeyEntry> = {\n    // P0-8, same change as the live keyring above: the external anchor carries the ROOT's declared\n    // activation, exactly as `gate/src/trust.ts` and the P0-1 fix do. [proof: RES-PAR-E2E-TENANTROOT]\n    [auth.root.kid]: { publicKey: auth.root.publicKey, type: 'ROOT', roles: [], revokedAt: null },",
    kind: "tests",
    suite: ["packages/e2e-demo", "npm", ["test"]],
  },
  {
    id: "p08-cross-resolver-equivalence",
    requires: ["phone-core"],
    control: "P0-8 — the cross-resolver proof observes the assembled DELEGATED entry's activation at the real verifier; deleting that carried value makes the equivalence proof itself fail. [proof: RES-PAR-XRES-EQUIV]",
    file: "packages/e2e-demo/src/pairing.ts",
    find: "    [auth.authority.kid]: { publicKey: auth.authority.publicKey, type: 'DELEGATED', roles: ['key-manifest-sign'], validFrom: auth.validFrom, revokedAt: null },",
    replace: "    [auth.authority.kid]: { publicKey: auth.authority.publicKey, type: 'DELEGATED', roles: ['key-manifest-sign'], revokedAt: null },",
    kind: "tests",
    suite: ["packages/e2e-demo", "npm", ["test"]],
  },
  {
    id: "res-inventory-reconcile-blocks",
    requires: ["phone-core"],
    control: "P0-8 census — a resolver REMOVED from the inventory turns the reconciliation gate RED (the tree is re-derived from the AST on every run; the inventory is never trusted)",
    file: "scripts/resolver-inventory.json",
    find: '    {\n      "id": "e2e-demo-assemblegatetrust-tenantroot-0",\n      "package": "e2e-demo",\n      "file": "packages/e2e-demo/src/pairing.ts",\n      "scope": "assembleGateTrust>tenantRoot",\n      "ordinal": 0,\n      "line": 321,\n      "kind": "construct",\n      "class": "demo",\n      "input": "the demo authority\'s declared ROOT window",\n      "output": "KeyEntry (ROOT)",\n      "validFrom": "explicit",\n      "revokedAt": "explicit",\n      "missingValue": "not expressible: constructor always sets both fields (P0-8 fix)",\n      "malformedValue": "not expressible: clock-derived canonical toISOString",\n      "timestampParser": "new Date(ms).toISOString() at generation",\n      "consumer": "§13 verify-evidence external tenant root (F7a)",\n      "proofs": [\n        "RES-PAR-E2E-TENANTROOT"\n      ]\n    },\n',
    replace: "",
    kind: "gate",
    suite: [".", "npm", ["run", "lint:resolver-parity"]],
  },
  {
    id: "res-parity-proof-must-resolve",
    requires: ["phone-core"],
    control: "P0-7 — a registered parity proof must RESOLVE to a live test; skipping it turns the reconciliation gate RED (a source claim about a control that does not run is the exact defect this batch adjudicated)",
    file: "packages/e2e-demo/test/keyring-resolver-parity.test.ts",
    find: "test('[PROOF:RES-PAR-E2E-TENANTROOT] the external tenant root map CARRIES the declared activation', async () => {",
    replace: "test.skip('[PROOF:RES-PAR-E2E-TENANTROOT] the external tenant root map CARRIES the declared activation', async () => {",
    kind: "gate",
    suite: [".", "npm", ["run", "lint:resolver-parity"]],
  },
  // ── noa.action-digest/0.1 (round-2 QA, 2026-08-12) ────────────────────────────────────────────
  // Round-2 QA observed that this module had NO entry here at all, so none of its controls were in
  // the repository's own L4 ratchet — its knockout evidence lived in a scratch script, which is the
  // "asserted census" shape this whole gate exists to end. These are the controls that can be
  // ISOLATED: each mutation leaves every other rule intact, so the named vector is the only thing
  // that can go red.
  //
  // Deliberately ABSENT, and this is the corrected half of the same finding: there is no entry for
  // the projection's `actionId`, `actionCanonical`, `actionParamsHash`, `executionGrantId` or
  // `executionNonce` members. They cannot be isolated by construction — `authorizationReceiptHash`
  // and `executionGrantHash` are hashes over the whole receipt and the whole grant, so any source
  // mutation that moves one of those five moves a whole-document hash too, and the attack is refused
  // either way. Registering a knockout that "passes" for that reason would be vacuous. See
  // docs/action-digest-spec.md §7.
  {
    id: "ad-verdict-must-be-allowed",
    control: "HIGH-1 — an action digest may only be built from an ALLOWED receipt. Without this check a cryptographically VALID human DENIAL correlates as the authorization for the action it denied: verifyChain VALID, verifyArtifact ok, digest MATCHED. Same class as the relay's APPROVED-over-a-denial defect, recurring in a new module.",
    file: "src/action-digest.ts",
    find: '  if (governance["verdict"] !== AUTHORIZING_VERDICT) {',
    replace: '  if (governance["verdict"] === "\\u0000never") {',
    kind: "tests",
    suite: [".", "npm", ["run", "test:action-digest"]],
  },
  {
    id: "ad-scope-identifier-not-blank",
    control: "HIGH-2 — emptiness is a property of the TRIMMED value. `length === 0` refused \"\" and accepted \"   \", so the semantic \"unknown tenant\" passed every verifier, and a padded tenant aliased to a different one anywhere that trims.",
    file: "src/action-digest.ts",
    find: '  if (strTrim(v).length === 0) return "blank";\n  if (strTrim(v) !== v) return "padded";',
    replace: '  if (v.length === 0) return "blank";',
    kind: "tests",
    suite: [".", "npm", ["run", "test:action-digest"]],
  },
  {
    id: "ad-chain-must-authenticate",
    control: "HIGH-3 — verifyActionDigest authenticates its own inputs by delegating to verifyChain. Without it, an attacker's key claiming the victim's kid mints an entire authorization and a matching digest; the previous revision disclosed that in prose instead, and prose does not enforce call ordering.",
    file: "src/action-digest.ts",
    find: '  if (chainVerdict.status !== "VALID" || chainVerdict.signaturesVerified !== true) {',
    replace: '  if (chainVerdict.count === -1) {',
    kind: "tests",
    suite: [".", "npm", ["run", "test:action-digest"]],
  },
  {
    id: "ad-grant-signature-verified",
    control: "HIGH-3 (grant half) — the grant's Ed25519 signature is verified under its own §6 domain tag with the key resolved by resolveVerificationKey, so an outsider cannot mint a grant. Role/expiry semantics remain verifyArtifact's and are documented as a residual, not claimed here.",
    file: "src/action-digest.ts",
    find: '  if (!verifyEd25519(grantKey.publicKey, signingMessage(GRANT_SIG_DOMAIN, canonicalize(grantWithoutSig)), grantSig["value"])) {',
    replace: '  if (grantSig["value"] === "\\u0000never") {',
    kind: "tests",
    suite: [".", "npm", ["run", "test:action-digest"]],
  },
  {
    id: "ad-grant-sig-object-is-closed",
    control: "MEDIUM-4 — the grant's nested `sig` object is closed, not just its top level. `sig.extra` does not break the §6 signature (the preimage is JCS(doc without sig)), so only the closed-world rule can refuse it — and verifyArtifact does.",
    file: "src/action-digest.ts",
    find: '    if (!arrayIncludes(GRANT_SIG_KEYS, k)) {',
    replace: '    if (k === "\\u0000never") {',
    kind: "tests",
    suite: [".", "npm", ["run", "test:action-digest"]],
  },
  {
    id: "ad-authorization-selected-by-grant-binding",
    control: "HIGH-3 (substitution) — the authorization receipt is selected from the verified chain by the grant's OWN approvalReceiptHash, so a caller cannot aim the verifier at a receipt the grant does not reference.",
    file: "src/action-digest.ts",
    find: '    if (sha256Prefixed(receiptHashInput(candidate as unknown as Receipt)) === wanted) {',
    replace: '    if (true) {',
    kind: "tests",
    suite: [".", "npm", ["run", "test:action-digest"]],
  },
  {
    id: "ad-expected-scope-enforced",
    control: "The ONE job `tenant`/`chain` do that the whole-document hashes do not: answering \"are these documents MINE?\". No property of the digest can answer it, because the digest knows nothing about who is asking.",
    file: "src/action-digest.ts",
    find: '  if (built.projection.tenant !== expect["tenant"]) {',
    replace: '  if (built.projection.tenant === "\\u0000never") {',
    kind: "tests",
    suite: [".", "npm", ["run", "test:action-digest"]],
  },
  {
    id: "ad-domain-separation-applied",
    control: "The digest is the projection hashed under NOA-ActionDigest-v0.1-dig, a tag disjoint from every SIGNING tag. Pointing it at the receipt signing tag makes reject-wrong-domain-tag verify — cross-protocol reuse of a value another verifier already accepts.",
    file: "src/action-digest.ts",
    find: 'export const ACTION_DIGEST_DOMAIN = "NOA-ActionDigest-v0.1-dig";',
    replace: 'export const ACTION_DIGEST_DOMAIN = "NOA-Receipt-v0.1-sig";',
    kind: "tests",
    suite: [".", "npm", ["run", "test:action-digest"]],
  },
  // ── P0-12 / P0-13 (2026-07-31, micro-batch B): HARDENING WHAT BATCH A BUILT ────────────────────
  // Both entries below exist because a control that batch A added did not hold: ROOT activation was
  // carried and never enforced, and the proof-resolution rule was defeated by a second spelling of
  // "skip". Each knockout targets the NEW control, not the old defect.
  {
    id: "p12-root-activation-enforced",
    control: "P0-12 — a trust ROOT is subject to its OWN activation window. Exempting ROOT from the activation branch left 1040 tests across five suites green before these proofs existed: carriage (P0-1) was proven, enforcement was not. [proof: RES-PAR-ROOT-ENFORCED]",
    file: "packages/approval-artifacts/src/verify.ts",
    find: "    if (entry.validFrom != null) {",
    replace: '    if (entry.validFrom != null && entry.type !== "ROOT") {',
    kind: "tests",
    suite: ["packages/approval-artifacts", "npm", ["test"]],
  },
  {
    id: "p13-proof-resolution-is-structural",
    requires: ["phone-core"],
    control: "P0-13 — proof resolution reads the AST, so a control cannot be disabled by a spelling the matcher does not know. Defanging the options-object rule makes `test(name, { skip: true }, fn)` certify as live again — the exact measured bypass (gate: skipped 3, lint exit 0). Since P0-15 this AST tier is DIAGNOSIS; the selftest ahead of the gate is what turns this mutation red.",
    file: "scripts/lib/proof-resolve.mjs",
    find: 'if (v.kind === ts.SyntaxKind.TrueKeyword || ts.isStringLiteral(v)) return "disabled";',
    replace: 'if (false) return "disabled";',
    kind: "gate",
    suite: [".", "npm", ["run", "lint:resolver-parity"]],
  },
  // ── P0-15 (2026-07-31, micro-batch B2): LIVENESS COMES FROM THE RUNNER, NOT FROM A MODEL OF IT ─
  // The proof-liveness control was bypassed in three consecutive rounds (line scan → {skip:true};
  // AST → indirect options, computed ["skip"], aliased describe.skip, dead if(false)). This entry
  // uses the FIRST of the four runtime-only spellings — an options object behind a variable, which
  // the AST tier provably resolves "live" — so it goes red only if the RUNNER tier catches it.
  // A knockout using a statically-visible spelling would prove the wrong tier.
  {
    id: "p15-proof-liveness-from-runner",
    requires: ["phone-core"],
    control: "P0-15 — a registered proof must appear as a PASSING test in a REAL `node --test` run; a skip spelled so that no static parse can see it (indirect options object) is still refused, because the runner is ground truth and the parser is only a model of it.",
    file: "packages/e2e-demo/test/keyring-resolver-parity.test.ts",
    find: "test('[PROOF:RES-PAR-E2E-TENANTROOT] the external tenant root map CARRIES the declared activation', async () => {",
    replace: "const __p15 = { skip: true };\ntest('[PROOF:RES-PAR-E2E-TENANTROOT] the external tenant root map CARRIES the declared activation', __p15, async () => {",
    kind: "gate",
    suite: [".", "npm", ["run", "lint:resolver-parity"]],
  },
  {
    id: "res-proof-knockout-coverage-required",
    requires: ["phone-core"],
    control: "F-4 — removing the sole declared knockout binding for one registered proof makes resolver parity fail with PROOF_WITHOUT_KNOCKOUT_BINDING. This meta-gate proves the binding rule only; requireNamedProofFailures separately checks behaviour when the tagged knockout executes.",
    file: "scripts/lint-control-knockout.mjs",
    find: '    control: "P0-6 — a non-canonical declared activation is refused instead of being normalised by Date.parse into a usable instant. [proof: RES-PAR-AA-STRICT]",\n    file: "packages/approval-artifacts/src/verify.ts",',
    replace: '    control: "P0-6 — a non-canonical declared activation is refused instead of being normalised by Date.parse into a usable instant.",\n    file: "packages/approval-artifacts/src/verify.ts",',
    kind: "gate",
    suite: [".", "node", ["scripts/lint-resolver-parity.mjs"]],
  },
  // ── L11 — INERT-BEFORE-WRITE (2026-08-12) ─────────────────────────────────────────────────────
  // A class that no gate in this repository could express until now. `scripts/lint-security-gates.mjs`
  // models dispatch as a CALL or a READ; `packages/adapter-core/src/policy-change-guard.mjs:58-60`
  // states it in the source: L2 and L8 "have no grammar for a write". So an ordinary `[]` or `{}`
  // filled on a decision path contributed ZERO findings to either budget, and the three files that
  // got fixed got fixed because a human read them.
  //
  // The two entries below are deliberately of DIFFERENT kinds, because they measure different
  // controls. The first is the fix itself and is measured by TESTS. The second is the ORDERING —
  // creation-time versus fill-time — and is measured by the GATE, because the two orderings are
  // behaviourally identical on every honest input and only differ while a poison is installed
  // mid-fill.
  {
    id: "l11-precheck-fallback-container-inert",
    control:
      "L11 — canonicalParamsHash's fallback stringifier builds its `parts`/`items` containers INERT " +
      "BEFORE the first write. The captured `arrayPush` applies the PRISTINE push, but push is " +
      "defined as Set(O, \"0\", v) and [[Set]] walks the RECEIVER's prototype chain, so an accessor at " +
      "Object.prototype[\"0\"] swallows the first element while `length` still moves. MEASURED: two " +
      "different tool calls collapsed onto ONE paramsHash, so an approval minted for a 10-unit " +
      "transfer authorises a 900,000-unit one — with NO builtin replaced at all.",
    file: "packages/adapter-core/src/pre-check.mjs",
    find: "    const parts = [];\n    objectSetPrototypeOf(parts, INERT_ARRAY_PROTOTYPE);",
    replace: "    const parts = [];",
    kind: "tests",
    suite: ["packages/adapter-core", "npm", ["test"]],
  },
  {
    id: "l11-reroot-at-creation-not-after-fill",
    control:
      "L11 — a container is re-rooted at CREATION, never after the fill. This is the distinction the " +
      "whole layer exists for, and it is not hypothetical: the fix that shipped for this class once " +
      "re-derived the house pattern and got it wrong by re-rooting AFTER the loop. The mutation moves " +
      "`objectSetPrototypeOf` below the fill — identical output on every honest input — and " +
      "`lint:inert-containers` must report it as L11-B. A gate that scored both orderings the same " +
      "way would pass the exact code that shipped the defect.",
    file: "packages/adapter-core/src/policy-change-guard.mjs",
    find: "  const canon = [];\n  objectSetPrototypeOf(canon, INERT_ARRAY_PROTOTYPE);\n  for (let i = 0; i < arr.length; i += 1) arrayPush(canon, sortKeysDeep(arr[i]));",
    replace: "  const canon = [];\n  for (let i = 0; i < arr.length; i += 1) arrayPush(canon, sortKeysDeep(arr[i]));\n  objectSetPrototypeOf(canon, INERT_ARRAY_PROTOTYPE);",
    kind: "gate",
    suite: [".", "npm", ["run", "lint:inert-containers"]],
  },
];

// Fail before measuring any baseline: an unknown key means the registry describes an experiment
// the runner does not implement, so running a partial experiment would manufacture evidence.
validateKnockoutRegistry(KNOCKOUTS);
for (const k of KNOCKOUTS) {
  for (const id of proofIdsFor(k)) {
    if (!PROOF_INVENTORY[id]) {
      throw new Error(`invalid knockout entry ${JSON.stringify(k.id)}: unknown proof id ${JSON.stringify(id)}`);
    }
  }
}

// ── R8-26/R8-27: MEASURE EVERY SUITE'S CLEAN BASELINE FIRST ────────────────────────────────────
// Without this, "the suite failed" cannot be distinguished from "the suite was already failing".
// `packages/gate` is exit 1 / 200 pass / 2 fail at HEAD — two owner-deferred ADR-0006 failures — and
// the six entries targeting it were reporting a kill for that, not for their own controls.
// ── DEPENDENCIES MISSING ⇒ DO NOT RUN THE GATE (KURAL 29 refusal #3) ──────────────────────────
// Entries declaring a dependency that is absent are NOT RUN. Measured 2026-08-04: with the private
// phone core absent in CI (`secrets.NOA_MOBILE_TOKEN` unset, and the `test` job has no checkout for
// it), three e2e-demo suites failed at BASELINE, which turned TEN knockouts into
// ANTI_VACUITY_FAILED — each truthfully reporting "the suite failed, but ONLY with the failures its
// baseline already had" — and blocked a merge on ten controls that are, locally, all fine.
//
// The exclusion is DECLARED (`requires: [...]`), never inferred from the failure shape: e2e-demo's
// poisoned baseline is "exit 1 with 3 named failures", the same shape as `packages/gate`'s
// legitimate owner-deferred red baseline above. A runner that guessed would excuse real failures.
const { runnable: DEPS_OK, setupFailed: DEPS_MISSING } = partitionByDependency(
  KNOCKOUTS, ROOT, DEPENDENCY_PROBES,
);
const selected = ONLY
  ? DEPS_OK.filter((k) => k.id === ONLY)
  : REQUIRES
    ? DEPS_OK.filter((k) => (k.requires ?? []).includes(REQUIRES))
    : DEPS_OK;
if (REQUIRES && selected.length === 0) {
  // No verdict is not a pass (KURAL 29): an armed job whose whole selection fell into
  // SETUP_FAILED — or matched nothing — must refuse loudly, not exit 0 having measured nothing.
  const declared = KNOCKOUTS.filter((k) => (k.requires ?? []).includes(REQUIRES));
  const setupFailed = DEPS_MISSING.filter((m) => declared.some((k) => k.id === m.id));
  console.error(
    `--requires ${REQUIRES}: 0 runnable entries selected ` +
    `(${declared.length} declared, ${setupFailed.length} SETUP_FAILED). ` +
    `The experiment did not happen; refusing to report a pass.`,
  );
  process.exit(1);
}

// Snapshot the worktree BEFORE anything runs, so residue is measured as a DIFFERENCE.
let WORKTREE_BEFORE = "";
try {
  WORKTREE_BEFORE = execFileSync("git", ["status", "--porcelain"], { cwd: ROOT, encoding: "utf8" }).trim();
} catch { /* not a git tree */ }

const suiteKey = (k) => JSON.stringify(k.suite);
const baselines = new Map();
for (const k of selected) {
  const key = suiteKey(k);
  if (baselines.has(key)) continue;
  const obs = observeSuite(ROOT, k.suite);
  // `out` is carried so runKnockout can CROSS-CHECK an entry's declared `kind` against what the
  // clean baseline actually printed (QA-16). Without it the declaration would be trusted.
  baselines.set(key, { exit: obs.exit, failing: obs.failing, findings: obs.findings, ms: obs.ms, timedOut: obs.timedOut, out: obs.out });
}

// A knockout whose baseline could not even be measured proves nothing, so say that rather than
// scoring it.
const unmeasurable = [...baselines.entries()].filter(([, b]) => b.timedOut);

const results = [];
for (const k of selected) {
  const baseline = baselines.get(suiteKey(k));
  if (baseline.timedOut) {
    results.push({ id: k.id, control: k.control, verdict: VERDICT.INVALID_TEST,
      detail: `the suite's CLEAN baseline timed out, so no mutation result from it can mean anything`, restored: true });
    continue;
  }
  const result = runKnockout({ root: ROOT, entry: k, registry: KNOCKOUTS, baseline });
  results.push(requireNamedProofFailures(k, result));
}

// ── REPORT ─────────────────────────────────────────────────────────────────────────────────────
console.log(`L4 control knockout: ${results.length} controls\n`);
console.log("  suite baselines (measured clean, before any mutation):");
for (const [key, b] of baselines) {
  const dir = JSON.parse(key)[0];
  console.log(`    ${dir.padEnd(28)} exit ${String(b.exit).padEnd(4)} ${b.failing.size} pre-existing failure(s)`);
  for (const f of b.failing) console.log(`      already failing: ${f}`);
}
console.log();

for (const r of results) {
  const mark = PASSING.has(r.verdict) ? "ok      " : "FINDING ";
  console.log(`  ${mark} ${String(r.verdict).padEnd(28)} ${r.id.padEnd(34)} ${r.control}`);
  if (r.detail) console.log(`           ${r.detail}`);
  if (r.restored === false) console.log(`           ⚠ RESTORATION UNPROVEN for ${r.file}`);
}

const passed = results.filter((r) => PASSING.has(r.verdict));
console.log(`\nproven load-bearing ${passed.length}/${results.length}`);

// ── WHAT WAS NOT MEASURED, SAID OUT LOUD ───────────────────────────────────────────────────────
// A silent exclusion is how a gate comes to report full coverage over a shrinking set. These
// entries are absent from BOTH sides of the ratio above — a control nobody asked did not fail to
// prove itself — so the only place their absence can be seen is here.
if (DEPS_MISSING.length > 0 && !ONLY) {
  const byDep = new Map();
  for (const e of DEPS_MISSING) {
    for (const d of e.missing) byDep.set(d, (byDep.get(d) ?? 0) + 1);
  }
  const summary = [...byDep].map(([d, n]) => `${n} × ${d}`).join(", ");
  console.log(
    `\n⚠ NOT MEASURED — ${DEPS_MISSING.length} control(s) were not run because a declared ` +
    `dependency is absent (${summary}).`,
  );
  console.log(`  These are neither kills nor findings: the experiment did not happen.`);
  for (const e of DEPS_MISSING) console.log(`  ${VERDICT.SETUP_FAILED.padEnd(26)} ${e.id} — needs ${e.missing.join(", ")}`);
  console.log(`  To measure them, make the dependency reachable (phone-core: set NOA_MOBILE_SRC, or`);
  console.log(`  check out NordenSoft/noa-mobile beside this repo / inside the workspace).`);
}

// ── RESIDUE: the worktree must be exactly as it was BEFORE the run ─────────────────────────────
// Compared against the PRE-RUN snapshot, not against emptiness. A developer legitimately has
// uncommitted work while running this; what must not change is anything the runner touched. Testing
// for a clean tree instead would make the check fire on the operator's own edits and be switched
// off, which is how a control earns the right to be ignored.
let residue = "";
try {
  const after = execFileSync("git", ["status", "--porcelain"], { cwd: ROOT, encoding: "utf8" }).trim();
  const before = new Set(WORKTREE_BEFORE.split("\n").map((l) => l.trim()).filter(Boolean));
  const introduced = after.split("\n").map((l) => l.trim()).filter(Boolean).filter((l) => !before.has(l));
  residue = introduced.join("\n");
} catch { /* not a git tree — the check below simply cannot run */ }

const bad = results.filter((r) => !PASSING.has(r.verdict));
const errors = [];
for (const r of bad) {
  errors.push(`  ${r.verdict.padEnd(26)} ${r.id} — ${r.detail || "(no detail)"}`);
}
if (residue) {
  errors.push(
    `  WORKTREE RESIDUE           the knockout run left the tree modified:\n` +
    residue.split("\n").map((l) => `      ${l}`).join("\n") +
    `\n      A knockout that cannot restore the tree has not produced a security result.`,
  );
}
for (const [key] of unmeasurable) errors.push(`  BASELINE UNMEASURABLE      ${JSON.parse(key)[0]}`);

// NO VERDICT IS NOT A PASS. Excusing an unmeasurable control is only honest while the rest of the
// gate still measures something; a run where EVERY entry was excluded has produced no security
// result at all, and exiting 0 there would report the strongest possible coverage from the weakest
// possible run. "The check could not run" and "the check passed" must never share an exit code.
if (results.length === 0 && DEPS_MISSING.length > 0) {
  errors.push(
    `  NOTHING MEASURED           all ${DEPS_MISSING.length} control(s) were excluded for absent ` +
    `dependencies, so this run proves nothing. A gate that measures zero controls is not green.`,
  );
}

if (errors.length) {
  console.error(`\n${errors.length} finding(s):`);
  for (const e of errors) console.error(e);
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
