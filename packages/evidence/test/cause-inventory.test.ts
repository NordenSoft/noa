/**
 * THE CAUSE INVENTORY — what the verifier CAN refuse, measured against what it DID refuse.
 *
 * ── WHAT THE FIRST VERSION OF THIS FILE GOT WRONG ────────────────────────────────────────────────
 *
 * It scanned two files for the literal token `fail(`, treated each call site as a cause, and let a
 * cause be excused by a hand-written `UNREACHABLE` row. An adversarial reviewer took it apart in
 * four moves, and every one of them is now a test below:
 *
 *   1. `const hiddenRefusal = fail; hiddenRefusal(...)` — an ALIAS. Invisible to a text scan.
 *   2. A new cause routed through a HELPER that returns `fail(...)`. Invisible for the same reason,
 *      and not hypothetical: four distinct R8 causes already flow through one `required(reason)`
 *      call at `enrolment.ts`, so the old scan saw one cause where there are four.
 *   3. A refusal in a file that does not declare its own `fail` helper. Outside the scan entirely.
 *   4. The one that mattered. Step 14's missing-ALLOWED-receipt check was DECLARED unreachable by
 *      this file — falsely; the role chokepoint returns `receipt: null` rather than refusing, so a
 *      bundle without `allowedReceipt` reaches it. The reviewer kept the literal `fail(...)` inside
 *      an `if (false)` branch and returned ok. Cause inventory GREEN 7/7, evidence suite GREEN
 *      446/446, and a bundle missing its approval receipt verified as VALID_FULL_CHAIN.
 *
 * The root cause of all four is one mistake: coverage was decided from SOURCE TEXT. Text cannot tell
 * a live branch from a dead one, cannot follow a helper, and cannot see through a rename.
 *
 * ── WHAT IT DOES NOW ─────────────────────────────────────────────────────────────────────────────
 *
 * COVERAGE IS DECIDED BY BEHAVIOUR. Every fixture in the corpus is run and every reason the verifier
 * ACTUALLY EMITTED is recorded. A cause is covered when the running verifier produced it. Nothing
 * else counts — a `fail(...)` no fixture can reach is ABSENT, not covered, whatever the source says
 * and whatever anyone declared about it.
 *
 * The source scan survives only to answer the other half of the question — WHAT COULD have been
 * emitted — and it is now written to be hard to hide from:
 *
 *   • every `src/*.ts` file, not a two-file allowlist;
 *   • REFUSAL PRODUCERS are found by fixed point, not by name: `fail`, anything aliased to it, and
 *     any function that returns a call to one. `required` is a producer, so its four call sites are
 *     four causes;
 *   • a producer call whose reason is its own caller's parameter is a FORWARD, not a cause — the
 *     causes are that wrapper's call sites, which is what makes the four R8 rows four rows;
 *   • and a refusal that cannot execute is a hard failure of its own, so the `if (false)` move is
 *     red before coverage is even considered.
 *
 * ── THE LEDGER IS DEBT, AND IT IS NOT AN EXCUSE ──────────────────────────────────────────────────
 *
 * There is no longer an `UNREACHABLE` category, because "I reasoned that this cannot happen" is
 * exactly the claim that was false. Every cause the corpus does not produce is ABSENT: it is written
 * down, it is counted, and the set must match EXACTLY — a new one is red, and one that gains a
 * fixture must be deleted from the list. The list can only shrink.
 *
 * KNOWN LIMIT, stated plainly: a cause on the ABSENT list can still be deleted or disabled without
 * turning anything red, because nothing exercises it. That is what being unmeasured MEANS. The list
 * is the honest count of it, and the dead-refusal rule below at least stops it being disabled in
 * place while still reading like a control.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";
import { verifyEvidence, loadSchemas } from "../src/verify-evidence.js";
import { b } from "./helpers/bytes.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const CONF = join(HERE, "..", "..", "conformance");
const SRC = join(HERE, "..", "..", "src");
const schemas = loadSchemas();

interface Fixture {
  expectVerdict: string; expectStep: string | null; expectCode: string | null;
  now: string; maxAgeHours: number; bundle: unknown;
  tenantRoot: Record<string, unknown>; checkpointKeyring: Record<string, unknown>;
  enrolmentRegistries?: unknown[]; audience?: string; purpose?: "audit" | "authorize";
}

/** A call site that supplies the REASON TEXT of a refusal. */
interface Cause {
  file: string;
  line: number;
  /** The static code where one is known (directly, or from the wrapper that carries it). */
  code: string;
  /** Literal fragments of the reason, in order. `null` when the reason carries no literal at all. */
  segments: string[] | null;
  expr: string;
  /** The producer this call went through — `fail` directly, or the wrapper's name. */
  via: string;
}

const srcFiles = (): string[] =>
  readdirSync(SRC).filter((f) => f.endsWith(".ts") && !f.endsWith(".d.ts")).sort();

// ── ENUMERATION ─────────────────────────────────────────────────────────────────────────────────

function literalSegments(node: ts.Node): string[] | null {
  if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) return [node.text];
  if (ts.isTemplateExpression(node)) {
    return [node.head.text, ...node.templateSpans.map((s) => s.literal.text)].filter((s) => s.length > 0);
  }
  if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.PlusToken) {
    const l = literalSegments(node.left);
    const r = literalSegments(node.right);
    if (l === null || r === null) return null;
    if (l.length === 0 || r.length === 0) return [...l, ...r];
    return [...l.slice(0, -1), l[l.length - 1]! + r[0]!, ...r.slice(1)];
  }
  if (ts.isParenthesizedExpression(node)) return literalSegments(node.expression);
  return null;
}

/** The function-like node that lexically encloses a node, if any. */
function enclosingFunction(node: ts.Node): ts.SignatureDeclaration | null {
  for (let p: ts.Node | undefined = node.parent; p; p = p.parent) {
    if (ts.isFunctionDeclaration(p) || ts.isArrowFunction(p) || ts.isFunctionExpression(p) || ts.isMethodDeclaration(p)) return p;
  }
  return null;
}

/** The name a function-like node is bound to (`function f()` or `const f = () => …`). */
function boundName(fn: ts.Node): string | null {
  if (ts.isFunctionDeclaration(fn) && fn.name) return fn.name.text;
  const p = fn.parent;
  if (p && ts.isVariableDeclaration(p) && ts.isIdentifier(p.name)) return p.name.text;
  return null;
}

interface Producer {
  /** Which argument carries the reason text. */
  reasonArg: number;
  /** The static code every call through this producer reports, when there is one. */
  code: string | null;
}

interface Parsed { file: string; sf: ts.SourceFile }

/** Is this call the direct value of a `return`, or of a concise arrow body? */
function isDirectlyReturned(call: ts.CallExpression): boolean {
  const p = call.parent;
  if (!p) return false;
  if (ts.isReturnStatement(p)) return true;
  if (ts.isArrowFunction(p) && p.body === call) return true;
  return false;
}

/**
 * Which parameter, if any, CARRIES the reason — as opposed to merely decorating it.
 *
 * Deliberately narrow, and the narrowness is the point. `required` builds its reason as
 * `` `${reason} (R8)` `` — the parameter IS the reason, with a suffix. `roleReceipt` builds
 * `` `${r.reason} [consumed by ${consumer}]` `` — `consumer` appears, but the reason comes from
 * somewhere else entirely and `consumer` is a label inside it. An "any parameter mentioned" rule
 * made every `roleReceipt(ctx, "allowedReceipt", S)` call look like a refusal cause whose reason was
 * the identifier `S`, which is how this scan first reported seventeen unreadable causes that are not
 * causes at all.
 */
function reasonCarrierParam(reasonExpr: ts.Expression, params: readonly (string | null)[]): number {
  if (ts.isIdentifier(reasonExpr)) return params.indexOf(reasonExpr.text);
  if (ts.isTemplateExpression(reasonExpr) && reasonExpr.head.text === "") {
    const first = reasonExpr.templateSpans[0]?.expression;
    if (first && ts.isIdentifier(first)) return params.indexOf(first.text);
  }
  return -1;
}

/**
 * REFUSAL PRODUCERS, by fixed point.
 *
 * Seeded with any function named `fail`, then repeatedly extended with (a) identifiers aliased to a
 * producer and (b) any function whose body returns a call to a producer. The reason argument index
 * is DERIVED, not assumed: it is the position of the parameter that the inner call passes into the
 * producer's own reason slot, so a wrapper that renames or reorders its parameters is still tracked.
 */
function findProducers(parsed: Parsed[]): Map<string, Producer> {
  const producers = new Map<string, Producer>();
  for (const { sf } of parsed) {
    const walk = (n: ts.Node): void => {
      if (ts.isFunctionDeclaration(n) && n.name?.text === "fail") {
        const idx = n.parameters.findIndex((p) => ts.isIdentifier(p.name) && p.name.text === "reason");
        producers.set("fail", { reasonArg: idx >= 0 ? idx : n.parameters.length - 1, code: null });
      }
      ts.forEachChild(n, walk);
    };
    walk(sf);
  }
  assert.ok(producers.has("fail"), "no `fail` refusal helper was found in src/ — this scan is measuring nothing");

  for (let pass = 0; pass < 8; pass += 1) {
    const before = producers.size;
    for (const { sf } of parsed) {
      const walk = (n: ts.Node): void => {
        // (a) ALIAS — `const hiddenRefusal = fail;`
        if (ts.isVariableDeclaration(n) && ts.isIdentifier(n.name) && n.initializer && ts.isIdentifier(n.initializer)) {
          const target = producers.get(n.initializer.text);
          if (target && !producers.has(n.name.text)) producers.set(n.name.text, { ...target });
        }
        // (b) WRAPPER — a function that RETURNS a producer call and passes its own parameter in as
        //     the reason. Both halves are required: `roleReceipt` mentions a parameter inside a
        //     reason it did not author and returns an object, and it is not a reason-forwarder.
        if (ts.isCallExpression(n) && ts.isIdentifier(n.expression) && producers.has(n.expression.text) && isDirectlyReturned(n)) {
          const inner = producers.get(n.expression.text)!;
          const fn = enclosingFunction(n);
          const name = fn ? boundName(fn) : null;
          if (fn && name && !producers.has(name)) {
            const reasonExpr = n.arguments[inner.reasonArg];
            if (reasonExpr) {
              const params = fn.parameters.map((p) => (ts.isIdentifier(p.name) ? p.name.text : null));
              const carried = reasonCarrierParam(reasonExpr, params);
              if (carried >= 0) {
                const codeArg = n.arguments[1];
                producers.set(name, {
                  reasonArg: carried,
                  code: codeArg && ts.isStringLiteral(codeArg) ? codeArg.text : inner.code,
                });
              }
            }
          }
        }
        ts.forEachChild(n, walk);
      };
      walk(sf);
    }
    if (producers.size === before) break;
  }
  return producers;
}

function enumerateCauses(parsed: Parsed[], producers: Map<string, Producer>): Cause[] {
  const causes: Cause[] = [];
  for (const { file, sf } of parsed) {
    const walk = (n: ts.Node): void => {
      if (ts.isCallExpression(n) && ts.isIdentifier(n.expression) && producers.has(n.expression.text)) {
        const prod = producers.get(n.expression.text)!;
        const reasonExpr = n.arguments[prod.reasonArg];
        if (reasonExpr) {
          // A FORWARD, not a cause: this call is inside a wrapper and is passing that wrapper's own
          // parameter through. The causes are the wrapper's call sites, counted separately.
          const fn = enclosingFunction(n);
          const enclosingName = fn ? boundName(fn) : null;
          const isForward =
            !!enclosingName && producers.has(enclosingName) && enclosingName !== n.expression.text &&
            reasonCarrierParam(reasonExpr, fn!.parameters.map((p) => (ts.isIdentifier(p.name) ? p.name.text : null))) >= 0;
          if (!isForward) {
            const codeArg = n.arguments[1];
            causes.push({
              file,
              line: sf.getLineAndCharacterOfPosition(n.getStart(sf)).line + 1,
              code: n.expression.text === "fail" && codeArg && ts.isStringLiteral(codeArg)
                ? codeArg.text
                : (prod.code ?? "<dynamic>"),
              segments: literalSegments(reasonExpr),
              expr: reasonExpr.getText(sf).replace(/\s+/g, " ").slice(0, 100),
              via: n.expression.text,
            });
          }
        }
      }
      ts.forEachChild(n, walk);
    };
    walk(sf);
  }
  return causes;
}

const PARSED: Parsed[] = srcFiles().map((file) => ({
  file,
  sf: ts.createSourceFile(file, readFileSync(join(SRC, file), "utf8"), ts.ScriptTarget.ES2022, true),
}));
const PRODUCERS = findProducers(PARSED);
const CAUSES = enumerateCauses(PARSED, PRODUCERS);
const at = (c: Cause) => `src/${c.file}:${c.line}`;

// ── THE CORPUS, RUN ONCE — THIS IS WHAT DECIDES COVERAGE ────────────────────────────────────────

interface Produced { fixture: string; code: string | undefined; reason: string }

const PRODUCED: Produced[] = (() => {
  const out: Produced[] = [];
  for (const slug of readdirSync(CONF)) {
    const abs = join(CONF, slug);
    if (!statSync(abs).isDirectory()) continue;
    for (const f of readdirSync(abs)) {
      if (!f.endsWith(".json")) continue;
      const fx = JSON.parse(readFileSync(join(abs, f), "utf8")) as Fixture;
      const res = verifyEvidence(b(fx.bundle), {
        tenantRoot: b(fx.tenantRoot),
        checkpointKeyring: b(fx.checkpointKeyring),
        ...(fx.enrolmentRegistries !== undefined ? { enrolmentRegistries: fx.enrolmentRegistries.map((r) => b(r)) } : {}),
        ...(fx.audience !== undefined ? { audience: fx.audience } : {}),
        ...(fx.purpose !== undefined ? { purpose: fx.purpose } : {}),
        now: fx.now, maxAgeMs: fx.maxAgeHours * 60 * 60 * 1000, schemas,
      });
      if (res.reason) out.push({ fixture: `${slug}/${f}`, code: res.code, reason: res.reason });
    }
  }
  return out;
})();

function carries(segments: readonly string[], reason: string): boolean {
  let from = 0;
  for (const seg of segments) {
    const i = reason.indexOf(seg, from);
    if (i < 0) return false;
    from = i + seg.length;
  }
  return true;
}

/** The fixtures that actually made the verifier emit this cause. Behaviour, not text. */
function evidenceFor(c: Cause): Produced[] {
  if (c.segments === null) return [];
  return PRODUCED.filter(
    (p) => (c.code === "<dynamic>" || p.code === c.code) && carries(c.segments!, p.reason),
  );
}

// ── THE LEDGER: causes the corpus does not produce. DEBT, not permission. ───────────────────────

interface Absent { code: string; fragment: string; why: string }

const ABSENT: readonly Absent[] = [
  // Bundle/artifact presence guards. The container schema makes most of these members mandatory, so
  // reaching them needs a bundle the ingest boundary already refuses — but "needs" is a claim, and
  // the Step 14 row that used to sit here was FALSE, so none of them is written as a fact any more.
  { code: "E_BUNDLE_SHAPE", fragment: "a mandatory artifact is missing or not an object", why: "step 0 re-reads members the container schema requires" },
  { code: "E_BUNDLE_SHAPE", fragment: "delegation/manifest/envelope missing", why: "step 1 re-reads members the container schema requires" },
  { code: "E_ENVELOPE_BINDING", fragment: "holdEnvelope missing", why: "step 2 re-reads a mandatory member" },
  { code: "E_HOLD_RESOLUTION", fragment: "holdResolution/holdEnvelope missing", why: "step 3 re-reads members its outcomes require" },
  { code: "E_VERDICT_BINDING", fragment: "deferredReceipt missing", why: "step 6 re-reads the genesis receipt" },
  { code: "E_TENANT_MISMATCH", fragment: "holdEnvelope.tenant missing", why: "the holdEnvelope schema requires tenant" },
  { code: "E_HOLD_ENVELOPE", fragment: "keyManifest.keys is not an array", why: "the keyManifest schema requires an array" },
  { code: "E_EXECUTED", fragment: "EXECUTED requires grant+consumption+executedReceipt+allowedReceipt", why: "the EXECUTED row of the container schema plus the role chokepoint" },
  { code: "E_EXECUTION_FAILED", fragment: "EXECUTION_FAILED requires grant+consumption+failedReceipt+allowedReceipt", why: "the EXECUTION_FAILED row of the same schema" },
  { code: "E_UNKNOWN", fragment: "UNKNOWN_AFTER_DISPATCH requires grant+executionUncertainty", why: "the UNKNOWN_AFTER_DISPATCH row of the same schema" },
  { code: "E_GRANT_EXPIRED", fragment: "GRANT_EXPIRED requires grant+allowedReceipt", why: "the GRANT_EXPIRED row of the same schema" },
  { code: "E_APPROVED_NO_EXEC", fragment: "APPROVED_NO_EXECUTION_EVIDENCE requires the Hold Resolution", why: "the APPROVED_NO_EXECUTION_EVIDENCE row of the same schema" },
  { code: "<dynamic>", fragment: "no executionConsumption to read a result from", why: "both callers prove the consumption present first" },
  { code: "<dynamic>", fragment: "grant/consumption missing for the G5 expiry check", why: "both callers prove both present first" },
  { code: "<dynamic>", fragment: "outcome carries no executionGrant to bind", why: "every caller proves the grant present first" },
  { code: "E_APPROVER_ROLE", fragment: "no authenticated decisionArtifact snapshot", why: "step 5 runs only after step 4 stored the snapshot; the pipeline-order test owns this" },
  { code: "E_SETTLEMENT_BINDING", fragment: "cannot read the verifier's own tenant/chain", why: "step 0 establishes both before any settlement artifact is read" },
  { code: "E_TEMPORAL_AUTH", fragment: "verifier-owned now is unparseable", why: "the ingest boundary refuses an unparseable now; immutable-ingest-boundary.test.ts owns it" },

  // Reachable and simply unmeasured. Every row is a rule that can be deleted today without turning
  // this corpus red.
  { code: "E_TENANT_MISMATCH", fragment: "checkpoint.chain (", why: "a checkpoint whose chain differs from the deferred receipt's scope.chain" },
  { code: "E_HOLD_RESOLUTION", fragment: "holdResolution.receivedAt unreadable", why: "an unreadable receivedAt on the resolution" },
  { code: "E_DELEGATION_CHAIN", fragment: "keyDelegation.permissions lacks key-manifest-sign", why: "a delegation used for a permission it does not carry" },
  { code: "E_DELEGATION_CHAIN", fragment: "keyDelegation not valid at holdResolution.receivedAt", why: "the delegation window does not contain the decision instant" },
  { code: "E_DELEGATION_CHAIN", fragment: "cannot evaluate verifier-controlled now", why: "an unparseable verifier now on the delegated-signer path" },
  { code: "E_DELEGATION_CHAIN", fragment: "delegated manifest signer is not authorized at verifier-controlled now", why: "the delegated signer's authority has lapsed by the verifier's clock" },
  { code: "E_DELEGATION_CHAIN", fragment: "is AFTER keyDelegation.expiresAt", why: "a manifest stamped after its delegation lapsed" },
  { code: "E_HOLD_ENVELOPE", fragment: "keyManifest not current at receivedAt", why: "a manifest whose window excludes the decision instant" },
  { code: "E_HOLD_ENVELOPE", fragment: "reject-only window", why: "the reject-only manifest window against the verifier's now" },
  { code: "E_HOLD_ENVELOPE", fragment: "holdEnvelope.keyManifestVersion", why: "an envelope naming another manifest version" },
  { code: "E_HOLD_ENVELOPE", fragment: "holdEnvelope.keyManifestHash != refHash(keyManifest)", why: "an envelope bound to a different manifest by hash" },
  { code: "E_ENVELOPE_BINDING", fragment: "holdEnvelope.deferredReceiptId != deferredReceipt.id", why: "the id half of F1 rule-a" },
  { code: "E_HOLD_RESOLUTION", fragment: "holdResolution invalid: ", why: "a resolution failing its own artifact verification" },
  { code: "E_HOLD_RESOLUTION", fragment: "holdResolution.holdEnvelopeHash != refHash(holdEnvelope)", why: "a resolution bound to a different envelope" },
  { code: "E_HOLD_RESOLUTION", fragment: "holdResolution manifest version/hash != envelope's", why: "a resolution disagreeing with the envelope" },
  { code: "E_HOLD_RESOLUTION", fragment: "holdResolution.decisionArtifactHash != refHash(decisionArtifact)", why: "a resolution bound to a different decision" },
  { code: "E_HOLD_RESOLUTION", fragment: "but no decisionArtifact is present in the bundle", why: "a resolution naming a decision the bundle lacks" },
  { code: "E_HOLD_RESOLUTION", fragment: "holdResolution.verdictReceiptHash != verdict receipt chain.hash (G4)", why: "the G4 resolution-to-verdict binding" },
  { code: "E_HOLD_RESOLUTION", fragment: "CANCELLED with no pre-crash ALLOWED receipt requires verdictReceiptHash == null", why: "a CANCELLED resolution naming a verdict receipt" },
  { code: "E_DECISION", fragment: "decisionArtifact is not a JSON object", why: "a decision artifact parsing to a non-object" },
  { code: "E_DECISION", fragment: "DENIED outcome requires decision=DENY, got ", why: "the DENIED half of decision polarity" },
  { code: "E_APPROVER_ROLE", fragment: "decision.approverKid != decision.sig.kid", why: "a decision signed by a key other than the approver it names" },
  { code: "E_APPROVER_ROLE", fragment: "!= decision approverKid", why: "a verdict receipt signed by a non-approver" },
  { code: "E_APPROVER_ROLE", fragment: "not an APPROVER in the manifest", why: "an approver kid absent from the manifest" },
  { code: "E_APPROVER_ROLE", fragment: "action HIGH needs approve-high|approve-critical", why: "the HIGH tier of the approver ladder" },
  { code: "E_VERDICT_BINDING", fragment: "verdict receipt scope.chain != deferred scope.chain", why: "a verdict receipt from another chain" },
  { code: "E_DENIED", fragment: "DENIED requires a bound DENY Decision Artifact", why: "a DENIED outcome whose decision is not bound" },
  { code: "E_EXPIRED", fragment: "EXPIRED outcome requires timeoutReceipt", why: "an EXPIRED outcome with no timeout receipt" },
  { code: "E_EXPIRED", fragment: "timeoutReceipt.agent.principal != POLICY", why: "a timeout receipt not attributed to the policy signer" },
  { code: "E_EXPIRED", fragment: "holdResolution.status != EXPIRED", why: "an EXPIRED outcome whose resolution disagrees" },
  { code: "E_CANCELLED", fragment: "holdResolution.status != CANCELLED", why: "a CANCELLED outcome whose resolution disagrees" },
  { code: "<dynamic>", fragment: "carries an executionGrant but no allowedReceipt", why: "a grant with no approval receipt to trace to" },
  { code: "E_EXECUTED", fragment: "executionConsumption invalid: ", why: "a consumption failing its own verification, EXECUTED path" },
  { code: "E_EXECUTION_FAILED", fragment: "executionConsumption invalid: ", why: "the same, EXECUTION_FAILED path" },
  { code: "E_EXECUTED", fragment: "executedReceipt.chain.prevHash != allowedReceipt.chain.hash", why: "an executed receipt not chained onto the approval" },
  { code: "E_EXECUTION_FAILED", fragment: "failedReceipt.chain.prevHash != allowedReceipt.chain.hash", why: "a failed receipt not chained onto the approval" },
  { code: "E_EXECUTION_FAILED", fragment: "grant not issued before the failure", why: "a grant issued after the failure it authorized" },
  { code: "E_UNKNOWN", fragment: "executionUncertainty invalid: ", why: "an uncertainty artifact failing its own verification" },
  { code: "E_UNKNOWN", fragment: "uncertainty.grantHash != refHash(grant)", why: "the UNKNOWN sibling of the step-10/11 grant binding" },
  { code: "E_UNKNOWN", fragment: "uncertainty.lastKnownState != DISPATCH_STARTED", why: "an uncertainty claiming another state" },
  { code: "E_UNKNOWN", fragment: "uncertainty.reason != PROCESS_CRASH_BEFORE_RECEIPT_COMMIT", why: "an uncertainty claiming another cause" },
  { code: "E_UNKNOWN", fragment: "uncertainty missing required bootId/uptimeResetAt (G3)", why: "the G3 liveness fields absent" },
  { code: "E_CHECKPOINT_RECONCILE", fragment: "chain is not genesis-rooted", why: "a chain whose first receipt is not seq 0" },
  { code: "E_CHECKPOINT_RECONCILE", fragment: "checkpoint structurally invalid: ", why: "a checkpoint failing its structural check" },
  { code: "E_CHECKPOINT_RECONCILE", fragment: "checkpoint signing key is retired", why: "a checkpoint signed by a retired key" },
  { code: "E_RECEIPT_ROLE", fragment: "but no step routed it through the receipt-role chokepoint", why: "the step-19 unrouted-receipt sweep" },
  // FOUND BY THE HELPER-AWARE SCAN, and invisible to every earlier version of this file: the four R8
  // causes share one `required(...)` callsite, so a scan that counted `fail(` sites saw one cause and
  // credited all four to whichever fixture reached any of them.
  { code: "E_SETTLEMENT_REQUIRED", fragment: "does not determinately assert a settlement for this approval", why: "R8 with an artifact whose reconciler code is non-determinate under an enrolled class — the one of the four R8 branches with no vector" },
];

/** A refusal whose reason carries no literal of its own. Declared, with where its causes ARE measured. */
const RELAYS: readonly { code: string; expr: string; why: string }[] = [
  { code: "E_DECISION", expr: "dParsed.reason", why: "the decision artifact's own parse refusal; its causes belong to the parser" },
  { code: "E_TEMPORAL_AUTH", expr: "err", why: "the temporal sub-check builds its own reason; branches pinned by test/authorization-window.test.ts" },
];

// ── THE PROPERTIES ──────────────────────────────────────────────────────────────────────────────

test("the scan sees the whole verifier — every src file, and refusals reached through helpers", () => {
  assert.ok(PARSED.length >= 8, `expected the verifier to span several files, parsed ${PARSED.length}`);
  assert.ok(CAUSES.length >= 120, `expected many refusal causes, enumerated ${CAUSES.length}`);
  assert.ok(PRODUCED.length >= 90, `expected most of the corpus to produce a reason, collected ${PRODUCED.length}`);
  assert.ok(new Set(PRODUCED.map((p) => p.reason)).size >= 60, "too few distinct reasons to measure anything");

  // THE HELPER CASE, pinned by name because it is the one that got past the old scan. `required` is
  // reached only through `fail`, and four separate R8 causes go through it — so a scan that counted
  // call sites of `fail` saw ONE cause where there are FOUR.
  assert.ok(PRODUCERS.has("required"), "the `required` wrapper in enrolment.ts is not recognised as a refusal producer");
  const viaRequired = CAUSES.filter((c) => c.via === "required");
  assert.equal(
    viaRequired.length, 4,
    `expected four R8 causes through the required() helper, found ${viaRequired.length}. If a branch was ` +
      `added or removed this number moves, and the ledger below moves with it.`,
  );
});

test("NO REFUSAL IS DEAD CODE — a control that cannot execute is not a control", () => {
  // THE REVIEWER'S BYPASS, closed at the root. The move was to keep the literal `fail(...)` in the
  // source, inside `if (false)`, and return ok — so a text scan still saw a refusal that could never
  // run, and a bundle missing its approval receipt verified as VALID_FULL_CHAIN.
  //
  // Any statically-false guard is refused, anywhere in the verifier, whether or not it wraps a
  // refusal. There is no legitimate reason for one to exist in this code, and treating it as a
  // whole-file rule means the next variant does not need to be anticipated.
  const dead: string[] = [];
  const isConstFalse = (e: ts.Expression): boolean => {
    if (e.kind === ts.SyntaxKind.FalseKeyword) return true;
    if (ts.isNumericLiteral(e) && Number(e.text) === 0) return true;
    if (ts.isStringLiteral(e) && e.text === "") return true;
    if (ts.isPrefixUnaryExpression(e) && e.operator === ts.SyntaxKind.ExclamationToken) {
      return e.operand.kind === ts.SyntaxKind.TrueKeyword;
    }
    if (ts.isParenthesizedExpression(e)) return isConstFalse(e.expression);
    if (ts.isBinaryExpression(e) && e.operatorToken.kind === ts.SyntaxKind.AmpersandAmpersandToken) {
      return isConstFalse(e.left) || isConstFalse(e.right);
    }
    return false;
  };
  for (const { file, sf } of PARSED) {
    const walk = (n: ts.Node): void => {
      const cond =
        ts.isIfStatement(n) ? n.expression
          : ts.isWhileStatement(n) ? n.expression
            : ts.isConditionalExpression(n) ? n.condition
              : null;
      if (cond && isConstFalse(cond)) {
        dead.push(`src/${file}:${sf.getLineAndCharacterOfPosition(n.getStart(sf)).line + 1}  ${n.getText(sf).replace(/\s+/g, " ").slice(0, 100)}`);
      }
      ts.forEachChild(n, walk);
    };
    walk(sf);
  }
  assert.deepEqual(
    dead, [],
    `these branches can never execute:\n  ${dead.join("\n  ")}\n` +
      `A refusal behind a constant-false guard reads in review as a control and enforces nothing. This ` +
      `is the exact shape an adversarial reviewer used to make Step 14 accept a bundle with no ALLOWED ` +
      `receipt while every gate stayed green.`,
  );
});

test("EVERY refusal cause the corpus does not produce is declared ABSENT — and the set matches exactly", () => {
  // COVERAGE IS BEHAVIOUR. `evidenceFor` reports the fixtures that made the verifier actually emit
  // this reason; source text decides nothing here.
  const uncovered = CAUSES.filter((c) => c.segments !== null && evidenceFor(c).length === 0);

  const undeclared: string[] = [];
  for (const c of uncovered) {
    const rows = ABSENT.filter((d) => d.code === c.code && c.segments!.join(" ").includes(d.fragment));
    if (rows.length === 0) undeclared.push(`${at(c)}  ${c.code}  via ${c.via}  ${JSON.stringify(c.segments!.join(" … ").slice(0, 110))}`);
  }
  assert.deepEqual(
    undeclared, [],
    `these refusal causes are produced by NO fixture and are declared nowhere:\n  ${undeclared.join("\n  ")}\n` +
      `Each can be deleted today without turning this suite red. Give it a vector, or add it to ABSENT ` +
      `— which is a DEBT list, not permission. Do not widen an existing fragment to absorb it.`,
  );

  // THE RATCHET, the other way. Debt that has been paid may not stay on the books, so the list can
  // only shrink through real work and can never quietly excuse a rule a fixture already reaches.
  const paid: string[] = [];
  for (const d of ABSENT) {
    const matched = CAUSES.filter((c) => c.segments !== null && c.code === d.code && c.segments.join(" ").includes(d.fragment));
    assert.equal(
      matched.length, 1,
      `ABSENT row ${d.code} ${JSON.stringify(d.fragment)} matches ${matched.length} cause(s) — a row must name ` +
        `exactly one, or it is excusing a rule nobody considered (or describing one that is gone).`,
    );
    if (evidenceFor(matched[0]!).length > 0) paid.push(`${d.code} ${JSON.stringify(d.fragment)} → now produced by ${evidenceFor(matched[0]!)[0]!.fixture}`);
  }
  assert.deepEqual(paid, [], `these ABSENT rows are stale — the cause now HAS a vector:\n  ${paid.join("\n  ")}\nDelete the row.`);
});

test("every reason this scan cannot read is a DECLARED relay", () => {
  const unreadable = CAUSES.filter((c) => c.segments === null).map((c) => ({ code: c.code, expr: c.expr, at: at(c) }));
  const undeclared = unreadable.filter((u) => !RELAYS.some((r) => r.code === u.code && r.expr === u.expr));
  assert.deepEqual(
    undeclared, [],
    `refusals whose reason this scan cannot read, and which are not declared relays: ` +
      `${undeclared.map((u) => `${u.at} ${u.code} ${u.expr}`).join("; ")}`,
  );
  const stale = RELAYS.filter((r) => !unreadable.some((u) => u.code === r.code && u.expr === r.expr));
  assert.deepEqual(stale, [], `RELAYS rows matching no site: ${stale.map((r) => `${r.code} ${r.expr}`).join("; ")}`);
});

test("no single fixture is the only evidence for two different rules", () => {
  const sole = new Map<string, Cause[]>();
  for (const c of CAUSES) {
    const ev = evidenceFor(c);
    if (ev.length !== 1) continue;
    sole.set(ev[0]!.fixture, [...(sole.get(ev[0]!.fixture) ?? []), c]);
  }
  const doubled = [...sole].filter(([, cs]) => cs.length > 1);
  assert.deepEqual(
    doubled.map(([f, cs]) => `${f} → ${cs.map(at).join(" + ")}`), [],
    "one fixture is the sole evidence for more than one rule — either they are one cause with two " +
      "messages, or one rule's text is a substring of the other's and is credited for a bundle it never refused.",
  );
});
