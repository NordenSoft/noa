/**
 * THE CAUSE INVENTORY — read out of the IMPLEMENTATION, not out of a list somebody keeps.
 *
 * ── THE DEFECT THIS FILE MEASURES, AND WHY ITS SIBLING WAS NOT ENOUGH ────────────────────────────
 *
 * `code-cause-pinning.test.ts` promises "one vector per cause" in its header and enforces something
 * much weaker in its property 3: every member of the `StepCode` UNION appears in some fixture's
 * metadata. A code is not a cause. `E_EXECUTION_FAILED` is produced by eight different rules, so one
 * fixture satisfies the union check for all eight, and the other seven are unmeasured while reading
 * in review as covered.
 *
 * That is not a hypothetical. It was measured on this branch: deleting the step-11 line
 *
 *     if (asStr(consumption.grantHash) !== refHash(b.executionGrant)) return fail(...)
 *
 * — the rule that ties an execution consumption to the grant it actually consumed — left the whole
 * evidence suite GREEN at 423/423, including all 116 process-boundary fixtures. A verifier that
 * accepts a gate-signed `EXECUTION_FAILED` consumption naming a DIFFERENT execution grant passed
 * every test in this repository.
 *
 * Adding one fixture for that line closes that line. It closes nothing else: the next binding
 * written without a vector is invisible in exactly the same way. So this file measures the CLASS.
 *
 * ── WHAT IT DOES ─────────────────────────────────────────────────────────────────────────────────
 *
 * The refusal causes are ENUMERATED FROM THE SOURCE with the TypeScript parser — every `fail(...)`
 * call site in the two files that hold this verifier's step rules, with the literal segments of its
 * reason string. Then every conformance fixture is run and its reason recorded. A cause is COVERED
 * when some fixture's reason carries that site's literal segments, in order, under that site's code.
 *
 * Every cause must then be one of three things, and there is no fourth:
 *
 *   COVERED     a fixture in the corpus produces it.
 *   UNREACHABLE declared below, with the earlier rule that makes it unreachable named. If a fixture
 *               ever DOES reach it, this file goes red — "I thought that was dead" is a claim, and
 *               it is measured like any other.
 *   NO_VECTOR   declared below: reachable, and no vector exercises it. This is DEBT, written down in
 *               the repository instead of hiding behind a green suite.
 *
 * A cause that is none of the three fails this test AND NAMES ITSELF. That is the property that was
 * missing: adding a security binding with no fixture is now red on the commit that adds it.
 *
 * ── THE RATCHET, WHICH IS WHAT KEEPS THE DECLARATIONS HONEST ─────────────────────────────────────
 *
 * A declaration list that only ever grows is the hand-kept list this file exists to replace. Three
 * rules stop that:
 *
 *   1. A declared row whose cause IS covered is RED. Debt that has been paid must be deleted from
 *      the ledger, so the ledger can only shrink through real work — it cannot go stale downward.
 *   2. A declared row that matches NO site, or more than one, is RED. A rule that is deleted or
 *      reworded takes its declaration with it instead of leaving a row that excuses a different one.
 *   3. The declarations are keyed on the REASON TEXT, not on a line number, so they survive a move
 *      and break on a rewrite — which is the direction that matters.
 *
 * ── KNOWN LIMITS, stated rather than glossed ─────────────────────────────────────────────────────
 *
 *   • SHARED HELPERS ARE CREDITED ONCE. `checkGrantBinding` and friends take the code as a
 *     parameter and are called from several steps, so a site reached from step 10 counts as covered
 *     for step 11 too. The per-CALLER matrix is finer than this file measures; what it does close is
 *     the site's existence.
 *   • THE DENOMINATOR IS THE `fail(...)` HELPER. The ingest boundary in `verify-evidence.ts` builds
 *     its refusals as object literals and is measured by `immutable-ingest-boundary.test.ts`
 *     instead. To stop a THIRD rule file appearing outside this scan, the last test below asserts
 *     that exactly the two scanned files declare a `fail(` helper.
 *   • A SITE WHOSE TEXT IS A SUBSTRING of a sibling's under the same code could be credited by the
 *     sibling's fixture. The last property below refuses that: no single fixture may be the only
 *     evidence for two different sites.
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

/** The two files that hold this verifier's step rules. Pinned, and the last test guards the pin. */
const RULE_FILES = ["steps.ts", "enrolment.ts"] as const;

interface Fixture {
  expectVerdict: string; expectStep: string | null; expectCode: string | null;
  now: string; maxAgeHours: number; bundle: unknown;
  tenantRoot: Record<string, unknown>; checkpointKeyring: Record<string, unknown>;
  enrolmentRegistries?: unknown[]; audience?: string; purpose?: "audit" | "authorize";
}

/** One `fail(...)` call site. `segments` is null when the reason is not a literal — see RELAYS. */
interface Site {
  file: string;
  line: number;
  /** The static code, or `<dynamic>` when the enclosing helper takes it as a parameter. */
  code: string;
  segments: string[] | null;
  /** The reason expression as written, for the RELAYS declaration and for error messages. */
  expr: string;
}

// ── ENUMERATION ─────────────────────────────────────────────────────────────────────────────────

/**
 * The literal parts of a reason expression, in order. `${…}` holes are dropped: what survives is
 * the text the rule ALWAYS emits, which is what a produced reason can be matched against.
 * Returns null for an expression that carries no literal of its own (a relayed reason).
 */
function literalSegments(node: ts.Node): string[] | null {
  if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) return [node.text];
  if (ts.isTemplateExpression(node)) {
    return [node.head.text, ...node.templateSpans.map((s) => s.literal.text)].filter((s) => s.length > 0);
  }
  if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.PlusToken) {
    const left = literalSegments(node.left);
    const right = literalSegments(node.right);
    if (left === null || right === null) return null;
    if (left.length === 0 || right.length === 0) return [...left, ...right];
    // The join is CONTIGUOUS text, so the two halves either side of the `+` become one segment.
    return [...left.slice(0, -1), left[left.length - 1]! + right[0]!, ...right.slice(1)];
  }
  if (ts.isParenthesizedExpression(node)) return literalSegments(node.expression);
  return null;
}

function enumerateSites(): Site[] {
  const sites: Site[] = [];
  for (const file of RULE_FILES) {
    const text = readFileSync(join(SRC, file), "utf8");
    const sf = ts.createSourceFile(file, text, ts.ScriptTarget.ES2022, true);
    const walk = (n: ts.Node): void => {
      if (ts.isCallExpression(n) && ts.isIdentifier(n.expression) && n.expression.text === "fail" && n.arguments.length >= 3) {
        const codeNode = n.arguments[1]!;
        const reasonNode = n.arguments[2]!;
        sites.push({
          file,
          line: sf.getLineAndCharacterOfPosition(n.getStart(sf)).line + 1,
          code: ts.isStringLiteral(codeNode) ? codeNode.text : "<dynamic>",
          segments: literalSegments(reasonNode),
          expr: reasonNode.getText(sf).replace(/\s+/g, " ").slice(0, 100),
        });
      }
      ts.forEachChild(n, walk);
    };
    walk(sf);
  }
  return sites;
}

const SITES = enumerateSites();
const at = (s: Site) => `src/${s.file}:${s.line}`;

// ── THE CORPUS, RUN ONCE ────────────────────────────────────────────────────────────────────────

interface Produced { fixture: string; code: string | undefined; reason: string }

function runCorpus(): Produced[] {
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
        now: fx.now,
        maxAgeMs: fx.maxAgeHours * 60 * 60 * 1000,
        schemas,
      });
      if (res.reason) out.push({ fixture: `${slug}/${f}`, code: res.code, reason: res.reason });
    }
  }
  return out;
}

const PRODUCED = runCorpus();

/** Every literal segment appears, in order, in the produced reason. */
function carries(segments: readonly string[], reason: string): boolean {
  let from = 0;
  for (const seg of segments) {
    const i = reason.indexOf(seg, from);
    if (i < 0) return false;
    from = i + seg.length;
  }
  return true;
}

/**
 * The fixtures that evidence a site. The CODE must agree too where the site names one statically —
 * without it `"consumption.grantHash != refHash(grant)"` (step 11) is credited by step 10's
 * `"consumption.grantHash != refHash(grant) (F1)"`, which is a different rule on a different path.
 */
function evidenceFor(site: Site): Produced[] {
  if (site.segments === null) return [];
  return PRODUCED.filter(
    (p) => (site.code === "<dynamic>" || p.code === site.code) && carries(site.segments!, p.reason),
  );
}

// ── THE DECLARATIONS ────────────────────────────────────────────────────────────────────────────

/**
 * A cause with no vector. `kind` says WHICH claim is being made, because they are different claims
 * and only one of them is debt.
 *
 *   UNREACHABLE — an earlier rule refuses every bundle that would reach this one. `why` names that
 *                 rule. The guard is a REFUSAL rather than a `null`, which is correct defensive
 *                 practice; it is unmeasurable precisely because it is unreachable.
 *   NO_VECTOR   — reachable, and no fixture exercises it. Debt. It is written here so a reader of
 *                 this repository can count it, which is the whole difference from where this
 *                 branch started.
 *
 * `fragment` identifies the site by its own text. It must match exactly one site.
 */
interface Declared {
  code: string;
  fragment: string;
  kind: "UNREACHABLE" | "NO_VECTOR";
  why: string;
}

const DECLARED: readonly Declared[] = [
  // NOTE, and it is the first thing this file proved. Four rows stood here declaring the per-outcome
  // absence rules UNREACHABLE "because step 0's union pre-rule refuses them first". That is FALSE:
  // `STEP_OWNED_ABSENCE` exempts exactly those three fields for exactly those four outcomes so the
  // owning step reports the contradiction under its own code. The ratchet below refuted the claim on
  // the one of the four that had a fixture, and the other three got the fixtures they were missing.
  // The rows are gone rather than reworded — which is what a ledger is for.

  // ── UNREACHABLE: the container schema (step 0, E_BUNDLE_SHAPE) already requires these members, so
  //    a bundle missing one never reaches the step that re-checks it. The re-check stays because a
  //    step function is exported and a downstream caller may drive it directly.
  {
    code: "E_BUNDLE_SHAPE", fragment: "a mandatory artifact is missing or not an object",
    kind: "UNREACHABLE",
    why: "the container schema refuses a bundle missing holdEnvelope/keyManifest/keyDelegation/deferredReceipt before step 0's body runs",
  },
  {
    code: "E_BUNDLE_SHAPE", fragment: "delegation/manifest/envelope missing",
    kind: "UNREACHABLE", why: "same container schema — step 1 re-reads members step 0 proved present",
  },
  {
    code: "E_ENVELOPE_BINDING", fragment: "holdEnvelope missing",
    kind: "UNREACHABLE", why: "same container schema; step 2 re-reads a mandatory member",
  },
  {
    code: "E_HOLD_RESOLUTION", fragment: "holdResolution/holdEnvelope missing",
    kind: "UNREACHABLE", why: "step 3 runs only for outcomes whose union includes holdResolution, and the envelope is mandatory",
  },
  {
    code: "E_VERDICT_BINDING", fragment: "deferredReceipt missing",
    kind: "UNREACHABLE", why: "same container schema; the deferred receipt is the genesis of the chain and mandatory",
  },
  {
    code: "E_TENANT_MISMATCH", fragment: "holdEnvelope.tenant missing",
    kind: "UNREACHABLE", why: "the holdEnvelope schema requires tenant, and the artifact is schema-checked at step 1",
  },
  {
    code: "E_HOLD_ENVELOPE", fragment: "keyManifest.keys is not an array",
    kind: "UNREACHABLE", why: "the keyManifest schema requires keys to be an array",
  },
  {
    code: "<dynamic>", fragment: "no executionConsumption to read a result from",
    kind: "UNREACHABLE",
    why: "both callers of checkConsumptionResult prove the consumption present first (steps.ts:1141, :1202); the source comment says so and this row is the measurement of that claim",
  },
  {
    code: "<dynamic>", fragment: "grant/consumption missing for the G5 expiry check",
    kind: "UNREACHABLE", why: "both callers of checkGrantUnexpiredAtConsumption prove both present first",
  },
  {
    code: "<dynamic>", fragment: "outcome carries no executionGrant to bind",
    kind: "UNREACHABLE", why: "every caller of checkGrantBinding proves the grant present first",
  },
  {
    code: "E_EXECUTED", fragment: "EXECUTED requires grant+consumption+executedReceipt+allowedReceipt",
    kind: "UNREACHABLE",
    why: "the EXECUTED row of the container schema makes all four mandatory, and the two receipts are resolved through the role chokepoint above, which refuses first",
  },
  {
    code: "E_EXECUTION_FAILED", fragment: "EXECUTION_FAILED requires grant+consumption+failedReceipt+allowedReceipt",
    kind: "UNREACHABLE", why: "the EXECUTION_FAILED row of the same schema, same chokepoint",
  },
  {
    code: "E_UNKNOWN", fragment: "UNKNOWN_AFTER_DISPATCH requires grant+executionUncertainty",
    kind: "UNREACHABLE", why: "the UNKNOWN_AFTER_DISPATCH row of the same schema",
  },
  {
    code: "E_GRANT_EXPIRED", fragment: "GRANT_EXPIRED requires grant+allowedReceipt",
    kind: "UNREACHABLE", why: "the GRANT_EXPIRED row of the same schema, plus the role chokepoint for the receipt",
  },
  {
    code: "E_APPROVED_NO_EXEC", fragment: "APPROVED_NO_EXECUTION_EVIDENCE requires the ALLOWED receipt",
    kind: "UNREACHABLE", why: "the role chokepoint resolves allowedReceipt and refuses before this line",
  },
  {
    code: "E_APPROVED_NO_EXEC", fragment: "APPROVED_NO_EXECUTION_EVIDENCE requires the Hold Resolution",
    kind: "UNREACHABLE", why: "the APPROVED_NO_EXECUTION_EVIDENCE row of the container schema makes holdResolution mandatory",
  },
  {
    code: "E_APPROVER_ROLE", fragment: "no authenticated decisionArtifact snapshot",
    kind: "UNREACHABLE",
    why: "step 5 runs only after step 4 authenticated the decision and stored the snapshot; the refusal is the fail-closed answer to a step-ordering bug, which the pipeline order test owns",
  },
  {
    code: "E_SETTLEMENT_BINDING", fragment: "cannot read the verifier's own tenant/chain",
    kind: "UNREACHABLE",
    why: "step 0 established the tenant and the genesis receipt's scope.chain before any settlement artifact is looked at; R-11's guard exists so the artifact can never supply them",
  },
  {
    code: "E_TEMPORAL_AUTH", fragment: "verifier-owned now is unparseable",
    kind: "UNREACHABLE",
    why: "verify-evidence.ts refuses an unparseable now at the ingest boundary, which immutable-ingest-boundary.test.ts measures",
  },

  // ── NO_VECTOR: reachable and unmeasured. DEBT. Every row here is a rule that can be deleted today
  //    without turning this corpus red, and that is exactly why it is written down.
  {
    code: "E_TENANT_MISMATCH", fragment: "checkpoint.chain (", kind: "NO_VECTOR",
    why: "a checkpoint whose chain differs from the deferred receipt's scope.chain",
  },
  {
    code: "E_HOLD_RESOLUTION", fragment: "holdResolution.receivedAt unreadable", kind: "NO_VECTOR",
    why: "an unreadable receivedAt on the resolution",
  },
  {
    code: "E_DELEGATION_CHAIN", fragment: "keyDelegation.permissions lacks key-manifest-sign", kind: "NO_VECTOR",
    why: "a delegation that authenticates but does not carry the permission it is being used for",
  },
  {
    code: "E_DELEGATION_CHAIN", fragment: "keyDelegation not valid at holdResolution.receivedAt", kind: "NO_VECTOR",
    why: "the delegation's window does not contain the decision instant",
  },
  {
    code: "E_DELEGATION_CHAIN", fragment: "cannot evaluate verifier-controlled now", kind: "NO_VECTOR",
    why: "an unparseable verifier now on the delegated-signer path",
  },
  {
    code: "E_DELEGATION_CHAIN", fragment: "delegated manifest signer is not authorized at verifier-controlled now", kind: "NO_VECTOR",
    why: "the delegated signer's authority has lapsed by the verifier's own clock",
  },
  {
    code: "E_DELEGATION_CHAIN", fragment: "is AFTER keyDelegation.expiresAt", kind: "NO_VECTOR",
    why: "a manifest stamped after the delegation that authorizes its signer had lapsed",
  },
  {
    code: "E_HOLD_ENVELOPE", fragment: "keyManifest not current at receivedAt", kind: "NO_VECTOR",
    why: "a manifest whose own window does not contain the decision instant",
  },
  {
    code: "E_HOLD_ENVELOPE", fragment: "reject-only window", kind: "NO_VECTOR",
    why: "the reject-only manifest window against the verifier's now",
  },
  {
    code: "E_HOLD_ENVELOPE", fragment: "holdEnvelope.keyManifestVersion", kind: "NO_VECTOR",
    why: "an envelope naming a manifest version other than the one supplied",
  },
  {
    code: "E_HOLD_ENVELOPE", fragment: "holdEnvelope.keyManifestHash != refHash(keyManifest)", kind: "NO_VECTOR",
    why: "an envelope bound to a different manifest by hash",
  },
  {
    code: "E_ENVELOPE_BINDING", fragment: "holdEnvelope.deferredReceiptId != deferredReceipt.id", kind: "NO_VECTOR",
    why: "the id half of F1 rule-a; the hash half is covered",
  },
  {
    code: "E_HOLD_RESOLUTION", fragment: "holdResolution invalid: ", kind: "NO_VECTOR",
    why: "a resolution that fails its own artifact verification",
  },
  {
    code: "E_HOLD_RESOLUTION", fragment: "holdResolution.holdEnvelopeHash != refHash(holdEnvelope)", kind: "NO_VECTOR",
    why: "a resolution bound to a different envelope",
  },
  {
    code: "E_HOLD_RESOLUTION", fragment: "holdResolution manifest version/hash != envelope's", kind: "NO_VECTOR",
    why: "a resolution disagreeing with the envelope about the manifest",
  },
  {
    code: "E_HOLD_RESOLUTION", fragment: "holdResolution.decisionArtifactHash != refHash(decisionArtifact)", kind: "NO_VECTOR",
    why: "a resolution bound to a different decision artifact",
  },
  {
    code: "E_HOLD_RESOLUTION", fragment: "but no decisionArtifact is present in the bundle", kind: "NO_VECTOR",
    why: "a resolution naming a decision the bundle does not carry",
  },
  {
    code: "E_HOLD_RESOLUTION", fragment: "holdResolution.verdictReceiptHash != verdict receipt chain.hash (G4)", kind: "NO_VECTOR",
    why: "the G4 resolution-to-verdict-receipt binding",
  },
  {
    code: "E_HOLD_RESOLUTION", fragment: "CANCELLED with no pre-crash ALLOWED receipt requires verdictReceiptHash == null", kind: "NO_VECTOR",
    why: "a CANCELLED resolution naming a verdict receipt it does not carry",
  },
  {
    code: "E_DECISION", fragment: "decisionArtifact is not a JSON object", kind: "NO_VECTOR",
    why: "a decision artifact that parses to a non-object",
  },
  {
    code: "E_DECISION", fragment: "DENIED outcome requires decision=DENY, got ", kind: "NO_VECTOR",
    why: "the DENIED half of the decision-polarity rule; the non-DENIED half is covered",
  },
  {
    code: "E_APPROVER_ROLE", fragment: "decision.approverKid != decision.sig.kid", kind: "NO_VECTOR",
    why: "a decision signed by a key other than the approver it names",
  },
  {
    code: "E_APPROVER_ROLE", fragment: "!= decision approverKid", kind: "NO_VECTOR",
    why: "a verdict receipt signed by a key other than the approver",
  },
  {
    code: "E_APPROVER_ROLE", fragment: "not an APPROVER in the manifest", kind: "NO_VECTOR",
    why: "an approver kid absent from the manifest's approver set",
  },
  {
    code: "E_APPROVER_ROLE", fragment: "action HIGH needs approve-high|approve-critical", kind: "NO_VECTOR",
    why: "the HIGH tier of the approver-role ladder; the CRITICAL tier is covered",
  },
  {
    code: "E_VERDICT_BINDING", fragment: "verdict receipt scope.chain != deferred scope.chain", kind: "NO_VECTOR",
    why: "a verdict receipt from another chain",
  },
  {
    code: "E_DENIED", fragment: "DENIED requires a bound DENY Decision Artifact", kind: "NO_VECTOR",
    why: "a DENIED outcome whose decision is not bound",
  },
  {
    code: "E_EXPIRED", fragment: "EXPIRED outcome requires timeoutReceipt", kind: "NO_VECTOR",
    why: "an EXPIRED outcome with no timeout receipt",
  },
  {
    code: "E_EXPIRED", fragment: "timeoutReceipt.agent.principal != POLICY", kind: "NO_VECTOR",
    why: "a timeout receipt not attributed to the policy signer",
  },
  {
    code: "E_EXPIRED", fragment: "holdResolution.status != EXPIRED", kind: "NO_VECTOR",
    why: "an EXPIRED outcome whose resolution says otherwise",
  },
  {
    code: "E_CANCELLED", fragment: "holdResolution.status != CANCELLED", kind: "NO_VECTOR",
    why: "a CANCELLED outcome whose resolution says otherwise",
  },
  {
    code: "<dynamic>", fragment: "carries an executionGrant but no allowedReceipt", kind: "NO_VECTOR",
    why: "a grant with no approval receipt to trace it to",
  },
  {
    code: "E_EXECUTED", fragment: "executionConsumption invalid: ", kind: "NO_VECTOR",
    why: "a consumption that fails its own artifact verification, on the EXECUTED path",
  },
  {
    code: "E_EXECUTION_FAILED", fragment: "executionConsumption invalid: ", kind: "NO_VECTOR",
    why: "the same, on the EXECUTION_FAILED path",
  },
  {
    code: "E_EXECUTED", fragment: "executedReceipt.chain.prevHash != allowedReceipt.chain.hash", kind: "NO_VECTOR",
    why: "an executed receipt that does not chain onto the approval",
  },
  {
    code: "E_EXECUTION_FAILED", fragment: "failedReceipt.chain.prevHash != allowedReceipt.chain.hash", kind: "NO_VECTOR",
    why: "a failed receipt that does not chain onto the approval",
  },
  {
    code: "E_EXECUTION_FAILED", fragment: "grant not issued before the failure", kind: "NO_VECTOR",
    why: "a grant issued after the failure it is supposed to have authorized",
  },
  {
    code: "E_UNKNOWN", fragment: "executionUncertainty invalid: ", kind: "NO_VECTOR",
    why: "an uncertainty artifact that fails its own verification",
  },
  {
    code: "E_UNKNOWN", fragment: "uncertainty.grantHash != refHash(grant)", kind: "NO_VECTOR",
    why: "the UNKNOWN_AFTER_DISPATCH sibling of the step-10/11 grant binding",
  },
  {
    code: "E_UNKNOWN", fragment: "uncertainty.lastKnownState != DISPATCH_STARTED", kind: "NO_VECTOR",
    why: "an uncertainty claiming a state other than the one this outcome is about",
  },
  {
    code: "E_UNKNOWN", fragment: "uncertainty.reason != PROCESS_CRASH_BEFORE_RECEIPT_COMMIT", kind: "NO_VECTOR",
    why: "an uncertainty claiming a cause other than the crash this outcome is about",
  },
  {
    code: "E_UNKNOWN", fragment: "uncertainty missing required bootId/uptimeResetAt (G3)", kind: "NO_VECTOR",
    why: "the G3 liveness fields absent; the inconsistent-order case IS covered",
  },
  {
    code: "E_CHECKPOINT_RECONCILE", fragment: "chain is not genesis-rooted", kind: "NO_VECTOR",
    why: "a chain whose first receipt is not seq 0 / prevHash null",
  },
  {
    code: "E_CHECKPOINT_RECONCILE", fragment: "checkpoint structurally invalid: ", kind: "NO_VECTOR",
    why: "a checkpoint that fails its own structural check",
  },
  {
    code: "E_CHECKPOINT_RECONCILE", fragment: "checkpoint signing key is retired", kind: "NO_VECTOR",
    why: "a checkpoint signed by a retired key",
  },
  {
    code: "E_RECEIPT_ROLE", fragment: "but no step routed it through the receipt-role chokepoint", kind: "NO_VECTOR",
    why: "the step-19 sweep's unrouted-receipt branch",
  },
];

/**
 * A `fail(...)` whose reason is relayed from elsewhere and carries no literal of its own. There is
 * nothing here for this file to match, so each is DECLARED with the upstream that owns its causes.
 * The set is asserted to be exactly this — a new unreadable reason expression is red.
 */
const RELAYS: readonly { code: string; expr: string; why: string }[] = [
  {
    code: "E_DECISION", expr: "dParsed.reason",
    why: "the decision artifact's own byte-boundary parse refusal; its causes belong to the parser and are measured where it is",
  },
  {
    code: "E_TEMPORAL_AUTH", expr: "err",
    why: "the temporal-authorization sub-check builds its own reason; its branches are pinned by test/authorization-window.test.ts",
  },
];

// ── THE PROPERTIES ──────────────────────────────────────────────────────────────────────────────

test("the enumeration actually found the rules — a scan that reads nothing proves nothing", () => {
  // Without this, a parser change that silently matched zero call sites would make every property
  // below vacuously true, which is the failure mode this whole file exists to prevent.
  assert.ok(SITES.length >= 120, `expected the rule files to hold many fail() sites, enumerated ${SITES.length}`);
  assert.ok(
    SITES.some((s) => s.file === "enrolment.ts"), "no sites were enumerated from enrolment.ts",
  );
  assert.ok(PRODUCED.length >= 90, `expected most of the corpus to produce a reason, collected ${PRODUCED.length}`);
  // The corpus really does discriminate: the produced reasons are not one string repeated.
  assert.ok(new Set(PRODUCED.map((p) => p.reason)).size >= 60, "the corpus produces too few distinct reasons to measure anything");
});

test("EVERY refusal cause is covered by a fixture, declared unreachable, or declared as debt", () => {
  const undeclared: string[] = [];
  for (const site of SITES) {
    if (site.segments === null) continue; // RELAYS owns these; the next test pins that set exactly.
    if (evidenceFor(site).length > 0) continue;
    const rows = DECLARED.filter((d) => d.code === site.code && site.segments!.join(" ").includes(d.fragment));
    if (rows.length === 0) {
      undeclared.push(`${at(site)}  ${site.code}  ${JSON.stringify(site.segments!.join(" … ").slice(0, 120))}`);
    }
  }
  assert.deepEqual(
    undeclared, [],
    `these refusal causes are produced by NO conformance fixture and are declared nowhere:\n  ${undeclared.join("\n  ")}\n` +
      `Each is a rule that can be DELETED today without turning this suite red. Give it a vector, or ` +
      `declare it in DECLARED with the kind and the reason. Do not widen a fragment to make an existing ` +
      `row absorb it — a row that covers two rules measures neither.`,
  );
});

test("RATCHET: a declared row whose cause IS covered must be deleted", () => {
  // The direction that keeps the ledger honest. Debt that has been paid may not stay on the books,
  // so the list can only shrink through real work — it can never quietly excuse a rule that a
  // fixture already reaches.
  const paid: string[] = [];
  for (const d of DECLARED) {
    const matched = SITES.filter((s) => s.segments !== null && s.code === d.code && s.segments.join(" ").includes(d.fragment));
    for (const site of matched) {
      const ev = evidenceFor(site);
      if (ev.length > 0) paid.push(`${d.kind} ${d.code} ${JSON.stringify(d.fragment)} → now covered by ${ev[0]!.fixture} (${at(site)})`);
    }
  }
  assert.deepEqual(
    paid, [],
    `these declarations are stale — the cause now HAS a vector:\n  ${paid.join("\n  ")}\n` +
      `Delete the row. A ledger that keeps paid debt stops being a count of what is unmeasured.` +
      (paid.some((p) => p.startsWith("UNREACHABLE"))
        ? `\nAn UNREACHABLE row appearing here is the stronger finding: a rule believed dead was reached ` +
          `by a real bundle, so the reasoning that declared it unreachable is wrong.`
        : ""),
  );
});

test("RATCHET: every declared row names exactly one live rule", () => {
  // A row matching nothing is a rule that was deleted or reworded and left its excuse behind. A row
  // matching several is a fragment wide enough to cover a rule nobody considered.
  const bad: string[] = [];
  for (const d of DECLARED) {
    const matched = SITES.filter((s) => s.segments !== null && s.code === d.code && s.segments.join(" ").includes(d.fragment));
    if (matched.length !== 1) bad.push(`${d.code} ${JSON.stringify(d.fragment)} matches ${matched.length} site(s)${matched.length > 1 ? `: ${matched.map(at).join(", ")}` : ""}`);
  }
  assert.deepEqual(bad, [], `declared rows that do not name exactly one rule:\n  ${bad.join("\n  ")}`);
});

test("every reason this scan cannot read is a DECLARED relay", () => {
  const unreadable = SITES.filter((s) => s.segments === null).map((s) => ({ code: s.code, expr: s.expr, at: at(s) }));
  const undeclared = unreadable.filter((u) => !RELAYS.some((r) => r.code === u.code && r.expr === u.expr));
  assert.deepEqual(
    undeclared, [],
    `these fail() sites pass a reason this scan cannot read, and are not declared relays: ` +
      `${undeclared.map((u) => `${u.at} ${u.code} ${u.expr}`).join("; ")}. Either write the reason as a ` +
      `literal so its causes can be enumerated, or declare it in RELAYS naming where its causes ARE measured.`,
  );
  const stale = RELAYS.filter((r) => !unreadable.some((u) => u.code === r.code && u.expr === r.expr));
  assert.deepEqual(stale, [], `RELAYS rows that match no site: ${stale.map((r) => `${r.code} ${r.expr}`).join("; ")}`);
});

test("no single fixture is the only evidence for two different rules", () => {
  // The substring hazard, closed. Two sites under one code where one's text is contained in the
  // other's would both be credited by the longer one's fixture, and the shorter rule would read as
  // measured while nothing exercises it.
  const soleEvidence = new Map<string, Site[]>();
  for (const site of SITES) {
    const ev = evidenceFor(site);
    if (ev.length !== 1) continue;
    const key = ev[0]!.fixture;
    soleEvidence.set(key, [...(soleEvidence.get(key) ?? []), site]);
  }
  const doubled = [...soleEvidence].filter(([, sites]) => sites.length > 1);
  assert.deepEqual(
    doubled.map(([f, sites]) => `${f} → ${sites.map(at).join(" + ")}`), [],
    `one fixture is the sole evidence for more than one rule. Either the two rules are one cause ` +
      `wearing two messages, or one rule's text is a substring of the other's and is being credited ` +
      `for a bundle it never refused.`,
  );
});

test("the scanned files are ALL the files that hold step rules", () => {
  // The scope guard. `fail(` is this verifier's refusal helper; a third file declaring one would
  // hold rules no property above can see, which is the same invisibility in a new place.
  const declaring = readdirSync(SRC)
    .filter((f) => f.endsWith(".ts"))
    .filter((f) => /\bfunction fail\(/.test(readFileSync(join(SRC, f), "utf8")));
  assert.deepEqual(
    declaring.sort(), [...RULE_FILES].sort(),
    `the set of files declaring a fail() helper changed. Add the new file to RULE_FILES — its rules ` +
      `are currently outside this inventory, which is exactly the blind spot this file closes.`,
  );
});
