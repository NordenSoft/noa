/**
 * S5 — THE ENROLMENT PLANE (R4-R7) AND THE SETTLEMENT REQUIREMENT IT UNLOCKS (R8/R9).
 *
 * ── WHAT ENROLMENT IS, AND WHY IT IS NOT IN THE BUNDLE ───────────────────────────────────────────
 *
 * "This action class requires settlement evidence before EXECUTED may be believed" is a statement
 * about a TENANT'S GOVERNANCE. It is not a statement about the bundle it adjudicates, and it must
 * not travel with it: a producer that holds the document saying "I owe you a witness" can simply
 * delete it, and if absence meant "unenrolled" the attacker would win by removing a file.
 *
 * So the registry is a VERIFIER INPUT — the third external document this verifier already takes,
 * beside `--tenant-root` and `--checkpoint-keyring` — and absence is never "unenrolled". Absence is
 * "the question was not asked", which changes no answer at all.
 *
 * ── THE ONE PROPERTY THAT GOVERNS EVERY RULE BELOW ───────────────────────────────────────────────
 *
 *   SUPPLYING A REGISTRY MAY ONLY EVER MAKE THE VERDICT HARDER TO REACH.
 *
 * Nothing a signer writes into a registry, and nothing a signer OMITS from one, buys a positive that
 * supplying no registry would not also have given. That sentence is load-bearing and it was FALSE in
 * an earlier design: there, a class positively absent from a `closed:true` registry received the
 * legacy positive with no settlement evidence at all — so a registry NARROWED to omit the payment
 * class was MORE permissive for that class than one that enrolled it, and the same document
 * recommended narrowing. Under these rules an absent class is `UNVERIFIED`. A signer can no longer
 * buy a verdict by omission.
 *
 * The only route to the permissive regime is a RELYING PARTY supplying no registry — its own
 * configuration decision, which no producer and no signer can make for it. That residual is conceded
 * and not claimed closed: it is the migration guarantee and the escape read from two sides.
 *
 * ── WHY `closed: true` IS REQUIRED BUT BUYS ALMOST NOTHING ───────────────────────────────────────
 *
 * It is the signer stating "for this audience, in this window, these are all the classes I make any
 * statement about at all". It gates whether the registry may be CONSULTED. It never makes an
 * omission permissive — a class outside a consulted registry is UNANSWERED. That is a strictly
 * weaker role than "an absence is a positive statement of non-enrolment", and it is the only role a
 * signed document can honestly play here.
 *
 * ── WHY `audience` IS MANDATORY ──────────────────────────────────────────────────────────────────
 *
 * Without it, "a registry scoped to one relying party" and "a policy downgrade" are the same bytes,
 * and a verifier holding two registries cannot tell intentional governance from an attack. It sits
 * INSIDE the signature, so a reader cannot be handed a registry written for somebody else and have
 * it silently apply — and a registry naming a different audience is NOT SELECTED rather than
 * REJECTED, which is why that outcome is `UNVERIFIED` and not `INVALID`. It costs nothing in
 * permissiveness, because no registry content can buy a positive.
 */
import { verifyArtifact, type KeyEntry } from "noa-approval-artifacts";
import { intrinsics } from "noa-receipt";
import { parseDocument, encodeDocument } from "./bytes.js";
import type { Ctx } from "./steps.js";
import type { StepName, StepResult } from "./types.js";

const pristineDateParse = intrinsics.dateParse;

export const ENROLMENT_SPEC = "noa.action-class-enrolment/0.1";

/** The registry row shape this module reads. Validated by the shipped schema at verify time. */
interface EnrolledClassRow {
  actionId?: unknown;
  actionSchema?: unknown;
  projection?: unknown;
  claimTier?: unknown;
}

interface RegistryDoc {
  spec?: unknown;
  tenant?: unknown;
  audience?: unknown;
  notBefore?: unknown;
  notAfter?: unknown;
  closed?: unknown;
  classes?: unknown;
}

/** A registry that AUTHENTICATED and is ADDRESSED TO THIS READER, with its index for messages. */
interface SelectedRegistry {
  index: number;
  doc: RegistryDoc;
}

function asObj(v: unknown): Record<string, unknown> | null {
  return typeof v === "object" && v !== null && !Array.isArray(v) ? (v as Record<string, unknown>) : null;
}
function asStr(v: unknown): string | null {
  return typeof v === "string" ? v : null;
}
function fail(step: StepName, code: StepResult["code"], reason: string): StepResult {
  return { step, ok: false, code, reason };
}
/** PRISTINE TIME — the same guard every other time comparison in this verifier uses. */
function parseTime(v: unknown): number {
  return typeof v === "string" ? pristineDateParse(v) : NaN;
}

/**
 * A `{id, version, hash}` triple, compared MEMBER BY MEMBER. Returned as a discriminated result so a
 * caller can tell "this row is about a different class" from "this row is about THIS class and
 * disagrees about it" — the distinction between an absence and a contradiction, which is the whole
 * difference between `UNVERIFIED` and `INVALID`.
 */
function projectionIdEqual(row: unknown, envelope: unknown): { idMatch: boolean; exact: boolean } {
  const r = asObj(row);
  const e = asObj(envelope);
  if (!r || !e) return { idMatch: false, exact: false };
  const idMatch = asStr(r.id) !== null && asStr(r.id) === asStr(e.id);
  const exact = idMatch && r.version === e.version && asStr(r.hash) !== null && asStr(r.hash) === asStr(e.hash);
  return { idMatch, exact };
}

/**
 * THE ENROLMENT PLANE. Returns a `StepResult` to REFUSE, or `null` when the class is not enrolled in
 * a way that changes anything (no registry supplied). On success it records the finding on `ctx`.
 *
 * ORDER, and it is normative rather than illustrative:
 *   R4  no registry            → NOT EVALUATED. Nothing else runs. THE MIGRATION GUARANTEE.
 *   R4  registries, no reader  → E_ENROLMENT_AUDIENCE      (UNVERIFIED)
 *   R5  authenticate + select  → E_ENROLMENT_UNVERIFIABLE  (UNVERIFIED)
 *   R5  selected, wrong tenant → E_ENROLMENT_MISMATCH      (INVALID)
 *   R5  selected, closed:false → E_ENROLMENT_NOT_CLOSED    (UNVERIFIED)
 *   R6  window, REJECT-ONLY    → E_ENROLMENT_OUT_OF_WINDOW (UNVERIFIED)
 *   R5' in-window rows contradict the bundle
 *                              → E_ENROLMENT_MISMATCH      (INVALID)
 *   R7  class absent           → E_ENROLMENT_CLASS_ABSENT  (UNVERIFIED)
 *   R7  class present          → ENROLLED. The caller now owes a settlement requirement.
 *
 * ── TWO ADJUDICATIONS THE SPEC TEXT LEFT CONTRADICTORY, DECIDED HERE AND WRITTEN DOWN ────────────
 *
 * (a) The rule table says selection requires "tenant-matched" AND lists "wrong tenant" as a
 *     structural CONTRADICTION. Both cannot hold: one silently drops the registry, the other
 *     accuses it. Decided: a registry that does not AUTHENTICATE under this reader's root is
 *     unverifiable (it could be anyone's); a registry that DOES authenticate under this root while
 *     declaring a different tenant is a contradiction, because our own governance signed a document
 *     about someone else and it was presented against this bundle. Authentication first, then
 *     audience, then tenant.
 *
 * (b) The rule table places the structural-contradiction scan BEFORE the window check. Applied
 *     literally to ROWS, that turns ordinary registry ROTATION into a hard `INVALID`: after a
 *     projection re-build the OLD registry — correctly out of window — still carries the OLD hash
 *     for the same class, which is exactly the "same class, different hash" shape the contradiction
 *     rule refuses. Decided: REGISTRY-level contradictions (tenant) keep their position; ROW-level
 *     contradictions are evaluated only on IN-WINDOW registries. A superseded registry is not a
 *     contradiction, it is a superseded registry — and the window rule stays reject-only either way,
 *     since being in window still establishes nothing on its own.
 */
export function checkEnrolment(ctx: Ctx, S: StepName): StepResult | null {
  const registries = ctx.enrolmentRegistries;

  // ── R4. NO REGISTRY ⇒ THE QUESTION IS NOT ASKED, AND NOTHING BELOW RUNS. ─────────────────────
  // This is the migration guarantee, and it is STRUCTURAL rather than promised: every historical
  // bundle is verified with no registry, so it takes this branch on line one and never reaches a
  // rule that could move it. `enrolment` stays `NOT_EVALUATED`; verdict, failing step, code and exit
  // code are exactly what this verifier returned before the enrolment plane existed.
  if (registries === undefined || registries.length === 0) return null;

  // ── R4. A REGISTRY THAT DOES NOT KNOW WHO IS READING IT CANNOT BE SCOPED. ────────────────────
  // Fail-closed rather than "consult it anyway": an unscoped registry is precisely the hole
  // `audience` exists to close, and reading one as if it were addressed here is how a document
  // written for another relying party silently becomes this one's policy.
  const audience = ctx.audience;
  if (audience === undefined || audience === "") {
    ctx.enrolment = "UNVERIFIABLE";
    return fail(S, "E_ENROLMENT_AUDIENCE",
      "enrolment registries were supplied but no --audience (relying-party identity) was: a registry that does not know who is reading it cannot be scoped, and an unscoped registry is exactly the hole audience exists to close (R4)");
  }

  // ── R5. AUTHENTICATE, THEN SELECT BY AUDIENCE. ──────────────────────────────────────────────
  const selected: SelectedRegistry[] = [];
  const rejected: string[] = [];
  for (let i = 0; i < registries.length; i++) {
    const parsed = parseDocument(registries[i]!, `enrolment registry ${i}`);
    if (!parsed.ok) {
      rejected.push(`#${i}: ${parsed.reason}`);
      continue;
    }
    const doc = asObj(parsed.value);
    if (!doc) {
      rejected.push(`#${i}: not a JSON object`);
      continue;
    }
    if (doc.spec !== ENROLMENT_SPEC) {
      rejected.push(`#${i}: spec ${JSON.stringify(doc.spec)} != ${ENROLMENT_SPEC}`);
      continue;
    }
    // The registry's authority IS the root delegation. `verifyArtifact` runs the shipped schema, the
    // Ed25519 signature, key activation/revocation and the F15 `action-class-enrol` role against the
    // SAME resolved keyring every other artifact in this bundle is checked against — the one whose
    // trust traces to the external `--tenant-root` through the root-signed delegation. A registry
    // signed by a kid the root never delegated resolves to no key and is refused here.
    //
    // BYTES-IN, CAPTURED ONCE: the ORIGINAL supplied bytes are what gets authenticated, and the
    // parse above is only how this module READS fields. Handing `verifyArtifact` a re-serialization
    // of the parsed tree would authenticate one byte string and read another — the exact
    // two-documents-one-name shape the byte boundary exists to make unconstructible.
    const av = verifyArtifact(registries[i]!, encodeDocument({
      schemas: ctx.schemas,
      keyring: (ctx.resolvedKeyring ?? {}) as Record<string, KeyEntry>,
      now: ctx.now,
    }));
    if (!av.ok) {
      rejected.push(`#${i}: ${av.reason}`);
      continue;
    }
    // ADDRESSED TO THIS READER? A registry naming a different audience is NOT SELECTED — it is not
    // evidence of wrongdoing, it is simply not addressed here. Exact string membership only: there
    // is no wildcard and no prefix rule, because a value meaning "I did not decide" must never be
    // readable as "I decided yes". The schema forbids `*` in an identifier; this comparison would
    // not honour one anyway.
    const aud = doc.audience;
    if (!Array.isArray(aud) || !aud.some((a) => a === audience)) {
      rejected.push(`#${i}: audience ${JSON.stringify(aud)} does not name ${JSON.stringify(audience)}`);
      continue;
    }
    selected.push({ index: i, doc: doc as RegistryDoc });
  }

  if (selected.length === 0) {
    ctx.enrolment = "UNVERIFIABLE";
    return fail(S, "E_ENROLMENT_UNVERIFIABLE",
      `no supplied enrolment registry both authenticates under this bundle's root delegation and names the reader ${JSON.stringify(audience)} in its audience — the verifier is configured but its configuration does not answer this question (R5): ${rejected.join("; ")}`);
  }

  // R5 — WRONG TENANT IS A CONTRADICTION, not an absence. This registry authenticated under THIS
  // reader's root, so it is our own governance making a statement about a different tenant, and it
  // was handed over as if it governed this bundle.
  for (const r of selected) {
    const t = asStr(r.doc.tenant);
    if (t !== ctx.tenant) {
      ctx.enrolment = "CONTRADICTED";
      return fail(S, "E_ENROLMENT_MISMATCH",
        `enrolment registry #${r.index} authenticates under this bundle's root delegation but declares tenant ${JSON.stringify(t)} while the bundle is ${JSON.stringify(ctx.tenant)} — a document about another tenant presented as governing this one is a contradiction, not a gap (R5)`);
    }
  }

  // R5 — `closed: false` is refused outright. A registry that does not even claim completeness for
  // its audience and window cannot be reasoned over: every omission in it is ambiguous between
  // "not enrolled" and "not mentioned", and this design refuses to read either as a permission.
  for (const r of selected) {
    if (r.doc.closed !== true) {
      ctx.enrolment = "UNVERIFIABLE";
      return fail(S, "E_ENROLMENT_NOT_CLOSED",
        `enrolment registry #${r.index} has closed != true — an open registry makes no complete statement for its audience and window, so it is never consulted (R5)`);
    }
  }

  // ── R6. THE WINDOW, AND IT IS REJECT-ONLY. ──────────────────────────────────────────────────
  // The instant tested is `holdResolution.receivedAt` — the gate-signed decision time, already
  // authenticated at step 3 — and NOT `now`, because testing against `now` would make archived
  // bundles rot. `receivedAt` is producer-chosen (the gate signs it, and the gate is the party this
  // design exists to distrust), so it may REFUSE enrolment and may never ESTABLISH it. Under these
  // rules that property is structural rather than carefully arranged: every failure on this plane is
  // non-positive, so no window position can move a verdict toward accept by any route.
  //
  // The residual, conceded: a gate that backdates `receivedAt` into an EARLIER registry's window can
  // still select which of two spec-compliant registries applies. What it can no longer do is
  // backdate into a window where the class is absent, because absence buys nothing. Closing it needs
  // the registry pinned at hold time, which no shipped artifact carries.
  const receivedAt = parseTime(ctx.receivedAt);
  const inWindow: SelectedRegistry[] = [];
  for (const r of selected) {
    const nb = parseTime(r.doc.notBefore);
    const na = parseTime(r.doc.notAfter);
    if (Number.isNaN(receivedAt) || Number.isNaN(nb) || Number.isNaN(na)) continue;
    if (receivedAt >= nb && receivedAt <= na) inWindow.push(r);
  }
  if (inWindow.length === 0) {
    ctx.enrolment = "OUT_OF_WINDOW";
    return fail(S, "E_ENROLMENT_OUT_OF_WINDOW",
      `no selected enrolment registry's [notBefore, notAfter] contains this bundle's gate-signed authorization instant ${JSON.stringify(ctx.receivedAt)} — the registries this reader holds do not cover these bytes (R6, reject-only)`);
  }

  // ── R5'/R7. THE CLASS KEY IS A PAIR, AND IT IS GATE-DERIVED. ────────────────────────────────
  //
  // The class is `holdEnvelope.actionSchema.{id,version,hash}` (identity) PAIRED with
  // `holdEnvelope.displayProjection.{id,version,hash}` (rendering). Both halves earn their place:
  // `actionSchema` is the identity, and it is the namespace `deferredReceipt.action.id` lives in;
  // `displayProjection` pins the renderer whose code produced the human's display, so a rendering
  // change drops the class out of enrolment — fail-closed on drift, by construction.
  //
  // Keying on the projection ALONE — which an earlier draft did — is keyed on the wrong namespace
  // entirely: the shipped fixtures carry `displayProjection.id = "deploy.display"` beside
  // `actionSchema.id = "deploy.apply"`, and it is the latter that equals `action.id`. Enrolling on
  // identity alone would let the display drift silently under a stable class; enrolling on rendering
  // alone cannot be tied to the action at all.
  //
  // WHAT PINNING THE PROJECTION HASH DOES **NOT** ESTABLISH, stated where the rule is: the hash is
  // over the renderer's SOURCE TEXT inside the gate process. It pins the renderer, not the rendered
  // output, and nothing here proves any display was ever shown to a human. The operational cost is
  // real and named: a bundler or minifier change re-hashes the projection with no semantic change
  // and silently de-enrols the class.
  const env = asObj(ctx.bundle.holdEnvelope);
  const envActionSchema = env?.actionSchema;
  const envProjection = env?.displayProjection;
  const deferredActionId = asStr(asObj(asObj(ctx.bundle.deferredReceipt)?.action)?.id);

  let enrolled = false;
  for (const r of inWindow) {
    const classes = Array.isArray(r.doc.classes) ? (r.doc.classes as EnrolledClassRow[]) : [];
    for (let k = 0; k < classes.length; k++) {
      const row = asObj(classes[k]);
      if (!row) continue;
      const rowActionId = asStr(row.actionId);
      const schema = projectionIdEqual(row.actionSchema, envActionSchema);
      const projection = projectionIdEqual(row.projection, envProjection);

      // IS THIS ROW ABOUT THIS CLASS AT ALL? Any of four handles makes it a candidate, and the
      // breadth is deliberate: a row that names this class by ANY of the identifiers it could
      // plausibly use must be ADJUDICATED, never silently skipped as "some other class". A rule that
      // only matched exact rows would turn every near-miss — a drifted hash, a RAW-mode envelope, an
      // id taken from the display namespace — into `CLASS_ABSENT`, which is a soft refusal for what
      // is actually two documents contradicting each other about the same object.
      const candidate =
        schema.idMatch
        || projection.idMatch
        || (rowActionId !== null && (rowActionId === deferredActionId
          || rowActionId === asStr(asObj(envActionSchema)?.id)
          || rowActionId === asStr(asObj(envProjection)?.id)));
      if (!candidate) continue;

      // A candidate row that disagrees is a CONTRADICTION between two documents about one object —
      // a hard rejection, not a gap in the reader's configuration. Each clause below is one of the
      // cross-checks that bind the registry to the rest of the evidence.
      const mismatch = ((): string | null => {
        // RAW mode is never enrollable, and `displayProjection` is null there: on a RAW hold the
        // display a human approved and the params a grant authorizes are two unrelated things, so a
        // registry claiming this class enrolled is claiming something the envelope cannot support.
        if (asStr(env?.mode) !== "ENFORCED") {
          return `holdEnvelope.mode is ${JSON.stringify(env?.mode)}, not "ENFORCED" — a RAW hold is never enrollable`;
        }
        // NO SEPARATE "displayProjection is null" CHECK, and its absence is a deliberate deletion
        // rather than an oversight. A null projection cannot equal the row's projection member for
        // member, so the exactness check below already refuses it with the same code — and a knockout
        // proved the two could not be told apart: removing either one left the corpus green, because
        // whichever survived refused first. Two controls that mask each other are one control with a
        // spare, and a spare that no test can distinguish reads in review as a defence while
        // measuring nothing.
        //
        // The `actionId` cross-check. This is what turns the console↔kernel `action.id` question from
        // silent semantic drift into a BLOCKING defect for enrolled classes, and it is why a class
        // must not be enrolled before the console points at the same identifier.
        if (rowActionId !== deferredActionId) {
          return `row.actionId ${JSON.stringify(rowActionId)} != deferredReceipt.action.id ${JSON.stringify(deferredActionId)}`
            + (rowActionId !== null && rowActionId === asStr(asObj(envProjection)?.id)
              ? " — the row names the DISPLAY-PROJECTION namespace where the ACTION-SCHEMA namespace belongs"
              : "");
        }
        if (!schema.exact) {
          return `row.actionSchema does not equal holdEnvelope.actionSchema member-for-member (id/version/hash)`;
        }
        if (!projection.exact) {
          return `row.projection does not equal holdEnvelope.displayProjection member-for-member (id/version/hash)`;
        }
        return null;
      })();
      if (mismatch !== null) {
        ctx.enrolment = "CONTRADICTED";
        return fail(S, "E_ENROLMENT_MISMATCH",
          `enrolment registry #${r.index} class[${k}] claims this bundle's class and contradicts it: ${mismatch} (R5)`);
      }
      enrolled = true;
    }
  }

  // ── R7. ABSENCE BUYS NOTHING. ───────────────────────────────────────────────────────────────
  // The class is positively absent from every selected, in-window, closed registry — and that is
  // `UNVERIFIED`, not a blessing. This is the rule that makes "a narrower registry is consulted by
  // fewer readers, never a more permissive statement" true. Under the design this replaced, these
  // exact bytes were VALID_FULL_CHAIN and exit 0.
  if (!enrolled) {
    ctx.enrolment = "CLASS_ABSENT";
    return fail(S, "E_ENROLMENT_CLASS_ABSENT",
      "this bundle's action class is absent from every selected, in-window enrolment registry — an omission is an unanswered question, never a statement that the class is unenrolled (R7)");
  }

  ctx.enrolment = "ENROLLED";
  return null;
}

/** The reconciler facts the settlement requirement reads. Supplied by the artifact plane (R1-R3). */
export interface SettlementFacts {
  /** the reconciler's outcome code for this bundle's artifact. */
  code: string;
  /** the reconciler's derived observer↔execution-signer relationship (S4 R-16). */
  observerRelationship: string;
}

/** The determinate coordinates a settlement claim must ship to be falsifiable by anyone (R-SE-4). */
const REQUIRED_WITNESS_COORDINATES = ["network", "asset", "payer", "txHash", "blockNumber"] as const;

/**
 * R8 + R9 — THE SETTLEMENT REQUIREMENT FOR AN ENROLLED CLASS, AND THE CEILING IT CANNOT PASS.
 *
 * Called ONLY when `checkEnrolment` reported `ENROLLED`. Every branch is non-positive, and that is
 * not a gap in this slice: the ONLY route to a positive for an enrolled class is a record of the
 * RELYING PARTY'S OWN NODE re-answering the chain queries and agreeing (R9's green path), and that
 * input does not exist in this verifier yet. Until it does, an enrolled class's ceiling is
 * `INCONCLUSIVE` / exit 6.
 *
 * That ceiling is the honest answer, not a limitation to work around. This verifier is offline and
 * opens no socket: it can establish that a settlement ASSERTION is authentic, bound to this exact
 * approval and inside the approved bounds — it cannot establish that the assertion is TRUE, because
 * the signer of the assertion is not the world. Returning a positive on a determinate offline
 * artifact is precisely the defect this design exists to close: a self-consistent forged `SETTLED`
 * artifact signed by any authorized observer key would otherwise produce a positive verdict and exit
 * 0 with nothing queried.
 *
 * R8's refusals are ABSENCES, never contradictions — a missing, non-determinate or
 * relationship-capped witness is "the question was asked and nothing admissible answered it", which
 * is `INCONCLUSIVE`. A witness that CONTRADICTS the bundle was already refused by the artifact plane
 * (R1-R3), which runs first precisely so "present ⇒ always checked" never depends on a verifier
 * input.
 */
export function checkSettlementRequired(ctx: Ctx, S: StepName, facts: SettlementFacts | null): StepResult | null {
  const required = (reason: string): StepResult => {
    ctx.settlement = "NOT_ESTABLISHED";
    return fail(S, "E_SETTLEMENT_REQUIRED", `${reason} (R8)`);
  };

  // R8 — W absent. The class is enrolled, so an EXECUTED claim owes a witness and this bundle
  // carries none. Not a rejection of the evidence: an absence.
  if (facts === null || ctx.bundle.settlementEvidence === undefined) {
    return required("this action class is enrolled for settlement evidence and the bundle carries no settlement artifact — EXECUTED here means the gate says it handed the request off, which is the claim enrolment exists to stop being enough");
  }

  // R8 — the artifact is present and authentic but does not DETERMINATELY assert a settlement. The
  // reconciler's only offline non-refusal code is the correlated-unreconfirmed one; anything else
  // that reached here is a non-determinate status.
  if (facts.code !== "SETTLEMENT_CORRELATED_UNRECONFIRMED") {
    return required(`the settlement artifact does not determinately assert a settlement for this approval (reconciler code ${facts.code})`);
  }

  // R8's `claimTier` and `witnessSpec` clauses have NO runtime check here, and the absence is
  // deliberate rather than an omission: both members are pinned to a single value by the shipped
  // schema (`claimTier` is a one-member enum, `witnessSpec` a const), and every registry is validated
  // against that schema before it is selected. A row cannot declare a weaker tier or a different
  // witness spec and still authenticate. Writing the check anyway would be a control that cannot
  // fire — worse than none, because it reads in review as a defence. The enum's enforcement is
  // measured by the `reject-unknown-claim-tier` conformance vector, not by a branch here.

  // R8 — the R-16 relationship cap. A key that says "I dispatched it" saying "and it settled" is one
  // party attesting to its own effect, so the observation is not admissible for an enrolled class.
  // It is CAPPED rather than REJECTED: this is today's honest deployment shape, and refusing it
  // outright would refuse the only shape that currently exists.
  if (facts.observerRelationship === "SAME_SIGNING_KEY") {
    return required("the settlement observer's key is the execution signer's own key — the party that says it dispatched the request is the party saying it settled, so the observation is not admissible for an enrolled class");
  }

  // R8 — the falsifiability coordinates. A settlement claim that ships no transaction hash, block or
  // network cannot be re-derived by any relying party, so it is not evidence anyone can check — and
  // an unfalsifiable assertion is an absence of evidence, not evidence.
  const witness = asObj(asObj(ctx.bundle.settlementEvidence)?.chainWitness);
  const missing = REQUIRED_WITNESS_COORDINATES.filter((c) => witness === null || witness[c] === undefined || witness[c] === null);
  if (missing.length > 0) {
    return required(`the settlement artifact omits the coordinates that make it falsifiable by a third party (${missing.join(", ")})`);
  }

  // ── R9. NOBODY RE-QUERIED. ──────────────────────────────────────────────────────────────────
  // The artifact is authentic, bound to this exact approval, in bounds, determinate and observed by
  // a party that is not the execution signer. That is the OFFLINE CEILING, and it is not a positive:
  // an attestation exists and this verifier did not verify what it asserts. The two-word name is
  // deliberate — a reader who saw `ATTESTED` beside a positive verdict read it as "established".
  ctx.settlement = "ATTESTED_UNVERIFIED";
  return fail(S, "E_SETTLEMENT_UNRECONFIRMED",
    "the settlement artifact is authentic, bound to this approval and within the approved bounds, and NOBODY RE-QUERIED THE CHAIN: an offline verifier can establish that an assertion is well-formed and bound, never that it is true. A positive requires a record of the relying party's own node answering the queries — an input the party being judged never holds (R9)");
}

/**
 * THE I3 CARRY-FORWARD — an enrolled class's FAILURE outcome may not be positive on the gate's word.
 *
 * ── THE ASYMMETRY, MEASURED ──────────────────────────────────────────────────────────────────────
 *
 * `EXECUTION_FAILED` is one of the two POSITIVE outcomes, so it pays no step-15 fresh-checkpoint tax.
 * Once enrolment makes `EXECUTED` cost a witness, it becomes the ONLY outcome that is both
 * step-15-exempt AND settlement-free — i.e. the cheap relabelling path for a gate hiding a spend.
 * Claim the failure, pay nothing, exit 0.
 *
 * ── WHAT THIS RULE DOES, AND THE TWO THINGS IT DELIBERATELY DOES NOT DO ──────────────────────────
 *
 * For an ENROLLED class the gate's own `FAILED_BEFORE_DISPATCH` is not sufficient on its own. A
 * determinate negative is claimable only where a party OTHER than the executed one observed the
 * non-dispatch, and no artifact admitted on this outcome carries such an observation — the outcome
 * union admits neither settlement member here, deliberately and under an owner-gated decision. So
 * for an enrolled class this outcome cannot presently reach a positive at all, and the honest
 * verdict is `INCONCLUSIVE`: the question was asked and nothing admissible answered it.
 *
 * It does NOT widen `POSITIVE_OUTCOMES`, and it does NOT widen the outcome-artifact union to admit a
 * witness on this outcome. Both are the owner's call, and the pressure this rule puts on that
 * decision is the point: the requirement is now visible as a refusal instead of invisible as a gap.
 *
 * It is scoped to ENROLLED classes ONLY. With no registry supplied nothing changes — every
 * historical `EXECUTION_FAILED` bundle keeps its verdict, its step, its code and its exit code.
 */
export function checkNonDispatchWitnessed(ctx: Ctx, S: StepName): StepResult | null {
  if (ctx.enrolment !== "ENROLLED") return null;
  ctx.settlement = "NOT_ESTABLISHED";
  return fail(S, "E_NON_DISPATCH_UNWITNESSED",
    "this action class is enrolled for settlement evidence, and the only thing asserting that nothing was dispatched is the gate's own consumption — the party being judged. A determinate non-dispatch is claimable only on an observation by a party that did not execute, and no artifact admitted on this outcome can carry one, so a failure label cannot escape the requirement an EXECUTED label would have owed");
}
