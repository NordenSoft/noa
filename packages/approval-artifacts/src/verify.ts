/**
 * The generic, context-aware side-artifact verifier — the reference logic the §6 conformance
 * vectors are run against, and the shared core a real gate / phone (D2) / `verify-evidence` (§13)
 * consumer builds on. It is deliberately fail-closed: a check it cannot positively satisfy REJECTS.
 *
 * A verification is the AND of five independent layers, each of which a rejection vector is designed
 * to trip exactly one of:
 *   1. STRUCTURAL   — the shipped schema/<spec>.schema.json (additionalProperties:false, enums,
 *                     patterns, discriminated pairing union). Catches `unknown-property` + shape.
 *   2. SIGNATURE    — for signed artifacts: sig.kid resolves in the keyring, the key is not revoked
 *                     as of the artifact's time (or the verifier-controlled `authorizationTime` at
 *                     live authorization boundaries), holds the F15 role, and the Ed25519 signature over
 *                     `<DOMAIN>: ++ SHA256(JCS(doc without sig))` verifies. Catches `tampered-content`
 *                     + `wrong-key`.
 *   3. REFHASH      — every declared cross-artifact `*Hash` equals the F1-correct hash (rule a/b/c) of
 *                     the referenced artifact. Catches `cross-artifact-hash-substitution` (+ the
 *                     transitive-tenant realization for tenant-less artifacts, F7b/G7).
 *   4. EQUALS       — declared field equalities (tenant, nonce, pinned ids, sig.kid ↔ self-kid).
 *                     Catches `wrong-tenant` / `wrong-nonce` where the artifact carries the field.
 *   5. TIME         — expiry (`mustBeAfter`) + freshness-window (`mustBeWithin`). Catches `expired`.
 */
import { ARTIFACTS } from "./domains.js";
import { evalSchema } from "./schema-eval.js";
import { signingMessage, verifyEd25519 } from "./crypto.js";
import { canonicalize } from "./jcs.js";
import { refHash, receiptRefHash, virtualHash } from "./refhash.js";
import { parseDocument } from "./inert-core/bytes.js";
import { hasOwn } from "./inert-core/intrinsics.js";
import { arrayIncludes, arraySome, strSplit } from "./inert-core/intrinsics.js";

export interface KeyEntry {
  publicKey: string; // base64(DER SPKI) Ed25519
  type: "GATE" | "APPROVER" | "AUDIT" | "ROOT" | "DELEGATED";
  roles: string[];
  /**
   * Activation time (Key Manifest `validFrom`). A signature made BEFORE its key was activated is
   * not authorized — the mirror image of `revokedAt`, and evaluated against the same artifact time.
   * Manifests already carried this field; `KeyEntry` did not, so every keyring resolver silently
   * dropped it and pre-activation signatures verified clean. OPTIONAL: an entry without it (a root
   * key, a test fixture) is treated as always-active, so this is additive for existing callers.
   */
  validFrom?: string | null;
  revokedAt?: string | null;
}

export interface VerifyContext {
  /** spec -> parsed schema object (the shipped schema/<spec>.schema.json). */
  schemas: Record<string, unknown>;
  keyring?: Record<string, KeyEntry>;
  /** verification-time "now"; enables the expiry + freshness checks. */
  now?: string;
  /**
   * Verifier-controlled time at which a live authorization is being accepted. When supplied,
   * revocation is evaluated at this time instead of a signer-controlled artifact timestamp.
   * Live gates MUST set this; offline evidence verification may omit it and separately prove a
   * trusted historical acceptance time.
   */
  authorizationTime?: string;
  /** riskClass of the held action — selects the F15 approver tier for a Decision Artifact. */
  riskClass?: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL" | "IRREVERSIBLE";
  equals?: Array<{ path: string; value: unknown }>;
  /**
   * Cross-artifact hash bindings (F1). `refEquals` additionally asserts fields ON the referenced
   * artifact — this is how a tenant-LESS artifact's tenant is enforced transitively (F7b/G7: e.g. a
   * Decision's tenant is bound only through its `holdEnvelopeHash` → the referenced envelope's
   * `tenant` must equal the expected tenant).
   */
  refHashChecks?: Array<{ path: string; rule: "side" | "receipt" | "virtual"; artifact: unknown; refEquals?: Array<{ path: string; value: unknown }> }>;
  mustBeAfter?: Array<{ path: string; time: string }>;
  mustBeWithin?: Array<{ path: string; min: string; max: string }>;
  /** F2: `virtualHash(the WHOLE subject)` must equal this value — the hash a signed parent commits
   *  to over the WHOLE object (e.g. the Hold Envelope's `displayCiphertextHash` over an Encrypted
   *  Display, so a relay-added `recipients[]` entry breaks it). */
  expectVirtualHash?: string;
}

export interface VerifyOutcome {
  ok: boolean;
  reason?: string;
}

function getPath(obj: unknown, path: string): unknown {
  let cur: unknown = obj;
  for (const seg of strSplit(path, ".")) {
    if (typeof cur !== "object" || cur === null) return undefined;
    cur = (cur as Record<string, unknown>)[seg];
  }
  return cur;
}

function computeRefHash(rule: "side" | "receipt" | "virtual", artifact: unknown): string {
  if (rule === "receipt") return receiptRefHash(artifact as Record<string, unknown>);
  if (rule === "virtual") return virtualHash(artifact);
  return refHash(artifact);
}

/**
 * ── P0-6 (2026-07-31): `Date.parse` IS NOT A SECURITY PARSER ──────────────────────────────────
 * This returned `pristineDateParse(v)` for any string. `Date.parse` does not reject malformed
 * input — it NORMALISES it into a plausible instant, and every comparison below then treats that
 * invented instant as the declared one. MEASURED end to end against the shipped decision vector,
 * with the unmodified vector ACCEPTED in the same run as the control:
 *
 *     validFrom "0"            -> Date.parse => 1999-12-31  -> key ACCEPTED (a past instant)
 *     validFrom "2026-02-30"   -> Date.parse => 2026-03-02  -> key ACCEPTED (the day does not exist)
 *     validFrom "" / "   " / not-a-timestamp -> NaN          -> refused, as intended
 *
 * So an operator who declares a FUTURE activation and mistypes it gets a key that is silently
 * active already. (An attacker who can author the key record gains nothing they did not already
 * have — this is an operator-error amplifier, not an authorization bypass, and it is recorded at
 * that severity rather than inflated.)
 *
 * The parser is now STRICT: calendar validity plus the epoch value are computed directly from the
 * numeric components. P0-11 widened accepted RFC 3339 spellings to `Z` or a numeric offset while
 * preserving `Z` as the only emitted spelling. It does not call `Date` or any `Date` method; the test
 * "P0-9: a targeted Date.prototype.toISOString poison cannot admit a non-existent activation
 * date" installs the targeted poison while pinning both refusal and an accepted control.
 *
 * COMPATIBILITY MEASURED BEFORE THIS CHANGE, not after: 1727 timestamps across the shipped
 * conformance corpora were scanned; **0** are non-canonical-but-parseable, so no record that
 * verified before stops verifying now.
 *
 * Fixed HERE rather than in a separate activation-only parser, deliberately: all 11 comparisons in
 * this file are security comparisons, and giving activation its own parser would create exactly the
 * resolver drift this batch exists to close.
 */
const CANONICAL_INSTANT = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?(?:Z|[+-]\d{2}:\d{2})$/;

function integerQuotient(nonNegative: number, divisor: number): number {
  return (nonNegative - (nonNegative % divisor)) / divisor;
}

function isLeapYear(year: number): boolean {
  return year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
}

function daysInMonth(year: number, month: number): number {
  if (month === 2) return isLeapYear(year) ? 29 : 28;
  if (month === 4 || month === 6 || month === 9 || month === 11) return 30;
  return 31;
}

/** Days since 1970-01-01, using the proleptic Gregorian calendar. */
function daysFromCivil(year: number, month: number, day: number): number {
  const shiftedYear = year - (month <= 2 ? 1 : 0);
  // The four-digit syntax limits shiftedYear to -1..9999, so -1 is the only negative era case.
  const era = shiftedYear < 0 ? -1 : integerQuotient(shiftedYear, 400);
  const yearOfEra = shiftedYear - era * 400;
  const shiftedMonth = month + (month > 2 ? -3 : 9);
  const dayOfYear = integerQuotient(153 * shiftedMonth + 2, 5) + day - 1;
  const dayOfEra = yearOfEra * 365
    + integerQuotient(yearOfEra, 4)
    - integerQuotient(yearOfEra, 100)
    + dayOfYear;
  return era * 146_097 + dayOfEra - 719_468;
}

function parseTime(v: unknown): number {
  if (typeof v !== "string") return NaN;
  if (!CANONICAL_INSTANT.test(v)) return NaN;

  const digit = (offset: number): number => +v[offset]!;
  const twoDigits = (offset: number): number => digit(offset) * 10 + digit(offset + 1);
  const year = digit(0) * 1_000 + digit(1) * 100 + digit(2) * 10 + digit(3);
  const month = twoDigits(5);
  const day = twoDigits(8);
  const hour = twoDigits(11);
  const minute = twoDigits(14);
  const second = twoDigits(17);
  const hasMilliseconds = v[19] === ".";
  const millisecond = hasMilliseconds
    ? digit(20) * 100 + digit(21) * 10 + digit(22)
    : 0;
  const zoneOffset = hasMilliseconds ? 23 : 19;
  let offsetMinutes = 0;
  if (v[zoneOffset] !== "Z") {
    const offsetHour = twoDigits(zoneOffset + 1);
    const offsetMinute = twoDigits(zoneOffset + 4);
    if (offsetHour > 23 || offsetMinute > 59) return NaN;
    const offsetSign = v[zoneOffset] === "+" ? 1 : -1;
    offsetMinutes = offsetSign * (offsetHour * 60 + offsetMinute);
  }

  if (month < 1 || month > 12) return NaN;
  if (day < 1 || day > daysInMonth(year, month)) return NaN;
  if (hour > 23 || minute > 59) return NaN;
  // Leap seconds (`:60`) are explicitly refused, preserving the existing parser contract.
  if (second > 59) return NaN;

  return daysFromCivil(year, month, day) * 86_400_000
    + hour * 3_600_000
    + minute * 60_000
    + second * 1_000
    + millisecond
    - offsetMinutes * 60_000;
}

function hasInvalidTime(...times: number[]): boolean {
  for (const time of times) {
    if (Number.isNaN(time)) return true;
  }
  return false;
}

/** Artifact fields that declare the identity of their own signer, independent of caller context. */
function signerIdentityPath(spec: string, doc: Record<string, unknown>): string | null {
  if (spec === "noa.hold/0.1" || spec === "noa.pairing-confirmation/0.1") return "gateKid";
  if (spec === "noa.decision/0.1") return "approverKid";
  if (spec === "noa.pairing/0.1") {
    if (doc.type === "CHALLENGE") return "gateKid";
    if (doc.type === "CONFIRMATION") return "approverKid";
  }
  return null;
}

/** F15 approver-tier requirement for a Decision, by the held action's riskClass. */
/**
 * THE F15 APPROVER LATTICE — one authoritative definition: THIS FUNCTION.
 *
 * (An earlier revision of this comment pointed at `docs/F15-APPROVER-LATTICE.md`, which does not
 * exist and never did. Since the entire point of this block is that there is exactly ONE definition
 * of the lattice, a dangling pointer to a second one is the specific error it was written to
 * prevent. The consumers — the gate's approval routes and `noa-approval-evidence` step 5 — call
 * into this rule rather than restating it; `THREAT-MODEL.md` describes it in prose.)
 *
 * The tiers are ORDERED, not disjoint: `approve-critical` strictly dominates `approve-high`. An
 * approver trusted with CRITICAL/IRREVERSIBLE actions is necessarily trusted with HIGH ones.
 *
 * This function previously returned `["approve-high"]` alone for HIGH, making the tiers
 * non-overlapping — so an `approve-critical` device was REJECTED (422) for an ordinary HIGH
 * approval, while the evidence verifier accepted exactly that bundle and the gate's own
 * `createAlphaTrust()` defaulted to `approve-critical` and documented it as covering all tiers.
 * Three components implemented three different lattices; this is the one they now share, because
 * it is the only one that is operationally coherent.
 */
function requiredApproverRole(riskClass: string | undefined): string[] {
  if (riskClass === "CRITICAL" || riskClass === "IRREVERSIBLE") return ["approve-critical"];
  if (riskClass === "HIGH") return ["approve-high", "approve-critical"];
  // LOW/MEDIUM are not in the F15 matrix; accept any approver tier (documented).
  return ["approve-high", "approve-critical"];
}

/**
 * Verify one side artifact against a verification context. **BOTH ARGUMENTS ARE BYTES** (ADR §3.1).
 *
 * ── WHY THE CONTEXT IS BYTES TOO, AND NOT ONLY THE ARTIFACT ──────────────────────────────────────
 * Review #6's C2 was found here: the function validated the schema and the signature and then
 * RE-READ the live artifact for the equality and time checks, so a getter that returned the signed
 * `approverKid` on reads 1-3 and `attacker-seat` on the equality read made a context REQUIRING
 * `attacker-seat` return `{ok:true}` — the signer never attested the value the verifier accepted.
 * The tell was that two equality assertions with CONTRADICTORY expected values both passed in one
 * call, which no inert object can do.
 *
 * The previous fix snapshotted the artifact AND the context — but deliberately EXCLUDED
 * `ctx.schemas` on a cost argument. That exclusion was the remaining hole, and it is the one C-03
 * went through: `ctx.schemas[spec]` on a plain `{}` resolves through `Object.prototype`, so a single
 * pollution supplied a permissive schema for an unregistered spec. Snapshotting the subject and
 * leaving one member of the policy live is the same defect one argument to the left, which is
 * exactly what the earlier comment said about `ctx` — and then it made an exception.
 *
 * There is now no exception, because there is no traversal: both arguments are decoded and parsed by
 * the same strict parser the kernel uses, and everything below reads `safeParse` output —
 * null-prototype, accessor-free, duplicate-key-free, depth-bounded. `ctx.schemas` is JSON (it is a
 * set of JSON Schema documents), so making it bytes costs a parse of a few kilobytes per call and
 * removes the last live object from the boundary.
 *
 * Never throws: every failure is a returned `{ok:false, reason}`.
 */
export function verifyArtifact(artifactBytes: Uint8Array | string, ctxBytes: Uint8Array | string): VerifyOutcome {
  const parsedArtifact = parseDocument(artifactBytes, "artifact");
  if (!parsedArtifact.ok) return { ok: false, reason: parsedArtifact.reason };
  const parsedCtx = parseDocument(ctxBytes, "context");
  if (!parsedCtx.ok) return { ok: false, reason: parsedCtx.reason };
  const artifact = parsedArtifact.value;
  const ctxValue = parsedCtx.value;
  if (typeof ctxValue !== "object" || ctxValue === null || Array.isArray(ctxValue)) {
    return { ok: false, reason: "context is not an object" };
  }
  const ctx = ctxValue as VerifyContext;
  if (typeof artifact !== "object" || artifact === null || Array.isArray(artifact)) {
    return { ok: false, reason: "artifact is not an object" };
  }
  const doc = artifact as Record<string, unknown>;
  const spec = doc.spec;
  // OWN-PROPERTY PROBE, never `in` (C-03). `spec in ARTIFACTS` walks the prototype chain, so one
  // `Object.defineProperty(Object.prototype, "attacker.unsigned/1", …)` registered an artifact type
  // nobody shipped. `ARTIFACTS` is now null-rooted as well (frozenTable re-roots), so this is belt
  // and braces — deliberately, because the two controls fail independently.
  if (typeof spec !== "string" || !hasOwn(ARTIFACTS, spec)) {
    return { ok: false, reason: `unknown or missing spec: ${JSON.stringify(spec)}` };
  }
  const meta = ARTIFACTS[spec]!;

  // 1. STRUCTURAL
  // Same own-property discipline: `ctx.schemas` came from `safeParse` (null-prototype), but the
  // probe does not depend on that being true — which is the point of a control.
  const schemas = ctx.schemas;
  if (typeof schemas !== "object" || schemas === null) return { ok: false, reason: `no schema loaded for ${spec}` };
  const schema = hasOwn(schemas, spec) ? schemas[spec] : undefined;
  if (!schema) return { ok: false, reason: `no schema loaded for ${spec}` };
  const structural = evalSchema(schema as Record<string, unknown>, artifact);
  if (!structural.ok) return { ok: false, reason: `schema: ${structural.errors.join("; ")}` };

  // 2. SIGNATURE (signed artifacts only)
  if (meta.domain !== null) {
    const sig = doc.sig as { kid?: unknown; value?: unknown } | undefined;
    if (!sig || typeof sig.kid !== "string" || typeof sig.value !== "string") {
      return { ok: false, reason: "missing sig.kid/value" };
    }
    const identityPath = signerIdentityPath(spec, doc);
    if (identityPath !== null && getPath(doc, identityPath) !== sig.kid) {
      return { ok: false, reason: `signer identity mismatch: ${identityPath} must equal sig.kid` };
    }
    const entry = ctx.keyring?.[sig.kid];
    if (!entry) return { ok: false, reason: `unknown signing key "${sig.kid}" (not in keyring)` };

    // Revocation normally follows the artifact's own time for historical/offline verification.
    // A live authorization boundary must instead supply a verifier-controlled authorizationTime;
    // otherwise a revoked signer can simply backdate its signed document past the revocation.
    const artifactTime =
      ctx.authorizationTime ??
      (doc.issuedAt as string | undefined) ??
      (doc.receivedAt as string | undefined) ??
      (doc.decidedAt as string | undefined) ??
      (doc.consumedAt as string | undefined) ??
      (doc.detectedAt as string | undefined) ??
      (doc.confirmedAt as string | undefined) ??
      (doc.acceptedAt as string | undefined) ??
      ctx.now;
    if (ctx.authorizationTime !== undefined && Number.isNaN(parseTime(ctx.authorizationTime))) {
      return { ok: false, reason: "invalid verifier-controlled authorizationTime" };
    }
    // ACTIVATION (validFrom) — the mirror of revocation, evaluated at the SAME artifact time. A key
    // that was not yet active cannot have validly signed: without this a compromised or
    // not-yet-issued device key could sign documents dated before its own activation and every
    // check downstream would pass, because the window was only ever closed at one end.
    if (entry.validFrom != null) {
      const from = parseTime(entry.validFrom);
      const at = parseTime(artifactTime);
      if (Number.isNaN(from) || Number.isNaN(at)) {
        return { ok: false, reason: `cannot evaluate activation time for signing key "${sig.kid}"` };
      }
      if (at < from) {
        return { ok: false, reason: `signing key "${sig.kid}" signed at ${artifactTime}, before its validFrom ${entry.validFrom}` };
      }
    }
    if (entry.revokedAt != null) {
      const rev = parseTime(entry.revokedAt);
      const at = parseTime(artifactTime);
      if (Number.isNaN(rev) || Number.isNaN(at)) {
        return { ok: false, reason: `cannot evaluate revocation time for signing key "${sig.kid}"` };
      }
      if (at >= rev) {
        return { ok: false, reason: `signing key "${sig.kid}" was revoked at ${entry.revokedAt}` };
      }
    }

    // F15 role/type enforcement (skipped where signerType/Role are null — e.g. pairing).
    if (meta.signerType && entry.type !== meta.signerType) {
      return { ok: false, reason: `signer type ${entry.type} != required ${meta.signerType}` };
    }
    let requiredRoles: string[] | null = null;
    if (spec === "noa.decision/0.1") requiredRoles = requiredApproverRole(ctx.riskClass);
    else if (meta.signerRole) requiredRoles = [meta.signerRole];
    if (requiredRoles && !arraySome(requiredRoles, (r) => arrayIncludes(entry.roles, r))) {
      return { ok: false, reason: `signer roles [${entry.roles.join(",")}] lack required ${requiredRoles.join("|")}` };
    }

    // Ed25519 over the §6 preimage: domain ++ SHA256(JCS(doc without sig)).
    const withoutSig = { ...doc };
    delete (withoutSig as Record<string, unknown>).sig;
    const msg = signingMessage(meta.domain, canonicalize(withoutSig));
    if (!verifyEd25519(entry.publicKey, msg, sig.value)) {
      return { ok: false, reason: `invalid signature (kid ${sig.kid})` };
    }
  }

  // 3. REFHASH (cross-artifact bindings, F1) + transitive refEquals (F7b/G7)
  for (const rc of ctx.refHashChecks ?? []) {
    const expected = computeRefHash(rc.rule, rc.artifact);
    const actual = getPath(doc, rc.path);
    if (actual !== expected) {
      return { ok: false, reason: `refHash mismatch at ${rc.path}: got ${String(actual)} expected ${expected}` };
    }
    for (const re of rc.refEquals ?? []) {
      const got = getPath(rc.artifact, re.path);
      if (got !== re.value) {
        return { ok: false, reason: `referenced artifact (${rc.path}) field ${re.path}: got ${JSON.stringify(got)} expected ${JSON.stringify(re.value)}` };
      }
    }
  }

  // 3b. Whole-object virtual-hash binding (F2 — e.g. displayCiphertextHash over the WHOLE object).
  if (ctx.expectVirtualHash !== undefined) {
    const got = virtualHash(doc);
    if (got !== ctx.expectVirtualHash) {
      return { ok: false, reason: `virtualHash mismatch: got ${got} expected ${ctx.expectVirtualHash} (parent-committed hash broken — e.g. recipients-swap)` };
    }
  }

  // 4. EQUALS
  for (const eq of ctx.equals ?? []) {
    const actual = getPath(doc, eq.path);
    if (actual !== eq.value) {
      return { ok: false, reason: `equality failed at ${eq.path}: got ${JSON.stringify(actual)} expected ${JSON.stringify(eq.value)}` };
    }
  }

  // 5. TIME
  for (const mb of ctx.mustBeAfter ?? []) {
    const t = parseTime(getPath(doc, mb.path));
    const limit = parseTime(mb.time);
    if (hasInvalidTime(t, limit) || t <= limit) {
      return { ok: false, reason: `time check failed: ${mb.path} must be after ${mb.time}` };
    }
  }
  for (const mw of ctx.mustBeWithin ?? []) {
    const t = parseTime(getPath(doc, mw.path));
    const min = parseTime(mw.min);
    const max = parseTime(mw.max);
    if (hasInvalidTime(t, min, max) || t < min || t > max) {
      return { ok: false, reason: `time check failed: ${mw.path} must be within [${mw.min}, ${mw.max}]` };
    }
  }

  return { ok: true };
}
