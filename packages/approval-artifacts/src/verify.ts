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

export interface KeyEntry {
  publicKey: string; // base64(DER SPKI) Ed25519
  type: "GATE" | "APPROVER" | "AUDIT" | "ROOT" | "DELEGATED";
  roles: string[];
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
  for (const seg of path.split(".")) {
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

function parseTime(v: unknown): number {
  if (typeof v !== "string") return NaN;
  return Date.parse(v);
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
function requiredApproverRole(riskClass: string | undefined): string[] {
  if (riskClass === "CRITICAL" || riskClass === "IRREVERSIBLE") return ["approve-critical"];
  if (riskClass === "HIGH") return ["approve-high"];
  // LOW/MEDIUM are not in the F15 matrix; accept any approver tier (documented).
  return ["approve-high", "approve-critical"];
}

export function verifyArtifact(artifact: unknown, ctx: VerifyContext): VerifyOutcome {
  if (typeof artifact !== "object" || artifact === null || Array.isArray(artifact)) {
    return { ok: false, reason: "artifact is not an object" };
  }
  const doc = artifact as Record<string, unknown>;
  const spec = doc.spec;
  if (typeof spec !== "string" || !(spec in ARTIFACTS)) {
    return { ok: false, reason: `unknown or missing spec: ${JSON.stringify(spec)}` };
  }
  const meta = ARTIFACTS[spec]!;

  // 1. STRUCTURAL
  const schema = ctx.schemas[spec];
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
    if (requiredRoles && !requiredRoles.some((r) => entry.roles.includes(r))) {
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
    if (Number.isNaN(t) || Number.isNaN(limit) || t <= limit) {
      return { ok: false, reason: `time check failed: ${mb.path} must be after ${mb.time}` };
    }
  }
  for (const mw of ctx.mustBeWithin ?? []) {
    const t = parseTime(getPath(doc, mw.path));
    const min = parseTime(mw.min);
    const max = parseTime(mw.max);
    if (Number.isNaN(t) || t < min || t > max) {
      return { ok: false, reason: `time check failed: ${mw.path} must be within [${mw.min}, ${mw.max}]` };
    }
  }

  return { ok: true };
}
