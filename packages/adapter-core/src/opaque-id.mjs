/**
 * opaque-id.mjs — deterministic PII-free pseudonymization for approver identifiers (D8).
 *
 * ALGORITHM MIRROR of the core library's `src/pii.ts` (`noa-receipt`). This package consumes the
 * PUBLISHED noa-receipt and cannot import an unpublished symbol from that source tree, so the
 * algorithm is duplicated here — keep the two BYTE-IDENTICAL (same domain tag, separator, and
 * normalization). Same rationale as approval-decision.mjs's RECEIPT_SIG_DOMAIN mirror.
 *
 * The D8 / GDPR-CCPA "hash-only PII" contract (THREAT-MODEL-ADDENDUM §5) forbids a raw, low-entropy
 * identifier (an email, a phone number) from ever entering the SIGNED receipt bytes. Approver
 * identity in a signed receipt (`governance.approval.by`) MUST therefore be an OPAQUE id — the same
 * shape the mobile/HTTP path already uses (an opaque device kid, `phone.ts:285`). This module gives
 * the offline CLI (approve-cli.mjs) that opaque id, plus a fail-closed guard (assertOpaqueApproverBy)
 * that the builders call so NO caller — present or future — can mint a signed receipt with raw PII.
 *
 * Convention (documented, frozen v1): `hmac-sha256:<64 hex>` over the NORMALIZED identifier
 * (trim + lowercase + email plus-tag stripping), keyed by a fixed domain-separation tag joined with
 * the receipt's tenant. Two properties:
 *   - DETERMINISTIC within a tenant — the same approver always maps to the same opaque id, so an
 *     auditor can correlate "who approved these N actions" WITHOUT ever seeing the raw email.
 *   - TENANT-DECORRELATED — the same email under two tenants yields two different ids.
 *
 * KEYLESS-HMAC HONEST BOUND (do not overclaim): the HMAC "key" here is the domain tag + the (public)
 * tenant id, NOT a per-tenant SECRET. This offline CLI has no secret-key infrastructure (its only key
 * material is the approver's Ed25519 SIGNING key, which must not double as a pseudonymization secret).
 * So this removes raw PII from signed bytes and defeats cross-tenant linkage, but it is NOT
 * brute-force-resistant against a KNOWN low-entropy email within a KNOWN tenant — a real secret-keyed
 * HMAC (the relay-side D8 path) is a future enhancement needing key infra. The raw email is retained
 * NOWHERE (neither signed nor local). NOTE: the operator's free-text `--reason` on a denial IS written
 * to the LOCAL, non-signed pending-store index (operator audit) — the retention/permissions of that
 * local file are an ops concern (see the ops runbook), never signed receipt bytes.
 */
import { createHmac } from "node:crypto";

/** Frozen domain-separation tag — bump the vN suffix only with a documented migration. */
const APPROVER_ID_DOMAIN = "noa-receipt/approver-id/v1";

/**
 * A NUL byte separator between the fixed domain tag and the tenant. Built with String.fromCharCode
 * (not a literal control char) so this source file stays pure text. Any single terminator gives
 * injectivity here because APPROVER_ID_DOMAIN is a fixed prefix; NUL is used because it cannot appear
 * in a normal tenant id, so no crafted tenant can straddle the domain/tenant boundary.
 */
const SEP = String.fromCharCode(0);

/**
 * Canonicalize an identifier before hashing so trivial variants do not defeat de-correlation:
 * trim, lowercase, and — for an email-shaped value (exactly one '@', non-empty local part) — strip
 * plus-addressing (`jane+audit@x` -> `jane@x`, since a `+tag` routes to the same mailbox). A value
 * with no '@' is only trimmed+lowercased (the CLI contract for `--by` is an email).
 * MUST stay identical to src/pii.ts's normalizeIdentifier.
 */
function normalizeIdentifier(raw) {
  const s = raw.trim().toLowerCase();
  const at = s.indexOf("@");
  if (at > 0 && s.indexOf("@", at + 1) === -1) {
    const local = s.slice(0, at);
    const domain = s.slice(at + 1);
    const plus = local.indexOf("+");
    const cleanLocal = plus <= 0 ? local : local.slice(0, plus);
    return `${cleanLocal}@${domain}`;
  }
  return s;
}

/**
 * Maps a raw approver identifier (e.g. an email) to an opaque, non-reversible, tenant-scoped id.
 * @param {string} identifier the raw identifier (email/phone) — never returned, never logged here.
 * @param {string|null|undefined} tenant the receipt's tenant, for cross-tenant de-correlation.
 * @returns {string} `hmac-sha256:<64 lowercase hex>` — safe to place in signed receipt bytes.
 */
export function opaqueApproverId(identifier, tenant = null) {
  if (typeof identifier !== "string" || identifier.length === 0) {
    throw new Error("opaqueApproverId: identifier must be a non-empty string");
  }
  // SEP-join so no tenant string can be crafted to collide two distinct (domain, tenant) key spaces.
  const key = `${APPROVER_ID_DOMAIN}${SEP}${tenant ?? ""}`;
  const hex = createHmac("sha256", key).update(normalizeIdentifier(identifier), "utf8").digest("hex");
  return `hmac-sha256:${hex}`;
}

/**
 * Fail-closed guard (defense-in-depth, D8): refuse a `by` that still carries a raw email. Any bare
 * '@' is treated as raw PII — opaque approver ids (`hmac-sha256:<hex>`, `HUMAN:hmac-sha256:<hex>`,
 * device kids) never contain '@'. The receipt builders call this so NO caller, present or future,
 * can mint a signed receipt with a raw email in `governance.approval.by`. Throws (never returns).
 * @param {string} by the approver id about to enter a signed receipt.
 */
export function assertOpaqueApproverBy(by) {
  if (typeof by === "string" && by.includes("@")) {
    throw new Error(
      "assertOpaqueApproverBy: `by` contains a raw email ('@') — approver identity in a signed receipt MUST be an opaque id (D8); pseudonymize it with opaqueApproverId(email, tenant) before building the receipt",
    );
  }
}
