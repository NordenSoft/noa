/**
 * opaque-id.mjs — deterministic PII-free pseudonymization for approver identifiers (D8).
 *
 * The D8 / GDPR-CCPA "hash-only PII" contract (THREAT-MODEL-ADDENDUM §5) forbids a raw, low-entropy
 * identifier (an email, a phone number) from ever entering the SIGNED receipt bytes. Approver
 * identity in a signed receipt (`governance.approval.by`) MUST therefore be an OPAQUE id — the same
 * shape the mobile/HTTP path already uses (an opaque device kid, `phone.ts:285`). This module gives
 * the offline CLI (approve-cli.mjs) that opaque id.
 *
 * Convention (documented, frozen v1): `hmac-sha256:<64 hex>` over the identifier, keyed by a fixed
 * domain-separation tag joined with the receipt's tenant. Two properties:
 *   - DETERMINISTIC within a tenant — the same approver always maps to the same opaque id, so an
 *     auditor can correlate "who approved these N actions" WITHOUT ever seeing the raw email.
 *   - TENANT-DECORRELATED — the same email under two tenants yields two different ids, so an opaque
 *     id cannot be joined across tenants (the D8 "low-entropy value correlates across tenants" point).
 *
 * HONEST BOUND (do not overclaim): the HMAC "key" here is the domain tag + the (public) tenant id,
 * NOT a per-tenant SECRET. The offline CLI has no secret-key infrastructure (its only key material is
 * the approver's Ed25519 SIGNING key, which must not double as a pseudonymization secret). So this
 * defeats cross-tenant linkage and removes the raw PII from the signed bytes, but it does NOT resist
 * a brute-force pre-image attack against a KNOWN low-entropy email within a KNOWN tenant — that would
 * require a per-tenant secret the relay-side D8 path has and this offline path does not. The raw email
 * is therefore retained NOWHERE (neither signed nor local); the operator supplied it on their own
 * command line. This is a strict improvement over the previous behaviour (raw email in signed bytes)
 * and matches the `hmac-sha256:` format the receipt schema already recognizes.
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
  const hex = createHmac("sha256", key).update(identifier, "utf8").digest("hex");
  return `hmac-sha256:${hex}`;
}
