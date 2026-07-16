/**
 * pii.ts — deterministic, PII-free pseudonymization for low-entropy receipt identifiers (D8).
 *
 * The D8 / GDPR-CCPA "hash-only PII" contract (THREAT-MODEL-ADDENDUM §5) forbids a raw, low-entropy
 * identifier (an email, a phone number) from entering the SIGNED receipt bytes. Any producer that puts
 * a human identifier into `governance.approval.by` MUST pseudonymize it first — this is that helper.
 * (The offline MCP approval CLI has its own byte-identical mirror at
 * `packages/adapter-core/src/opaque-id.mjs`, because that package consumes the PUBLISHED noa-receipt
 * and cannot import an unpublished symbol from this source tree. Keep the two ALGORITHM-IDENTICAL:
 * same domain tag, same separator, same normalization.)
 *
 * Convention (documented, frozen v1): `hmac-sha256:<64 hex>` over the NORMALIZED identifier, keyed by
 * a fixed domain-separation tag joined with the receipt's tenant. Properties:
 *   - DETERMINISTIC within a tenant — the same approver always maps to the same opaque id (auditable).
 *   - TENANT-DECORRELATED — the same email under two tenants yields two different ids.
 *
 * KEYLESS-HMAC HONEST BOUND (do not overclaim): the HMAC "key" is the domain tag + the (public)
 * tenant id, NOT a per-tenant SECRET. There is no secret-key infrastructure in the offline producer
 * path. So this removes raw PII from signed bytes and defeats cross-tenant linkage, but it is NOT
 * brute-force-resistant against a KNOWN low-entropy email within a KNOWN tenant — a real secret-keyed
 * HMAC (the relay-side D8 path) is a future enhancement that needs key infra. This is a strict
 * improvement over raw-email-in-signed-bytes and matches the `hmac-sha256:` format the schema accepts.
 */
import { createHmac } from "node:crypto";

/** Frozen domain-separation tag — bump the vN suffix only with a documented migration. */
const APPROVER_ID_DOMAIN = "noa-receipt/approver-id/v1";

/**
 * NUL separator between the fixed domain tag and the tenant. Built with String.fromCharCode (not a
 * literal control char) so this source file stays pure text; NUL cannot occur in a normal tenant id.
 */
const SEP = String.fromCharCode(0);

/**
 * Canonicalize an identifier before hashing so trivial variants do not defeat de-correlation:
 * trim, lowercase, and — for an email-shaped value (exactly one '@', non-empty local part) — strip
 * plus-addressing (`jane+audit@x` -> `jane@x`, since a `+tag` routes to the same mailbox). A value
 * with no '@' is only trimmed+lowercased (the CLI contract for `--by` is an email).
 */
function normalizeIdentifier(raw: string): string {
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
 * @param identifier the raw identifier (email/phone) — never returned, never logged here.
 * @param tenant the receipt's tenant, for cross-tenant de-correlation.
 * @returns `hmac-sha256:<64 lowercase hex>` — safe to place in signed receipt bytes.
 */
export function opaqueApproverId(identifier: string, tenant: string | null = null): string {
  if (typeof identifier !== "string" || identifier.length === 0) {
    throw new Error("opaqueApproverId: identifier must be a non-empty string");
  }
  const key = `${APPROVER_ID_DOMAIN}${SEP}${tenant ?? ""}`;
  const hex = createHmac("sha256", key).update(normalizeIdentifier(identifier), "utf8").digest("hex");
  return `hmac-sha256:${hex}`;
}
