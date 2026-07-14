/**
 * F7 external-trust-root anchoring: resolve the bundle's Key Manifest into the concrete keyrings the
 * verifier trusts, ONLY via the EXTERNAL `--tenant-root` + `--checkpoint-keyring` inputs — never a
 * key taken from the bundle itself (that would be self-authorization, F7a). The delegation chain is
 * `external tenant-root ──signs──> keyDelegation ──authorizes──> delegated manifest-signer
 * ──signs──> keyManifest ──lists──> gate/approver/audit keys`. Step 1 of the verifier does the
 * CRYPTOGRAPHIC verification of that chain (via `verifyArtifact`); these helpers are the mechanical
 * shape-reading + keyring assembly the step consumes. Nothing here trusts a signature by itself.
 */
import type { KeyEntry } from "noa-approval-artifacts";
import type { Keyring } from "noa-receipt";

/** A resolved manifest key entry (a read-only reflection of the frozen `noa.key-manifest/0.1`
 *  shape — validated by its own schema at verify-time, never redefined here). */
export interface ManifestKey {
  kid: string;
  type: "GATE" | "APPROVER" | "AUDIT";
  roles: string[];
  publicKey?: string;
  hpkePublicKey?: string;
  validFrom: string;
  revokedAt: string | null;
}

export interface ManifestDoc {
  spec: string;
  tenant: string;
  version: number;
  issuedAt: string;
  expiresAt: string;
  previousManifestHash: string | null;
  keys: ManifestKey[];
  sig: { alg: string; kid: string; value: string };
}

export interface DelegationDoc {
  spec: string;
  tenant: string;
  delegatedKid: string;
  delegatedPublicKey: string;
  permissions: string[];
  validFrom: string;
  expiresAt: string;
  sig: { alg: string; kid: string; value: string };
}

/**
 * Normalize a `--tenant-root` file into a `Record<string, KeyEntry>` of ROOT keys. Accepts either
 * the terse `{ "<kid>": "<base64 SPKI>" }` form (wrapped as `{type:"ROOT", roles:[]}`) or a full
 * KeyEntry map (used verbatim — but any entry MUST be `type:"ROOT"`, else it is dropped so a
 * non-root key can never masquerade as the trust anchor).
 */
export function asRootKeyEntryMap(raw: unknown): Record<string, KeyEntry> {
  const out: Record<string, KeyEntry> = {};
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) return out;
  for (const [kid, v] of Object.entries(raw as Record<string, unknown>)) {
    if (typeof v === "string") {
      out[kid] = { publicKey: v, type: "ROOT", roles: [] };
    } else if (typeof v === "object" && v !== null) {
      const e = v as Partial<KeyEntry>;
      if (e.type === "ROOT" && typeof e.publicKey === "string") {
        out[kid] = { publicKey: e.publicKey, type: "ROOT", roles: Array.isArray(e.roles) ? e.roles : [], revokedAt: e.revokedAt ?? null };
      }
    }
  }
  return out;
}

/**
 * Normalize a `--checkpoint-keyring` file into a `Record<string, string>` (kid -> base64 SPKI), the
 * shape `noa-receipt`'s `verifyChain`/`verifyCheckpoint` consume. Accepts terse `kid->string` or
 * `kid->{publicKey}`.
 */
export function asStringKeyring(raw: unknown): Keyring {
  const out: Keyring = {};
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) return out;
  for (const [kid, v] of Object.entries(raw as Record<string, unknown>)) {
    if (typeof v === "string") out[kid] = v;
    else if (typeof v === "object" && v !== null && typeof (v as { publicKey?: unknown }).publicKey === "string") {
      out[kid] = (v as { publicKey: string }).publicKey;
    }
  }
  return out;
}

/**
 * The resolved KeyEntry keyring `verifyArtifact` uses for EVERY signed side artifact: the external
 * ROOT key(s) + the root-delegated manifest-signer (so the Key Manifest itself verifies, F15
 * `key-manifest-sign`) + every gate/approver/audit key the manifest lists (with its type, roles,
 * and revocation). This is the ONLY keyring downstream artifacts are checked against — its trust
 * traces entirely to the external root through the delegation (verified separately in step 1).
 */
export function buildResolvedKeyring(
  rootKeyring: Record<string, KeyEntry>,
  delegation: DelegationDoc,
  manifest: ManifestDoc,
): Record<string, KeyEntry> {
  const out: Record<string, KeyEntry> = { ...rootKeyring };
  // the root-delegated manifest-signing key (verifies the Key Manifest; role per F15).
  out[delegation.delegatedKid] = {
    publicKey: delegation.delegatedPublicKey,
    type: "DELEGATED",
    roles: Array.isArray(delegation.permissions) ? [...delegation.permissions] : [],
  };
  // the gate/approver/audit keys the manifest lists.
  for (const k of manifest.keys) {
    if (typeof k.publicKey === "string") {
      out[k.kid] = { publicKey: k.publicKey, type: k.type, roles: Array.isArray(k.roles) ? [...k.roles] : [], revokedAt: k.revokedAt ?? null };
    }
    // AUDIT keys have no ed25519 publicKey (hpke-only, never a signer) — omitted from the signer keyring.
  }
  return out;
}

/**
 * The `Record<string,string>` receipt keyring `verifyChain` consumes: every gate/approver signer key
 * the manifest lists (the DEFERRED/ALLOWED/BLOCKED/EXECUTED/timeout receipt signers). It deliberately
 * does NOT include the external checkpoint keyring: the reused `noa.checkpoint/0.1` anchor is
 * authenticated SEPARATELY against `--checkpoint-keyring` (step 17), never against a manifest-derived
 * key — otherwise a compromised gate that forged a manifest could self-authorize its own tail anchor,
 * defeating F7. Chain integrity (this keyring) and tail-completeness (the external checkpoint keyring)
 * are two independent trust roots.
 */
export function buildReceiptKeyring(manifest: ManifestDoc): Keyring {
  const out: Keyring = {};
  for (const k of manifest.keys) {
    if ((k.type === "GATE" || k.type === "APPROVER") && typeof k.publicKey === "string") {
      out[k.kid] = k.publicKey;
    }
  }
  return out;
}
