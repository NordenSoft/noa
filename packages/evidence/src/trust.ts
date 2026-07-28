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
import { parseDocument } from "./bytes.js";

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
 * Normalize a `--tenant-root` DOCUMENT (bytes, or its JSON text) into a `Record<string, KeyEntry>`
 * of ROOT keys. Accepts either the terse `{ "<kid>": "<base64 SPKI>" }` form (wrapped as
 * `{type:"ROOT", roles:[]}`) or a full KeyEntry map (used verbatim — but any entry MUST be
 * `type:"ROOT"`, else it is dropped so a non-root key can never masquerade as the trust anchor).
 */
export function asRootKeyEntryMap(input: Uint8Array | string): Record<string, KeyEntry> {
  // BYTES-IN. This is PUBLISHED and independently callable, and every entry is read four times
  // (type, publicKey twice, roles, revokedAt) while building the TRUST ROOT — which is exactly why
  // it used to snapshot: a flipping getter could let a ROOT-typed entry be validated and a
  // different key be installed. The `--tenant-root` is a FILE, so it now arrives as bytes and the
  // kernel's parser produces the inert tree; four reads of parser output cannot disagree, and the
  // getter the snapshot defended against is not expressible in a byte document. An unparseable
  // document (including a caller-owned object handed in where bytes belong) is the fail-closed
  // empty root: no key resolves, so every signature check fails.
  const parsed = parseDocument(input, "tenant root");
  if (!parsed.ok) return {};
  const raw: unknown = parsed.value;
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
 * Normalize a `--checkpoint-keyring` DOCUMENT (bytes, or its JSON text) into a
 * `Record<string, string>` (kid -> base64 SPKI), the shape `noa-receipt`'s `verifyChain`/
 * `verifyCheckpoint` consume. Accepts terse `kid->string` or `kid->{publicKey}`.
 */
export function asStringKeyring(input: Uint8Array | string): Keyring {
  // BYTES-IN — same reasoning as `asRootKeyEntryMap` above. An unparseable document is the
  // fail-closed empty keyring, which `verifyEvidence` turns into UNVERIFIED (F7a), never VALID.
  const parsed = parseDocument(input, "checkpoint keyring");
  if (!parsed.ok) return {};
  const raw: unknown = parsed.value;
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
  // TODO(bytes-in): the snapshot that used to stand here is GONE and nothing replaces it for a
  // DIRECT caller. Inside this package the three arguments are no longer caller-owned objects:
  // `rootKeyring` is `asRootKeyEntryMap`'s own output over a parsed byte document, and `delegation`
  // and `manifest` are sub-trees of the bundle the kernel's parser produced — none of them can
  // carry a getter, so re-snapshotting them was already a no-op on this path. But `index.ts`
  // publishes this function, and a direct caller may still hand it three live objects; the old
  // comment said as much ("NOT safe when called directly, which the package entry point permits").
  // These are INTERMEDIATE VALUES, not documents — re-serializing a sub-tree of an
  // already-parsed bundle just to re-parse it here would be theatre — so the honest answer is that
  // the direct-call hazard is now the caller's, and closing it properly means either the kernel
  // publishing its options/ingest boundary or this function ceasing to be public. Reported.
  const out: Record<string, KeyEntry> = { ...rootKeyring };
  // The two shape checks the deleted snapshot used to make redundant: a delegation or manifest that
  // is not a plain object with the expected members yields the fail-closed empty/partial keyring
  // instead of a TypeError escaping this function.
  if (delegation === null || typeof delegation !== "object") return {};
  // the root-delegated manifest-signing key (verifies the Key Manifest; role per F15).
  out[delegation.delegatedKid] = {
    publicKey: delegation.delegatedPublicKey,
    type: "DELEGATED",
    roles: Array.isArray(delegation.permissions) ? [...delegation.permissions] : [],
    // `delegation.validFrom` IS this key's activation time — the same rule every manifest key below
    // already follows, and the same rule `verifyArtifact` applies to every other signer: a key is
    // authorized from its activation instant, evaluated at the ARTIFACT's own time.
    //
    // This was previously left unapplied, with the shipped fixtures cited as the reason to defer the
    // question (their manifest `issuedAt` 09:30 precedes this delegation's `validFrom` 10:00). That
    // reasoning had it backwards: `verifyArtifact` already resolves a Key Manifest's artifact time
    // from `doc.issuedAt`, so the codebase's own convention is that `issuedAt` IS the issuance/
    // signing instant — which makes the fixture a defect, not a rival reading, and the fixture has
    // been corrected (delegation opens 10:00, manifest issued 10:30). Leaving the field unapplied
    // meant a delegated signer could stamp a manifest with any date before its own delegation and
    // every downstream check still passed, because the window was open at neither end here.
    validFrom: delegation.validFrom ?? null,
  };
  // the gate/approver/audit keys the manifest lists.
  if (manifest === null || typeof manifest !== "object" || !Array.isArray(manifest.keys)) return out;
  for (const k of manifest.keys) {
    if (typeof k.publicKey === "string") {
      // validFrom is carried through (it was previously DROPPED here, so a manifest key's activation
      // time never reached verifyArtifact and pre-activation signatures verified clean).
      out[k.kid] = { publicKey: k.publicKey, type: k.type, roles: Array.isArray(k.roles) ? [...k.roles] : [], validFrom: k.validFrom ?? null, revokedAt: k.revokedAt ?? null };
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
  // TODO(bytes-in): same residual as `buildResolvedKeyring` above — on this package's own path the
  // manifest is a sub-tree of the kernel-parsed bundle and carries no getters, but the function is
  // published and a direct caller can still pass a live object. An empty keyring stays the
  // fail-closed outcome for anything this loop cannot read.
  const out: Keyring = {};
  if (manifest === null || typeof manifest !== "object" || !Array.isArray(manifest.keys)) return out;
  for (const k of manifest.keys) {
    if ((k.type === "GATE" || k.type === "APPROVER") && typeof k.publicKey === "string") {
      out[k.kid] = k.publicKey;
    }
  }
  return out;
}
