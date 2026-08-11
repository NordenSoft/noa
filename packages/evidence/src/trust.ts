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
import { SIGNING_KEY_LIFECYCLE_SPEC, type Keyring, type SigningKeyLifecycle } from "noa-receipt";
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
        // P0-1: `validFrom` is carried through, exactly as the manifest resolver below does it.
        // It was DROPPED here while `revokedAt` was kept, so a trust root's activation window was
        // open at one end: `verify.ts:234` enforces activation only when the field is non-null, and
        // a signature dated BEFORE a root's own declared activation therefore verified clean.
        // `KeyEntry`'s docstring already named this class — "every keyring resolver silently
        // dropped it and pre-activation signatures verified clean" — and the manifest sibling 80
        // lines down was fixed for it. This one was not.
        //
        // `?? null` and nothing more, deliberately: the parser must NOT invent a second activation
        // rule. An ABSENT value stays absent (legacy roots remain always-active, the documented
        // compatibility rule), and a MALFORMED value is carried so `verify.ts:236-239` refuses it
        // with "cannot evaluate activation time". Dropping a malformed value here would skip the
        // check entirely and fail OPEN — the same shape as the defect being fixed.
        out[kid] = { publicKey: e.publicKey, type: "ROOT", roles: Array.isArray(e.roles) ? e.roles : [], validFrom: e.validFrom ?? null, revokedAt: e.revokedAt ?? null };
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
      const fields = Object.getOwnPropertyNames(v);
      if (fields.length !== 1 || fields[0] !== "publicKey") {
        throw new Error(
          `refusing to flatten signing key ${JSON.stringify(kid)}: conversion would discard lifecycle or authorization fields`,
        );
      }
      out[kid] = (v as { publicKey: string }).publicKey;
    } else {
      throw new Error(`checkpoint keyring entry ${JSON.stringify(kid)} is not a static public key`);
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
  // BYTES-IN RESIDUAL — and what now stands where the deleted snapshot stood, because a comment
  // that only says "nothing replaces it" is a defense claim nobody can act on.
  //
  // On this package's own path the three arguments are not caller-owned objects: `rootKeyring` is
  // `asRootKeyEntryMap`'s output over a parsed byte document, and `delegation`/`manifest` are
  // sub-trees of the bundle the kernel's parser produced, so no getter is expressible. But
  // `index.ts` publishes this function, and a DIRECT caller may still hand it three live objects.
  // Re-serializing an already-parsed sub-tree just to re-parse it here would be theatre, so the
  // guard is the one that actually costs nothing and closes the actual hazard:
  //
  //   EVERY caller-owned field is read EXACTLY ONCE, into a local, before it is used. A flipping
  //   getter cannot be validated as one value and installed as another, because no field is read
  //   twice. What this function returns is then a FRESH graph of primitives and fresh arrays —
  //   it shares no object with the caller's input, so a post-return mutation of the manifest cannot
  //   reach the keyring downstream verification is performed against.
  //
  // What this does NOT close, stated rather than implied: the caller still chooses what to pass,
  // and a `kid` is used as an object key (see `buildReceiptKeyring`'s note). This is a snapshot of
  // VALUES, not an authorization check.
  const out: Record<string, KeyEntry> = { ...rootKeyring };
  // The shape checks the deleted snapshot used to make redundant: a delegation or manifest that is
  // not a plain object with the expected members yields the fail-closed empty/partial keyring
  // instead of a TypeError escaping this function.
  if (delegation === null || typeof delegation !== "object") return {};
  // the root-delegated manifest-signing key (verifies the Key Manifest; role per F15).
  const delegatedKid = delegation.delegatedKid;
  const delegatedPublicKey = delegation.delegatedPublicKey;
  const permissions = delegation.permissions;
  // `delegation.validFrom` IS this key's activation time — the same lifecycle field every manifest
  // key below carries. `verifyArtifact` evaluates it only at caller-owned `authorizationTime` or
  // `now`; it never treats the manifest's signed `issuedAt` as an activation witness.
  //
  // This was previously left unapplied, with the shipped fixtures cited as the reason to defer the
  // question (their manifest `issuedAt` 09:30 precedes this delegation's `validFrom` 10:00). The
  // fixture was corrected (delegation opens 10:00, manifest issued 10:30), but signer-chosen
  // `issuedAt` is only a chronology constraint inside the delegation document model; it is not
  // the trusted time used by the generic key-activation check.
  const delegationValidFrom = delegation.validFrom;
  out[delegatedKid] = {
    publicKey: delegatedPublicKey,
    type: "DELEGATED",
    roles: Array.isArray(permissions) ? [...permissions] : [],
    validFrom: delegationValidFrom ?? null,
  };
  // the gate/approver/audit keys the manifest lists.
  const keys = manifest === null || typeof manifest !== "object" ? undefined : manifest.keys;
  if (!Array.isArray(keys)) return out;
  for (const k of keys) {
    if (k === null || typeof k !== "object") continue;
    const publicKey = k.publicKey;
    // AUDIT keys have no ed25519 publicKey (hpke-only, never a signer) — omitted from the signer keyring.
    if (typeof publicKey !== "string") continue;
    const kid = k.kid;
    const type = k.type;
    const roles = k.roles;
    // validFrom is carried through (it was previously DROPPED here, so a manifest key's activation
    // time never reached verifyArtifact and pre-activation signatures verified clean).
    const validFrom = k.validFrom;
    const revokedAt = k.revokedAt;
    out[kid] = { publicKey, type, roles: Array.isArray(roles) ? [...roles] : [], validFrom: validFrom ?? null, revokedAt: revokedAt ?? null };
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
export function buildReceiptKeyring(manifest: ManifestDoc): SigningKeyLifecycle {
  // BYTES-IN RESIDUAL — same guard as `buildResolvedKeyring` above, for the same reason. On this
  // package's own path the manifest is a sub-tree of the kernel-parsed bundle and carries no
  // getters; the function is published, so a direct caller can still pass a live object. Every
  // caller-owned field below is therefore read EXACTLY ONCE into a local — `type` and `publicKey`
  // used to be read twice each (check, then use), which is the flipping-getter window by
  // definition — and the returned keyring is a fresh graph of primitives that shares nothing with
  // the caller's object. An empty keyring stays the fail-closed outcome for anything this loop
  // cannot read.
  const out: Record<string, { publicKey: string; retiredAt: string | null }> = {};
  const keys = manifest === null || typeof manifest !== "object" ? undefined : manifest.keys;
  if (!Array.isArray(keys)) {
    return { spec: SIGNING_KEY_LIFECYCLE_SPEC, keys: out };
  }
  for (const k of keys) {
    if (k === null || typeof k !== "object") continue;
    const type = k.type;
    if (type !== "GATE" && type !== "APPROVER") continue;
    const publicKey = k.publicKey;
    if (typeof publicKey !== "string") continue;
    const kid = k.kid;
    const revokedAt = k.revokedAt;
    out[kid] = { publicKey, retiredAt: revokedAt ?? null };
  }
  return { spec: SIGNING_KEY_LIFECYCLE_SPEC, keys: out };
}
