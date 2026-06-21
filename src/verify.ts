import type { Receipt, Checkpoint } from "./types.js";
import { validateReceiptShape } from "./schema.js";
import { receiptHashInput, checkpointHashInput } from "./canonicalize.js";
import { sha256Hex } from "./hash.js";
import { verifyEd25519, type Keyring, type IdentityManifest } from "./keys.js";
import { signingMessage, RECEIPT_SIG_DOMAIN, CHECKPOINT_SIG_DOMAIN } from "./signing.js";
import { safeParse } from "./safe-json.js";

export type VerifyStatus =
  | "VALID" // structure + hash-chain + signatures all verified against the supplied keyring
  | "UNVERIFIED" // hash-chain ok, but NO keyring supplied so signatures were not authenticated
  | "UNTRUSTED" // signature authenticated, but the (agent.id, sig.kid) pairing is NOT authorized by the supplied identity manifest (cross-agent impersonation)
  | "TAMPERED" // an integrity check failed (incl. an unknown signing key when a keyring IS supplied)
  | "MALFORMED"; // not a well-formed receipt chain

export interface VerifyOptions {
  /** Trust root: kid -> base64 SPKI public key. Supply it to authenticate signatures. */
  keyring?: Keyring;
  /** Signed checkpoint asserting the expected head — enables tail-truncation detection. */
  checkpoint?: Checkpoint;
  /** Hard cap on receipts processed (DoS bound). */
  maxReceipts?: number;
  /**
   * Optional `agent.id -> authorized kid(s)` binding (a trust input, like the keyring). When supplied,
   * a receipt whose `(agent.id, sig.kid)` pairing is not authorized is rejected as UNTRUSTED — this is
   * what makes a VALID result mean "THIS agent.id signed", not just "a keyring-trusted key signed".
   * Omit it to keep kid-level attribution (the weaker, documented guarantee).
   */
  identityManifest?: IdentityManifest;
}

export interface VerifyResult {
  status: VerifyStatus;
  chain: string | null;
  count: number;
  signaturesVerified: boolean;
  tailChecked: boolean;
  badSeq?: number;
  reason?: string;
  warnings: string[];
}

const DEFAULT_MAX_RECEIPTS = 1_000_000;

function fail(
  status: VerifyStatus,
  reason: string,
  chain: string | null,
  count: number,
  badSeq?: number,
): VerifyResult {
  const r: VerifyResult = { status, chain, count, signaturesVerified: false, tailChecked: false, reason, warnings: [] };
  if (badSeq !== undefined) r.badSeq = badSeq;
  return r;
}

/**
 * Verify a NOA receipt chain. Pure, offline, deterministic — no network, no NOA cloud.
 *
 * Trust model (stated honestly; see THREAT-MODEL.md):
 *  - The supplied keyring is the trust root. With it, every signature is authenticated and a
 *    key is held continuous per (agent.id): a mid-chain key swap is rejected, and an unknown
 *    kid is treated as TAMPERED (not silently accepted — that would be TOFU on attacker input).
 *  - Without a keyring, signatures cannot be authenticated → status UNVERIFIED (never VALID).
 *  - IDENTITY: with an `identityManifest` (agent.id -> authorized kid(s)), a receipt whose
 *    (agent.id, sig.kid) pairing is not authorized is UNTRUSTED — this upgrades attribution from
 *    "a keyring-trusted key signed" to "THIS agent.id signed". Without it, attribution is kid-level:
 *    in a multi-key keyring any trusted key can assert any agent.id (cross-agent impersonation).
 *  - Without a checkpoint, TAIL-TRUNCATION cannot be detected offline (reported in warnings).
 *  - FORK / EQUIVOCATION: an offline verifier only sees the branch it is given; it cannot know
 *    the signer also signed a different history at the same seq. Detecting that needs an
 *    external witness / transparency log (v1.0). Reported in warnings.
 */
export function verifyChain(receipts: unknown, opts: VerifyOptions = {}): VerifyResult {
  const maxReceipts = opts.maxReceipts ?? DEFAULT_MAX_RECEIPTS;

  if (!Array.isArray(receipts)) return fail("MALFORMED", "input is not an array of receipts", null, 0);
  if (receipts.length === 0) return fail("MALFORMED", "empty receipt array", null, 0);
  if (receipts.length > maxReceipts) return fail("MALFORMED", `too many receipts (>${maxReceipts})`, null, receipts.length);

  // Validate the optional identity manifest (a trust input). Fail-closed: a malformed manifest is an
  // operator error, never silently ignored (that would re-open the very impersonation gap it closes).
  const manifest = opts.identityManifest;
  if (manifest !== undefined) {
    if (typeof manifest !== "object" || manifest === null || Array.isArray(manifest)) {
      return fail("MALFORMED", "identityManifest must be an object (agent.id -> kid[])", null, 0);
    }
    // Validate over the SAME own-property view the enforcement points read (hasOwnProperty —
    // includes NON-ENUMERABLE own props). Object.entries() only sees enumerable own props, so a
    // non-enumerable own entry (e.g. one set via Object.defineProperty by a non-JSON consumer)
    // would escape validation yet still be read by 4c-bis/§5b — letting an unvalidated value
    // authorize an impersonation, or a non-array value throw out of this never-throws API.
    for (const aid of Object.getOwnPropertyNames(manifest)) {
      const kids = (manifest as Record<string, unknown>)[aid];
      if (!Array.isArray(kids) || !kids.every((k) => typeof k === "string")) {
        return fail("MALFORMED", `identityManifest["${aid}"] must be an array of kid strings`, null, 0);
      }
    }
  }

  // 1. Structural validation of every element (runs BEFORE any hashing).
  for (let idx = 0; idx < receipts.length; idx++) {
    const res = validateReceiptShape(receipts[idx]);
    if (!res.ok) {
      return fail("MALFORMED", `receipt[${idx}]: ${res.errors.join("; ")}`, null, receipts.length, idx);
    }
  }
  const list = receipts as Receipt[];

  // 2. Single chain partition.
  const chainId = list[0]!.scope.chain;
  for (const r of list) {
    if (r.scope.chain !== chainId) {
      return fail("TAMPERED", "multiple chain partitions in one input", chainId, list.length);
    }
  }

  // 3. Order by seq; require contiguous 0..n-1, unique.
  const bySeq = new Map<number, Receipt>();
  for (const r of list) {
    if (bySeq.has(r.chain.seq)) return fail("TAMPERED", `duplicate seq ${r.chain.seq}`, chainId, list.length, r.chain.seq);
    bySeq.set(r.chain.seq, r);
  }
  const ordered: Receipt[] = [];
  for (let s = 0; s < list.length; s++) {
    const r = bySeq.get(s);
    if (!r) return fail("TAMPERED", `seq gap: missing seq ${s}`, chainId, list.length, s);
    ordered.push(r);
  }

  const haveKeyring = opts.keyring !== undefined;
  const keyring = opts.keyring ?? {};
  const warnings: string[] = [];

  // 4. Walk the chain: hash, key-pinning, signature, linkage, timestamp monotonicity.
  const pinnedKid = new Map<string, string>(); // agent.id -> kid (key continuity)
  let prev: Receipt | null = null;

  for (const r of ordered) {
    const seq = r.chain.seq;

    // 4a. Hash integrity.
    let hashInput: string;
    try {
      hashInput = receiptHashInput(r);
    } catch {
      // canonicalization refused the content (e.g. non-well-formed Unicode that slipped past
      // structural validation) — treat as malformed, never throw out of the public API.
      return fail("MALFORMED", "receipt contains non-canonicalizable content", chainId, list.length, seq);
    }
    const recomputed = "sha256:" + sha256Hex(hashInput);
    if (recomputed !== r.chain.hash) {
      return fail("TAMPERED", "hash mismatch (content altered)", chainId, list.length, seq);
    }

    // 4b. Key continuity per agent.id (rejects mid-chain key swap).
    const pinned = pinnedKid.get(r.agent.id);
    if (pinned === undefined) pinnedKid.set(r.agent.id, r.sig.kid);
    else if (pinned !== r.sig.kid) {
      return fail("TAMPERED", `key swap for agent "${r.agent.id}" (kid ${pinned} -> ${r.sig.kid})`, chainId, list.length, seq);
    }

    // 4c. Signature. With a keyring, an unknown kid is TAMPERED, not a soft pass.
    if (haveKeyring) {
      const pub = keyring[r.sig.kid];
      if (!pub) return fail("TAMPERED", `unknown signing key "${r.sig.kid}" not in keyring`, chainId, list.length, seq);
      const ok = verifyEd25519(pub, signingMessage(RECEIPT_SIG_DOMAIN, hashInput), r.sig.value);
      if (!ok) return fail("TAMPERED", `invalid signature (kid ${r.sig.kid})`, chainId, list.length, seq);
    }

    // 4c-bis. Identity binding — ONLY meaningful once the signature is AUTHENTICATED (gated on
    // haveKeyring, mirroring spec §5b which runs after §5). Authenticating the signature proves "a
    // keyring-trusted key signed this"; this proves "that key is AUTHORIZED to speak for THIS agent.id".
    // An authenticated-but-unauthorized pairing is exactly cross-agent impersonation → reject as
    // UNTRUSTED (distinct from TAMPERED: bytes intact + key real, BINDING not). Without a keyring the
    // kid is unauthenticated, so an UNTRUSTED verdict would overclaim authentication never performed —
    // the result stays UNVERIFIED (with a warning) instead.
    if (haveKeyring && manifest !== undefined) {
      const allowed = Object.prototype.hasOwnProperty.call(manifest, r.agent.id) ? manifest[r.agent.id]! : undefined;
      if (allowed === undefined || !allowed.includes(r.sig.kid)) {
        return fail("UNTRUSTED", `agent "${r.agent.id}" is not authorized for signing key "${r.sig.kid}" (identity manifest)`, chainId, list.length, seq);
      }
    }

    // 4d. Linkage.
    if (seq === 0) {
      if (r.chain.prevHash !== null) return fail("TAMPERED", "genesis prevHash must be null", chainId, list.length, 0);
    } else if (r.chain.prevHash !== prev!.chain.hash) {
      return fail("TAMPERED", `broken linkage at seq ${seq}`, chainId, list.length, seq);
    }

    // 4e. Timestamp monotonicity (soft — clocks are not a security primitive, but a regression is suspicious).
    if (prev) {
      const a = Date.parse(prev.ts);
      const b = Date.parse(r.ts);
      if (!Number.isNaN(a) && !Number.isNaN(b) && b < a) {
        warnings.push(`non-monotonic timestamp at seq ${seq} (ts went backwards)`);
      }
    }
    prev = r;
  }

  // 5. Tail-truncation check (only possible with a checkpoint).
  const head = ordered[ordered.length - 1]!;
  let tailChecked = false;
  if (opts.checkpoint) {
    const cp = opts.checkpoint;
    const cpVerify = verifyCheckpoint(cp, opts.keyring);
    if (cpVerify === "bad spec" || cpVerify === "malformed checkpoint") {
      return fail("TAMPERED", `checkpoint invalid: ${cpVerify}`, chainId, list.length);
    }
    // The checkpoint signature is held to the SAME trust root as receipts: with a keyring, a
    // checkpoint that is not authenticated (bad signature OR a kid not in the keyring) is
    // TAMPERED — never silently honored. Otherwise an attacker could mint their own key, drop
    // the tail, and forge a checkpoint over the truncated head (a trust-root bypass on the only
    // anti-truncation control). Mirrors the receipt unknown-kid rule above.
    if (haveKeyring && cpVerify !== "ok") {
      return fail("TAMPERED", `checkpoint not authenticated against keyring (${cpVerify})`, chainId, list.length);
    }
    if (cp.chain !== chainId) return fail("TAMPERED", "checkpoint chain mismatch", chainId, list.length);
    if (cp.highestSeq !== head.chain.seq || cp.headHash !== head.chain.hash) {
      return fail("TAMPERED", "chain head does not match checkpoint (tail truncated/extended)", chainId, list.length, head.chain.seq);
    }
    // 5b. Checkpoint IDENTITY binding (mirrors receipt 4c-bis). Without it, B1's per-agent authorization
    // would cover receipts but NOT the checkpoint — so a co-trusted-but-unauthorized key (authorized for
    // some OTHER agent) could truncate the tail and forge a checkpoint over the truncated head, defeating
    // the only offline anti-truncation control in exactly the multi-key deployment B1 hardens. When a
    // manifest is supplied (and the signature is authenticated), the checkpoint's kid MUST be authorized
    // for the HEAD receipt's agent.id — the agent whose tail it certifies.
    if (haveKeyring && manifest !== undefined) {
      const allowed = Object.prototype.hasOwnProperty.call(manifest, head.agent.id) ? manifest[head.agent.id]! : undefined;
      if (allowed === undefined || !allowed.includes(cp.sig.kid)) {
        return fail("UNTRUSTED", `checkpoint signing key "${cp.sig.kid}" is not authorized for head agent "${head.agent.id}" (identity manifest)`, chainId, list.length, head.chain.seq);
      }
    }
    // tailChecked is true ONLY for an authenticated checkpoint — an unauthenticated head match
    // is not a tail check and must not be reported as one.
    tailChecked = cpVerify === "ok";
    if (cpVerify !== "ok") {
      warnings.push("checkpoint present but not authenticated (no keyring) — tail NOT verified");
    }
  } else {
    warnings.push("no checkpoint supplied: tail-truncation (deleting most-recent receipts) cannot be detected offline");
  }

  // 6. Equivocation/fork is fundamentally undetectable offline from a single branch.
  warnings.push("fork/equivocation is not detectable offline: this verifies the branch you were given, not that the signer signed no other history at the same seq (needs an external witness — v1.0)");

  if (!haveKeyring) {
    warnings.push("no keyring supplied: signatures were NOT authenticated (status UNVERIFIED, not VALID)");
  }
  if (manifest === undefined) {
    warnings.push("no identityManifest supplied: attribution is kid-level — a VALID result proves a keyring-trusted key signed, NOT which agent.id (cross-agent impersonation undefended in a multi-key keyring)");
  } else if (!haveKeyring) {
    warnings.push("identityManifest supplied but no keyring: identity NOT bound — signatures are unauthenticated, so the (agent.id, kid) pairing was not enforced (status stays UNVERIFIED, never UNTRUSTED)");
  }

  const status: VerifyStatus = haveKeyring ? "VALID" : "UNVERIFIED";
  return { status, chain: chainId, count: list.length, signaturesVerified: haveKeyring, tailChecked, warnings };
}

/**
 * Verify a chain from its RAW JSON text, parsed by the hardened safeParse (duplicate-key /
 * __proto__ / float / depth / size / surrogate rejection). Prefer this over
 * `verifyChain(JSON.parse(text))` for untrusted input: the strict-parse guarantees are a
 * property of THIS entry point, not of a caller's own `JSON.parse` (which silently accepts
 * duplicate keys). Returns MALFORMED instead of throwing on bad input.
 */
export function verifyChainText(text: string, opts: VerifyOptions = {}): VerifyResult {
  let parsed: unknown;
  try {
    parsed = safeParse(text);
  } catch (e) {
    return { status: "MALFORMED", chain: null, count: 0, signaturesVerified: false, tailChecked: false, reason: (e as Error).message, warnings: [] };
  }
  return verifyChain(parsed, opts);
}

type CheckpointVerdict = "ok" | "unverified" | "bad spec" | "malformed checkpoint" | "bad checkpoint signature";

export function verifyCheckpoint(cp: Checkpoint, keyring?: Keyring): CheckpointVerdict {
  if (cp.spec !== "noa.checkpoint/0.1") return "bad spec";
  if (typeof cp.chain !== "string" || typeof cp.headHash !== "string" || typeof cp.highestSeq !== "number") {
    return "malformed checkpoint";
  }
  if (!cp.sig || typeof cp.sig.kid !== "string" || typeof cp.sig.value !== "string") return "malformed checkpoint";
  const pub = keyring?.[cp.sig.kid];
  if (!pub) return "unverified";
  let msg: Buffer;
  try {
    msg = signingMessage(CHECKPOINT_SIG_DOMAIN, checkpointHashInput(cp));
  } catch {
    return "malformed checkpoint";
  }
  const ok = verifyEd25519(pub, msg, cp.sig.value);
  return ok ? "ok" : "bad checkpoint signature";
}
