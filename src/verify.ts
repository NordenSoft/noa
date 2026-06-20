import type { Receipt, Checkpoint } from "./types.js";
import { validateReceiptShape } from "./schema.js";
import { receiptHashInput, checkpointHashInput } from "./canonicalize.js";
import { sha256Hex, sha256Digest } from "./hash.js";
import { verifyEd25519, type Keyring } from "./keys.js";

export type VerifyStatus =
  | "VALID" // structure + hash-chain + signatures all verified
  | "STRUCTURE_VALID_UNVERIFIED_SIG" // hash-chain ok, but no keyring (or unknown kid) to verify signatures
  | "TAMPERED" // an integrity check failed
  | "MALFORMED"; // not a well-formed receipt chain

export interface VerifyOptions {
  keyring?: Keyring;
  /** Signed checkpoint asserting the expected head — enables tail-truncation detection. */
  checkpoint?: Checkpoint;
  /** Hard cap on receipts processed (DoS bound). */
  maxReceipts?: number;
}

export interface VerifyResult {
  status: VerifyStatus;
  chain: string | null;
  count: number;
  signaturesVerified: boolean;
  tailChecked: boolean;
  /** seq at which the first problem was found (for TAMPERED/MALFORMED). */
  badSeq?: number;
  reason?: string;
  /** Honest caveats the caller should surface (e.g. tail-truncation not checked). */
  warnings: string[];
}

const DEFAULT_MAX_RECEIPTS = 1_000_000;

function fail(status: VerifyStatus, reason: string, chain: string | null, count: number, badSeq?: number): VerifyResult {
  const r: VerifyResult = { status, chain, count, signaturesVerified: false, tailChecked: false, reason, warnings: [] };
  if (badSeq !== undefined) r.badSeq = badSeq;
  return r;
}

/**
 * Verify a NOA receipt chain. Pure, offline, deterministic — no network, no NOA cloud.
 *
 * Trust model (be honest):
 *  - With a keyring, signatures are verified and a key is PINNED per (agent.id): a mid-chain
 *    key swap is rejected. The keyring is the trust root — obtain genesis keys out-of-band.
 *  - Without a checkpoint, TAIL-TRUNCATION (deleting the most recent receipts) cannot be
 *    detected offline. This is reported in `warnings`, never silently passed.
 */
export function verifyChain(receipts: unknown, opts: VerifyOptions = {}): VerifyResult {
  const maxReceipts = opts.maxReceipts ?? DEFAULT_MAX_RECEIPTS;

  if (!Array.isArray(receipts)) return fail("MALFORMED", "input is not an array of receipts", null, 0);
  if (receipts.length === 0) return fail("MALFORMED", "empty receipt array", null, 0);
  if (receipts.length > maxReceipts) return fail("MALFORMED", `too many receipts (>${maxReceipts})`, null, receipts.length);

  // 1. Structural validation of every element.
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

  // 4. Walk the chain: hash, signature, linkage, key-pinning.
  const pinnedKid = new Map<string, string>(); // agent.id -> kid
  const keyring = opts.keyring;
  let allSigsVerified = true;
  let anySigUnverifiable = false;
  let prev: Receipt | null = null;

  for (const r of ordered) {
    const seq = r.chain.seq;

    // 4a. Hash integrity.
    const hashInput = receiptHashInput(r);
    const recomputed = "sha256:" + sha256Hex(hashInput);
    if (recomputed !== r.chain.hash) {
      return fail("TAMPERED", "hash mismatch (content altered)", chainId, list.length, seq);
    }

    // 4b. Key pinning per agent.id.
    const pinned = pinnedKid.get(r.agent.id);
    if (pinned === undefined) {
      pinnedKid.set(r.agent.id, r.sig.kid);
    } else if (pinned !== r.sig.kid) {
      return fail("TAMPERED", `key swap for agent "${r.agent.id}" (kid ${pinned} -> ${r.sig.kid})`, chainId, list.length, seq);
    }

    // 4c. Signature.
    const pub = keyring?.[r.sig.kid];
    if (pub) {
      const ok = verifyEd25519(pub, sha256Digest(hashInput), r.sig.value);
      if (!ok) return fail("TAMPERED", `invalid signature (kid ${r.sig.kid})`, chainId, list.length, seq);
    } else {
      allSigsVerified = false;
      anySigUnverifiable = true;
    }

    // 4d. Linkage.
    if (seq === 0) {
      if (r.chain.prevHash !== null) return fail("TAMPERED", "genesis prevHash must be null", chainId, list.length, 0);
    } else {
      if (r.chain.prevHash !== prev!.chain.hash) {
        return fail("TAMPERED", `broken linkage at seq ${seq}`, chainId, list.length, seq);
      }
    }
    prev = r;
  }

  // 5. Tail-truncation check (only possible with a checkpoint).
  const head = ordered[ordered.length - 1]!;
  let tailChecked = false;
  const warnings: string[] = [];
  if (opts.checkpoint) {
    const cp = opts.checkpoint;
    const cpVerify = verifyCheckpoint(cp, keyring);
    if (cpVerify !== "ok" && cpVerify !== "unverified") {
      return fail("TAMPERED", `checkpoint invalid: ${cpVerify}`, chainId, list.length);
    }
    if (cp.chain !== chainId) return fail("TAMPERED", "checkpoint chain mismatch", chainId, list.length);
    if (cp.highestSeq !== head.chain.seq || cp.headHash !== head.chain.hash) {
      return fail("TAMPERED", "chain head does not match checkpoint (tail truncated/extended)", chainId, list.length, head.chain.seq);
    }
    tailChecked = true;
    if (cpVerify === "unverified") warnings.push("checkpoint signature not verified (kid not in keyring)");
  } else {
    warnings.push("no checkpoint supplied: tail-truncation (deleting most-recent receipts) cannot be detected offline");
  }

  if (anySigUnverifiable) {
    warnings.push("one or more signatures could not be verified (no keyring or unknown kid)");
  }

  const status: VerifyStatus = allSigsVerified ? "VALID" : "STRUCTURE_VALID_UNVERIFIED_SIG";
  return {
    status,
    chain: chainId,
    count: list.length,
    signaturesVerified: allSigsVerified,
    tailChecked,
    warnings,
  };
}

type CheckpointVerdict = "ok" | "unverified" | string;

export function verifyCheckpoint(cp: Checkpoint, keyring?: Keyring): CheckpointVerdict {
  if (cp.spec !== "noa.checkpoint/0.1") return "bad spec";
  if (typeof cp.chain !== "string" || typeof cp.headHash !== "string" || typeof cp.highestSeq !== "number") {
    return "malformed checkpoint";
  }
  const pub = keyring?.[cp.sig?.kid];
  if (!pub) return "unverified";
  const ok = verifyEd25519(pub, sha256Digest(checkpointHashInput(cp)), cp.sig.value);
  return ok ? "ok" : "bad checkpoint signature";
}
