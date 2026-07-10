/**
 * L2 on-receipt policy-compliance (B4) — wires the deterministic evaluator INTO the receipt.
 *
 * `complianceCommit` produces the three binding hashes a receipt commits (policyHash + readSetHash +
 * inputsHash) PLUS the recorded verdict (re-run at commit time);
 * `verifyReceiptCompliance` is the offline proof: given the policy + the recorded inputs (out-of-band,
 * since inputs may be PII and are NEVER placed raw on the receipt), it confirms those hashes authenticate
 * exactly that policy + those inputs, RE-RUNS the deterministic evaluator, and — when the commitment
 * records a verdict — REQUIRES the re-run verdict to equal the recorded one (else ok:false).
 *
 * Honesty razor: this proves "policy P, re-run over the RECORDED inputs I, yields verdict V, and V equals
 * the decision the receipt recorded" — it is substitution-resistant (a receipt cannot commit DENY-inputs
 * while claiming ALLOW). It is NOT proof the policy was in force at decision time, nor that I is
 * true/complete, nor that P is a good rule.
 *
 * AUTHENTICITY: the L2 check operates on the receipt's `governance.compliance` block, which is
 * attacker-mutable on a NON-authentic receipt. By itself it does NOT establish that the receipt is genuine.
 * The carrier MUST be independently authenticated — either pass `{ keyring }` here (the carrier's own hash
 * + Ed25519 signature are then verified BEFORE the L2 check; a non-authentic carrier ⇒ ok:false), or call
 * `verifyChain([...], { keyring })` and require VALID first. Never report "compliant" off a carrier you
 * have not authenticated. Never throws (fail-closed).
 *
 * ATTRIBUTION: `{ keyring }` carrier-auth is KID-LEVEL — it proves "a keyring-trusted key
 * signed this carrier", NOT "THIS agent.id signed it". In a multi-key keyring a co-trusted key can sign a
 * receipt claiming `agent.id=victim` and still pass carrier-auth (ok:true), exactly the cross-agent
 * impersonation `verifyChain` rejects as UNTRUSTED only when given an identityManifest. To get the same
 * attribution guarantee here, ALSO pass `{ identityManifest }`: the carrier's `(agent.id, sig.kid)` pairing
 * is then required to be authorized (mirrors verify.ts 4c-bis) — an unauthorized pairing ⇒ ok:false. Without
 * an identityManifest, L2 attribution stays kid-level (the weaker, documented guarantee).
 */
import type { Receipt } from "../types.js";
import type { Policy, InputSnapshot } from "./dsl.js";
import { policyHash, readSetHash } from "./dsl.js";
import { evaluate } from "./eval.js";
import { canonicalize } from "../jcs.js";
import { sha256Prefixed, sha256Hex } from "../hash.js";
import { validateReceiptShape } from "../schema.js";
import { receiptHashInput } from "../canonicalize.js";
import { verifyEd25519, type Keyring, type IdentityManifest } from "../keys.js";
import { signingMessage, RECEIPT_SIG_DOMAIN } from "../signing.js";

export interface ComplianceCommit {
  policyHash: string;
  readSetHash: string;
  inputsHash: string;
  /** The recorded policy decision (re-run at commit time). Lets verifyReceiptCompliance reconcile a
   *  re-run verdict against the decision the receipt claims — closes the "records a verdict it never
   *  re-derives" gap. */
  verdict: "ALLOW" | "DENY";
}

/**
 * The on-receipt commitment for (policy, inputs): the three binding hashes PLUS the recorded verdict.
 * inputsHash binds the decision inputs by hash only (no raw PII). The verdict is produced by re-running
 * the deterministic evaluator NOW, so a later verifyReceiptCompliance can confirm the recorded decision
 * reproduces (substitution-resistant: a receipt cannot commit DENY-inputs while claiming ALLOW).
 */
export function complianceCommit(policy: Policy, inputs: InputSnapshot): ComplianceCommit {
  return {
    policyHash: policyHash(policy),
    readSetHash: readSetHash(policy),
    inputsHash: sha256Prefixed(canonicalize(inputs)),
    verdict: evaluate(policy, inputs).verdict,
  };
}

export interface ComplianceResult {
  ok: boolean;
  reason?: string;
  /** The reproduced verdict from re-running the committed policy over the recorded inputs. */
  policyVerdict?: "ALLOW" | "DENY";
  ruleFired?: string | null;
}

export interface VerifyComplianceOptions {
  /**
   * Trust root (kid -> base64 SPKI). When supplied, the CARRIER receipt is authenticated BEFORE the L2
   * check: its structure is validated, its `chain.hash` is recomputed from the canonical body, and its
   * Ed25519 signature is verified against the keyring. A non-authentic carrier (bad shape / hash / unknown
   * kid / bad signature) ⇒ ok:false. Omit it ONLY when the caller has already authenticated the carrier
   * via `verifyChain([...], { keyring })` → VALID (see the module-level authenticity note).
   *
   * NOTE: keyring carrier-auth is KID-LEVEL (a keyring-trusted key signed), NOT agent-level. To bind WHICH
   * agent.id signed, ALSO pass `identityManifest` below.
   */
  keyring?: Keyring;
  /**
   * Optional `agent.id -> authorized kid(s)` binding (the SAME trust class as the keyring). Meaningful ONLY
   * alongside `keyring` (it gates an AUTHENTICATED carrier). When supplied, after carrier-auth succeeds, a
   * carrier whose `(agent.id, sig.kid)` pairing is not authorized is rejected (ok:false) — upgrading L2
   * attribution from "a keyring-trusted key signed" to "THIS agent.id signed" (mirrors verify.ts 4c-bis /
   * the UNTRUSTED verdict). Omit it to keep kid-level attribution (the weaker, documented guarantee).
   */
  identityManifest?: IdentityManifest;
}

/**
 * Offline L2 proof. Confirms the receipt's committed (policyHash, readSetHash, inputsHash) authenticate
 * the supplied policy + inputs, then re-runs the deterministic evaluator. ok:true ⇒ "this receipt
 * committed to THIS policy + THESE inputs, and re-running them reproduces policyVerdict". Fail-closed.
 *
 * Pass `{ keyring }` to ALSO authenticate the carrier here (recommended); otherwise this presumes the
 * caller already authenticated the carrier (verifyChain → VALID). Without that, ok:true says nothing about
 * the receipt being genuine — only that the committed block is internally policy-consistent.
 *
 * Pass `{ keyring, identityManifest }` to ALSO bind WHICH agent.id signed: after carrier-auth,
 * an unauthorized `(agent.id, sig.kid)` pairing ⇒ ok:false. Without an identityManifest, attribution is
 * kid-level (a keyring-trusted key signed, not necessarily THIS agent.id).
 */
export function verifyReceiptCompliance(
  receipt: Receipt,
  policy: Policy,
  inputs: InputSnapshot,
  opts: VerifyComplianceOptions = {},
): ComplianceResult {
  try {
    if (typeof receipt !== "object" || receipt === null) {
      return { ok: false, reason: "receipt is not an object" };
    }
    // SNAPSHOT THE CARRIER ONCE (TOCTOU hardening): a LIVE receipt with a flipping accessor could
    // return an EVIL governance.compliance on the first read (the comparison source) and the REAL signed
    // block on later reads (carrier auth) — authenticating one block while comparing another → a false
    // "compliant" green on an authenticated carrier. structuredClone fires every accessor EXACTLY ONCE,
    // producing accessor-free data; ALL reads below (carrier auth AND the L2 compare) use this ONE snapshot.
    // (Mirrors the identityManifest read-once snapshot + accessor hardening elsewhere in this module.) Reading
    // INSIDE the try also honors the "never throws" contract for null / throwing-accessor receipts (#3/#7).
    const snap = structuredClone(receipt) as Receipt;
    const c = snap.governance?.compliance;
    if (!c) return { ok: false, reason: "receipt carries no governance.compliance commitment" };
    // SNAPSHOT THE POLICY + INPUTS ONCE (TOCTOU hardening). Both arguments are caller-supplied LIVE
    // objects read MORE THAN ONCE: `policy` by policyHash + readSetHash + evaluate; `inputs` by the inputsHash
    // check + evaluate. A flipping accessor (a getter that returns one value on read#1 and another on read#2)
    // could split the hash check from the re-run — e.g. present ALLOW-inputs to inputsHash and DENY-inputs to
    // evaluate (or vice-versa) → a false COMPLIANT (ok:true) that the receipt never actually committed to.
    // structuredClone fires every accessor EXACTLY ONCE into plain, accessor-free data; ALL reads below
    // (hash checks AND evaluate) use these snapshots, never the live args. Inside the try ⇒ a throwing accessor
    // / non-cloneable arg fails closed (ok:false), honoring the "never throws" contract.
    const policySnap = structuredClone(policy) as Policy;
    const inputsSnap = structuredClone(inputs) as InputSnapshot;
    // CARRIER AUTHENTICATION: when a keyring is supplied, prove the receipt itself is
    // genuine BEFORE trusting its compliance block — otherwise a forged/tampered receipt (verifyChain ⇒
    // TAMPERED) would still get a green "compliant" signal off its attacker-mutable governance.compliance.
    if (opts.keyring) {
      const shape = validateReceiptShape(snap);
      if (!shape.ok) return { ok: false, reason: `carrier receipt malformed: ${shape.errors.join("; ")}` };
      const hashInput = receiptHashInput(snap);
      if ("sha256:" + sha256Hex(hashInput) !== snap.chain.hash) {
        return { ok: false, reason: "carrier receipt hash mismatch — not authentic" };
      }
      const pub = opts.keyring[snap.sig.kid];
      if (!pub) return { ok: false, reason: `carrier receipt signing key "${snap.sig.kid}" not in keyring` };
      if (!verifyEd25519(pub, signingMessage(RECEIPT_SIG_DOMAIN, hashInput), snap.sig.value)) {
        return { ok: false, reason: "carrier receipt signature not authenticated" };
      }
      // IDENTITY BINDING: the signature is now AUTHENTICATED, so — exactly like verify.ts
      // 4c-bis — when an identityManifest is supplied, require the carrier's (agent.id, sig.kid) pairing to
      // be authorized. Without this, keyring carrier-auth is kid-level: a co-trusted key could sign a receipt
      // claiming agent.id=victim and pass (ok:true) while verifyChain([...],{keyring,identityManifest}) returns
      // UNTRUSTED on the SAME receipt. Read the manifest via the SAME read-once snapshot discipline (Map copy,
      // arrays sliced by value) so a flipping accessor cannot split validation from enforcement; read agent.id
      // / sig.kid from the read-once `snap`, never the live receipt. (Inside the outer try ⇒ a throwing manifest
      // accessor fails closed.)
      if (opts.identityManifest !== undefined) {
        const live = opts.identityManifest;
        if (typeof live !== "object" || live === null || Array.isArray(live)) {
          return { ok: false, reason: "identityManifest must be an object (agent.id -> kid[])" };
        }
        const manifest = new Map<string, string[]>();
        for (const aid of Object.getOwnPropertyNames(live)) {
          const kidsLive = (live as Record<string, unknown>)[aid]; // ONE read of the entry
          if (!Array.isArray(kidsLive)) {
            return { ok: false, reason: `identityManifest["${aid}"] must be an array of kid strings` };
          }
          const kids = Array.prototype.slice.call(kidsLive) as unknown[]; // copy by value
          if (!kids.every((k) => typeof k === "string")) {
            return { ok: false, reason: `identityManifest["${aid}"] must be an array of kid strings` };
          }
          manifest.set(aid, kids as string[]);
        }
        const allowed = manifest.get(snap.agent.id);
        if (allowed === undefined || !allowed.includes(snap.sig.kid)) {
          return { ok: false, reason: `agent "${snap.agent.id}" not authorized for signing key "${snap.sig.kid}" (identity manifest)` };
        }
      }
    }
    if (policyHash(policySnap) !== c.policyHash) return { ok: false, reason: "policyHash mismatch — supplied policy is not the committed one" };
    if (readSetHash(policySnap) !== c.readSetHash) return { ok: false, reason: "readSetHash mismatch" };
    if (sha256Prefixed(canonicalize(inputsSnap)) !== c.inputsHash) return { ok: false, reason: "inputsHash mismatch — supplied inputs are not the recorded ones" };
    const ev = evaluate(policySnap, inputsSnap);
    // Verdict RECONCILIATION: when the commitment records a verdict, the re-run MUST
    // reproduce it. This is what makes spec §9's "re-runs and confirms the committed verdict reproduces"
    // literally true: a receipt that commits inputs which evaluate to DENY while recording ALLOW is
    // rejected. Backward-compatible — a commitment WITHOUT a verdict skips the check and just returns the
    // re-run verdict (the prior behaviour).
    if (c.verdict !== undefined && ev.verdict !== c.verdict) {
      return { ok: false, reason: `verdict mismatch — recorded decision does not reproduce (recorded ${c.verdict}, re-run ${ev.verdict})`, policyVerdict: ev.verdict, ruleFired: ev.ruleFired };
    }
    return { ok: true, policyVerdict: ev.verdict, ruleFired: ev.ruleFired };
  } catch (e) {
    return { ok: false, reason: `compliance check error: ${(e as Error).message}` };
  }
}
