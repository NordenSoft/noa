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
import { evaluateParsed } from "./eval.js";
import { parseDocument } from "../bytes.js";
import { inertOptions, type OptionSchema } from "../opts.js";
import { canonicalize } from "../jcs.js";
import { sha256Prefixed, sha256Hex } from "../hash.js";
import { validateReceiptShapeParsed } from "../schema.js";
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
    verdict: evaluateParsed(policy, inputs).verdict,
  };
}

export interface ComplianceResult {
  ok: boolean;
  reason?: string;
  /**
   * H2 (review #6) — WHAT `ok:true` IS A CLAIM ABOUT, made machine-readable.
   *
   * `ok:true` used to be one word for two very different guarantees, and the weaker one was the
   * DEFAULT. Without a keyring nothing was authenticated at all: an attacker who replaced the whole
   * `governance.compliance` block with one committed under an allow-everything policy got `ok:true`,
   * because the L2 hashes line up with whatever policy the attacker also supplied. That mode is now
   * refused outright (see below) — the L2 proof over an unauthenticated carrier proves nothing.
   *
   * What survives is the honest distinction between the two authenticated modes, and it is a FIELD,
   * not a comment, so a caller can gate on it:
   *
   *   KID_LEVEL   — a keyring-trusted key signed this carrier. It does NOT establish that the
   *                 receipt's own `agent.id` is the party that signed: in a multi-key keyring a
   *                 co-trusted key can sign a receipt claiming someone else's agent.id.
   *   AGENT_BOUND — additionally, an identityManifest authorized (agent.id, sig.kid).
   *
   * Absent on every `ok:false`.
   */
  attribution?: "KID_LEVEL" | "AGENT_BOUND";
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
   * agent.id signed, ALSO pass `identityManifest` below. Supplied as JSON bytes.
   */
  keyring?: Uint8Array | string;
  /**
   * Optional `agent.id -> authorized kid(s)` binding (the SAME trust class as the keyring). Meaningful ONLY
   * alongside `keyring` (it gates an AUTHENTICATED carrier). When supplied, after carrier-auth succeeds, a
   * carrier whose `(agent.id, sig.kid)` pairing is not authorized is rejected (ok:false) — upgrading L2
   * attribution from "a keyring-trusted key signed" to "THIS agent.id signed" (mirrors verify.ts 4c-bis /
   * the UNTRUSTED verdict). Omit it to keep kid-level attribution (the weaker, documented guarantee).
   * Supplied as JSON bytes.
   */
  identityManifest?: Uint8Array | string;
}

/** The document members arrive decoded to text; there are no scalar members here. */
interface InertComplianceOptions {
  readonly keyring?: string;
  readonly identityManifest?: string;
}

const COMPLIANCE_OPTION_SCHEMA: OptionSchema = Object.freeze(Object.assign(Object.create(null), {
  keyring: { kind: "document" },
  identityManifest: { kind: "document" },
})) as OptionSchema;

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
  receipt: Uint8Array | string,
  policy: Uint8Array | string,
  inputs: Uint8Array | string,
  opts: VerifyComplianceOptions = {},
): ComplianceResult {
  // ── THE BOUNDARY ───────────────────────────────────────────────────────────────────────────────
  // Three documents and one options object. The receipt is the CARRIER of a signed commitment, the
  // policy is hash-pinned, and the inputs are committed by hash — all three are artifacts under
  // comparison, so all three are bytes. Only the trust configuration stays an object, admitted by
  // the schema.
  const admitted = inertOptions<InertComplianceOptions>(COMPLIANCE_OPTION_SCHEMA, opts, "options");
  if (!admitted.ok) return { ok: false, reason: admitted.reason };
  const o = admitted.value;
  const rParsed = parseDocument(receipt, "receipt");
  if (!rParsed.ok) return { ok: false, reason: rParsed.reason };
  const pParsed = parseDocument(policy, "policy");
  if (!pParsed.ok) return { ok: false, reason: pParsed.reason };
  const iParsed = parseDocument(inputs, "inputs");
  if (!iParsed.ok) return { ok: false, reason: iParsed.reason };
  try {
    if (typeof rParsed.value !== "object" || rParsed.value === null) {
      return { ok: false, reason: "receipt is not an object" };
    }
    // THE THREE SNAPSHOTS THAT USED TO LIVE HERE ARE GONE, AND THE REASON THEY EXISTED IS THE
    // REASON THEY ARE GONE. Each argument was read MORE THAN ONCE — the receipt by carrier
    // authentication and by the L2 comparison, the policy by `policyHash` + `readSetHash` +
    // `evaluate`, the inputs by `inputsHash` and by `evaluate` — so a flipping accessor could
    // authenticate one block while comparing another, or present ALLOW-inputs to the hash and
    // DENY-inputs to the evaluator, yielding a false COMPLIANT the receipt never committed to.
    // Parsed bytes cannot return two different values to two reads, so every one of those splits is
    // unrepresentable rather than defended.
    const snap = rParsed.value as Receipt;
    const c = snap.governance?.compliance;
    if (!c) return { ok: false, reason: "receipt carries no governance.compliance commitment" };
    const policySnap = pParsed.value as Policy;
    const inputsSnap = iParsed.value as InputSnapshot;
    // CARRIER AUTHENTICATION: when a keyring is supplied, prove the receipt itself is
    // genuine BEFORE trusting its compliance block — otherwise a forged/tampered receipt (verifyChain ⇒
    // TAMPERED) would still get a green "compliant" signal off its attacker-mutable governance.compliance.
    //
    // PRESENCE, not truthiness: `o.keyring !== undefined` (mirrors verify.ts's `haveKeyring`). A prior
    // `if (opts.keyring)` truthy-check let ANY falsy-but-supplied keyring (`""`, `0`, `null`) silently
    // SKIP carrier-auth entirely — the caller explicitly asked to authenticate the carrier and the check
    // never ran, yet ok:true could still come back. Presence-gating + the non-object guard immediately
    // below makes every supplied-but-malformed keyring fail CLOSED instead of being ignored.
    const haveKeyring = o.keyring !== undefined;
    let keyringParsed: Keyring | undefined;
    if (haveKeyring) {
      const kParsed = parseDocument(o.keyring, "keyring");
      if (!kParsed.ok) return { ok: false, reason: kParsed.reason };
      if (typeof kParsed.value !== "object" || kParsed.value === null || Array.isArray(kParsed.value)) {
        return { ok: false, reason: "keyring must be an object (kid -> base64 SPKI)" };
      }
      keyringParsed = kParsed.value as Keyring;
    }
    // ── H2 (review #6): NO TRUST ROOT ⇒ NO POSITIVE VERDICT. ──────────────────────────────────────
    // This was the only verifier in the repository that returned a POSITIVE result with no trust
    // input at all. `verifyChain` returns UNVERIFIED without a keyring; `verifyEvidence` returns
    // UNVERIFIED without a tenant root (F7a); this returned `ok:true`. Two tests froze the
    // consequence: swapping the ENTIRE compliance block for one committed under an attacker-authored
    // allow-everything policy returned ok:true (the hashes agree because the attacker supplied both
    // halves), and an impersonated receipt returned ok:true even when the caller HAD supplied an
    // identityManifest — the binding silently no-opped because it gates on carrier-auth, which never
    // ran. Both were commented as documented gaps; a comment is not a control, and a test asserting
    // ok:true for an impersonated receipt codifies the unsafe behaviour regardless of what is written
    // above it.
    //
    // The L2 proof is a statement about bytes the receipt COMMITTED to. Over a carrier nobody
    // authenticated, those bytes are attacker-supplied on both sides of every comparison, so the
    // proof is vacuous. Fail closed, exactly like every sibling verifier.
    if (!haveKeyring) {
      return {
        ok: false,
        reason:
          "no keyring supplied — the compliance carrier cannot be authenticated, and the L2 hash proof " +
          "over an unauthenticated receipt proves nothing (its governance.compliance block is attacker-mutable). " +
          "Pass { keyring } (and { identityManifest } to bind WHICH agent signed).",
      };
    }
    let attribution: "KID_LEVEL" | "AGENT_BOUND" = "KID_LEVEL";
    {
      const keyring = keyringParsed as Keyring;
      const shape = validateReceiptShapeParsed(snap);
      if (!shape.ok) return { ok: false, reason: `carrier receipt malformed: ${shape.errors.join("; ")}` };
      const hashInput = receiptHashInput(snap);
      if ("sha256:" + sha256Hex(hashInput) !== snap.chain.hash) {
        return { ok: false, reason: "carrier receipt hash mismatch — not authentic" };
      }
      const pub = keyring[snap.sig.kid];
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
      if (o.identityManifest !== undefined) {
        const mParsed = parseDocument(o.identityManifest, "identityManifest");
        if (!mParsed.ok) return { ok: false, reason: mParsed.reason };
        const live = mParsed.value;
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
        attribution = "AGENT_BOUND";
      }
    }
    if (policyHash(policySnap) !== c.policyHash) return { ok: false, reason: "policyHash mismatch — supplied policy is not the committed one" };
    if (readSetHash(policySnap) !== c.readSetHash) return { ok: false, reason: "readSetHash mismatch" };
    if (sha256Prefixed(canonicalize(inputsSnap)) !== c.inputsHash) return { ok: false, reason: "inputsHash mismatch — supplied inputs are not the recorded ones" };
    const ev = evaluateParsed(policySnap, inputsSnap);
    // Verdict RECONCILIATION: when the commitment records a verdict, the re-run MUST
    // reproduce it. This is what makes spec §9's "re-runs and confirms the committed verdict reproduces"
    // literally true: a receipt that commits inputs which evaluate to DENY while recording ALLOW is
    // rejected. Backward-compatible — a commitment WITHOUT a verdict skips the check and just returns the
    // re-run verdict (the prior behaviour).
    if (c.verdict !== undefined && ev.verdict !== c.verdict) {
      return { ok: false, reason: `verdict mismatch — recorded decision does not reproduce (recorded ${c.verdict}, re-run ${ev.verdict})`, policyVerdict: ev.verdict, ruleFired: ev.ruleFired };
    }
    return { ok: true, policyVerdict: ev.verdict, ruleFired: ev.ruleFired, attribution };
  } catch {
    // BOUNDARY 2, recurring (found by the C2 entry-point probe, not by a reviewer): this used to
    // interpolate `(e as Error).message`, so a hostile value — a revoked Proxy, an object with a
    // throwing `message` getter — threw AGAIN inside the catch and escaped raw, defeating the
    // "never throws / fail-closed" contract on the exact input class the contract exists for. The
    // thrown value is not read at all; there is nothing left to weaponize.
    return { ok: false, reason: "compliance check failed closed: an input could not be reduced to inert data (a hostile getter, a proxy trap, or a non-plain object)" };
  }
}
