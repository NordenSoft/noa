/**
 * approval-decision.mjs — mints the human-decision receipt(s) in the R4
 * DEFERRED -> ALLOWED -> EXECUTED chain, `prev`-chained onto the DEFERRED receipt.
 *
 * No auto re-execution here (avoids a TOCTOU between decision and execution, and keeps execution
 * authority with the agent): this module only records a signed DECISION + (on approve) a single-use
 * TTL'd ticket; actual execution happens later, when the agent retries and the proxy sees the
 * ticket (create-proxy-server.mjs).
 *
 * Signs with its OWN identity (`agent.id: "human-approval-cli"` by default, principal HUMAN) —
 * never the agent's private key; per-agent.id key-pinning (enforced by verifyChain's identity
 * manifest) is what keeps this safe within one chain.
 */
import { buildReceipt, verifyEd25519, receiptHashInput, sha256Prefixed, sha256Digest } from "noa-receipt";
import { randomUUID } from "node:crypto";
import { assertOpaqueApproverBy } from "./opaque-id.mjs";

/**
 * The domain-separation tag noa-receipt's own builder binds every receipt signature to (its
 * src/signing.ts `RECEIPT_SIG_DOMAIN`, frozen with the noa.receipt/0.1 spec). noa-receipt does not
 * re-export it, and its only public verifier, `verifyChain`, authenticates a WHOLE chain from
 * genesis (contiguous seq 0..n-1). An approval is minted for a DEFERRED hold that can legitimately
 * sit at ANY seq > 0 (a session may EXECUTE small calls before a big one is held), and the live
 * proxy holds only the chain HEAD — never the full prior chain — so the [deferred, allowed] pair is
 * NOT a genesis-rooted chain and verifyChain would (correctly, but unhelpfully) report a seq-gap.
 * verifyApprovalReceipt below therefore re-assembles the EXACT signed message from noa-receipt's OWN
 * exported primitives (receiptHashInput + sha256Digest + verifyEd25519) — it invents no hash and no
 * signature scheme, only mirrors the one-line domain framing the library keeps internal. Any drift
 * here can ONLY fail closed (a real approval would stop verifying — caught immediately by the
 * approval-decision + proxy Scenario R tests), never admit a forgery.
 */
const RECEIPT_SIG_DOMAIN = "NOA-Receipt-v0.1-sig";

export const DEFAULT_APPROVAL_TICKET_TTL_MS = 15 * 60 * 1000; // 15 minutes

/**
 * Builds the ALLOWED decision receipt + mints the transition ticket. Pure (no I/O) — the caller
 * (approve-cli.mjs) is responsible for persisting into the pending-store. `by` is expected to already
 * be an OPAQUE approver id (D8: the CLI pseudonymizes the raw email before calling this; see
 * approve-cli.mjs + opaque-id.mjs) — this builder embeds it verbatim into the signed bytes.
 * @param {{ deferredReceipt: object, by: string, ts: string, signer: { kid: string, privateKey: string }, agentId?: string, ticketTtlMs?: number }} args
 */
export function buildApprovalReceipt({ deferredReceipt, by, ts, signer, agentId = "human-approval-cli", ticketTtlMs = DEFAULT_APPROVAL_TICKET_TTL_MS }) {
  assertOpaqueApproverBy(by); // D8 fail-closed: refuse a raw-email `by` before it reaches signed bytes.
  const receipt = buildReceipt(
    {
      id: `${deferredReceipt.id}-approved`,
      ts,
      scope: deferredReceipt.scope,
      agent: { id: agentId, model: null, principal: "HUMAN" },
      action: deferredReceipt.action,
      governance: { mode: "on", verdict: "ALLOWED", ruleId: deferredReceipt.governance.ruleId, approval: { by, at: ts }, sandboxed: false, compliance: deferredReceipt.governance.compliance },
    },
    deferredReceipt,
    signer,
  );
  return { receipt, ticket: randomUUID(), ticketExpiresAt: new Date(Date.parse(ts) + ticketTtlMs).toISOString() };
}

/**
 * Builds the BLOCKED decision receipt for a denial. No ticket — the held call is terminally
 * refused; the session unblocks once the pending-store status becomes "denied".
 *
 * D8 / GDPR-CCPA (THREAT-MODEL-ADDENDUM §5): the `ruleId` is a FIXED machine-readable code
 * `"human-denied"` — a human's free-text denial reason is NEVER folded into it (a signed, hash-chained,
 * structured field must not carry free text: PII-at-rest + injection risk). The reason, if the operator
 * supplied one, is kept only in the LOCAL non-signed pending-store index (recordDenied), never in the
 * signed bytes. `by` is expected to already be an OPAQUE approver id (the CLI pseudonymizes the raw
 * email before calling this; see approve-cli.mjs + opaque-id.mjs) — this builder embeds it verbatim.
 * @param {{ deferredReceipt: object, by: string, ts: string, signer: { kid: string, privateKey: string }, agentId?: string }} args
 */
export function buildDenialReceipt({ deferredReceipt, by, ts, signer, agentId = "human-approval-cli" }) {
  assertOpaqueApproverBy(by); // D8 fail-closed: refuse a raw-email `by` before it reaches signed bytes.
  const receipt = buildReceipt(
    {
      id: `${deferredReceipt.id}-denied`,
      ts,
      scope: deferredReceipt.scope,
      agent: { id: agentId, model: null, principal: "HUMAN" },
      action: deferredReceipt.action,
      governance: { mode: "on", verdict: "BLOCKED", ruleId: "human-denied", approval: { by, at: ts }, sandboxed: false, compliance: deferredReceipt.governance.compliance },
    },
    deferredReceipt,
    signer,
  );
  return { receipt };
}

/**
 * verifyApprovalReceipt — the fail-closed inverse of buildApprovalReceipt. Before a proxy adopts an
 * externally-built ALLOWED receipt onto its live session chain, it MUST prove the receipt is a
 * genuine, signed human approval — not just structurally consistent seq/prevHash (which anyone able
 * to write the pending-store file could forge). Checks, in order, ALL fail-closed:
 *   (a) a trusted approver keyring is supplied at all;
 *   (b) verdict is exactly "ALLOWED" and governance.approval carries a human (by/at);
 *   (c) scope.chain matches this session's live chain (when `expectedChain` is given);
 *   (d) the receipt's content hash recomputes (the SAME integrity check verifyChain does);
 *   (e) the signing kid is present in the trusted approver keyring AND its Ed25519 signature over
 *       the receipt is valid;
 *   (f) when an `identityManifest` is given, the signing kid is authorized for the receipt's
 *       agent.id (the approval seat) — so a co-trusted key can never impersonate the human seat.
 *   (g) when an `expectedAction` ({ id, paramsHash }) is given, the receipt's OWN action.id +
 *       action.paramsHash MUST equal it — the approval is cryptographically bound to the EXACT held
 *       action. Without this, a genuine, validly-signed approval for action X (e.g. a small refund a
 *       low-privilege approver may sign) could be adopted to authorize a DIFFERENT held action Y (a
 *       large refund) on the same chain: signature + chain verify, but the human never approved Y.
 *
 * Returns `{ ok: true }` or `{ ok: false, reason }` — never throws (any unexpected throw is caught
 * and reported as a failure, i.e. fail-closed). See the RECEIPT_SIG_DOMAIN note above for why this
 * verifies a single receipt directly rather than calling verifyChain.
 *
 * @param {object} allowedReceipt
 * @param {{ approverKeyring?: Record<string,string>, identityManifest?: Record<string,string[]>, expectedChain?: string, expectedAction?: { id?: string, paramsHash?: string } }} [opts]
 * @returns {{ ok: boolean, reason?: string }}
 */
export function verifyApprovalReceipt(allowedReceipt, { approverKeyring, identityManifest, expectedChain, expectedAction } = {}) {
  try {
    if (!approverKeyring || typeof approverKeyring !== "object" || Array.isArray(approverKeyring)) {
      return { ok: false, reason: "no trusted approver keyring supplied — approval cannot be authenticated" };
    }
    const r = allowedReceipt;
    if (!r || typeof r !== "object") return { ok: false, reason: "approval receipt is not an object" };

    if (!r.governance || typeof r.governance !== "object" || r.governance.verdict !== "ALLOWED") {
      return { ok: false, reason: `approval verdict is not ALLOWED (got ${JSON.stringify(r.governance?.verdict)})` };
    }
    const approval = r.governance.approval;
    if (!approval || typeof approval !== "object" || typeof approval.by !== "string" || approval.by.length === 0 || typeof approval.at !== "string" || approval.at.length === 0) {
      return { ok: false, reason: "approval receipt has no human approver (governance.approval.by/at)" };
    }

    if (!r.scope || typeof r.scope.chain !== "string" || r.scope.chain.length === 0) {
      return { ok: false, reason: "approval receipt has no scope.chain" };
    }
    if (expectedChain !== undefined && r.scope.chain !== expectedChain) {
      return { ok: false, reason: `approval receipt scope.chain ${JSON.stringify(r.scope.chain)} does not match this session's chain ${JSON.stringify(expectedChain)}` };
    }

    if (!r.agent || typeof r.agent.id !== "string" || r.agent.id.length === 0) {
      return { ok: false, reason: "approval receipt has no agent.id" };
    }

    const sig = r.sig;
    if (!sig || typeof sig !== "object" || sig.alg !== "ed25519" || typeof sig.kid !== "string" || sig.kid.length === 0 || typeof sig.value !== "string" || sig.value.length === 0) {
      return { ok: false, reason: "approval receipt has a malformed signature block" };
    }

    let hashInput;
    try {
      hashInput = receiptHashInput(r);
    } catch {
      return { ok: false, reason: "approval receipt is not canonicalizable" };
    }
    if (!r.chain || sha256Prefixed(hashInput) !== r.chain.hash) {
      return { ok: false, reason: "approval receipt hash does not match its content (tampered)" };
    }

    const pub = approverKeyring[sig.kid];
    if (typeof pub !== "string" || pub.length === 0) {
      return { ok: false, reason: `signing key ${JSON.stringify(sig.kid)} is not in the trusted approver keyring` };
    }
    const message = Buffer.concat([Buffer.from(RECEIPT_SIG_DOMAIN + ":", "utf8"), sha256Digest(hashInput)]);
    let sigOk = false;
    try {
      sigOk = verifyEd25519(pub, message, sig.value);
    } catch {
      sigOk = false;
    }
    if (!sigOk) return { ok: false, reason: `invalid approver signature (kid ${sig.kid})` };

    if (identityManifest !== undefined) {
      if (typeof identityManifest !== "object" || identityManifest === null || Array.isArray(identityManifest)) {
        return { ok: false, reason: "identityManifest must be an object (agent.id -> kid[])" };
      }
      const authorizedKids = identityManifest[r.agent.id];
      if (!Array.isArray(authorizedKids) || !authorizedKids.includes(sig.kid)) {
        return { ok: false, reason: `agent ${JSON.stringify(r.agent.id)} is not authorized for signing key ${JSON.stringify(sig.kid)} (identity manifest)` };
      }
    }

    // (g) ACTION BINDING (fail-closed) — checked AFTER authenticity (sig + hash + identity) so a
    // genuine-but-wrong-action approval is proven real first, then refused for the mismatch. The
    // approval authenticated above authorizes exactly ONE action; it may only be adopted for the
    // held request when the receipt's own action matches it. `r.action.paramsHash` is content-bound
    // by the signature check above (it is inside `r`'s hashed content), so an attacker cannot alter
    // the approved params without invalidating the signature.
    if (expectedAction !== undefined) {
      if (!expectedAction || typeof expectedAction !== "object" || Array.isArray(expectedAction)) {
        return { ok: false, reason: "expectedAction must be an object ({ id, paramsHash })" };
      }
      if (!r.action || typeof r.action !== "object") {
        return { ok: false, reason: "approval receipt has no action to bind against the held request" };
      }
      if (r.action.id !== expectedAction.id || r.action.paramsHash !== expectedAction.paramsHash) {
        return {
          ok: false,
          reason: `approval is for a different action (approved ${JSON.stringify(r.action.id)}/${JSON.stringify(r.action.paramsHash)}, held ${JSON.stringify(expectedAction.id)}/${JSON.stringify(expectedAction.paramsHash)})`,
        };
      }
    }

    return { ok: true };
  } catch (err) {
    return { ok: false, reason: `approval-receipt verification failed closed (${err?.message ?? "unknown error"})` };
  }
}
