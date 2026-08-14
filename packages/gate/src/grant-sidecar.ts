#!/usr/bin/env node
/**
 * noa-gate-grant-signer — THE AUTHORITY ROOT, OUT OF THE PROCESS IT DEFENDS, BEHIND A POLICY GATE.
 *
 * A standalone process holding the ONLY copy of the gate's `execution-signer` private key, reachable
 * over a Unix domain socket. What makes it different from `noa-signer-sidecar` — and the reason that
 * package was not simply reused — is that a bare signing oracle does not close the defect:
 *
 *     "KMS alone is insufficient; an attacker who can *ask* an HSM to sign has the key in effect."
 *
 * `noa-signer-sidecar`'s own README says it plainly: *"The sidecar signs whatever bytes it is asked
 * to sign … Anyone who can reach the socket and is permitted to connect to it can produce a valid
 * signature under this process's key."* Moving the grant key behind that would relocate the key and
 * change nothing about who can mint a grant. So this process VALIDATES, per request, that the grant
 * it is being asked to sign is backed by a genuine human approval, using trust material it holds
 * ITSELF, and refuses otherwise.
 *
 * ── WHAT IS LOAD-BEARING AND WHAT IS NOT ────────────────────────────────────────────────────────
 * The threat model is a FULLY COMPROMISED GATE PROCESS. That process holds the gate's `hold-signer`
 * and receipt keys, so everything the GATE signs — the Hold Envelope, the DEFERRED receipt — is
 * forgeable by the attacker and is checked here only for CONSISTENCY. The load-bearing legs are the
 * two artifacts signed by the APPROVER's device key, which is on the phone and not in the gate:
 *
 *   1. `noa.decision/0.1`  — the approver signed `decision: APPROVE` over a specific Hold Envelope
 *                            (by `holdEnvelopeHash`), so a genuine decision cannot be re-pointed at
 *                            a forged envelope.
 *   2. the ALLOWED receipt — the approver signed `governance.verdict: ALLOWED` over a specific
 *                            `action.paramsHash`, and the grant may carry NO OTHER paramsHash.
 *
 * Everything else in the request hangs off those two by hash. The single sentence this process
 * exists to make true: **the parameters in a signed grant are the parameters a human approved.**
 *
 * ── ATTESTATIONS ARE SIGNED, NOT AUTHORIZED ─────────────────────────────────────────────────────
 * The Consumption, the Execution Uncertainty and the Hold Resolution need the same F15 role as the
 * grant (`domains.ts`), so they must live here too or the gate would have to keep an
 * `execution-signer` key and could mint grants with it (`exec-signer.ts`, "why all four move"). They
 * are signed WITHOUT an approval proof, under their own domain tags, on an op that REFUSES the grant
 * spec outright. Domain separation is what makes that safe: a signature produced under
 * `NOA-ExecConsume-v0.1-sig` is not a signature under `NOA-ExecGrant-v0.1-sig` and never verifies as
 * one. It is also the honest limit — a compromised gate can still obtain a signed attestation that
 * says something false, exactly as it could before this change; see `NON-CLAIMS.md`.
 *
 * Protocol — one JSON line per request, one JSON line per response, one connection per operation:
 *
 *   {"op":"pubkey"}                                  -> {"kid":"…","pub":"…","alg":"ed25519"}
 *   {"op":"sign-grant","artifact":{…},"proof":{…}}   -> {"artifact":{…signed…}} | {"error":"…"}
 *   {"op":"sign-attestation","artifact":{…}}         -> {"artifact":{…signed…}} | {"error":"…"}
 *   (anything malformed/unknown)                     -> {"error":"<reason>"}
 *
 * Flags:
 *   --key-file <path>    required. The execution-signer identity (mode 0600, O_NOFOLLOW-hardened
 *                        load — `noa-mcp-adapter-core`'s loadOrCreateKeyFile). Minted on first run.
 *   --trust-file <path>  required. THIS PROCESS'S OWN trust material: tenant, the approver keyring
 *                        and the receipt keyring. Nothing in a request is ever used as trust
 *                        material — that is the whole point of the boundary.
 *   --socket <path>      required. Unix domain socket. Its directory must have no world bits.
 *   --socket-mode <oct>  optional, default 600. Use 660 with a shared group when the sidecar runs as
 *                        a DIFFERENT OS user from the gate — which is the deployment posture in
 *                        which "the gate process cannot read this key" is actually true.
 *   --max-approval-age-ms <n>  optional, default 900000 (15 min — the gate's default hold TTL).
 *   --max-grant-ttl-ms <n>     optional, default 300000 (5 min — the gate's default grant TTL). The
 *                        longest lifetime this signer will put its key behind.
 *   --replay-file <path> optional, defaults to `<key-file>.spent-approvals.jsonl`. The DURABLE
 *                        record of which approvals have already been granted. Survives restart by
 *                        design: an in-memory-only version handed a second grant to the same
 *                        approval across a bounce.
 */

import { createServer, connect } from "node:net";
import {
  chmodSync, closeSync, constants as fsConstants, existsSync, fstatSync, fsyncSync,
  openSync, readFileSync, renameSync, statSync, unlinkSync, writeSync,
} from "node:fs";
import { dirname } from "node:path";
import {
  ARTIFACTS,
  evalSchema,
  generateKeyPair,
  parseDocument,
  receiptRefHash,
  refHash,
  signArtifact,
  verifyArtifact,
  type KeyEntry,
} from "noa-approval-artifacts";
import { verifyChain, isHex64, type SigningKeyLifecycle } from "noa-receipt";
import { loadOrCreateKeyFile } from "noa-mcp-adapter-core";
import { describeThrown, thrownCode } from "noa-mcp-adapter-core/safe-throw";
import { encodeDocument } from "./bytes.js";
import { EXECUTION_GRANT_SPEC, executionDomainFor } from "./exec-signer.js";
import { loadSchemas } from "./schemas.js";

/** PRISTINE TIME, same capture discipline as `engine.ts`: the approval-freshness comparison is an
 *  authorization decision and must not dispatch through a globally-replaceable `Date.parse`. */
const sidecarDateParse = Date.parse;

const MAX_LINE_BYTES = 256 * 1024;
const DEFAULT_MAX_APPROVAL_AGE_MS = 15 * 60 * 1000;
/** Tolerance for the gate's clock running ahead of this process's. Small on purpose: it widens the
 *  window in which a future-dated approval is accepted. */
const CLOCK_SKEW_MS = 60 * 1000;
/** Retention of the anti-replay set EQUALS the freshness window, which is why forgetting an entry
 *  can never open a replay window: anything old enough to be evicted is already refused as stale. */
const MAX_REPLAY_ENTRIES = 10_000;
/** Longest grant lifetime this signer will authorize. Matches the gate's own default `grantTtlMs`;
 *  a deployment that wants a longer window must widen it HERE, where the caller cannot. */
const DEFAULT_MAX_GRANT_TTL_MS = 5 * 60 * 1000;

// ── this process's own trust material ────────────────────────────────────────────────────────────

export interface GrantSignerTrust {
  spec: "noa.grant-signer-trust/1";
  tenant: string;
  /** kid -> KeyEntry, for `verifyArtifact`. MUST contain the APPROVER device key(s); the gate's own
   *  public key may be present for consistency checks but carries no authority here. */
  keyring: Record<string, KeyEntry>;
  /** kid -> public key + retirement, for `verifyChain` over the DEFERRED → ALLOWED pair. */
  receiptKeyring: SigningKeyLifecycle;
  maxApprovalAgeMs?: number;
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}
function asString(v: unknown): string | null {
  return typeof v === "string" && v.length > 0 ? v : null;
}
function getPath(obj: unknown, dotted: string): unknown {
  let cur: unknown = obj;
  for (const seg of dotted.split(".")) {
    if (!isRecord(cur)) return undefined;
    cur = cur[seg];
  }
  return cur;
}

/**
 * Read `--trust-file` through ONE hardened descriptor.
 *
 * This file IS the trust root of the policy gate: it names the keys an approval is authenticated
 * against. It was being read with a plain `readFileSync` on a PATH — which follows a symlink, never
 * looks at the mode, and re-opens what an earlier check inspected. `--key-file` next door has had
 * the CWE-367 treatment since `noa-mcp-adapter-core`'s `key-file.mjs`; the file that decides WHO MAY
 * APPROVE had none of it (adversarial review 2026-08-12). Same discipline, applied to it:
 * O_NOFOLLOW so a planted symlink fails the open itself, `fstat` on the descriptor rather than a
 * second stat on the path, regular-file only, and no group/other WRITE — a trust root anyone else
 * can rewrite is not a trust root. Group READ stays legal: the different-UID deployment this whole
 * process exists for needs it.
 */
function readTrustFile(trustFile: string): string {
  let fd: number;
  try {
    fd = openSync(trustFile, fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0));
  } catch (err) {
    if (thrownCode(err) === "ELOOP") {
      throw new Error(`grant sidecar: --trust-file "${trustFile}" is a symlink — refusing to follow it (CWE-367 symlink-attack guard). Point it directly at the intended regular file.`);
    }
    throw new Error(`grant sidecar: --trust-file "${trustFile}" could not be opened (${describeThrown(err)})`);
  }
  try {
    const st = fstatSync(fd);
    if (!st.isFile()) throw new Error(`grant sidecar: --trust-file "${trustFile}" is not a regular file — refusing to load trust material from a special file`);
    if ((st.mode & 0o022) !== 0) {
      throw new Error(
        `grant sidecar: --trust-file "${trustFile}" is writable by group or others (mode 0${(st.mode & 0o777).toString(8)}) — ` +
          `this file decides which keys may approve, so anyone who can rewrite it can authorize anything. chmod it to 0400 or 0600.`,
      );
    }
    return readFileSync(fd, "utf8");
  } finally {
    closeSync(fd);
  }
}

/**
 * Load the sidecar's OWN trust material. Refuses a file that contains no APPROVER key: a policy gate
 * with nothing to check an approval against can never authorize anything, and a signer that can
 * never authorize is a misconfiguration wearing the costume of a security posture.
 */
export function loadGrantSignerTrust(trustFile: string): GrantSignerTrust {
  const parsed = parseDocument(readTrustFile(trustFile), "trust file");
  if (!parsed.ok) throw new Error(`grant sidecar: --trust-file "${trustFile}" is not a valid document (${parsed.reason})`);
  const doc = parsed.value;
  if (!isRecord(doc)) throw new Error(`grant sidecar: --trust-file "${trustFile}" is not an object`);
  if (doc["spec"] !== "noa.grant-signer-trust/1") {
    throw new Error(`grant sidecar: --trust-file "${trustFile}" has spec ${JSON.stringify(doc["spec"])}, expected "noa.grant-signer-trust/1"`);
  }
  const tenant = asString(doc["tenant"]);
  if (!tenant) throw new Error("grant sidecar: --trust-file has no tenant");
  const keyring = doc["keyring"];
  const receiptKeyring = doc["receiptKeyring"];
  if (!isRecord(keyring)) throw new Error("grant sidecar: --trust-file has no keyring");
  if (!isRecord(receiptKeyring) || !isRecord(receiptKeyring["keys"])) {
    throw new Error("grant sidecar: --trust-file has no receiptKeyring { spec, keys }");
  }
  const approvers = Object.values(keyring).filter((e) => isRecord(e) && e["type"] === "APPROVER");
  if (approvers.length === 0) {
    throw new Error(
      `grant sidecar: --trust-file "${trustFile}" contains no APPROVER key — this process would refuse every request. A policy gate with nothing to verify an approval against is a misconfiguration, not a posture.`,
    );
  }
  // ── CROSS-KEYRING AGREEMENT (CRITICAL, found by adversarial review 2026-08-12) ─────────────────
  // THE DEFECT: this file authenticates the Decision Artifact against `keyring` and the ALLOWED
  // receipt against `receiptKeyring`, then bound the two together by comparing `kid` STRINGS. A
  // trust file in which one kid maps to the phone's public key in one map and to the compromised
  // GATE's public key in the other therefore satisfied every check: the decision verified against
  // the real approver, the receipt verified against the attacker, the strings matched, and the
  // sidecar signed a grant for attacker-chosen parameters. Reproduced end to end; the shipped
  // verifier then returned ok:true on the result.
  //
  // A kid is a NAME. Two maps that disagree about which KEY a name denotes do not describe one
  // trust root, they describe two — and the whole point of this process is to have exactly one. So
  // agreement is enforced here, at load, where the operator can still fix it, and re-checked per
  // request in `validateGrantRequest` (defence in depth: these fail independently).
  //
  // The gate engine already had this exact control for its own two keyrings
  // (`engine.ts`, TRUST_KEYRING_INCONSISTENT). It was not mirrored here. Same class, one file over.
  const receiptKeys = receiptKeyring["keys"] as Record<string, unknown>;
  for (const [kid, entry] of Object.entries(keyring)) {
    if (!isRecord(entry)) throw new Error(`grant sidecar: --trust-file keyring entry ${JSON.stringify(kid)} is not an object`);
    if (!Object.prototype.hasOwnProperty.call(receiptKeys, kid)) continue;
    const receiptEntry = receiptKeys[kid];
    const receiptPub = isRecord(receiptEntry) ? receiptEntry["publicKey"] : receiptEntry;
    if (receiptPub !== entry["publicKey"]) {
      throw new Error(
        `grant sidecar: --trust-file resolves kid ${JSON.stringify(kid)} to DIFFERENT public keys in keyring and receiptKeyring. ` +
          `A kid is a name; two maps that disagree about which key it denotes are two trust roots, and this process must have exactly one. ` +
          `Refusing to start rather than authenticate a decision against one key and its receipt against another.`,
      );
    }
  }
  const maxAge = doc["maxApprovalAgeMs"];
  return {
    spec: "noa.grant-signer-trust/1",
    tenant,
    keyring: keyring as Record<string, KeyEntry>,
    receiptKeyring: receiptKeyring as unknown as SigningKeyLifecycle,
    ...(typeof maxAge === "number" && Number.isFinite(maxAge) && maxAge > 0 ? { maxApprovalAgeMs: maxAge } : {}),
  };
}

// ── the policy gate ──────────────────────────────────────────────────────────────────────────────

export interface ValidateGrantInput {
  /** The UNSIGNED `noa.execution-grant/0.1` document the gate is asking to have signed. */
  grant: Record<string, unknown>;
  /** The approver-signed material, plus the gate-signed material it hangs off. */
  proof: Record<string, unknown>;
  trust: GrantSignerTrust;
  schemas: Record<string, unknown>;
  nowMs: number;
  maxApprovalAgeMs: number;
  maxGrantTtlMs: number;
}

export type ValidateGrantResult =
  | { ok: true; approvalRef: string; approvalMs: number }
  | { ok: false; reason: string };

const refuse = (reason: string): ValidateGrantResult => ({ ok: false, reason });

/**
 * Decide whether this grant document is backed by a genuine approval. PURE — no clock of its own, no
 * I/O, no key material — so it can be driven directly from a test with an adversarial request.
 *
 * Fail-closed throughout: every check that cannot be positively satisfied REFUSES.
 */
export function validateGrantRequest(input: ValidateGrantInput): ValidateGrantResult {
  const { grant, proof, trust, schemas, nowMs, maxApprovalAgeMs } = input;
  const nowIso = new Date(nowMs).toISOString();

  // 0. The document must be an unsigned grant. A caller-supplied `sig` would be re-signed into a
  //    document carrying two answers about who signed it.
  if (grant["spec"] !== EXECUTION_GRANT_SPEC) return refuse(`not an Execution Grant (spec ${JSON.stringify(grant["spec"])})`);
  if (Object.prototype.hasOwnProperty.call(grant, "sig")) return refuse("grant document already carries a sig");
  if (grant["maxUses"] !== 1) return refuse("grant must declare maxUses: 1");
  for (const f of ["grantId", "holdId", "paramsHash", "holdEnvelopeHash", "approvalReceiptHash", "issuedAt", "expiresAt", "nonce"]) {
    if (!asString(grant[f])) return refuse(`grant field ${f} is missing or not a non-empty string`);
  }
  // `nonce` is the on-chain correlation seed (D7) and the grant schema pins `^[0-9a-f]{64}$`. Enforced
  // HERE, before this process signs anything, so a UUID-nonce (or any non-hex64) grant costs zero
  // signer invocations rather than being minted and rejected by every verifier downstream. The
  // in-process `issueGrant` surface enforces the identical rule.
  if (!isHex64(grant["nonce"])) return refuse("grant.nonce must be exactly 64 lowercase hex characters (the D7 correlation seed; grant schema ^[0-9a-f]{64}$)");

  const holdEnvelope = proof["holdEnvelope"];
  const decisionArtifact = proof["decisionArtifact"];
  const deferredReceipt = proof["deferredReceipt"];
  const approvalReceipt = proof["approvalReceipt"];
  if (!isRecord(holdEnvelope)) return refuse("proof.holdEnvelope missing");
  if (!isRecord(decisionArtifact)) return refuse("proof.decisionArtifact missing");
  if (!isRecord(deferredReceipt)) return refuse("proof.deferredReceipt missing");
  if (!isRecord(approvalReceipt)) return refuse("proof.approvalReceipt missing");

  // 1. THE ALLOWED RECEIPT — the approver's signature over the approved parameters.
  //    Read first because its `action.riskClass` selects the F15 approver tier the Decision Artifact
  //    is then held to, and because `paramsHash` is the value the whole request exists to bind.
  if (getPath(approvalReceipt, "governance.verdict") !== "ALLOWED") return refuse("approval receipt is not an ALLOWED verdict");
  if (getPath(approvalReceipt, "agent.principal") !== "HUMAN") return refuse("approval receipt does not declare principal HUMAN");
  if (getPath(approvalReceipt, "scope.tenant") !== trust.tenant) return refuse("approval receipt is for a different tenant");
  const approvedParamsHash = asString(getPath(approvalReceipt, "action.paramsHash"));
  const approvedRisk = asString(getPath(approvalReceipt, "action.riskClass"));
  const approvalBy = asString(getPath(approvalReceipt, "governance.approval.by"));
  const approvalAt = asString(getPath(approvalReceipt, "governance.approval.at"));
  const receiptKid = asString(getPath(approvalReceipt, "sig.kid"));
  if (!approvedParamsHash) return refuse("approval receipt carries no action.paramsHash");
  if (!approvedRisk) return refuse("approval receipt carries no action.riskClass");
  if (!approvalBy || !approvalAt || !receiptKid) return refuse("approval receipt carries no governance.approval.by/at or sig.kid");
  if (approvalBy !== receiptKid) return refuse("governance.approval.by does not name the key that signed the approval receipt");

  const approverEntry = Object.prototype.hasOwnProperty.call(trust.keyring, receiptKid) ? trust.keyring[receiptKid] : undefined;
  if (!approverEntry || approverEntry.type !== "APPROVER") {
    return refuse(`the approval receipt's signer ${JSON.stringify(receiptKid)} is not an APPROVER key in this signer's own trust material`);
  }
  // CROSS-KEYRING AGREEMENT, per request. `loadGrantSignerTrust` refuses a disagreeing trust file at
  // startup; this is the same check at the point of use, so an injected or hand-built trust object
  // that never went through the loader cannot reintroduce the confusion. The two controls fail
  // independently on purpose — that is what makes this defence in depth rather than a duplicate.
  const receiptKeyEntry = Object.prototype.hasOwnProperty.call(trust.receiptKeyring.keys, receiptKid)
    ? trust.receiptKeyring.keys[receiptKid]
    : undefined;
  if (!receiptKeyEntry || receiptKeyEntry.publicKey !== approverEntry.publicKey) {
    return refuse(
      `kid ${JSON.stringify(receiptKid)} resolves to different public keys in the artifact keyring and the receipt keyring — ` +
        `a decision authenticated against one key and its receipt against another is not one approval`,
    );
  }

  // 2. THE APPROVAL IS FRESH, by THIS process's clock. Every timestamp in the request is chosen by
  //    the caller, so a bound derived from the request alone bounds nothing; the only independent
  //    clock in this exchange is the one on this side of the socket.
  const approvalMs = sidecarDateParse(approvalAt);
  if (!Number.isFinite(approvalMs)) return refuse("approval.at is not a parseable instant");
  if (approvalMs > nowMs + CLOCK_SKEW_MS) return refuse("approval.at is in this signer's future");
  if (nowMs - approvalMs > maxApprovalAgeMs) {
    return refuse(`approval is ${Math.round((nowMs - approvalMs) / 1000)}s old, past the ${Math.round(maxApprovalAgeMs / 1000)}s freshness window`);
  }

  // 3. THE RECEIPT CHAIN — the ALLOWED receipt links onto the DEFERRED receipt of THIS hold, and its
  //    own signature verifies under the approver key held HERE.
  //    The DEFERRED leg is signed by the gate, i.e. by a key the attacker in this threat model
  //    already has; it is a consistency check, not an authority check. What the attacker cannot do
  //    is move a genuine ALLOWED receipt onto a different hold, because the Decision Artifact in
  //    step 4 commits to the envelope and the envelope commits to the deferred receipt.
  const chain = verifyChain(encodeDocument([deferredReceipt, approvalReceipt]), {
    keyring: encodeDocument(trust.receiptKeyring),
    requireTenantConsistency: true,
  });
  if (chain.status !== "VALID") return refuse(`receipt chain invalid: ${chain.reason ?? chain.status}`);
  if (receiptRefHash(deferredReceipt) !== asString(holdEnvelope["deferredReceiptHash"])) {
    return refuse("the deferred receipt presented is not the one the hold envelope commits to");
  }

  // 4. THE HOLD ENVELOPE — structure, tenant, ENFORCED mode.
  //    Signed by the gate, therefore forgeable by the attacker: this establishes shape, not truth.
  //    It matters because the Decision Artifact below commits to THIS envelope by hash, so the
  //    envelope is the join between an approver's decision and a hold.
  const envCheck = verifyArtifact(encodeDocument(holdEnvelope), encodeDocument({
    schemas,
    keyring: trust.keyring,
    now: nowIso,
    authorizationTime: nowIso,
    equals: [{ path: "tenant", value: trust.tenant }],
  }));
  if (!envCheck.ok) return refuse(`hold envelope invalid: ${envCheck.reason}`);
  if (holdEnvelope["mode"] !== "ENFORCED") {
    return refuse("hold envelope is not ENFORCED — a RAW acknowledgement is not authorization and may never carry a grant");
  }
  // THE HOLD'S OWN DEADLINE, against THIS process's clock (adversarial review 2026-08-12).
  // The approval-freshness window bounds how old an APPROVAL may be; it said nothing about the hold
  // the approval belongs to. Measured before this check existed: a hold with a 1-minute TTL was
  // granted two minutes after it expired, and the grant passed the shipped verifier. A hold that has
  // run out is a hold whose human answer arrived too late — `EXPIRED` is a distinct terminal state,
  // never an approval (Red Line 6), and no grant may outlive it.
  const envelopeExpiryMs = sidecarDateParse(asString(holdEnvelope["expiresAt"]) ?? "");
  if (!Number.isFinite(envelopeExpiryMs)) return refuse("hold envelope carries no parseable expiresAt");
  // NO SKEW ALLOWANCE IN THE UNSAFE DIRECTION (independent review 2026-08-13, round 3). This read
  // `nowMs > envelopeExpiryMs + CLOCK_SKEW_MS` and therefore ACCEPTED an approval for the whole first
  // minute after the hold had run out — measured live by the reviewer: a genuine approval granted 30s
  // past the deadline returned `ok: true`. The skew allowance exists so a gate whose clock runs
  // slightly AHEAD is not punished for a future-dated `issuedAt`; spent on an expiry it does the
  // opposite and hands the tolerance to the attacker's side of the boundary. The two directions are
  // not symmetric and must not share a constant: refusing one second late costs a human another tap,
  // accepting one second late is an authorization no human gave inside the window they were shown.
  if (nowMs > envelopeExpiryMs) {
    return refuse(`the hold expired ${Math.round((nowMs - envelopeExpiryMs) / 1000)}s ago — an expired hold is not an approval and may never carry a grant`);
  }
  if (asString(grant["holdEnvelopeHash"]) !== refHash(holdEnvelope)) return refuse("grant.holdEnvelopeHash does not hash this envelope");
  if (grant["holdId"] !== holdEnvelope["holdId"]) return refuse("grant.holdId does not match the envelope's holdId");

  // 5. THE DECISION ARTIFACT — the approver signed APPROVE over THIS envelope. Signature, F15 tier
  //    for the approved riskClass, the envelope binding and the transitive tenant are all delegated
  //    to the shipped verifier rather than restated here.
  const daCheck = verifyArtifact(encodeDocument(decisionArtifact), encodeDocument({
    schemas,
    keyring: trust.keyring,
    now: nowIso,
    authorizationTime: nowIso,
    riskClass: approvedRisk,
    equals: [{ path: "decision", value: "APPROVE" }],
    refHashChecks: [
      { path: "holdEnvelopeHash", rule: "side", artifact: holdEnvelope, refEquals: [{ path: "tenant", value: trust.tenant }] },
    ],
  }));
  if (!daCheck.ok) return refuse(`decision artifact invalid: ${daCheck.reason}`);
  if (decisionArtifact["approverKid"] !== receiptKid) {
    return refuse("the decision artifact and the approval receipt were signed by different keys");
  }

  // 6. THE TWO BINDINGS THAT ARE THE WHOLE POINT.
  const approvalRef = receiptRefHash(approvalReceipt);
  if (asString(grant["approvalReceiptHash"]) !== approvalRef) {
    return refuse("grant.approvalReceiptHash does not hash the approval presented");
  }
  if (grant["paramsHash"] !== approvedParamsHash) {
    return refuse(
      `grant.paramsHash ${JSON.stringify(grant["paramsHash"])} is not the paramsHash a human approved (${JSON.stringify(approvedParamsHash)})`,
    );
  }

  // 7. THE GRANT'S OWN WINDOW, bounded against THIS process's clock.
  //    Found by attacking this function rather than by writing it: every check above binds WHAT the
  //    grant authorizes, and none of them bounded FOR HOW LONG. A compromised gate could therefore
  //    take a genuine approval, obtain its one legitimate grant, and choose `expiresAt` ten years
  //    out — a long-lived capability for the approved parameters, since the single-use burn lives in
  //    the store the attacker controls. Post-dating `issuedAt` is the same trick shifted: a grant
  //    that becomes usable later. Both are bounded here, where the clock is not the caller's.
  const issuedMs = sidecarDateParse(asString(grant["issuedAt"]) ?? "");
  const expiresMs = sidecarDateParse(asString(grant["expiresAt"]) ?? "");
  if (!Number.isFinite(issuedMs) || !Number.isFinite(expiresMs)) return refuse("grant issuedAt/expiresAt are not parseable instants");
  if (expiresMs <= issuedMs) return refuse("grant expiresAt does not follow issuedAt");
  if (Math.abs(issuedMs - nowMs) > CLOCK_SKEW_MS) {
    return refuse(`grant.issuedAt is ${Math.round((issuedMs - nowMs) / 1000)}s from this signer's clock, outside the ${Math.round(CLOCK_SKEW_MS / 1000)}s skew allowance`);
  }
  if (expiresMs - issuedMs > input.maxGrantTtlMs) {
    return refuse(`grant lifetime ${Math.round((expiresMs - issuedMs) / 1000)}s exceeds the ${Math.round(input.maxGrantTtlMs / 1000)}s this signer will authorize`);
  }
  // THE GRANT MAY NOT OUTLIVE THE HOLD IT CAME FROM (independent review 2026-08-13, round 3).
  // Bounding the grant's DURATION is not the same statement as bounding its END, and only the first
  // was enforced: with a `maxGrantTtlMs` of five minutes, a grant issued against a hold expiring in
  // thirty seconds was accepted and stayed valid 270s past that hold — measured by the reviewer. The
  // comment above the deadline check already claimed "no grant may outlive it", which made this the
  // worse kind of gap: a property asserted in prose, believed by every later reader, enforced
  // nowhere. The human answered a question that was open until `holdEnvelope.expiresAt`; authority
  // derived from that answer ends where the question ended.
  if (expiresMs > envelopeExpiryMs) {
    return refuse(`grant expires ${Math.round((expiresMs - envelopeExpiryMs) / 1000)}s after the hold it derives from — a grant may not outlive its hold`);
  }

  return { ok: true, approvalRef, approvalMs };
}

// ── replay: one grant per approval ───────────────────────────────────────────────────────────────

/**
 * ONE GRANT PER APPROVAL — DURABLE, and expiring on the APPROVAL's clock, not on ours.
 *
 * The gate's `UNUSED→RESERVED` compare-and-set is single-use enforcement for a grant that EXISTS; it
 * cannot stop a compromised gate from asking for a second grant over the same approval with a fresh
 * `grantId` and `nonce`, which would be two independently valid authorizations for one human
 * decision. Keyed on the approval's own receipt hash — approver-signed content — never on a
 * caller-chosen id.
 *
 * ── TWO DEFECTS THIS SHAPE EXISTS TO CLOSE (adversarial review 2026-08-12) ──────────────────────
 * 1. IT WAS PROCESS-LOCAL. A restart inside the freshness window forgot every claim, and the same
 *    approval bought a second valid grant. An anti-replay record that does not survive the process
 *    is a record of this process's uptime, not of what has been authorized. It is now appended to a
 *    file and fsync'd BEFORE the response is written, so a crash can only ever lose liveness (an
 *    approval burnt without a grant delivered), never safety (two grants for one approval).
 * 2. RETENTION STARTED AT FIRST USE. An entry was dropped `maxApprovalAgeMs` after the GRANT, while
 *    an approval is accepted up to `CLOCK_SKEW_MS` into the future — so an approval stamped `t0+60s`
 *    first granted at `t0` was forgotten at `t0+900001ms` while still inside its own freshness
 *    window, and granted again. Reproduced. Retention is now anchored to the APPROVAL's timestamp
 *    plus the same window and skew the freshness check uses, so an entry can only be evicted once
 *    the approval it records would itself be refused as stale. The two rules are derived from one
 *    pair of constants and cannot drift apart.
 */
export class ApprovalReplayStore {
  private readonly seen = new Map<string, number>();

  /**
   * @param retentionMs the approval-freshness window; an entry lives until the approval it records
   *        is itself too old to be accepted.
   * @param persistPath append-only durability. `null` is IN-MEMORY ONLY and is for tests that drive
   *        the class directly; the shipped process always passes a path.
   */
  constructor(private readonly retentionMs: number, private readonly persistPath: string | null = null) {
    if (persistPath !== null) this.load(persistPath);
  }

  /** True when this approval had not been granted before (and is now durably recorded). */
  claim(approvalRef: string, approvalMs: number, nowMs: number): boolean {
    this.prune(nowMs);
    if (this.seen.has(approvalRef)) return false;
    if (this.seen.size >= MAX_REPLAY_ENTRIES) {
      // Fail CLOSED. Evicting a live entry to make room is how a replay window opens quietly.
      throw new Error("grant sidecar: anti-replay set is full — refusing to sign rather than forget an approval");
    }
    // DURABILITY BEFORE THE ANSWER. If this throws, nothing is claimed and nothing is returned; if
    // it succeeds and the caller then dies, the approval is spent. That asymmetry is the correct
    // one for an authority root: a lost grant costs a human one more tap, a duplicated grant costs
    // an unapproved execution.
    if (this.persistPath !== null) this.append(approvalRef, approvalMs);
    this.seen.set(approvalRef, approvalMs);
    return true;
  }

  /** An entry survives until the approval it records is itself outside the freshness window. */
  private expiryFor(approvalMs: number): number {
    return approvalMs + this.retentionMs + CLOCK_SKEW_MS;
  }

  private prune(nowMs: number): void {
    for (const [ref, approvalMs] of this.seen) {
      if (nowMs > this.expiryFor(approvalMs)) this.seen.delete(ref);
    }
  }

  private append(ref: string, approvalMs: number): void {
    const fd = openSync(this.persistPath!, fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_APPEND | (fsConstants.O_NOFOLLOW ?? 0), 0o600);
    try {
      writeSync(fd, JSON.stringify({ ref, approvalMs }) + "\n");
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
  }

  /** Rebuild from the journal. A malformed line is FATAL, never skipped: a record we cannot read is
   *  an approval we cannot prove is unspent, and quietly dropping it is the replay this class
   *  exists to prevent. */
  private load(file: string): void {
    let text: string;
    try {
      text = readFileSync(file, "utf8");
    } catch (err) {
      if (thrownCode(err) === "ENOENT") return; // first run
      throw err;
    }
    for (const line of text.split("\n")) {
      if (line.trim() === "") continue;
      const parsed = parseDocument(line, "replay journal entry");
      if (!parsed.ok || !isRecord(parsed.value)) {
        throw new Error(`grant sidecar: replay journal "${file}" has an unreadable entry — refusing to start with an anti-replay record it cannot read`);
      }
      const ref = asString(parsed.value["ref"]);
      const at = parsed.value["approvalMs"];
      if (!ref || typeof at !== "number" || !Number.isFinite(at)) {
        throw new Error(`grant sidecar: replay journal "${file}" has a malformed entry — refusing to start`);
      }
      this.seen.set(ref, at);
    }
  }

  /** Rewrite the journal without entries whose approvals are already too stale to be accepted.
   *  Safe by construction: only entries the freshness check would refuse anyway are dropped. */
  compact(nowMs: number): void {
    if (this.persistPath === null) return;
    this.prune(nowMs);
    const body = [...this.seen].map(([ref, approvalMs]) => JSON.stringify({ ref, approvalMs })).join("\n");
    const tmp = `${this.persistPath}.compact`;
    const fd = openSync(tmp, fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_TRUNC | (fsConstants.O_NOFOLLOW ?? 0), 0o600);
    try {
      writeSync(fd, body === "" ? "" : body + "\n");
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
    renameSync(tmp, this.persistPath);
  }

  /** Test/diagnostic reader — how many approvals are currently remembered. */
  get size(): number {
    return this.seen.size;
  }
}

// ── the process ──────────────────────────────────────────────────────────────────────────────────

interface SidecarOptions {
  keyFile: string;
  trustFile: string;
  socket: string;
  socketMode: number;
  maxApprovalAgeMs: number | null;
  maxGrantTtlMs: number | null;
  replayFile: string | null;
}

export function parseSidecarArgs(argv: string[]): SidecarOptions {
  const opts: Partial<SidecarOptions> = { socketMode: 0o600, maxApprovalAgeMs: null, maxGrantTtlMs: null, replayFile: null };
  for (let i = 0; i < argv.length; i++) {
    const flag = argv[i];
    const value = argv[++i];
    if (value === undefined) throw new Error(`grant sidecar: flag "${flag}" needs a value`);
    if (flag === "--key-file") opts.keyFile = value;
    else if (flag === "--trust-file") opts.trustFile = value;
    else if (flag === "--socket") opts.socket = value;
    else if (flag === "--socket-mode") opts.socketMode = Number.parseInt(value, 8);
    else if (flag === "--max-approval-age-ms") opts.maxApprovalAgeMs = Number.parseInt(value, 10);
    else if (flag === "--max-grant-ttl-ms") opts.maxGrantTtlMs = Number.parseInt(value, 10);
    else if (flag === "--replay-file") opts.replayFile = value;
    else throw new Error(`grant sidecar: unknown flag "${flag}"`);
  }
  if (!opts.keyFile) throw new Error("grant sidecar: --key-file is required");
  if (!opts.trustFile) throw new Error("grant sidecar: --trust-file is required");
  if (!opts.socket) throw new Error("grant sidecar: --socket is required");
  if (!Number.isInteger(opts.socketMode) || opts.socketMode! < 0 || opts.socketMode! > 0o777) {
    throw new Error("grant sidecar: --socket-mode must be an octal file mode");
  }
  if (opts.maxApprovalAgeMs !== null && (!Number.isInteger(opts.maxApprovalAgeMs) || opts.maxApprovalAgeMs! <= 0)) {
    throw new Error("grant sidecar: --max-approval-age-ms must be a positive integer");
  }
  if (opts.maxGrantTtlMs !== null && (!Number.isInteger(opts.maxGrantTtlMs) || opts.maxGrantTtlMs! <= 0)) {
    throw new Error("grant sidecar: --max-grant-ttl-ms must be a positive integer");
  }
  return opts as SidecarOptions;
}

/**
 * The socket's directory must not be world-accessible.
 *
 * DELIBERATELY LOOSER THAN `noa-signer-sidecar`'s owner-only rule, and the reason is the whole point
 * of this process: the custody claim is only true when this runs as a DIFFERENT OS user from the
 * gate, and an owner-only directory would make that deployment impossible to connect to. Group
 * access is therefore allowed; world access is not, on any deployment.
 */
export function assertSocketDirIsNotWorldAccessible(socketPath: string): void {
  const dir = dirname(socketPath);
  let st;
  try {
    st = statSync(dir);
  } catch (err) {
    throw new Error(`grant sidecar: --socket directory "${dir}" does not exist (${describeThrown(err)}). Create it with mode 0700 (or 0750 with a shared group) first.`);
  }
  if (!st.isDirectory()) throw new Error(`grant sidecar: --socket directory "${dir}" is not a directory`);
  // No WORLD access at all, and no GROUP WRITE. The earlier rule masked `0o007` only, so a
  // group-writable directory (0770) was accepted — and anyone in that group can unlink the socket
  // and bind their own listener in its place, which is a full impersonation of the authority root
  // (adversarial review 2026-08-12). Group READ+TRAVERSE stays legal because the different-UID
  // deployment this process exists for requires it.
  if ((st.mode & 0o007) !== 0 || (st.mode & 0o020) !== 0) {
    throw new Error(
      `grant sidecar: --socket directory "${dir}" is world-accessible or group-writable (mode 0${(st.mode & 0o777).toString(8)}) — ` +
        `refusing to listen for signing requests there. A directory a third party can write is a directory in which they can replace this socket. ` +
        `chmod it to 0700, or 0750 with a group shared with the gate.`,
    );
  }
}

/** Remove a socket file left by an unclean shutdown — VERIFIED stale, never assumed: a live listener
 *  on the path stops this process rather than being stolen from. Mirrors `noa-signer-sidecar`. */
function clearStaleSocket(socketPath: string): Promise<void> {
  return new Promise((resolve, reject) => {
    if (!existsSync(socketPath)) return resolve();
    const probe = connect(socketPath);
    probe.once("connect", () => {
      probe.destroy();
      reject(new Error(`grant sidecar: --socket "${socketPath}" already has a live listener — refusing to start a second signer on the same path`));
    });
    probe.once("error", (err) => {
      const code = thrownCode(err);
      if (code === "ECONNREFUSED" || code === "ENOENT") {
        try {
          unlinkSync(socketPath);
        } catch (unlinkErr) {
          if (thrownCode(unlinkErr) !== "ENOENT") return reject(unlinkErr);
        }
        return resolve();
      }
      reject(err);
    });
  });
}

function readOneLine(socket: import("node:net").Socket, onLine: (line: string) => void, onError: () => void): void {
  let buf = "";
  let done = false;
  socket.setEncoding("utf8");
  socket.on("data", (chunk: string) => {
    if (done) return;
    buf += chunk;
    if (buf.length > MAX_LINE_BYTES) {
      done = true;
      onError();
      socket.destroy();
      return;
    }
    const nl = buf.indexOf("\n");
    if (nl !== -1) {
      done = true;
      onLine(buf.slice(0, nl));
    }
  });
  socket.on("error", () => {
    if (!done) {
      done = true;
      onError();
    }
  });
}

export interface GrantSidecarHandlerDeps {
  identity: { kid: string; privateKey: string; publicKey: string };
  trust: GrantSignerTrust;
  schemas: Record<string, unknown>;
  replay: ApprovalReplayStore;
  maxApprovalAgeMs: number;
  maxGrantTtlMs: number;
  now: () => number;
}

/**
 * The request handler, as a pure-ish function of its dependencies so a test can drive the real
 * decision logic without a socket. Returns the response object; never throws.
 */
export function handleGrantSignerRequest(deps: GrantSidecarHandlerDeps, line: string): Record<string, unknown> {
  const parsed = parseDocument(line, "request");
  if (!parsed.ok) return { error: `malformed request (${parsed.reason})` };
  const req = parsed.value;
  if (!isRecord(req)) return { error: "request is not an object" };
  const op = req["op"];

  if (op === "pubkey") return { kid: deps.identity.kid, pub: deps.identity.publicKey, alg: "ed25519" };

  if (op !== "sign-grant" && op !== "sign-attestation") return { error: `unknown op ${JSON.stringify(op)}` };

  const artifact = req["artifact"];
  if (!isRecord(artifact)) return { error: `${String(op)}: "artifact" must be an object` };
  const spec = artifact["spec"];

  let domain: string;
  try {
    domain = executionDomainFor(spec);
  } catch (err) {
    return { error: describeThrown(err) };
  }

  if (op === "sign-attestation") {
    // THE OP SPLIT IS A REFUSAL, NOT A CONVENTION. Without this line the ungated attestation op
    // would sign a grant document under the grant domain and hand back full authority.
    if (spec === EXECUTION_GRANT_SPEC) {
      return { error: "sign-attestation: an Execution Grant is authority, not an attestation — use sign-grant with an approval proof" };
    }
  }

  // ── ORDER OF OPERATIONS, AND IT IS THE WHOLE OF FINDING 8 ────────────────────────────────────
  // The replay slot used to be claimed BEFORE signing and BEFORE the schema self-check. Every way
  // the request could still fail after that point therefore BURNED the human's approval: one
  // schema-forbidden extra property on the submitted document permanently wedged a genuine
  // approval, with the only remedy being another human tap. Measured.
  //
  // The order is now: validate the approval -> sign -> check the signed bytes against the shipped
  // schema -> claim the slot -> answer. Claiming last means every refusal is FREE, and only a
  // request that is about to be answered spends the approval.
  //
  // WHAT REMAINS, STATED RATHER THAN HIDDEN: the claim and the delivery of the response are in two
  // different processes, so no ordering makes them one transaction. A response lost after the claim
  // burns the approval. That is the direction to fail — an approval spent without a grant delivered
  // costs one more tap, whereas a grant delivered without the approval spent is a second
  // authorization for one human decision. `NON-CLAIMS.md` says so too.
  let grantClaim: { ref: string; approvalMs: number } | null = null;
  if (op === "sign-grant") {
    if (spec !== EXECUTION_GRANT_SPEC) return { error: "sign-grant: artifact is not an Execution Grant" };
    const proof = req["proof"];
    if (!isRecord(proof)) return { error: "sign-grant: an approval proof is required" };
    const verdict = validateGrantRequest({
      grant: artifact,
      proof,
      trust: deps.trust,
      schemas: deps.schemas,
      nowMs: deps.now(),
      maxApprovalAgeMs: deps.maxApprovalAgeMs,
      maxGrantTtlMs: deps.maxGrantTtlMs,
    });
    if (!verdict.ok) return { error: `REFUSED: ${verdict.reason}` };
    grantClaim = { ref: verdict.approvalRef, approvalMs: verdict.approvalMs };
  }

  let signed: Record<string, unknown>;
  try {
    signed = signArtifact(encodeDocument(artifact), domain, { kid: deps.identity.kid, privateKey: deps.identity.privateKey });
  } catch (err) {
    return { error: `signing failed: ${describeThrown(err)}` };
  }

  // Structural self-check against the SHIPPED schema, after signing and before the bytes leave this
  // process. A document that would be rejected by every consumer must never be handed out carrying
  // this key's signature; that is how an unusable artifact becomes a support ticket instead of a
  // refusal.
  const meta = Object.prototype.hasOwnProperty.call(ARTIFACTS, String(spec)) ? ARTIFACTS[String(spec)] : undefined;
  const schema = meta && Object.prototype.hasOwnProperty.call(deps.schemas, meta.spec) ? deps.schemas[meta.spec] : undefined;
  if (!schema) return { error: `no schema loaded for ${String(spec)}` };
  const structural = evalSchema(schema as Record<string, unknown>, signed);
  if (!structural.ok) return { error: `signed artifact fails its own schema: ${structural.errors.join("; ")}` };

  if (grantClaim !== null) {
    try {
      if (!deps.replay.claim(grantClaim.ref, grantClaim.approvalMs, deps.now())) {
        return { error: "REFUSED: this approval has already been granted once — one human decision authorizes one grant" };
      }
    } catch (err) {
      // A durability failure must never return a signature. The bytes exist in this frame; they do
      // not leave it.
      return { error: `REFUSED: could not durably record this approval as spent (${describeThrown(err)})` };
    }
  }

  return { artifact: signed };
}

async function main(): Promise<void> {
  const opts = parseSidecarArgs(process.argv.slice(2));
  assertSocketDirIsNotWorldAccessible(opts.socket);
  await clearStaleSocket(opts.socket);

  const trust = loadGrantSignerTrust(opts.trustFile);
  const maxApprovalAgeMs = opts.maxApprovalAgeMs ?? trust.maxApprovalAgeMs ?? DEFAULT_MAX_APPROVAL_AGE_MS;
  // DURABLE ANTI-REPLAY, always. Defaults beside the key file rather than being optional: an
  // in-memory-only anti-replay set is a record of this process's uptime, and a restart inside the
  // freshness window handed a second grant to the same approval (adversarial review 2026-08-12).
  const replayFile = opts.replayFile ?? `${opts.keyFile}.spent-approvals.jsonl`;
  const replay = new ApprovalReplayStore(maxApprovalAgeMs, replayFile);
  // Drop entries whose approvals are already too stale to be accepted, so the journal cannot grow
  // without bound. Only ever removes records the freshness check would refuse anyway.
  replay.compact(Date.now());
  const identity = loadOrCreateKeyFile({
    keyFile: opts.keyFile,
    mintKeyPair: () => generateKeyPair(`noa-grant-signer:${new Date().toISOString()}-${process.pid}`),
    callerLabel: "grant sidecar",
  });
  const deps: GrantSidecarHandlerDeps = {
    identity,
    trust,
    schemas: loadSchemas(),
    replay,
    maxApprovalAgeMs,
    maxGrantTtlMs: opts.maxGrantTtlMs ?? DEFAULT_MAX_GRANT_TTL_MS,
    now: () => Date.now(),
  };

  const server = createServer((socket) => {
    readOneLine(
      socket,
      (line) => {
        const response = handleGrantSignerRequest(deps, line);
        socket.end(JSON.stringify(response) + "\n");
      },
      () => {
        // A peer influences a socket error's message; the operational event is the whole record.
        console.error("noa-gate-grant-signer: connection error");
        socket.destroy();
      },
    );
  });

  server.on("error", (err) => {
    console.error(`noa-gate-grant-signer: fatal server error: ${describeThrown(err).replace(/\s+/g, " ").slice(0, 300)}`);
    process.exit(1);
  });

  await new Promise<void>((resolve) => server.listen(opts.socket, () => resolve()));
  chmodSync(opts.socket, opts.socketMode);
  console.error(
    `noa-gate-grant-signer: listening on ${opts.socket} (kid=${identity.kid}, tenant=${trust.tenant}, ` +
      `approval freshness ${maxApprovalAgeMs}ms, ${replay.size} spent approval(s) recovered from ${replayFile})`,
  );

  const shutdown = (): void => {
    server.close(() => {
      try {
        unlinkSync(opts.socket);
      } catch {
        // already gone — fine
      }
      process.exit(0);
    });
  };
  process.on("SIGTERM", shutdown);
  process.on("SIGINT", shutdown);
}

// Only when RUN, never when imported by a test or by the gate.
if (process.argv[1] && process.argv[1].endsWith("grant-sidecar.js")) {
  main().catch((err: unknown) => {
    console.error(`noa-gate-grant-signer: fatal — ${describeThrown(err).replace(/\s+/g, " ").slice(0, 300)}`);
    process.exit(1);
  });
}
