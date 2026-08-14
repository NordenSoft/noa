/**
 * BOTH public grant-signing surfaces refuse a non-hex64 nonce BEFORE any signer is invoked
 * (added 2026-08-14).
 *
 * `grant.nonce` is the on-chain D7 correlation seed and the grant schema pins `^[0-9a-f]{64}$`. A
 * UUID (or any other spelling) yields a grant every verifier rejects, so signing one mints an
 * unusable authorization — a gate that hands out authorizations nobody can use. Before this guard,
 * `issueGrant` and the grant sidecar's `validateGrantRequest` checked only for a non-empty string,
 * so both would spend a real signer invocation on a doomed grant. The tests assert the stronger
 * property the fix guarantees: ZERO signer invocations on invalid input, not merely a rejected
 * result.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { issueGrant } from "../src/grants.js";
import { validateGrantRequest } from "../src/grant-sidecar.js";
import type { ExecutionSigner } from "../src/exec-signer.js";
import type { HoldEnvelope, Receipt } from "../src/types.js";

/** A signer that counts invocations and asserts it is never touched on the bad-input path. */
function countingSigner(): { signer: ExecutionSigner; calls: () => number } {
  let n = 0;
  const bump = <T extends Record<string, unknown>>(doc: T) => {
    n++;
    return { ...doc, sig: { alg: "ed25519" as const, kid: "spy", value: "x" } };
  };
  return {
    signer: { kid: "spy", publicKey: "pub", signGrant: (doc) => bump(doc), signAttestation: (doc) => bump(doc) },
    calls: () => n,
  };
}

test("issueGrant refuses a UUID nonce and NEVER invokes the signer", () => {
  const { signer, calls } = countingSigner();
  assert.throws(
    () => issueGrant({
      grantId: "g1", holdId: "h1", paramsHash: "sha256:" + "a".repeat(64),
      // The guard is the FIRST statement, so these dummies are never read.
      holdEnvelope: {} as HoldEnvelope,
      allowedReceipt: {} as Receipt,
      deferredReceipt: {} as Receipt,
      decisionArtifact: {},
      issuedAt: "2026-08-14T10:00:00.000Z",
      expiresAt: "2026-08-14T10:05:00.000Z",
      nonce: randomUUID(),
      signer,
    }),
    /64 lowercase hex/,
    "a UUID nonce must be refused with the named format rule",
  );
  assert.equal(calls(), 0, "the signer must not have been invoked for an invalid nonce");
});

test("issueGrant refuses uppercase / short / long hex too, still zero invocations", () => {
  for (const bad of ["9C".repeat(32), "9c".repeat(31), "9c".repeat(33), "", "9c".repeat(31) + "g1"]) {
    const { signer, calls } = countingSigner();
    assert.throws(
      () => issueGrant({
        grantId: "g", holdId: "h", paramsHash: "sha256:" + "a".repeat(64),
        holdEnvelope: {} as HoldEnvelope, allowedReceipt: {} as Receipt, deferredReceipt: {} as Receipt,
        decisionArtifact: {}, issuedAt: "2026-08-14T10:00:00.000Z", expiresAt: "2026-08-14T10:05:00.000Z",
        nonce: bad, signer,
      }),
      /64 lowercase hex/,
      `accepted: ${JSON.stringify(bad)}`,
    );
    assert.equal(calls(), 0);
  }
});

test("issueGrant with a well-formed hex64 nonce DOES reach the signer (anti-vacuity)", () => {
  const { signer, calls } = countingSigner();
  // Minimal shapes that survive refHash/receiptRefHash structural reads on the happy path.
  const holdEnvelope = { spec: "noa.hold-envelope/0.1", holdId: "h1" } as unknown as HoldEnvelope;
  const receipt = { chain: { hash: "sha256:" + "b".repeat(64) } } as unknown as Receipt;
  const grant = issueGrant({
    grantId: "g1", holdId: "h1", paramsHash: "sha256:" + "a".repeat(64),
    holdEnvelope, allowedReceipt: receipt, deferredReceipt: receipt, decisionArtifact: {},
    issuedAt: "2026-08-14T10:00:00.000Z", expiresAt: "2026-08-14T10:05:00.000Z",
    nonce: "9c".repeat(32), signer,
  });
  assert.equal(calls(), 1, "a valid nonce must reach the signer exactly once");
  assert.equal(grant.nonce, "9c".repeat(32));
});

test("validateGrantRequest refuses a UUID nonce before the sidecar signs (grant-sidecar surface)", () => {
  // The nonce format is checked right after the field-presence loop and BEFORE the approval proof is
  // read, and handleGrantSignerRequest only calls signArtifact when the verdict is ok — so a false
  // verdict here is zero signing by construction.
  const verdict = validateGrantRequest({
    grant: {
      spec: "noa.execution-grant/0.1", grantId: "g", holdId: "h",
      paramsHash: "sha256:" + "a".repeat(64), holdEnvelopeHash: "sha256:" + "b".repeat(64),
      approvalReceiptHash: "sha256:" + "c".repeat(64), issuedAt: "2026-08-14T10:00:00.000Z",
      expiresAt: "2026-08-14T10:05:00.000Z", maxUses: 1, nonce: randomUUID(),
    },
    proof: {},
    trust: { spec: "noa.grant-signer-trust/1", tenant: "t", keyring: {}, receiptKeyring: { spec: "noa.signing-key-lifecycle/0.1", keys: {} } } as never,
    schemas: {},
    nowMs: Date.now(),
    maxApprovalAgeMs: 900_000,
    maxGrantTtlMs: 300_000,
  });
  assert.equal(verdict.ok, false);
  assert.match(verdict.ok ? "" : verdict.reason, /64 lowercase hex/);
});
