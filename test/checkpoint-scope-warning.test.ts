/**
 * Regression: `tailChecked: true` must not be an unqualified claim.
 *
 * THREAT-MODEL.md ("Re-heading truncation among co-trusted keys", T-tail-reheading) already
 * states the residual honestly: without an `identityManifest`, checkpoint authentication is
 * KID-LEVEL, so *any* keyring-trusted key can forge a checkpoint over any head. The §5b
 * genesis-binding that closes this only runs when a manifest is supplied.
 *
 * The defect this file pins is not the residual itself — it is the RUNTIME SIGNAL. In that
 * configuration `verifyChain` returned:
 *
 *     { status: "VALID", tailChecked: true, warnings: [ fork/equivocation, kid-level-attribution ] }
 *
 * `tailChecked: true` is the field a relying party reads as "the tail was verified", and neither
 * warning tells it that the tail check it just passed is only as strong as the *weakest* holder
 * of any key in the keyring. A co-trusted key can drop the most recent receipts, mint its own
 * checkpoint over the truncated head, and the caller sees an affirmative tail check.
 *
 * The fix is ADDITIVE and changes no verdict: when a checkpoint authenticates but no
 * identityManifest is supplied, the result carries an explicit warning naming the consequence.
 * Verdicts, `tailChecked`, and every existing warning are untouched — this only stops the
 * result object from over-claiming in the one configuration where the doc says it must not.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { verifyChain } from "../src/verify.js";
import { generateKeyPair } from "../src/keys.js";
import { buildReceipt, buildCheckpoint, type BuildInput } from "../src/builder.js";
import type { Keyring } from "../src/index.js";

const victim = generateKeyPair("victim-key");
const attacker = generateKeyPair("attacker-key");

/** Both keys are in the keyring — the multi-key deployment the threat model describes. */
const keyring: Keyring = {
  [victim.kid]: victim.publicKey,
  [attacker.kid]: attacker.publicKey,
};

function mkInput(id: string, ruleId: string): BuildInput {
  return {
    id,
    ts: "2026-07-27T10:00:00Z",
    scope: { tenant: "t1", chain: "shared" },
    agent: { id: "agent-1", model: null, principal: "SERVICE" },
    action: {
      id: "payment.refund",
      canonical: "payment.refund",
      riskClass: "HIGH",
      paramsHash: "sha256:" + "11".repeat(32),
      reversible: false,
      rollbackRef: null,
    },
    governance: { mode: "on", verdict: "EXECUTED", ruleId, approval: null, sandboxed: false },
  };
}

const r0 = buildReceipt(mkInput("rcpt_v_0", "r0"), null, { kid: victim.kid, privateKey: victim.privateKey });
const r1 = buildReceipt(mkInput("rcpt_v_1", "r1"), r0, { kid: victim.kid, privateKey: victim.privateKey });
const r2 = buildReceipt(mkInput("rcpt_v_2", "INCRIMINATING"), r1, { kid: victim.kid, privateKey: victim.privateKey });

test("an authenticated checkpoint with NO identityManifest warns that the tail check is kid-level (co-trusted key can forge it)", () => {
  // The attacker drops the incriminating seq-2 receipt and mints its own checkpoint over seq 1
  // using its OWN co-trusted key. This is the documented T-tail-reheading residual.
  const forged = buildCheckpoint(r1, "2026-07-27T11:00:00Z", { kid: attacker.kid, privateKey: attacker.privateKey });
  const res = verifyChain([r0, r1], { keyring, checkpoint: forged });

  // The verdict is UNCHANGED by this fix — the residual is real and documented, not a bug to
  // silently re-verdict. What must change is that the caller is TOLD.
  assert.equal(res.status, "VALID", "verdict must be unchanged (the residual is documented, not re-verdicted)");
  assert.equal(res.tailChecked, true, "tailChecked is unchanged — the checkpoint did authenticate");
  assert.equal(res.count, 2, "the tail was in fact truncated: seq 2 is gone");

  // THE ASSERTION THIS FILE EXISTS FOR: the caller must not be left reading `tailChecked: true`
  // with no statement of what that check is worth here.
  const warned = res.warnings.some(
    (w) => /checkpoint/i.test(w) && /identityManifest/i.test(w) && /(kid-level|any keyring-trusted key)/i.test(w),
  );
  assert.equal(
    warned,
    true,
    "expected a warning naming the kid-level scope of the checkpoint/tail check when no identityManifest is supplied; got: " +
      JSON.stringify(res.warnings, null, 1),
  );
});

test("the same chain WITH an identityManifest is rejected UNTRUSTED (the §5b genesis binding still fires)", () => {
  const forged = buildCheckpoint(r1, "2026-07-27T11:00:00Z", { kid: attacker.kid, privateKey: attacker.privateKey });
  const res = verifyChain([r0, r1], {
    keyring,
    checkpoint: forged,
    identityManifest: { "agent-1": [victim.kid] },
  });
  assert.equal(res.status, "UNTRUSTED", res.reason);
  assert.match(res.reason ?? "", /not authorized for chain opener/);
});

test("the new warning does NOT fire when an identityManifest IS supplied (no false positive on the hardened path)", () => {
  const legit = buildCheckpoint(r2, "2026-07-27T11:00:00Z", { kid: victim.kid, privateKey: victim.privateKey });
  const res = verifyChain([r0, r1, r2], {
    keyring,
    checkpoint: legit,
    identityManifest: { "agent-1": [victim.kid] },
  });
  assert.equal(res.status, "VALID", res.reason);
  assert.equal(res.tailChecked, true);
  const warned = res.warnings.some((w) => /checkpoint/i.test(w) && /identityManifest/i.test(w));
  assert.equal(warned, false, "the kid-level checkpoint warning must not fire when the manifest is present");
});

test("no checkpoint supplied → the pre-existing no-checkpoint warning still fires, and the new one does not", () => {
  const res = verifyChain([r0, r1, r2], { keyring });
  assert.equal(res.tailChecked, false);
  assert.equal(
    res.warnings.some((w) => /no checkpoint supplied/.test(w)),
    true,
    "the pre-existing no-checkpoint warning must be preserved",
  );
  assert.equal(
    res.warnings.some((w) => /checkpoint/i.test(w) && /identityManifest/i.test(w)),
    false,
    "the kid-level CHECKPOINT warning is about an authenticated checkpoint; it must not fire when there is none",
  );
});
