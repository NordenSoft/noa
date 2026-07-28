/**
 * D13/F8a atomic single-use grant (§15 DoD): the gate's atomic grant record — not a wrapper-local
 * flag — is the enforcement. Two concurrent reservations cannot both win; a second TERMINAL report
 * is `409 GRANT_ALREADY_REPORTED`; a report before reserve is refused (reserve strictly
 * pre-dispatch).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { setupGate, signPhoneDecision, sampleCommandParams } from "./helpers.js";

function approveAndGrant(fx: ReturnType<typeof setupGate>, chain: string): string {
  const created = fx.engine.createHold(fx.agent, `idem-${chain}`, {
    mode: "ENFORCED",
    action: { canonical: "noa.command.exec", riskClass: "HIGH", reversible: false },
    params: sampleCommandParams(),
    chain,
  });
  const holdId = (created.body as { holdId: string }).holdId;
  const hold = fx.store.getHold(holdId)!;
  const { receipt, decisionArtifact } = signPhoneDecision({ trust: fx.trust, deferredReceipt: hold.deferredReceipt, holdEnvelope: hold.holdEnvelope, decision: "APPROVE" });
  const decided = fx.engine.decide(holdId, { receipt, decisionArtifact });
  return (decided.body as { grantId: string }).grantId;
}

test("two racing reservations: first wins RESERVED, the loser gets 409 GRANT_ALREADY_RESERVED", () => {
  const fx = setupGate({ approverRole: "approve-high" });
  const grantId = approveAndGrant(fx, "chain-race");

  const first = fx.engine.reserve(grantId, fx.agent);
  const second = fx.engine.reserve(grantId, fx.agent);
  assert.equal(first.status, 200);
  assert.equal((first.body as { status: string }).status, "RESERVED");
  assert.equal(second.status, 409);
  assert.equal((second.body as { error: string }).error, "GRANT_ALREADY_RESERVED");
});

test("report before reserve is refused (409 GRANT_NOT_RESERVED) — reserve strictly pre-dispatch (F8a)", () => {
  const fx = setupGate({ approverRole: "approve-high" });
  const grantId = approveAndGrant(fx, "chain-noreserve");
  const r = fx.engine.report(grantId, { result: "DISPATCHED" }, fx.agent);
  assert.equal(r.status, 409);
  assert.equal((r.body as { error: string }).error, "GRANT_NOT_RESERVED");
});

test("a second TERMINAL report → 409 GRANT_ALREADY_REPORTED (one-shot, F8c)", () => {
  const fx = setupGate({ approverRole: "approve-high" });
  const grantId = approveAndGrant(fx, "chain-oneshot");
  assert.equal(fx.engine.reserve(grantId, fx.agent).status, 200);
  const first = fx.engine.report(grantId, { result: "DISPATCHED" }, fx.agent);
  assert.equal(first.status, 200);
  const second = fx.engine.report(grantId, { result: "DISPATCHED" }, fx.agent);
  assert.equal(second.status, 409);
  assert.equal((second.body as { error: string }).error, "GRANT_ALREADY_REPORTED");
});

test("an expired grant cannot be reserved (410 GRANT_EXPIRED)", () => {
  const fx = setupGate({ approverRole: "approve-high", config: { grantTtlMs: 1000 } });
  const grantId = approveAndGrant(fx, "chain-gexp");
  fx.clock.advance(1001);
  const r = fx.engine.reserve(grantId, fx.agent);
  assert.equal(r.status, 410);
  assert.equal((r.body as { error: string }).error, "GRANT_EXPIRED");
});

/**
 * ── C-04 — THIS TEST USED TO CERTIFY THE DEFECT ────────────────────────────────────────────────
 *
 * Until 2026-07-28 the assertion below read, verbatim and GREEN:
 *
 *     assert.equal(fx.engine.reserve(grantId, fx.agent).status, 200);            // dispatch AUTHORIZED
 *     const r = fx.engine.report(grantId, { result: "FAILED_BEFORE_DISPATCH" }, fx.agent);
 *     assert.equal(r.status, 200);
 *     assert.equal(body.consumption["result"], "FAILED_BEFORE_DISPATCH");        // signed, determinate
 *     assert.equal(body.attemptReceipt.governance.verdict, "FAILED");
 *
 * It pinned, as correct behaviour, a gate-signed determinate "no side effect occurred" issued on
 * the word of the party being judged, AFTER the gate had authorized a dispatch. Nothing in the
 * suite disagreed with it, because the suite's only opinion on the matter was this test. That is
 * the sharpest available illustration of why L4/L5 exist: a green suite is evidence about the
 * suite, and a control nothing measures is indistinguishable from a control that is wrong.
 *
 * It is INVERTED rather than deleted. Deleting it would leave the repository with no record that
 * the behaviour was once asserted, and no mechanical objection if someone restores it.
 */
test("C-04: a RESERVED grant's FAILED_BEFORE_DISPATCH report is an ATTRIBUTED CLAIM, never a signed determinate outcome", () => {
  const fx = setupGate({ approverRole: "approve-high" });
  const grantId = approveAndGrant(fx, "chain-fail");
  // The CAS ran: the gate AUTHORIZED a dispatch and from here cannot observe what followed.
  assert.equal(fx.engine.reserve(grantId, fx.agent).status, 200);

  const r = fx.engine.report(grantId, { result: "FAILED_BEFORE_DISPATCH" }, fx.agent);

  assert.equal(r.status, 202, "an unverifiable claim is acknowledged (202), never signed as fact (200)");
  const body = r.body as Record<string, unknown>;
  assert.equal(body["status"], "UNCERTAINTY_PENDING_GATE_CORROBORATION", "it routes through the EXISTING uncertainty mechanism — no new wire outcome");
  assert.equal(body["claimRecorded"], "FAILED_BEFORE_DISPATCH", "the claim is not discarded; it is recorded as a claim");
  assert.equal(body["consumption"], undefined, "no consumption is signed");
  assert.equal(body["attemptReceipt"], undefined, "no FAILED attempt receipt is signed");

  // The claim is attributed in gate-local state — "X said this", never "this is what happened".
  const rec = fx.engine.getGrant(grantId)!;
  assert.equal(rec.claimedResult, "FAILED_BEFORE_DISPATCH");
  assert.equal(rec.claimedBy, fx.agent.id);
  assert.equal(rec.consumption, null, "no signed consumption exists for an unverifiable claim");
  assert.notEqual(rec.status, "REPORTED", "the grant is not terminally consumed by a claim the gate cannot verify");
});

/**
 * The complementary half, and it matters exactly as much: over-deleting the determinate negative
 * would be its own defect. `UNUSED` means the F8a CAS never ran, so the gate itself knows no
 * dispatch was ever authorized — that is a GATE observation, not the caller's word, and it stays
 * determinate and signed. An over-correction that made every refusal look like an unknown would
 * teach operators that UNKNOWN means nothing.
 */
test("C-04 did not over-correct: an UNUSED grant (the gate's OWN observation) still signs a determinate FAILED_BEFORE_DISPATCH", () => {
  const fx = setupGate({ approverRole: "approve-high" });
  const grantId = approveAndGrant(fx, "chain-fail-unused");
  // NO reserve() — the CAS never runs, so the grant never leaves UNUSED.
  assert.equal(fx.engine.getGrant(grantId)!.status, "UNUSED");

  const r = fx.engine.report(grantId, { result: "FAILED_BEFORE_DISPATCH" }, fx.agent);

  assert.equal(r.status, 200);
  const body = r.body as { consumption: Record<string, unknown>; attemptReceipt: Record<string, unknown> };
  assert.equal(body.consumption["result"], "FAILED_BEFORE_DISPATCH");
  assert.equal(typeof (body.consumption["sig"] as { value: string }).value, "string");
  assert.equal((body.attemptReceipt["governance"] as { verdict: string }).verdict, "FAILED");
  assert.equal(fx.engine.getGrant(grantId)!.status, "REPORTED", "a determinate outcome DOES terminally consume the grant");
});

test("C-04: a caller cannot manufacture an authorization it never obtained — DISPATCHED/UNKNOWN on an UNUSED grant stay 409", () => {
  for (const result of ["DISPATCHED", "UNKNOWN"] as const) {
    const fx = setupGate({ approverRole: "approve-high" });
    const grantId = approveAndGrant(fx, `chain-409-${result}`);
    const r = fx.engine.report(grantId, { result }, fx.agent);
    assert.equal(r.status, 409, `${result} without a reservation must not be accepted`);
    assert.equal((r.body as { error: string }).error, "GRANT_NOT_RESERVED");
  }
});
