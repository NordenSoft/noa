/**
 * D13/F8a atomic single-use grant (§15 DoD): the gate's atomic grant record — not a wrapper-local
 * flag — is the enforcement. Two concurrent reservations cannot both win; a second TERMINAL report
 * is `409 GRANT_ALREADY_REPORTED`; a report before reserve is refused (reserve strictly
 * pre-dispatch).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { setupGate, signPhoneDecision, sampleCommandParams, body } from "./helpers.js";

function approveAndGrant(fx: ReturnType<typeof setupGate>, chain: string, idem = `idem-${chain}`): string {
  const created = fx.engine.createHold(fx.agent, idem, body({
    mode: "ENFORCED",
    action: { canonical: "noa.command.exec", riskClass: "HIGH", reversible: false },
    params: sampleCommandParams(),
    chain,
  }));
  const holdId = (created.body as { holdId: string }).holdId;
  const hold = fx.store.getHold(holdId)!;
  const { receipt, decisionArtifact } = signPhoneDecision({ trust: fx.trust, deferredReceipt: hold.deferredReceipt, holdEnvelope: hold.holdEnvelope, decision: "APPROVE" });
  const decided = fx.engine.decide(holdId, body({ receipt, decisionArtifact }));
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
  const r = fx.engine.report(grantId, body({ result: "DISPATCHED" }), fx.agent);
  assert.equal(r.status, 409);
  assert.equal((r.body as { error: string }).error, "GRANT_NOT_RESERVED");
});

test("a second TERMINAL report → 409 GRANT_ALREADY_REPORTED (one-shot, F8c)", () => {
  const fx = setupGate({ approverRole: "approve-high" });
  const grantId = approveAndGrant(fx, "chain-oneshot");
  assert.equal(fx.engine.reserve(grantId, fx.agent).status, 200);
  const first = fx.engine.report(grantId, body({ result: "DISPATCHED" }), fx.agent);
  assert.equal(first.status, 200);
  const second = fx.engine.report(grantId, body({ result: "DISPATCHED" }), fx.agent);
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

test("a SHORT hold still yields a grant — the window is CLAMPED to the hold, not fixed at the TTL", () => {
  // LIVENESS, not safety — and it was broken by the safety fix that shipped hours earlier the same
  // day. The signer sidecar now refuses any grant that would outlive its hold (correct, and the
  // bound this engine must respect). But the engine asked for `receivedAt + grantTtlMs`
  // unconditionally, so whenever a hold had LESS life left than the configured ceiling, every
  // request the engine could make was one the sidecar HAD to refuse — on every retry, until the
  // hold expired. Holds accept TTLs down to `minTtlMs`, so short holds could never be granted at
  // all. A second-voice review reproduced it against a live sidecar:
  //     ttl-15min -> status 200, grant issued
  //     ttl-2min  -> REFUSED: grant expires 180s after the hold it derives from; hold left PENDING
  // Nothing was signed and no approval was burnt, so the direction was safe — but the effective
  // approval window had silently become `holdTTL - grantTtlMs`, which nobody chose and nothing
  // wrote down. This pins the clamp.
  const fx = setupGate({ approverRole: "approve-high", config: { grantTtlMs: 600_000 } }); // 10-min ceiling
  const created = fx.engine.createHold(fx.agent, "idem-short-hold", body({
    mode: "ENFORCED",
    action: { canonical: "noa.command.exec", riskClass: "HIGH", reversible: false },
    params: sampleCommandParams(),
    chain: "chain-short-hold",
    ttlMs: 60_000,                                                                         // 1-minute hold
  }));
  assert.equal(created.status, 201, "a 60s hold must be inside minTtlMs — otherwise this test proves nothing");
  const holdId = (created.body as { holdId: string }).holdId;
  const hold = fx.store.getHold(holdId)!;
  const { receipt, decisionArtifact } = signPhoneDecision({ trust: fx.trust, deferredReceipt: hold.deferredReceipt, holdEnvelope: hold.holdEnvelope, decision: "APPROVE" });
  const decided = fx.engine.decide(holdId, body({ receipt, decisionArtifact }));
  assert.equal(decided.status, 200, "a short hold must still produce a grant");

  const grantId = (decided.body as { grantId: string }).grantId;
  const grant = fx.store.getGrant(grantId)!.grant;
  const grantEnd = Date.parse(grant.expiresAt);
  const holdEnd = Date.parse(hold.holdEnvelope.expiresAt);
  assert.ok(
    grantEnd <= holdEnd,
    `grant ends ${(grantEnd - holdEnd) / 1000}s after its hold — the sidecar refuses exactly this`,
  );
  // CONTROL: the clamp must not collapse the window to nothing, or "issued" would mean nothing and
  // the assertion above would pass for a grant that authorizes no instant at all.
  assert.ok(grantEnd > Date.parse(grant.issuedAt), "the clamped grant must still have a live window");
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

  const r = fx.engine.report(grantId, body({ result: "FAILED_BEFORE_DISPATCH" }), fx.agent);

  assert.equal(r.status, 202, "an unverifiable claim is acknowledged (202), never signed as fact (200)");
  const resBody = r.body as Record<string, unknown>;
  assert.equal(resBody["status"], "UNCERTAINTY_PENDING_GATE_CORROBORATION", "it routes through the EXISTING uncertainty mechanism — no new wire outcome");
  assert.equal(resBody["claimRecorded"], "FAILED_BEFORE_DISPATCH", "the claim is not discarded; it is recorded as a claim");
  assert.equal(resBody["consumption"], undefined, "no consumption is signed");
  assert.equal(resBody["attemptReceipt"], undefined, "no FAILED attempt receipt is signed");

  // The claim is attributed in gate-local state — "X said this", never "this is what happened".
  const rec = fx.engine.getGrant(grantId)!;
  assert.equal(rec.claimedResult, "FAILED_BEFORE_DISPATCH");
  assert.equal(rec.claimedBy, fx.agent.id);
  assert.equal(rec.consumption, null, "no signed consumption exists for an unverifiable claim");
  assert.notEqual(rec.status, "REPORTED", "the grant is not terminally consumed by a claim the gate cannot verify");
});

/**
 * ── THIS TEST ALSO CERTIFIED A DEFECT, AND IT WAS MINE ─────────────────────────────────────────
 *
 * The first version of the C-04 fix (b92d517) asserted here that an `UNUSED` grant STILL signs a
 * determinate FAILED_BEFORE_DISPATCH, on the reasoning that "the F8a CAS never ran, so the gate
 * never authorized a dispatch". Adversarial review falsified the premise: `decide()` issues a
 * gate-SIGNED ExecutionGrant and `holdView()` hands it to the agent while the record is still
 * `UNUSED`. The authorization IS the signed grant; `reserve()` is only the single-use burn, and it
 * is a voluntary call the executing party alone decides whether to make.
 *
 * So the fix had RELOCATED C-04 and made it cheaper: an agent holding the signed grant could
 * execute out of band, skip `reserve()` entirely, and collect the same signed "it did not run" with
 * one fewer HTTP call than the original attack. The line the first fix deleted — the `UNUSED` 409 —
 * was the only thing that had been blocking it.
 *
 * INVERTED, not deleted, for the same reason as the test above: so there is a standing mechanical
 * objection if anyone restores it.
 */
test("C-04: an UNUSED grant signs NOTHING — the gate authorized at decide(), so reserve() is not an observation", () => {
  const fx = setupGate({ approverRole: "approve-high" });
  const grantId = approveAndGrant(fx, "chain-fail-unused");
  assert.equal(fx.engine.getGrant(grantId)!.status, "UNUSED");

  // The agent already holds the gate's SIGNED authorization at this point — that is the premise
  // the old assertion got wrong, so it is asserted here rather than assumed.
  const grant = fx.engine.getGrant(grantId)!.grant;
  assert.equal(typeof grant.sig.value, "string");
  assert.ok(grant.sig.value.length > 0, "the grant is signed and released BEFORE any reservation");

  const r = fx.engine.report(grantId, body({ result: "FAILED_BEFORE_DISPATCH" }), fx.agent);

  assert.equal(r.status, 409, "no state of this method observes non-dispatch, so none may sign a determinate negative");
  assert.equal((r.body as { error: string }).error, "GRANT_NOT_RESERVED");
  const rec = fx.engine.getGrant(grantId)!;
  assert.equal(rec.consumption, null, "nothing is signed");
  assert.equal(rec.status, "UNUSED", "and the grant is not consumed by a report the gate cannot act on");
});

/**
 * NOT AN OVER-CORRECTION — the determinate negative survives where it is genuinely observed.
 * `guard()` refuses BEFORE calling `execute()` on every pre-dispatch path (deny, expiry,
 * cancellation, params mismatch, a lost reserve race) and reports `ran: false`. There the
 * non-dispatch is observed by someone other than the tool: the wrapper never invoked it. That half
 * is enumerated in packages/gate/test/no-tool-claim-is-retry-safe.test.ts; this asserts the
 * boundary from the engine's side, so the two cannot drift apart.
 */
test("C-04 did not over-correct: a caller that never reserved is refused, not silently accepted", () => {
  const fx = setupGate({ approverRole: "approve-high" });
  for (const result of ["DISPATCHED", "FAILED_BEFORE_DISPATCH", "UNKNOWN"] as const) {
    const grantId = approveAndGrant(fx, `chain-nores-${result}`, `idem-nores-${result}`);
    const r = fx.engine.report(grantId, body({ result }), fx.agent);
    assert.equal(r.status, 409, `${result} on an UNUSED grant must be refused`);
    assert.equal((r.body as { error: string }).error, "GRANT_NOT_RESERVED");
    assert.equal(fx.engine.getGrant(grantId)!.consumption, null, "and must sign nothing");
  }
});

/**
 * NC-2.7 — found by adversarially probing the C-04 fix, and it is NOT a C-04 regression.
 *
 * Two holds may legitimately exist for the same action and the same `paramsHash` on one chain —
 * that is what retrying a genuinely-failed action looks like. So an attacker can dispatch
 * invocation A and then, entirely honestly, obtain a determinate signed FAILED receipt for a
 * SECOND invocation B that was refused before reservation. Every statement the gate makes is true:
 * B's grant never left UNUSED.
 *
 * The residual risk is CORRELATION, not epistemics: a consumer that aggregates terminal verdicts by
 * `action.canonical` + `action.paramsHash` conflates A and B and can read "this action failed" while
 * A was dispatched. This test pins the property that makes the confusion AVOIDABLE — the artifacts
 * must stay distinguishable by their grant binding. If a future change stopped binding `grantHash`,
 * the non-claim would silently become unfixable-at-the-consumer, and this fails.
 */
test("NC-2.7: two invocations of the SAME action stay distinguishable by grant binding, not by action fields", () => {
  const fx = setupGate({ approverRole: "approve-high" });
  const grantA = approveAndGrant(fx, "chain-corr", "idem-A");
  assert.equal(fx.engine.reserve(grantA, fx.agent).status, 200, "A is dispatched");

  // A DISTINCT idempotency key — the gate correctly collapses a repeat of the same key onto one
  // hold, so the realistic case is a caller that simply submits a new request.
  const grantB = approveAndGrant(fx, "chain-corr", "idem-B");
  assert.notEqual(grantB, grantA, "a second hold yields its own grant");
  assert.equal(fx.engine.reserve(grantB, fx.agent).status, 200);
  const rB = fx.engine.report(grantB, body({ result: "DISPATCHED" }), fx.agent);
  assert.equal(rB.status, 200);

  const resBody = rB.body as { consumption: Record<string, unknown>; attemptReceipt: Record<string, unknown> };
  const recA = fx.engine.getGrant(grantA)!;
  const recB = fx.engine.getGrant(grantB)!;

  // A is untouched: B's terminal artifact says nothing about A.
  assert.equal(recA.status, "RESERVED", "the first invocation is NOT resolved by the second's report");
  assert.equal(recA.consumption, null, "no consumption is signed for the first invocation");

  // THE PINNED PROPERTY: the artifacts are separable by their grant binding. The action fields are
  // identical by construction, so the grant binding is the ONLY thing that keeps two invocations of
  // one action distinguishable to a consumer.
  assert.notEqual(
    resBody.consumption["grantHash"],
    undefined,
    "the consumption MUST bind its grant — without it the two invocations become indistinguishable",
  );
  assert.notEqual(recB.grant.grantId, recA.grant.grantId);
  assert.notEqual(
    (resBody.attemptReceipt["chain"] as { seq: number }).seq,
    undefined,
    "the terminal receipt MUST carry a chain position",
  );
});
