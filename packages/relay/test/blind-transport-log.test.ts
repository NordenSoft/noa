/**
 * BLIND TRANSPORT, THE SURFACES NOBODY PINNED — the operational log and the lifecycle projection.
 *
 * Blind transport (commit 127ff8b, extended by 5cfc796) says the relay may report THAT a decision
 * arrived and never WHAT it was: the relay's keyring has no root, so a verdict in its own voice is
 * indistinguishable from a real one to any reader who does not re-verify the signed receipt.
 *
 * Four PUBLISHED surfaces were narrowed and each got a test. Two more sites carried the same
 * information and got nothing:
 *
 *   1. `this.log("hold.decided", { status: hold.status })` and its rejection twin. `makeHarness`
 *      passed no `log` at all, so the sink was a no-op and there was no way to assert on it even if
 *      someone had wanted to. A rule that holds only on the routes somebody remembered to check is a
 *      habit, not a control.
 *
 *   2. The projection itself, written out by hand at four sites — and one copy had already drifted.
 *      The `409` refusal spelled it `status === "EXPIRED" ? "EXPIRED" : "DECIDED"`, so a
 *      `CANCELLED_LOCAL_STATE_LOST` hold published `DECIDED` there while `holdView` published
 *      `CANCELLED_LOCAL_STATE_LOST` for the identical record. Two routes, one hold, two answers, and
 *      a client told a decision exists when local state was lost and no human ever decided.
 *
 * HONEST SCOPE. The log is NOT a wire leak and this file does not claim it is: nothing in this
 * repository consumes those events and they never reach an HTTP response. The finding that called it
 * "a fifth verdict leak" overstated the reach, and it was downgraded on that measurement. What is
 * real is authorship — the relay writing "APPROVED" in its own voice into a stream an operator or a
 * compliance pipeline may read as an approval record. `gate/src/engine.ts:815` writes the identical
 * field and is entirely correct to; the gate holds the keys and signs that verdict. Same field, same
 * value, different entitlement.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { makeHarness, makeAgent, makeDevice, signDecisionReceipt, bodyOf, PARAMS_HASH } from "./helpers.js";

const ACTION = { canonical: "wire.transfer", riskClass: "CRITICAL", paramsHash: PARAMS_HASH };
const VERDICT_WORDS = ["APPROVED", "DENIED", "HUMAN_APPROVED", "HUMAN_DENIED"];

/** One decided hold, with the log captured. `verdict` chooses which human answer is signed. */
function decided(verdict: "ALLOWED" | "BLOCKED") {
  const h = makeHarness();
  const cust = makeAgent(h, "customer-agent");
  const dev = makeDevice(h, cust.agent, "approver", 7);
  const { holdId } = bodyOf<{ holdId: string }>(h.engine.createHold(cust.agent, "idem-1", { action: ACTION }));
  const receipt = signDecisionReceipt({
    kid: dev.kid, privateKey: dev.privateKey,
    canonical: ACTION.canonical, paramsHash: ACTION.paramsHash, verdict,
  });
  const res = h.engine.decide(dev.device, holdId, { receipt });
  return { h, cust, dev, holdId, res };
}

/** Every log field, flattened to one string — so a verdict cannot hide in a field nobody named. */
function logText(h: ReturnType<typeof makeHarness>): string {
  let s = "";
  for (const e of h.logs) s += `${e.event} ${JSON.stringify(e.fields)}\n`;
  return s;
}

test("the relay's own log never records the human's verdict in the relay's voice", () => {
  for (const verdict of ["ALLOWED", "BLOCKED"] as const) {
    const { h, res } = decided(verdict);
    assert.equal(res.status, 200, "precondition: the honest decision must be accepted");

    const decidedEvents = h.logs.filter((e) => e.event === "hold.decided");
    assert.equal(decidedEvents.length, 1, "precondition: exactly one hold.decided must have been emitted");
    const fields = decidedEvents[0]!.fields;

    // The relay's own state machine is UNCHANGED and is still asserted directly against the store —
    // narrowing the published surface was never meant to make the relay forget.
    assert.equal(h.store.getHold(String(fields["holdId"]))!.status, verdict === "ALLOWED" ? "APPROVED" : "DENIED",
      "the internal state machine must still hold the real status");

    assert.equal(fields["lifecycle"], "DECIDED", "the log must report the lifecycle the relay owns");
    assert.equal(fields["status"], undefined, "`status` is the relay asserting a verdict it cannot author");
    assert.equal(fields["reasonCode"], undefined, "`reasonCode` is the same overreach under another name");

    // What the relay OBSERVED is allowed and wanted: a receipt arrived, its verdict field said this,
    // this kid signed it. That is a pointer to evidence, not a substitute for it — which is why the
    // signer kid must be present. Without it the line is an unattributable assertion again.
    assert.equal(fields["receiptVerdict"], verdict, "the observed receipt verdict must survive for diagnosis");
    assert.equal(typeof fields["signerKid"], "string", "an observation must name whose signature it observed");
    assert.ok(String(fields["signerKid"]).length > 0, "signerKid must not be empty");

    // ANTI-VACUITY. The words really are absent from the WHOLE log, not merely from the fields this
    // test happened to name — and the same words are present in the store, so their absence above is
    // a property of the log and not of the run.
    const text = logText(h);
    for (const w of VERDICT_WORDS) {
      assert.ok(!text.includes(w), `the relay logged "${w}" in its own voice:\n${text}`);
    }
    assert.ok(h.logs.length >= 2, `precondition: the log must actually contain events (got ${h.logs.length})`);
  }
});

test("a re-decide is refused without the relay naming what was decided, on the wire AND in the log", () => {
  const { h, dev, holdId } = decided("ALLOWED");

  const second = signDecisionReceipt({
    kid: dev.kid, privateKey: dev.privateKey,
    canonical: ACTION.canonical, paramsHash: ACTION.paramsHash, verdict: "BLOCKED",
  });
  const res = h.engine.decide(dev.device, holdId, { receipt: second });

  assert.equal(res.status, 409, "a second decision must be refused, never silently dropped");
  const body = res.body as Record<string, unknown>;
  assert.equal(body["error"], "HOLD_ALREADY_RESOLVED");
  assert.equal(body["lifecycle"], "DECIDED");
  assert.equal(body["status"], undefined, "the 409 body must not carry the verdict");

  const rejected = h.logs.filter((e) => e.event === "hold.decision_rejected");
  assert.equal(rejected.length, 1, "precondition: the refusal must have been logged");
  assert.equal(rejected[0]!.fields["currentStatus"], undefined, "the refusal log must not name the verdict");
  assert.equal(rejected[0]!.fields["currentLifecycle"], "DECIDED");
  // The one distinction an operator genuinely needs out of this line, kept without a verdict:
  // "already decided, evidence is on file" versus "expired with nothing on file".
  assert.equal(rejected[0]!.fields["hasDecisionReceipt"], true);

  const text = logText(h);
  for (const w of VERDICT_WORDS) {
    assert.ok(!text.includes(w), `the refusal path logged "${w}":\n${text}`);
  }
});

test("one hold has ONE lifecycle — the 409 and holdView cannot disagree about a lost-state hold", () => {
  const h = makeHarness();
  const cust = makeAgent(h, "customer-agent");
  const dev = makeDevice(h, cust.agent, "approver", 7);
  const { holdId } = bodyOf<{ holdId: string }>(h.engine.createHold(cust.agent, "idem-1", { action: ACTION }));

  // CANCELLED_LOCAL_STATE_LOST: terminal, not PENDING, and NOT a decision. This is the state the two
  // hand-written copies of the projection disagreed about.
  const hold = h.store.getHold(holdId)!;
  hold.status = "CANCELLED_LOCAL_STATE_LOST";
  h.store.putHold(hold);

  const view = bodyOf<{ lifecycle: string }>(h.engine.getHold(cust.agent, holdId));

  const late = signDecisionReceipt({
    kid: dev.kid, privateKey: dev.privateKey,
    canonical: ACTION.canonical, paramsHash: ACTION.paramsHash, verdict: "ALLOWED",
  });
  const refusal = h.engine.decide(dev.device, holdId, { receipt: late });
  assert.equal(refusal.status, 409, "precondition: a decision on a lost-state hold must be refused");
  const refusalLifecycle = (refusal.body as Record<string, unknown>)["lifecycle"];

  assert.equal(view.lifecycle, "CANCELLED_LOCAL_STATE_LOST",
    "the read route must report the relay's own operational state, which is not a decision");
  assert.equal(refusalLifecycle, view.lifecycle,
    "two routes reported different lifecycles for the SAME hold — the 409 said a decision exists when none was made");

  // ANTI-VACUITY: the projection is not simply an identity function. A genuinely decided hold still
  // collapses APPROVED to DECIDED on both routes, which is the property blind transport bought.
  const { h: h2, holdId: id2, cust: cust2 } = decided("ALLOWED");
  assert.equal(h2.store.getHold(id2)!.status, "APPROVED");
  assert.equal(bodyOf<{ lifecycle: string }>(h2.engine.getHold(cust2.agent, id2)).lifecycle, "DECIDED");
});
