/**
 * P1-4 / R8-14 — A DECISION MUST BIND TO **THIS** HOLD, NOT MERELY TO THE SAME ACTION.
 *
 * ─── THE DEFECT ─────────────────────────────────────────────────────────────────────────────────
 *
 * `engine.ts` bound a decision to a hold on `(canonical, paramsHash)` alone. Two holds for the same
 * action carry the same pair, so a signed approval for hold A is accepted verbatim on hold B: same
 * signature, same registered device, same verdict. The relay records hold B as APPROVED by a human
 * who was never shown hold B.
 *
 * ⚠ SEVERITY, STATED HONESTLY: **the GATE refuses this** — its own decide path binds on the
 * deferred-receipt chain — so no execution grant is forged and no money moves. What breaks is that
 * **the relay's record can show an approval the gate rejected.** A relay record is what an operator
 * reads during an incident, so a false APPROVED there is a false answer to "did a human agree to
 * this", even when nothing executed.
 *
 * ⚠ AND NOT EVERY HOLD IS A GATE HOLD — that correction is the reason this file has two classes.
 * An earlier draft of this header assumed every hold carries a deferred receipt, so the rule it
 * described required one on every decide. `deferredReceipt` is OPTIONAL in the published contract
 * (`README.md:62`) and the **third gate** relies on that: curl/python/cron agents post a bare
 * `{action}` hold and a headless approver decides it with an UNCHAINED receipt — documented at
 * `packages/e2e-demo/examples/http-agent/run-local-stack.mjs:13-14`, decided with `null` as the
 * previous receipt at `:153`. Requiring the receipt would have deleted a shipped surface (KURAL 16),
 * not narrowed a contract.
 *
 * Binding only WHEN a receipt happens to be present is the opposite failure: any authenticated agent
 * can open a bare hold, so the adversary declines the guard by omitting the field.
 *
 * **The rule is therefore SYMMETRIC BY CLASS, and the class is fixed at creation:** a chained hold
 * takes only a decision chained onto exactly its own deferred receipt; a bare hold takes only an
 * unchained decision. Crossing classes is refused in both directions, which is what stops a captured
 * phone approval from landing on an attacker's bare hold.
 *
 * ─── THE BINDING ALREADY EXISTS IN THE ARTIFACT — NOTHING NEW GOES ON THE WIRE ───────────────────
 *
 * Measured before touching the engine, because the previous item in this workstream was a rule that
 * contradicted the frozen spec and had to be reverted:
 *
 *   noa-mobile/src/transport/decision.ts:82-83
 *       buildApprovalReceipt(receiptInput, deferredReceipt, signer)
 *       buildDenialReceipt(receiptInput, deferredReceipt, signer)
 *
 * **The shipping phone already chains its decision receipt onto the hold's deferred receipt**, so
 * `chain.prevHash` is present in what a real client sends today. The relay can require it with NO
 * client change, no format change, and no new field.
 *
 * What did NOT chain was this package's own test helper (`prev = null`, a genesis receipt) — the
 * fixture had drifted from the client it stands in for, which is why the gap was invisible here.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { buildReceipt, type Receipt } from "noa-signer";
import { safeRefHash } from "../src/crypto.js";
import { makeHarness, makeAgent, makeDevice, bodyOf, PARAMS_HASH } from "./helpers.js";

const ACTION = { canonical: "wire.transfer", riskClass: "CRITICAL" as const, paramsHash: PARAMS_HASH };

/** A decision receipt CHAINED onto a specific deferred receipt — what the shipping phone produces. */
function signChainedDecision(
  d: { kid: string; privateKey: string },
  deferred: Receipt,
  verdict: "ALLOWED" | "BLOCKED",
): Receipt {
  const ts = "2026-07-14T12:00:00.000Z";
  return buildReceipt(
    {
      id: `verdict-${deferred.id}`,
      ts,
      scope: deferred.scope,
      agent: { id: "approver-device", model: null, principal: "HUMAN" },
      action: deferred.action,
      governance: { mode: "approvals_on", verdict, sandboxed: false, approval: { by: d.kid, at: ts } },
    },
    deferred,
    { kid: d.kid, privateKey: d.privateKey },
  );
}

/** Open a hold WITH a deferred receipt.
 *
 *  ⚠ THE RELAY DOES NOT MINT THE DEFERRED RECEIPT — the gate does, and posts it with the hold
 *  (`engine.ts:368` reads it from the request body). The relay is a transport. A first version of this
 *  fixture called `createHold({ action })` alone and every test failed on a null deferred receipt,
 *  INCLUDING the control — which is what stopped me from reading the attack results as evidence. */
function openHold(
  h: ReturnType<typeof makeHarness>,
  agent: ReturnType<typeof makeAgent>,
  dev: { kid: string; privateKey: string },
  idem: string,
) {
  const ts = `2026-07-14T1${idem.length % 9}:00:00.000Z`;
  const deferred = buildReceipt(
    {
      id: `deferred-${idem}`,
      ts,
      scope: { chain: `chain-${idem}` },
      agent: { id: "agent-1", model: null, principal: "SERVICE" },
      action: { id: "act-1", ...ACTION, reversible: false, rollbackRef: null },
      governance: { mode: "approvals_on", verdict: "DEFERRED", sandboxed: false },
    },
    null,
    { kid: dev.kid, privateKey: dev.privateKey },
  );
  const created = h.engine.createHold(agent.agent, idem, { action: ACTION, deferredReceipt: deferred });
  const { holdId } = bodyOf<{ holdId: string }>(created);
  assert.ok(holdId, `fixture: createHold failed — ${JSON.stringify(created.body)}`);
  return { holdId, deferred };
}

/** CONTROL FIRST — every assertion below is a refusal, and a harness that refuses everything would
 *  satisfy all of them. This is also the outage guard: the legitimate path must keep working. */
test("CONTROL — a decision chained onto ITS OWN hold is ACCEPTED (the honest path must not break)", () => {
  const h = makeHarness();
  const cust = makeAgent(h, "customer", "tenant-a");
  const dev = makeDevice(h, cust.agent);
  const { holdId, deferred } = openHold(h, cust, dev, "idem-honest");

  const res = h.engine.decide(dev.device, holdId, { receipt: signChainedDecision(dev, deferred, "ALLOWED") });
  assert.equal(res.status, 200, `the legitimate decision was refused: ${JSON.stringify(res.body)}`);
  assert.equal(h.store.getHold(holdId)!.status, "APPROVED");
});

test("CONTROL — a RETRY of the same decision on the same hold is not broken by the binding", () => {
  // Ship this or the fix is an outage: a phone that resends after a dropped response must not be
  // told its own approval belongs to a different hold. First-wins concurrency (D17) may answer 409
  // HOLD_ALREADY_RESOLVED, which is the correct duplicate answer — what it must NEVER be is
  // ACTION_BINDING_MISMATCH, because that would blame the binding for an ordinary retry.
  const h = makeHarness();
  const cust = makeAgent(h, "customer", "tenant-a");
  const dev = makeDevice(h, cust.agent);
  const { holdId, deferred } = openHold(h, cust, dev, "idem-retry");
  const receipt = signChainedDecision(dev, deferred, "ALLOWED");

  assert.equal(h.engine.decide(dev.device, holdId, { receipt }).status, 200);
  const again = h.engine.decide(dev.device, holdId, { receipt });
  assert.notEqual((again.body as { error?: string }).error, "ACTION_BINDING_MISMATCH",
    "an ordinary retry was rejected as a binding mismatch — the fix would be an outage");
});

test("R8-14: an approval signed for hold A is REFUSED on hold B, same action, same device", () => {
  const h = makeHarness();
  const cust = makeAgent(h, "customer", "tenant-a");
  const dev = makeDevice(h, cust.agent);

  const a = openHold(h, cust, dev, "idem-hold-a");
  const b = openHold(h, cust, dev, "idem-hold-b");
  assert.notEqual(a.holdId, b.holdId, "fixture precondition: two DISTINCT holds");
  assert.equal(
    safeRefHash(a.deferred as unknown as Record<string, unknown>) !==
      safeRefHash(b.deferred as unknown as Record<string, unknown>),
    true,
    "fixture precondition: the two holds have DIFFERENT deferred receipts, or there is nothing to bind to",
  );

  // A genuine, correctly-signed approval — for hold A.
  const forHoldA = signChainedDecision(dev, a.deferred, "ALLOWED");

  const replayed = h.engine.decide(dev.device, b.holdId, { receipt: forHoldA });
  assert.notEqual(replayed.status, 200,
    "a human's approval of hold A was recorded as an approval of hold B. The signature, the device " +
      "and the verdict are all genuine; only the QUESTION is different. The gate refuses this, so no " +
      "grant is forged — but the relay's record now answers 'did a human agree to THIS' with a yes " +
      "that never happened.");
  assert.equal((replayed.body as { error?: string }).error, "ACTION_BINDING_MISMATCH",
    `the refusal must name the binding (got ${JSON.stringify(replayed.body)})`);
  assert.equal(h.store.getHold(b.holdId)!.status, "PENDING", "hold B must be untouched by the refused replay");
});

test("R8-14: an unchained decision is refused ON A CHAINED HOLD — the phone always chains", () => {
  // ⚠ SCOPE CORRECTED. This test once claimed "an unchained decision cannot be bound to any hold at
  // all". That is false: on a BARE hold an unchained decision is the ONLY correct answer (see the
  // third-gate control below). The claim is true only of a hold that carries a deferred receipt —
  // which is what this test builds. The shipping phone always chains (measured:
  // noa-mobile/src/transport/decision.ts:82-83 passes the deferred receipt), so on a chained hold an
  // unchained decision cannot be bound to anything, and accepting one would make the binding
  // optional in practice.
  const h = makeHarness();
  const cust = makeAgent(h, "customer", "tenant-a");
  const dev = makeDevice(h, cust.agent);
  const { holdId, deferred } = openHold(h, cust, dev, "idem-unchained");

  const ts = "2026-07-14T12:00:00.000Z";
  const unchained = buildReceipt(
    {
      id: "verdict-unchained",
      ts,
      scope: deferred.scope,
      agent: { id: "approver-device", model: null, principal: "HUMAN" },
      action: deferred.action,
      governance: { mode: "approvals_on", verdict: "ALLOWED", sandboxed: false, approval: { by: dev.kid, at: ts } },
    },
    null,
    { kid: dev.kid, privateKey: dev.privateKey },
  );

  const res = h.engine.decide(dev.device, holdId, { receipt: unchained });
  assert.notEqual(res.status, 200, "an unbindable decision was accepted");
  assert.equal((res.body as { error?: string }).error, "ACTION_BINDING_MISMATCH");
});

/* ─── THE BARE CLASS — the third gate ──────────────────────────────────────────────────────────
 *
 * Everything above is about holds the GATE opened. These four are about the other shipped surface:
 * a curl/python/cron agent posting a bare `{action}` hold, decided by a headless approver with an
 * unchained receipt. It has no deferred receipt to chain onto, and that is not a degenerate case —
 * it is a documented flow (`run-local-stack.mjs:13-14`). The first test here is the outage guard for
 * it, and it is the reason the rule is symmetric rather than "a receipt is mandatory".
 */

/** Open a hold the way the third gate does: bare `{action}`, no envelope, no deferred receipt. */
function openBareHold(
  h: ReturnType<typeof makeHarness>,
  agent: ReturnType<typeof makeAgent>,
  idem: string,
) {
  const created = h.engine.createHold(agent.agent, idem, { action: ACTION });
  const { holdId } = bodyOf<{ holdId: string }>(created);
  assert.ok(holdId, `fixture: bare createHold failed — ${JSON.stringify(created.body)}`);
  return holdId;
}

/** An UNCHAINED decision — what `run-local-stack.mjs:153` signs (`null` as the previous receipt). */
function signUnchainedDecision(d: { kid: string; privateKey: string }, verdict: "ALLOWED" | "BLOCKED"): Receipt {
  const ts = "2026-07-14T12:00:00.000Z";
  return buildReceipt(
    {
      id: "verdict-bare",
      ts,
      scope: { chain: "chain-bare" },
      agent: { id: "approver-human-1", model: null, principal: "HUMAN" },
      action: { id: "act-bare", ...ACTION, reversible: false, rollbackRef: null },
      governance: { mode: "approvals_on", verdict, sandboxed: false, approval: { by: d.kid, at: ts } },
    },
    null,
    { kid: d.kid, privateKey: d.privateKey },
  );
}

test("CONTROL — a BARE hold accepts an UNCHAINED decision (the third gate must keep working)", () => {
  // THE OUTAGE GUARD. A first version of this rule required a deferred receipt on every decide, which
  // would have silently deleted this entire flow — every curl/python/cron agent would have received
  // 422 on a correct approval. Requiring the receipt was not a contract narrowing, it was a feature
  // deletion, and this control is what makes that impossible to ship again.
  const h = makeHarness();
  const cust = makeAgent(h, "customer", "tenant-a");
  const dev = makeDevice(h, cust.agent);
  const holdId = openBareHold(h, cust, "idem-bare-honest");

  const res = h.engine.decide(dev.device, holdId, { receipt: signUnchainedDecision(dev, "ALLOWED") });
  assert.equal(res.status, 200, `the third gate's legitimate decision was refused: ${JSON.stringify(res.body)}`);
  assert.equal(h.store.getHold(holdId)!.status, "APPROVED");
});

test("R8-14: a CHAINED decision is refused on a BARE hold — classes do not cross", () => {
  // The direction that makes the rule a rule rather than a preference. Without it, an attacker who
  // can open a bare hold accepts any captured phone approval on it: the hold has nothing to bind to,
  // so a "bind only when present" check would wave it through. The guard an adversary can decline by
  // omitting a field is not a guard.
  const h = makeHarness();
  const cust = makeAgent(h, "customer", "tenant-a");
  const dev = makeDevice(h, cust.agent);

  const gateHold = openHold(h, cust, dev, "idem-gate-hold");
  const phoneApproval = signChainedDecision(dev, gateHold.deferred, "ALLOWED");
  const bareId = openBareHold(h, cust, "idem-bare-target");

  const res = h.engine.decide(dev.device, bareId, { receipt: phoneApproval });
  assert.notEqual(res.status, 200,
    "a human's approval of a gate-opened hold was accepted on a bare hold the attacker opened");
  assert.equal((res.body as { error?: string }).error, "ACTION_BINDING_MISMATCH");
  assert.equal(h.store.getHold(bareId)!.status, "PENDING");
});

test("R8-14: a hold whose deferred receipt has NO READABLE chain hash refuses ALL decisions", () => {
  // Rule 4 — the unbindable hold, and it is reachable rather than theoretical: `parseReceiptOrNull`
  // (engine.ts:410-413) accepts ANY object whose `spec` is "noa.receipt/0.1" and never looks at
  // `chain` at all, so a hold really can be created carrying a "receipt" with no chain.
  //
  // ⚠ WHAT THIS BRANCH ACTUALLY PROTECTS — measured, not assumed, because the first version of this
  // test KILLED NOTHING. Knocking the branch out left all 9 tests green, which meant the test was
  // decoration. The reason: the fixture used `chain: { prevHash: null }`, where the fall-through
  // comparison `presentedPrev !== drChain.hash` still evaluates (`null !== undefined` → refuse). The
  // *acceptance* corner belongs to the collapsed one-liner form (`expectedPrev === null || ...`),
  // which this engine does NOT use — so repeating that rationale here would have described someone
  // else's code. What the branch really prevents, on the shape below, is a **TypeError**: with
  // `chain` absent, `drChain` is undefined and the fall-through dereferences it. A caller-supplied
  // document that crashes the decide path is its own defect, so the fixture is now the shape that
  // reaches it and the assertion is a CLEAN refusal rather than merely a non-200.
  const h = makeHarness();
  const cust = makeAgent(h, "customer", "tenant-a");
  const dev = makeDevice(h, cust.agent);

  const created = h.engine.createHold(cust.agent, "idem-unreadable", {
    action: ACTION,
    deferredReceipt: { spec: "noa.receipt/0.1", id: "no-chain-at-all" },
  });
  const { holdId } = bodyOf<{ holdId: string }>(created);
  assert.ok(holdId, `fixture: the hold must be CREATED — the refusal under test is at decide time`);

  let res: ReturnType<typeof h.engine.decide>;
  try {
    res = h.engine.decide(dev.device, holdId, { receipt: signUnchainedDecision(dev, "ALLOWED") });
  } catch (e) {
    assert.fail(
      `the decide path THREW on a caller-supplied deferred receipt (${String(e)}). A malformed ` +
        `document must produce a refusal, not an exception — a throw here is reachable by any ` +
        `authenticated agent and takes the route down instead of turning the decision away.`,
    );
  }
  assert.notEqual(res.status, 200, "an unbindable hold accepted a decision as if it were bare");
  assert.equal((res.body as { error?: string }).error, "ACTION_BINDING_MISMATCH");
});

/* ─── THE BINDING TARGET MUST NOT BE TRANSPLANTABLE ────────────────────────────────────────────── */

test("R8-14: a deferred receipt already used by another hold is REFUSED at creation", () => {
  // The bypass adjacent to the fix. Binding a decision to this hold's deferred receipt buys nothing
  // if the TARGET can be copied: the agent reads hold A's deferred receipt, opens hold B carrying the
  // same one, and A's approval then chains CORRECTLY onto B — the binding passes and the replay
  // succeeds. Same adversary as R8-14 itself.
  const h = makeHarness();
  const cust = makeAgent(h, "customer", "tenant-a");
  const dev = makeDevice(h, cust.agent);
  const a = openHold(h, cust, dev, "idem-original");

  const cloned = h.engine.createHold(cust.agent, "idem-clone", {
    action: ACTION,
    deferredReceipt: a.deferred,
  });
  assert.equal(cloned.status, 409,
    `hold B was created carrying hold A's binding target — A's approval now chains onto B correctly ` +
      `and the decision binding is bypassed (got ${JSON.stringify(cloned.body)})`);
  assert.equal((cloned.body as { error?: string }).error, "DEFERRED_RECEIPT_REUSED");
});

test("CONTROL — an idempotent retry of the SAME hold request is not broken by the reuse guard", () => {
  // Ship this or the guard is an outage: an agent that resends after a dropped response must get its
  // original 200 back, not a 409 telling it that the hold it just created already used this receipt.
  // This is what pins the guard BELOW the idempotency return rather than above it.
  const h = makeHarness();
  const cust = makeAgent(h, "customer", "tenant-a");
  const dev = makeDevice(h, cust.agent);
  const dupIdem = "idem-retry-same-body";
  const first = openHold(h, cust, dev, dupIdem);

  const retry = h.engine.createHold(cust.agent, dupIdem, { action: ACTION, deferredReceipt: first.deferred });
  assert.equal(retry.status, 200, `an honest retry was refused: ${JSON.stringify(retry.body)}`);
  assert.equal(bodyOf<{ holdId: string; idempotent?: boolean }>(retry).holdId, first.holdId,
    "the retry must replay the ORIGINAL hold, not mint a second one");
  assert.equal(bodyOf<{ idempotent?: boolean }>(retry).idempotent, true);
});
