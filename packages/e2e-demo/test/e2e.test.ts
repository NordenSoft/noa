/**
 * The 5 end-to-end golden-demo scenarios (D3 directive), all deterministic + 0-fail:
 *   (a) happy path      → EXECUTED · verify-evidence VALID_FULL_CHAIN · verifyChain VALID
 *   (b) REDDET (deny)   → the action never ran, and the DENIED bundle still verifies
 *   (c) timeout         → a POLICY-signed BLOCKED (approval-timeout) receipt
 *   (d) tampered decision → the gate rejects it (hold stays PENDING, no grant)
 *   (e) params mismatch → the exact-execution wrapper refuses (approve A, run B is impossible)
 *
 * Each scenario stands up its own freshly-paired gate + relay on loopback and tears them down.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { verifyChain } from 'noa-receipt';
import { createLogger } from '../src/log.js';
import {
  setupHarness,
  teardownHarness,
  runApprovedFlow,
  runTimeoutFlow,
  runTamperFlow,
  runParamsMismatchProbe,
} from '../src/harness.js';

test('(a) happy path: agent → gate → relay → phone(approve) → gate → EXECUTED; evidence + chain VALID', async () => {
  const ctx = await setupHarness({ echo: false });
  try {
    const r = await runApprovedFlow(ctx, 'APPROVE');
    assert.equal(r.guardResult.outcome, 'EXECUTED', 'guard executed the approved action');
    assert.equal(r.executeSpy.ran, true, 'the harmless side effect ran');
    assert.equal(r.verdict.verdict, 'VALID_FULL_CHAIN', `verify-evidence: ${r.verdict.verdict} (${r.verdict.reason ?? ''})`);
    assert.equal(r.verdict.outcome, 'EXECUTED');

    const vc = verifyChain([r.artifacts.deferredReceipt, r.artifacts.allowedReceipt, r.artifacts.executedReceipt] as never[], {
      keyring: ctx.trust.receiptKeyring,
      requireTenantConsistency: true,
    });
    assert.equal(vc.status, 'VALID', `verifyChain: ${vc.status}`);
    assert.equal(vc.count, 3);
    // Evidence for the report:
    console.log('  (a) evidence=%o chain=%o durMs=%d', { verdict: r.verdict.verdict, outcome: r.verdict.outcome }, { status: vc.status, count: vc.count }, r.elapsedMs);
  } finally {
    await teardownHarness(ctx);
  }
});

test('(b) REDDET: the phone denies → the action never runs, and the DENIED bundle verifies', async () => {
  const ctx = await setupHarness({ echo: false });
  try {
    const r = await runApprovedFlow(ctx, 'DENY');
    assert.equal(r.guardResult.outcome, 'DENIED', 'guard reports DENIED');
    assert.equal(r.executeSpy.ran, false, 'the side effect NEVER ran (proven)');
    assert.equal(r.executeSpy.calls, 0, 'execute was never even called');
    assert.equal(r.gateHoldId ? ctx.gate.store.getHold(r.gateHoldId)?.grantId : 'x', null, 'no Execution Grant was issued on a denial');
    assert.equal(r.verdict.verdict, 'VALID_FULL_CHAIN', `verify-evidence(DENIED): ${r.verdict.verdict} (${r.verdict.reason ?? ''})`);
    assert.equal(r.verdict.outcome, 'DENIED');
    console.log('  (b) evidence=%o ran=%o', { verdict: r.verdict.verdict, outcome: r.verdict.outcome }, r.executeSpy.ran);
  } finally {
    await teardownHarness(ctx);
  }
});

test('(c) timeout: no decision → gate mints a POLICY-signed BLOCKED approval-timeout receipt (verifyChain VALID)', async () => {
  const ctx = await setupHarness({ echo: false });
  try {
    const r = await runTimeoutFlow(ctx);
    const gov = r.timeoutReceipt.governance as { verdict: string; ruleId?: string };
    const agent = r.timeoutReceipt.agent as { principal: string };
    // Directive requirement: the POLICY-signed BLOCKED approval-timeout receipt.
    assert.equal(r.outcome, 'EXPIRED');
    assert.equal(gov.verdict, 'BLOCKED', 'timeout verdict is BLOCKED (never ALLOWED)');
    assert.equal(gov.ruleId, 'approval-timeout', 'ruleId is approval-timeout (not a human denial)');
    assert.equal(agent.principal, 'POLICY', 'signed by the POLICY principal, never a human key');

    // Cryptographic proof: the timeout receipt is a valid gate-signed extension of the DEFERRED chain.
    const vc = verifyChain([r.deferredReceipt, r.timeoutReceipt] as never[], { keyring: ctx.trust.receiptKeyring, requireTenantConsistency: true });
    assert.equal(vc.status, 'VALID', `verifyChain([DEFERRED, timeout]): ${vc.status}`);
    assert.equal(vc.count, 2);

    // HONEST observed property (surfaced, not hidden): the §13 verifier enforces Hold-Envelope
    // freshness (steps.ts:219 `expiresAt > now`). A timed-out hold's envelope is, by definition, past
    // its expiry at verify time, so the post-expiry EXPIRED bundle is deterministically rejected at
    // STEP_1_HOLD_ENVELOPE — the verifier correctly refuses to treat a stale-envelope bundle as fresh.
    assert.equal(r.verdict.verdict, 'INVALID', 'post-expiry EXPIRED bundle is INVALID by envelope-freshness rule');
    assert.equal(r.verdict.failedStep, 'STEP_1_HOLD_ENVELOPE', 'rejection is the named envelope-freshness step');
    console.log('  (c) timeout=%o verifyChain=%o evidence(freshness)=%o', { verdict: gov.verdict, ruleId: gov.ruleId, principal: agent.principal }, { status: vc.status, count: vc.count }, { verdict: r.verdict.verdict, step: r.verdict.failedStep });
  } finally {
    await teardownHarness(ctx);
  }
});

test('(d) tampered decision: the gate D18 re-verification rejects it; hold stays PENDING, no grant', async () => {
  const ctx = await setupHarness({ echo: false });
  try {
    const r = await runTamperFlow(ctx);
    assert.equal(r.gateStatus, 422, `gate rejects the tampered decision (got ${r.gateStatus}: ${JSON.stringify(r.gateBody)})`);
    assert.equal(r.holdStatusAfter, 'PENDING', 'the hold is NOT resolved by a tampered decision');
    assert.equal(r.grantIdAfter, null, 'no Execution Grant is issued for a tampered decision');
    console.log('  (d) gateStatus=%d error=%o holdAfter=%s', r.gateStatus, r.gateBody?.['error'], r.holdStatusAfter);
  } finally {
    await teardownHarness(ctx);
  }
});

test('(e) params mismatch: the exact-execution wrapper refuses (approve A, run B is impossible)', async () => {
  const logger = createLogger({ scope: 'test-e', echo: false });
  const r = await runParamsMismatchProbe(logger);
  assert.equal(r.guardResult.outcome, 'REFUSED_PARAMS_MISMATCH', `wrapper refuses the mismatch (got ${r.guardResult.outcome})`);
  assert.equal(r.guardResult.ran, false, 'the action did NOT run');
  assert.equal(r.executeSpy.ran, false, 'the side effect NEVER ran');
  assert.equal(r.reserveCalled, false, 'the grant was NEVER reserved (refusal is strictly pre-dispatch)');
  console.log('  (e) outcome=%s ran=%o reserved=%o', r.guardResult.outcome, r.executeSpy.ran, r.reserveCalled);
});
