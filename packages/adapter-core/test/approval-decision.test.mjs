import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPair, verifyChain, buildReceipt } from "noa-receipt";
import { preCheck } from "../src/pre-check.mjs";
import { REFUND_GUARD_POLICY } from "../src/policy.mjs";
import { buildApprovalReceipt, buildDenialReceipt, verifyApprovalReceipt } from "../src/approval-decision.mjs";

function makeChainAgentAndApprover(tag) {
  const agentKp = generateKeyPair(`agent-${tag}`);
  const approverKp = generateKeyPair(`approver-${tag}`);
  return {
    agentSigner: { kid: agentKp.kid, privateKey: agentKp.privateKey },
    approverSigner: { kid: approverKp.kid, privateKey: approverKp.privateKey },
    keyring: { [agentKp.kid]: agentKp.publicKey, [approverKp.kid]: approverKp.publicKey },
  };
}

test("buildApprovalReceipt: verdict ALLOWED, governance.approval filled, chained onto DEFERRED (2 different signing agents), verifyChain VALID", () => {
  const { agentSigner, approverSigner, keyring } = makeChainAgentAndApprover("1");
  const approvalRules = [{ id: "big-refund", match: { type: "exact", action: "payment.refund" }, threshold: { path: "amountMinor", op: "ge", value: 4000 } }];
  const { receipt: deferred } = preCheck({ name: "payment.refund", args: { amountMinor: 4200 } }, { signer: agentSigner, policy: REFUND_GUARD_POLICY, approvalRules });
  assert.equal(deferred.governance.verdict, "DEFERRED");

  const { receipt: allowed, ticket, ticketExpiresAt } = buildApprovalReceipt({ deferredReceipt: deferred, by: "HUMAN:jane@acme.example", ts: "2026-07-11T10:05:00.000Z", signer: approverSigner });
  assert.equal(allowed.governance.verdict, "ALLOWED");
  assert.deepEqual(allowed.governance.approval, { by: "HUMAN:jane@acme.example", at: "2026-07-11T10:05:00.000Z" });
  assert.equal(allowed.agent.principal, "HUMAN");
  assert.equal(allowed.chain.seq, deferred.chain.seq + 1);
  assert.equal(allowed.chain.prevHash, deferred.chain.hash);
  assert.ok(ticket.length > 0);
  assert.ok(Date.parse(ticketExpiresAt) > Date.parse("2026-07-11T10:05:00.000Z"));
  assert.equal(verifyChain([deferred, allowed], { keyring }).status, "VALID");
});

test("buildDenialReceipt: verdict BLOCKED, ruleId is the FIXED code 'human-denied' (D8: free-text reason NEVER folded into signed ruleId), approval filled, chained onto DEFERRED", () => {
  const { agentSigner, approverSigner, keyring } = makeChainAgentAndApprover("2");
  const approvalRules = [{ id: "big-refund", match: { type: "exact", action: "payment.refund" }, threshold: { path: "amountMinor", op: "ge", value: 4000 } }];
  const { receipt: deferred } = preCheck({ name: "payment.refund", args: { amountMinor: 4200 } }, { signer: agentSigner, policy: REFUND_GUARD_POLICY, approvalRules });

  // Pass a free-text reason to PROVE it is now ignored (regression guard against the old
  // `human-denied:${reason}` PII/injection leak). `by` here is an already-opaque id (the CLI
  // pseudonymizes the email upstream; this pure builder embeds `by` verbatim).
  const { receipt: denied } = buildDenialReceipt({ deferredReceipt: deferred, by: "HUMAN:hmac-sha256:" + "a".repeat(64), reason: "looks-fraudulent", ts: "2026-07-11T10:05:00.000Z", signer: approverSigner });
  assert.equal(denied.governance.verdict, "BLOCKED");
  assert.equal(denied.governance.ruleId, "human-denied");
  assert.ok(!JSON.stringify(denied).includes("looks-fraudulent"), "free-text reason must never appear in the signed denial receipt");
  assert.deepEqual(denied.governance.approval, { by: "HUMAN:hmac-sha256:" + "a".repeat(64), at: "2026-07-11T10:05:00.000Z" });
  assert.equal(verifyChain([deferred, denied], { keyring }).status, "VALID");
});

test("THE MONEY TEST: DEFERRED -> ALLOWED -> EXECUTED, three receipts, ONE scope.chain, verifyChain VALID end-to-end", () => {
  const { agentSigner, approverSigner, keyring } = makeChainAgentAndApprover("3");
  const approvalRules = [{ id: "big-refund", match: { type: "exact", action: "payment.refund" }, threshold: { path: "amountMinor", op: "ge", value: 4000 } }];

  const { receipt: deferred, decision: d1 } = preCheck({ name: "payment.refund", args: { amountMinor: 4200 } }, { signer: agentSigner, policy: REFUND_GUARD_POLICY, approvalRules });
  assert.equal(d1, "DEFERRED");

  const { receipt: allowed, ticket } = buildApprovalReceipt({ deferredReceipt: deferred, by: "HUMAN:jane@acme.example", ts: "2026-07-11T10:05:00.000Z", signer: approverSigner });
  assert.ok(ticket);

  // This test proves the RECEIPT-LEVEL chain shape the ticket-consumption flow is required to
  // produce; the proxy-level "who actually consumes the ticket and forwards" is proven separately
  // in mcp-proxy's smoke.mjs Scenario R.
  const executed = buildReceipt(
    {
      id: `${deferred.id}-executed`,
      ts: "2026-07-11T10:06:00.000Z",
      scope: deferred.scope,
      agent: deferred.agent,
      action: deferred.action,
      governance: { mode: "on", verdict: "EXECUTED", ruleId: `approval-ticket-consumed:${deferred.governance.ruleId}`, approval: null, sandboxed: false, compliance: deferred.governance.compliance },
    },
    allowed,
    agentSigner,
  );

  const chain = [deferred, allowed, executed];
  // AGENT-LEVEL IDENTITY BINDING (not just kid-level): with only { keyring }, verifyChain's
  // attribution is kid-level — ANY keyring-trusted key may sign for ANY agent.id (see
  // src/verify.ts's identityManifest docs). An identityManifest pins WHO may sign for WHOM:
  // the proxy agent's kid for "mcp-agent" (preCheck's default agent id), the approver's kid for
  // "human-approval-cli" — so a co-trusted key can never impersonate the human approval seat.
  const identityManifest = {
    "mcp-agent": [agentSigner.kid],
    "human-approval-cli": [approverSigner.kid],
  };
  const v = verifyChain(chain, { keyring, identityManifest });
  assert.equal(v.status, "VALID");
  assert.equal(v.count, 3);
  assert.deepEqual(chain.map((r) => r.governance.verdict), ["DEFERRED", "ALLOWED", "EXECUTED"]);
  assert.deepEqual(chain.map((r) => r.chain.seq), [0, 1, 2]);

  // Negative control: a manifest that authorizes the AGENT's kid for the human-approval seat
  // (i.e. the agent forging its own "approval") must be rejected as UNTRUSTED, not VALID.
  const forgedManifest = {
    "mcp-agent": [agentSigner.kid],
    "human-approval-cli": [agentSigner.kid],
  };
  assert.equal(
    verifyChain(chain, { keyring, identityManifest: forgedManifest }).status,
    "UNTRUSTED",
    "the ALLOWED receipt's (agent.id, kid) pairing must be enforced — an unauthorized pairing can never verify VALID",
  );
});

function makeApprovedFixture(tag) {
  const agentKp = generateKeyPair(`agent-${tag}`);
  const approverKp = generateKeyPair(`approver-${tag}`);
  const approvalRules = [{ id: "big-refund", match: { type: "exact", action: "payment.refund" }, threshold: { path: "amountMinor", op: "ge", value: 4000 } }];
  const { receipt: deferred } = preCheck({ name: "payment.refund", args: { amountMinor: 4200 } }, { signer: { kid: agentKp.kid, privateKey: agentKp.privateKey }, policy: REFUND_GUARD_POLICY, approvalRules });
  const { receipt: allowed } = buildApprovalReceipt({ deferredReceipt: deferred, by: "HUMAN:jane@acme.example", ts: "2026-07-11T10:05:00.000Z", signer: { kid: approverKp.kid, privateKey: approverKp.privateKey } });
  return { agentKp, approverKp, deferred, allowed, approverKeyring: { [approverKp.kid]: approverKp.publicKey } };
}

test("verifyApprovalReceipt: a REAL buildApprovalReceipt output verifies ok against the trusted approver keyring (signing-message reconstruction matches noa-receipt's own signer)", () => {
  const { allowed, approverKeyring, deferred } = makeApprovedFixture("v-ok");
  assert.deepEqual(verifyApprovalReceipt(allowed, { approverKeyring, expectedChain: deferred.scope.chain }), { ok: true });
});

test("verifyApprovalReceipt: fails closed on an UNTRUSTED signer (kid not in the approver keyring) — the core forgery defense", () => {
  const { allowed } = makeApprovedFixture("v-untrusted");
  const strangerKp = generateKeyPair("stranger");
  const r = verifyApprovalReceipt(allowed, { approverKeyring: { [strangerKp.kid]: strangerKp.publicKey } });
  assert.equal(r.ok, false);
  assert.match(r.reason, /not in the trusted approver keyring/);
});

test("verifyApprovalReceipt: fails closed when no approver keyring is supplied at all", () => {
  const { allowed } = makeApprovedFixture("v-nokeyring");
  assert.equal(verifyApprovalReceipt(allowed, {}).ok, false);
  assert.equal(verifyApprovalReceipt(allowed).ok, false);
});

test("verifyApprovalReceipt: fails closed on a garbage signature under a TRUSTED kid (tampered sig.value)", () => {
  const { allowed, approverKeyring } = makeApprovedFixture("v-badsig");
  const tampered = { ...allowed, sig: { ...allowed.sig, value: "AAAA-not-a-real-signature-just-garbage-bytes" } };
  const r = verifyApprovalReceipt(tampered, { approverKeyring });
  assert.equal(r.ok, false);
  // A mutated sig.value does not change the content hash, so this fails at the signature step.
  assert.match(r.reason, /invalid approver signature/);
});

test("verifyApprovalReceipt: fails closed on tampered CONTENT (hash no longer matches)", () => {
  const { allowed, approverKeyring } = makeApprovedFixture("v-tamper");
  const tampered = { ...allowed, governance: { ...allowed.governance, approval: { by: "HUMAN:someone-else@evil.invalid", at: allowed.governance.approval.at } } };
  const r = verifyApprovalReceipt(tampered, { approverKeyring });
  assert.equal(r.ok, false);
  assert.match(r.reason, /hash does not match/);
});

test("verifyApprovalReceipt: fails closed when the verdict is not ALLOWED", () => {
  const agentKp = generateKeyPair("v-verdict-agent");
  const approverKp = generateKeyPair("v-verdict-approver");
  const approvalRules = [{ id: "big-refund", match: { type: "exact", action: "payment.refund" }, threshold: { path: "amountMinor", op: "ge", value: 4000 } }];
  const { receipt: deferred } = preCheck({ name: "payment.refund", args: { amountMinor: 4200 } }, { signer: { kid: agentKp.kid, privateKey: agentKp.privateKey }, policy: REFUND_GUARD_POLICY, approvalRules });
  const { receipt: denied } = buildDenialReceipt({ deferredReceipt: deferred, by: "HUMAN:jane@acme.example", reason: "no", ts: "2026-07-11T10:05:00.000Z", signer: { kid: approverKp.kid, privateKey: approverKp.privateKey } });
  const r = verifyApprovalReceipt(denied, { approverKeyring: { [approverKp.kid]: approverKp.publicKey } });
  assert.equal(r.ok, false);
  assert.match(r.reason, /verdict is not ALLOWED/);
});

test("verifyApprovalReceipt: fails closed on a scope.chain that does not match this session's chain", () => {
  const { allowed, approverKeyring } = makeApprovedFixture("v-chain");
  const r = verifyApprovalReceipt(allowed, { approverKeyring, expectedChain: "some-other-session:chain#tok-seg9" });
  assert.equal(r.ok, false);
  assert.match(r.reason, /does not match this session's chain/);
});

test("verifyApprovalReceipt: identityManifest binds the approver seat — an authorized kid passes, an unauthorized one is rejected", () => {
  const { allowed, approverKp, approverKeyring } = makeApprovedFixture("v-manifest");
  // buildApprovalReceipt's default agent.id is "human-approval-cli".
  assert.equal(verifyApprovalReceipt(allowed, { approverKeyring, identityManifest: { "human-approval-cli": [approverKp.kid] } }).ok, true);
  const otherKp = generateKeyPair("v-manifest-other");
  const r = verifyApprovalReceipt(allowed, { approverKeyring, identityManifest: { "human-approval-cli": [otherKp.kid] } });
  assert.equal(r.ok, false);
  assert.match(r.reason, /identity manifest/);
});

test("verifyApprovalReceipt (G1): expectedAction binds the approval to the EXACT held action — a genuine signed approval for a DIFFERENT action.paramsHash (or a different action.id) is refused, the matching one passes", () => {
  const { allowed, approverKeyring } = makeApprovedFixture("v-action-bind");
  // The genuine, validly-signed approval, checked against its OWN action, still verifies ok.
  assert.deepEqual(
    verifyApprovalReceipt(allowed, { approverKeyring, expectedAction: { id: allowed.action.id, paramsHash: allowed.action.paramsHash } }),
    { ok: true },
    "an approval bound to its own action must still pass",
  );
  // Same genuine signature, but the held request's params differ (e.g. a $50 held vs a $1 approved):
  // the approved action.paramsHash no longer equals the held one -> fail-closed.
  const rParams = verifyApprovalReceipt(allowed, { approverKeyring, expectedAction: { id: allowed.action.id, paramsHash: "sha256:" + "9".repeat(64) } });
  assert.equal(rParams.ok, false);
  assert.match(rParams.reason, /different action/);
  // A different action.id (approved a benign tool, held a dangerous one) is likewise refused.
  const rId = verifyApprovalReceipt(allowed, { approverKeyring, expectedAction: { id: "some.other.action", paramsHash: allowed.action.paramsHash } });
  assert.equal(rId.ok, false);
  assert.match(rId.reason, /different action/);
  // A malformed expectedAction fails closed (never silently skips the binding).
  assert.equal(verifyApprovalReceipt(allowed, { approverKeyring, expectedAction: "not-an-object" }).ok, false);
});
