import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { recordDeferred, recordApproved, recordDenied, consumeApprovalTicket, findOutstanding, loadPendingIndex, PendingStoreError } from "../src/pending-store.mjs";

function tmpStorePath() {
  return join(mkdtempSync(join(tmpdir(), "noa-pending-store-test-")), "pending.jsonl");
}

const FAKE_DEFERRED_RECEIPT = {
  id: "rcpt_0",
  ts: "2026-07-11T10:00:00.000Z",
  scope: { tenant: "acme", chain: "acme:mcp" },
  agent: { id: "mcp-agent", model: null, principal: "POLICY" },
  action: { id: "payment.refund", canonical: "payment.refund", riskClass: "HIGH", paramsHash: "sha256:" + "0".repeat(64), reversible: false, rollbackRef: null },
  governance: { mode: "on", verdict: "DEFERRED", ruleId: "approval:big-refund", approval: null, sandboxed: false, compliance: null },
  chain: { seq: 0, prevHash: null, hash: "sha256:" + "1".repeat(64) },
  sig: { alg: "ed25519", kid: "k1", value: "v1" },
};

function seed(path) {
  recordDeferred(path, { deferredReceipt: FAKE_DEFERRED_RECEIPT, tenant: "acme", agentId: "mcp-agent", actionId: "payment.refund", paramsHash: FAKE_DEFERRED_RECEIPT.action.paramsHash });
}

test("recordDeferred + loadPendingIndex + findOutstanding: folds to 'pending', scoped by (tenant,agentId)", () => {
  const path = tmpStorePath();
  seed(path);
  const rec = loadPendingIndex(path).get("rcpt_0");
  assert.equal(rec.status, "pending");
  assert.equal(rec.actionId, "payment.refund");
  assert.equal(findOutstanding(path, { tenant: "acme", agentId: "mcp-agent" })?.id, "rcpt_0");
  assert.equal(findOutstanding(path, { tenant: "acme", agentId: "someone-else" }), null, "different agentId must not see another's outstanding request");
  assert.equal(findOutstanding(path, { tenant: "other-tenant", agentId: "mcp-agent" }), null, "different tenant must not leak");
});

test("recordApproved -> 'approved'; consumeApprovalTicket succeeds ONCE then fails closed on a second call (ticket-repeat -> DENY-shaped error)", () => {
  const path = tmpStorePath();
  seed(path);
  const allowedReceiptStub = { ...FAKE_DEFERRED_RECEIPT, id: "rcpt_0-approved", governance: { ...FAKE_DEFERRED_RECEIPT.governance, verdict: "ALLOWED" } };
  recordApproved(path, { id: "rcpt_0", by: "HUMAN:jane@acme.example", ticketExpiresAt: "2099-01-01T00:00:00.000Z", allowedReceipt: allowedReceiptStub });
  assert.equal(loadPendingIndex(path).get("rcpt_0").status, "approved");

  const consumed = consumeApprovalTicket(path, "rcpt_0", Date.parse("2026-07-11T10:05:00.000Z"));
  assert.equal(consumed.allowedReceipt.id, "rcpt_0-approved");
  assert.equal(loadPendingIndex(path).get("rcpt_0").status, "consumed");
  assert.throws(() => consumeApprovalTicket(path, "rcpt_0", Date.parse("2026-07-11T10:06:00.000Z")), PendingStoreError);
});

test("consumeApprovalTicket: fails closed on expired ticket (TTL), unknown id, and a never-approved 'pending' id", () => {
  const pathExpired = tmpStorePath();
  seed(pathExpired);
  recordApproved(pathExpired, { id: "rcpt_0", by: "HUMAN:jane@acme.example", ticketExpiresAt: "2026-07-11T10:15:00.000Z", allowedReceipt: { id: "rcpt_0-approved" } });
  assert.throws(() => consumeApprovalTicket(pathExpired, "rcpt_0", Date.parse("2026-07-11T10:16:00.000Z")), PendingStoreError);

  const pathOther = tmpStorePath();
  assert.throws(() => consumeApprovalTicket(pathOther, "nope", Date.now()), PendingStoreError);
  seed(pathOther);
  assert.throws(() => consumeApprovalTicket(pathOther, "rcpt_0", Date.now()), PendingStoreError, "never approved -> not consumable");
});

test("recordDenied -> 'denied'; findOutstanding no longer reports it (session unblocked)", () => {
  const path = tmpStorePath();
  seed(path);
  recordDenied(path, { id: "rcpt_0", by: "HUMAN:jane@acme.example", reason: "looks wrong", deniedReceipt: { id: "rcpt_0-denied" } });
  assert.equal(loadPendingIndex(path).get("rcpt_0").status, "denied");
  assert.equal(findOutstanding(path, { tenant: "acme", agentId: "mcp-agent" }), null);
});

test("recordDeferred: fail-closed on an unwritable path (R4 rule: pending-store yazılamazsa DENY)", () => {
  assert.throws(
    () => recordDeferred("/nonexistent-dir-xyz/pending.jsonl", { deferredReceipt: FAKE_DEFERRED_RECEIPT, tenant: "acme", agentId: "a", actionId: "x", paramsHash: "sha256:" + "0".repeat(64) }),
    PendingStoreError,
  );
});

test("FIX-2 cross-session isolation: two sessions sharing ONE file with the SAME receipt id stay independent — S2 can never see/burn S1's approved ticket, and S1's own approval survives S2's later hold", () => {
  const path = tmpStorePath();
  const AGENT = "shared-agent"; // one logical agent, two proxy processes / sessions
  const s1Deferred = { ...FAKE_DEFERRED_RECEIPT, id: "rcpt_0", scope: { tenant: "acme", chain: "acme:session-S1#tok1-seg1" } };
  const s2Deferred = { ...FAKE_DEFERRED_RECEIPT, id: "rcpt_0", scope: { tenant: "acme", chain: "acme:session-S2#tok2-seg1" } };

  // S1 defers then is human-approved.
  recordDeferred(path, { deferredReceipt: s1Deferred, tenant: "acme", agentId: AGENT, sessionId: "session-S1", actionId: "payment.refund", paramsHash: s1Deferred.action.paramsHash });
  recordApproved(path, { id: "rcpt_0", by: "HUMAN:jane@acme.example", ticketExpiresAt: "2099-01-01T00:00:00.000Z", allowedReceipt: { id: "rcpt_0-approved" }, tenant: "acme", sessionId: "session-S1" });

  // A FOREIGN session (same tenant+agentId, different sessionId) can never SELECT S1's ticket.
  assert.equal(findOutstanding(path, { tenant: "acme", agentId: AGENT, sessionId: "session-S2" }), null, "S2 must not see S1's outstanding approval");
  assert.equal(findOutstanding(path, { tenant: "acme", agentId: AGENT, sessionId: "session-S1" })?.status, "approved", "S1 still sees its own approval");

  // S2 now records its OWN deferred hold under the SAME receipt id "rcpt_0". This must NOT clobber
  // S1's approved record (the naive id-only fold would).
  recordDeferred(path, { deferredReceipt: s2Deferred, tenant: "acme", agentId: AGENT, sessionId: "session-S2", actionId: "payment.refund", paramsHash: s2Deferred.action.paramsHash });
  assert.equal(findOutstanding(path, { tenant: "acme", agentId: AGENT, sessionId: "session-S1" })?.status, "approved", "S1's approval SURVIVES S2's same-id hold (criterion 2)");
  assert.equal(findOutstanding(path, { tenant: "acme", agentId: AGENT, sessionId: "session-S2" })?.status, "pending", "S2 has its own independent pending hold");

  // S1's ticket is consumable by S1 (criterion 2: S1 executes); S2's coincidental retry never burned it.
  const consumed = consumeApprovalTicket(path, "rcpt_0", Date.now(), { tenant: "acme", sessionId: "session-S1" });
  assert.equal(consumed.allowedReceipt.id, "rcpt_0-approved");
  assert.equal(findOutstanding(path, { tenant: "acme", agentId: AGENT, sessionId: "session-S1" }), null, "S1's ticket consumed exactly once");
  assert.equal(findOutstanding(path, { tenant: "acme", agentId: AGENT, sessionId: "session-S2" })?.status, "pending", "S2 unaffected by S1 consuming");
});

test("G2 multi-tenant isolation: two DIFFERENT tenants sharing ONE file with the SAME (sessionId, id) never cross-fold — tenant B's 'created' cannot clobber/hide tenant A's 'approved' ticket, and A can still consume its own", () => {
  const path = tmpStorePath();
  const SESSION = "shared-sess";
  const ID = "rcpt_0";
  const aDeferred = { ...FAKE_DEFERRED_RECEIPT, id: ID, scope: { tenant: "tenant-A", chain: "tenant-A:sess#seg1" } };
  const bDeferred = { ...FAKE_DEFERRED_RECEIPT, id: ID, scope: { tenant: "tenant-B", chain: "tenant-B:sess#seg1" } };

  // tenant-A defers under (SESSION, ID) then is human-approved.
  recordDeferred(path, { deferredReceipt: aDeferred, tenant: "tenant-A", agentId: "agent", sessionId: SESSION, actionId: "payment.refund", paramsHash: aDeferred.action.paramsHash });
  recordApproved(path, { id: ID, by: "HUMAN:a@x.example", ticketExpiresAt: "2099-01-01T00:00:00.000Z", allowedReceipt: { id: "rcpt_0-approved" }, tenant: "tenant-A", sessionId: SESSION });

  // tenant-B (a DIFFERENT tenant) defers under the coincidentally-identical (SESSION, ID). Under an
  // id-only or (sessionId,id)-only key this fresh "created" would clobber tenant-A's approved record.
  recordDeferred(path, { deferredReceipt: bDeferred, tenant: "tenant-B", agentId: "agent", sessionId: SESSION, actionId: "payment.refund", paramsHash: bDeferred.action.paramsHash });

  assert.equal(findOutstanding(path, { tenant: "tenant-A", agentId: "agent", sessionId: SESSION })?.status, "approved", "A's approval SURVIVES B's same-(sessionId,id) hold");
  assert.equal(findOutstanding(path, { tenant: "tenant-B", agentId: "agent", sessionId: SESSION })?.status, "pending", "B has its OWN independent pending hold");

  // A consumes its own ticket exactly once; B is untouched.
  const consumed = consumeApprovalTicket(path, ID, Date.now(), { tenant: "tenant-A", sessionId: SESSION });
  assert.equal(consumed.allowedReceipt.id, "rcpt_0-approved");
  assert.equal(findOutstanding(path, { tenant: "tenant-A", agentId: "agent", sessionId: SESSION }), null, "A's ticket consumed exactly once");
  assert.equal(findOutstanding(path, { tenant: "tenant-B", agentId: "agent", sessionId: SESSION })?.status, "pending", "B unaffected by A consuming");
});

test("FIX-3 fail-closed: a parseable line naming an UNRECOGNIZED event refuses the whole load (a truncated 'consume' can never silently resurrect a spent ticket)", () => {
  const path = tmpStorePath();
  seed(path);
  recordApproved(path, { id: "rcpt_0", by: "HUMAN:jane@acme.example", ticketExpiresAt: "2099-01-01T00:00:00.000Z", allowedReceipt: { id: "rcpt_0-approved" } });
  // Append a well-formed JSON line whose event name is NOT recognized (e.g. "consume" vs "consumed").
  writeFileSync(path, readFileSync(path, "utf8") + JSON.stringify({ event: "consume", id: "rcpt_0", ts: "2026-07-11T10:05:00.000Z" }) + "\n");
  assert.throws(() => loadPendingIndex(path), PendingStoreError, "an unrecognized event name must refuse the load, never be skipped");
});

test("FIX-4 fail-closed TTL: a missing/malformed ticketExpiresAt is treated as ALREADY EXPIRED, never consumable forever (NaN <= now was always false)", () => {
  const path = tmpStorePath();
  seed(path);
  // A recordApproved with NO ticketExpiresAt (a caller bug, or a direct API user bypassing approve-cli).
  recordApproved(path, { id: "rcpt_0", by: "HUMAN:jane@acme.example", ticketExpiresAt: undefined, allowedReceipt: { id: "rcpt_0-approved" } });
  const tenYears = Date.now() + 1000 * 60 * 60 * 24 * 365 * 10;
  assert.throws(() => consumeApprovalTicket(path, "rcpt_0", tenYears), PendingStoreError, "a ticket with no valid expiry must not be consumable, even 10 years later");
});

test("loadPendingIndex: a corrupt non-empty line REFUSES the whole load (fail-closed) — a torn 'consumed' marker can never silently resurrect an already-spent ticket", () => {
  const path = tmpStorePath();
  seed(path);
  recordApproved(path, { id: "rcpt_0", by: "HUMAN:jane@acme.example", ticketExpiresAt: "2099-01-01T00:00:00.000Z", allowedReceipt: { id: "rcpt_0-approved" } });
  consumeApprovalTicket(path, "rcpt_0", Date.parse("2026-07-11T10:05:00.000Z"));
  // Simulate a crash mid-append: tear the trailing "consumed" line into a partial JSON fragment.
  // A loader that silently SKIPPED this line would fold the record back to "approved" — letting
  // consumeApprovalTicket succeed a SECOND time off the same ticket (a replay). Fail-closed
  // loading makes the whole store unreadable until an operator repairs it instead.
  const text = readFileSync(path, "utf8");
  writeFileSync(path, text.slice(0, text.length - 10));
  assert.throws(() => loadPendingIndex(path), PendingStoreError, "a torn line must refuse the load, never be skipped");
  assert.throws(
    () => consumeApprovalTicket(path, "rcpt_0", Date.parse("2026-07-11T10:06:00.000Z")),
    PendingStoreError,
    "the replay can never succeed off a torn consumed marker",
  );
});

test("FIX-H strict fold: a SECOND 'created' on an already-approved record REFUSES the load — a duplicate 'created' can never silently reset an approved/consumed ticket back to 'pending' (self-lockout / DoS)", () => {
  const path = tmpStorePath();
  seed(path);
  recordApproved(path, { id: "rcpt_0", by: "HUMAN:jane@acme.example", ticketExpiresAt: "2099-01-01T00:00:00.000Z", allowedReceipt: { id: "rcpt_0-approved" } });
  assert.equal(loadPendingIndex(path).get("rcpt_0").status, "approved");
  // An attacker (or a torn writer) appends a SECOND "created" for the SAME record key. The old
  // permissive fold reset the record to "pending", WIPING the real approval; the strict fold refuses.
  seed(path);
  assert.throws(
    () => loadPendingIndex(path),
    PendingStoreError,
    "a duplicate 'created' must refuse the load, never reset the live approval back to 'pending'",
  );
});

test("FIX-H strict fold (deployed-reality preserved): an 'approved' AFTER 'consumed' is ACCEPTED — the forged-approval-burns-the-ticket -> genuine-re-approval RECOVERY the mcp-proxy Scenario-R smoke relies on must still fold to 'approved'; single-use is enforced cryptographically (adoptApprovedReceipt chain continuity), NOT by this operational index", () => {
  const path = tmpStorePath();
  seed(path);
  // A FORGED approval is appended (attacker with pending-store write access). The proxy consumes the
  // ticket BEFORE it verifies the approver signature, so the forged adoption attempt BURNS the ticket.
  recordApproved(path, { id: "rcpt_0", by: "HUMAN:attacker@nowhere.invalid", ticketExpiresAt: "2099-01-01T00:00:00.000Z", allowedReceipt: { id: "rcpt_0-forged" } });
  consumeApprovalTicket(path, "rcpt_0", Date.parse("2026-07-11T10:05:00.000Z")); // burned -> [created, approved, consumed]
  assert.equal(loadPendingIndex(path).get("rcpt_0").status, "consumed");
  // The operator now appends a GENUINE re-approval to recover. This created->approved->consumed->approved
  // sequence is exactly what Scenario-R produces and MUST remain loadable (rejecting it would break the
  // recovery). It is NOT a replay: a resurrected/replayed ALLOWED receipt still fails adoptApprovedReceipt's
  // seq/prevHash/segmentId continuity check once the chain has moved on, so it can never execute twice.
  recordApproved(path, { id: "rcpt_0", by: "HUMAN:approver@example.com", ticketExpiresAt: "2099-01-01T00:00:00.000Z", allowedReceipt: { id: "rcpt_0-approved-genuine" } });
  const rec = loadPendingIndex(path).get("rcpt_0");
  assert.equal(rec.status, "approved", "re-approval after a burned ticket folds back to 'approved' (recovery preserved)");
  assert.equal(rec.allowedReceipt.id, "rcpt_0-approved-genuine", "the fold reflects the LATEST (genuine) approval");
});

test("FIX-H strict fold: a 'consumed' event on a still-'pending' record (no 'approved' between) REFUSES the load — consumption requires a real prior approval", () => {
  const path = tmpStorePath();
  seed(path); // [created] -> pending
  // Forge a "consumed" directly onto the pending record, skipping "approved".
  writeFileSync(path, readFileSync(path, "utf8") + JSON.stringify({ event: "consumed", id: "rcpt_0", ts: "2026-07-11T10:05:00.000Z" }) + "\n");
  assert.throws(
    () => loadPendingIndex(path),
    PendingStoreError,
    "consuming a never-approved record must refuse the load",
  );
});

test("FIX-H strict fold (regression): the LEGITIMATE lifecycles created->approved->consumed and created->denied still fold cleanly, no false rejection", () => {
  const pathConsumed = tmpStorePath();
  seed(pathConsumed);
  recordApproved(pathConsumed, { id: "rcpt_0", by: "HUMAN:jane@acme.example", ticketExpiresAt: "2099-01-01T00:00:00.000Z", allowedReceipt: { id: "rcpt_0-approved" } });
  const consumed = consumeApprovalTicket(pathConsumed, "rcpt_0", Date.parse("2026-07-11T10:05:00.000Z"));
  assert.equal(consumed.allowedReceipt.id, "rcpt_0-approved");
  assert.equal(loadPendingIndex(pathConsumed).get("rcpt_0").status, "consumed", "the full legit lifecycle still loads");

  const pathDenied = tmpStorePath();
  seed(pathDenied);
  recordDenied(pathDenied, { id: "rcpt_0", by: "HUMAN:jane@acme.example", reason: "looks wrong", deniedReceipt: { id: "rcpt_0-denied" } });
  assert.equal(loadPendingIndex(pathDenied).get("rcpt_0").status, "denied", "created -> denied still loads");
});

test("FIX-H2 defense-in-depth: consumeApprovalTicket refuses a cross-tenant consume on the LEGACY (no-sessionId) id-only fold key — a caller from a different tenant can never consume this record's ticket, but the rightful tenant still consumes exactly once", () => {
  const path = tmpStorePath();
  // A LEGACY record (no sessionId) => recordKeyOf falls back to the bare id, so tenant is NOT part of
  // the fold key. tenant-A defers under "rcpt_0" and is human-approved.
  recordDeferred(path, { deferredReceipt: FAKE_DEFERRED_RECEIPT, tenant: "tenant-A", agentId: "mcp-agent", actionId: "payment.refund", paramsHash: FAKE_DEFERRED_RECEIPT.action.paramsHash });
  recordApproved(path, { id: "rcpt_0", by: "HUMAN:a@x.example", ticketExpiresAt: "2099-01-01T00:00:00.000Z", allowedReceipt: { id: "rcpt_0-approved" }, tenant: "tenant-A" });

  // A caller claiming tenant-B resolves the same bare-id key and finds tenant-A's record — the belt
  // must refuse rather than hand tenant-A's ticket to tenant-B.
  assert.throws(
    () => consumeApprovalTicket(path, "rcpt_0", Date.now(), { tenant: "tenant-B" }),
    PendingStoreError,
    "a caller from a different tenant must never consume this record's ticket",
  );
  // The failed cross-tenant attempt must NOT have burned the ticket: the rightful tenant still consumes.
  const consumed = consumeApprovalTicket(path, "rcpt_0", Date.now(), { tenant: "tenant-A" });
  assert.equal(consumed.allowedReceipt.id, "rcpt_0-approved");
  assert.equal(loadPendingIndex(path).get("rcpt_0").status, "consumed", "tenant-A consumed its own ticket exactly once");
});
