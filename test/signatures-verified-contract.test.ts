/**
 * P1-13 — `signaturesVerified` AND `tailChecked` ARE SUCCESS-QUALIFIERS, NOT PROGRESS REPORTS.
 *
 * ─── THE AMBIGUITY THAT PRODUCED THIS FILE ──────────────────────────────────────────────────────
 *
 * `fail()` (`src/verify.ts:125`) hardcodes `signaturesVerified: false` at all 35 call sites, and 19
 * of those sit AFTER signature checking begins at `:401`. Read as source, that looks like a lie: a
 * chain can fail at receipt N for a reason that is not cryptographic at all — tenant drift, chain
 * order, a malformed later field — while receipts 1..N-1 authenticated perfectly, and the result
 * still says no signatures were verified.
 *
 * It is not a lie, and the alternative is the actual defect. Under the other reading ("a keyring was
 * supplied, so checking ran") a **TAMPERED verdict would carry `signaturesVerified: true`** — a
 * positive sub-claim riding a failed check. That is the same shape as a CI job reporting success
 * having skipped its tests: **a run that did not complete must never report its sub-checks as
 * passed.** So the field means "this result is backed by COMPLETED authentication of the whole
 * input", the status and `reason` carry how far the run actually got, and `false` on every failure
 * is correct by contract.
 *
 * ─── WHY THIS FILE EXISTS AT ALL ────────────────────────────────────────────────────────────────
 *
 * The adjudication changed no behaviour, which is precisely the risk: a contract that lives only in
 * a comment is one refactor away from being "simplified" into the reading it rejected. The two tests
 * below are the exact cases that made the meaning ambiguous — a post-authentication non-cryptographic
 * failure, and a tampered checkpoint over sound receipts — converted from open questions into guards.
 *
 * Existing suites already pin the easy directions (`test/identity-binding.test.ts:48,72` pin false on
 * failure; `mcp-proxy/test/smoke.mjs` asserts the same), and every one of them assumes this reading.
 * What none of them covered is a failure that happens AFTER real signatures verified — which is the
 * only case where the two readings disagree.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPair } from "../src/keys.js";
import { buildReceipt, buildCheckpoint, type BuildInput, type Signer } from "../src/builder.js";
import { verifyChain } from "../src/verify.js";
import { sha256Prefixed } from "../src/hash.js";
import { b } from "./helpers/bytes.js";

const alice = generateKeyPair("alice-key");
const mallory = generateKeyPair("mallory-key");
const signer: Signer = { kid: alice.kid, privateKey: alice.privateKey };
// Mallory is IN the keyring on purpose: the checkpoint test below is about a co-trusted key, not an
// unknown one. An unknown key would fail for a different reason and prove nothing about this field.
const keyring = { [alice.kid]: alice.publicKey, [mallory.kid]: mallory.publicKey };

function mkInput(seq: number, tenant: string): BuildInput {
  return {
    id: `rcpt_${seq}`,
    ts: `2026-06-21T10:0${seq}:00.000Z`,
    scope: { tenant, chain: "c1" },
    agent: { id: "alice", model: null, principal: "SERVICE" },
    action: {
      id: "payment.refund", canonical: "payment.refund", riskClass: "CRITICAL",
      paramsHash: sha256Prefixed(`p${seq}`), reversible: false, rollbackRef: null,
    },
    governance: { mode: "on", verdict: "EXECUTED", ruleId: "r", approval: null, sandboxed: false },
  };
}

/** Build a chain of `n` genuinely-signed receipts; `driftAt` switches tenant at that index. */
function chainOf(n: number, driftAt = -1) {
  const out = [];
  let prev = null;
  for (let i = 0; i < n; i++) {
    const r = buildReceipt(mkInput(i, i === driftAt ? "OTHER-TENANT" : "t"), prev, signer);
    out[out.length] = r;
    prev = r;
  }
  return out;
}

/** CONTROL FIRST — both assertions below are about `false`, and a verifier that failed everything
 *  would satisfy them. This proves the honest chain reaches `true`, so `false` means something. */
test("CONTROL — a complete, fully-authenticated chain reports signaturesVerified TRUE", () => {
  const r = verifyChain(b(chainOf(5)), { keyring: b(keyring) });
  assert.equal(r.status, "VALID", r.reason);
  assert.equal(r.signaturesVerified, true,
    "the honest path does not reach true — every `false` assertion below would then be vacuous");
});

test("P1-13: a NON-CRYPTOGRAPHIC failure after 3 sound signatures still reports FALSE", () => {
  // THE CASE THE TWO READINGS DISAGREE ABOUT. Receipts 0-2 authenticate with a real key; receipt 3
  // carries a different tenant. Nothing cryptographic went wrong, and three signatures genuinely
  // verified — yet the run did not complete, so it carries no positive sub-claim.
  const r = verifyChain(b(chainOf(5, 3)), { keyring: b(keyring) });

  assert.notEqual(r.status, "VALID", "fixture precondition: the drift must actually be refused");
  assert.equal(r.signaturesVerified, false,
    "a refused chain reported signaturesVerified:true because signatures HAD verified before the " +
      "failure. That is a positive sub-claim riding a failed check — a relying party reading this " +
      "field on a TAMPERED verdict would be told the input was cryptographically backed when the " +
      "verifier refused it.");
  assert.equal(r.tailChecked, false, "same contract, same reasoning, for the tail flag");
});

test("P1-13: a TAMPERED CHECKPOINT over sound receipts reports FALSE for both flags", () => {
  // The other half of the ambiguity: here EVERY receipt signature verified and the failure is at the
  // checkpoint. Mallory is co-trusted, so this is not an unknown-key refusal — it is a genuine
  // signature over a head that is not this chain's.
  const chain = chainOf(3);
  const foreign = buildReceipt(mkInput(9, "t"), null, signer);
  const cp = buildCheckpoint(foreign, "2026-06-21T11:00:00.000Z",
    { kid: mallory.kid, privateKey: mallory.privateKey });

  const r = verifyChain(b([...chain, cp]), { keyring: b(keyring) });

  assert.notEqual(r.status, "VALID", "fixture precondition: a checkpoint over a foreign head must be refused");
  assert.equal(r.signaturesVerified, false,
    "every receipt signature verified, so a progress-report reading would say true here — and a " +
      "caller would read a refused verdict as cryptographically backed");
  assert.equal(r.tailChecked, false,
    "the tail was NOT certified for this chain; reporting otherwise is the tail-reheading claim itself");
});
