/**
 * PERMANENT SECURITY REGRESSION SUITE — trusted-input provenance.
 *
 * Every test here encodes an attack that was INDEPENDENTLY REPRODUCED against this package before a
 * line of the fix was written (`docs/GATE-PROVENANCE-FINDINGS-2026-07-30.md`). Each asserts the
 * SECURE outcome, so on the pre-fix tree this suite is expected to be RED. That is the point: these
 * are the acceptance gate for ADR-0005, and restoring any vulnerable behaviour must turn them RED
 * again.
 *
 * RULES THIS FILE OBEYS (owner instruction, 2026-07-30 Phase 2):
 *   1. Test the SECURITY OUTCOME, never the implementation's internal structure. A test asserting
 *      "the code calls parseDocument()" would pass a refactor that reintroduced the hole.
 *   2. Every attack has an ANTI-VACUITY CONTROL in the same run — the honest path must still work.
 *      A suite where everything is refused is indistinguishable from a broken fixture, and this
 *      project has twice read an unfailable run as a passing one.
 *   3. Where an attack depends on a value being read twice, assert on the OBSERVABLE DECISION, not
 *      on a read count. Read counts are an implementation detail; a signed HUMAN_APPROVED on a
 *      denied action is a defect under any implementation.
 *   4. Prove the poison FIRED. Zero reads means the fixture changed, not the gate — that is an
 *      inconclusive run, never a pass.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { setupGate, signPhoneDecision, sampleCommandParams, body } from "./helpers.js";
// The gate's own refHash, used to assert that what the gate SIGNED is the hash of what it VERIFIED.
import { refHash } from "noa-approval-artifacts";

/** A value that reports `first` to the opening reads and `second` afterwards. Models exactly one
 *  thing: a caller-owned object whose reads are not stable. */
function twoFaced(first: string, second: string, flipAfter: number): { get: () => string; reads: () => number } {
  let n = 0;
  return {
    get: () => {
      n += 1;
      return n <= flipAfter ? first : second;
    },
    reads: () => n,
  };
}

/** Clone `obj`, replacing exactly one key with a two-faced accessor: read #1 returns `firstRead`,
 *  every later read returns `laterRead`. Own enumerable keys are copied as plain values so
 *  `JSON.stringify` produces byte-identical output on read #1 to the object that was signed.
 *
 *  ⚠ WHY THIS SHAPE AND NOT A SIMPLER ONE. My first attempt at this test poisoned only
 *  `decisionArtifact.decision` — and the test PASSED, which I nearly recorded as "already secure".
 *  It passed because `engine.ts:469` cross-checks the artifact's decision against the receipt's
 *  `governance.verdict`, and flipping one without the other is caught. The working attack flips BOTH,
 *  in OPPOSITE directions, because the two fields are read in opposite orders relative to their
 *  signature checks. A test built from my model of the bug would have been vacuous; this one is
 *  ported from the harness that actually reproduces it. */
function poisonKey(
  obj: Record<string, unknown>,
  key: string,
  firstRead: string,
  laterRead: string,
): { view: Record<string, unknown>; reads: () => number } {
  const face = twoFaced(firstRead, laterRead, 1);
  const view = Object.create(Object.getPrototypeOf(obj) as object) as Record<string, unknown>;
  for (const k of Object.keys(obj)) {
    if (k === key) continue;
    Object.defineProperty(view, k, { value: obj[k], enumerable: true, writable: true, configurable: true });
  }
  Object.defineProperty(view, key, { enumerable: true, configurable: true, get: face.get });
  return { view, reads: face.reads };
}

const ACTION = { canonical: "noa.command.exec", riskClass: "CRITICAL", reversible: false } as const;

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// M3 — a signed human DENIAL must never yield HUMAN_APPROVED.
//
// Measured pre-fix: `engine.ts:448` verifies the approver signature over
// `encodeDocument(decisionArtifact)` — and `bytes.ts:18` is `JSON.stringify`, which INVOKES
// ACCESSORS. `engine.ts:459` then re-reads `decisionArtifact["decision"]` LIVE off the same
// caller-owned object. A two-faced accessor returns the signed DENY to the signature check and
// APPROVE to the authorization check. Nothing is forged: the signature genuinely covers DENY.
//
// ⚠ CONVERTED, NOT DELETED (ADR-0005 Slice 1, owner instruction). The entry point now takes
// `Uint8Array`, so the attack's PRECONDITION — two reads of one caller-owned field — is no longer
// constructible: `body(...)` serializes the poisoned object ONCE and the gate parses those bytes.
// Deleting a test because its attack can no longer be expressed would delete the evidence that it
// can no longer be expressed. So the test still builds the identical two-faced object and now
// asserts the NEW truth: the poison fires EXACTLY ONCE, and the outcome is secure. If a future
// refactor reopens a second read, `readsAfter === 1` breaks and this test goes RED again.
// ─────────────────────────────────────────────────────────────────────────────────────────────────

test("M3: a signed DENY cannot become APPROVED by re-reading the artifact", () => {
  const fx = setupGate({ approverRole: "approve-critical" });
  const created = fx.engine.createHold(fx.agent, "idem-m3", body({
    action: ACTION, params: sampleCommandParams(), chain: "chain-m3",
  }));
  assert.equal(created.status, 201, `fixture precondition: hold created (got ${created.status})`);
  const holdId = (created.body as { holdId: string }).holdId;
  const hold = fx.store.getHold(holdId)!;

  // The human reads the request and REFUSES. This signature is genuine and covers "DENY".
  const { receipt, decisionArtifact } = signPhoneDecision({
    trust: fx.trust, deferredReceipt: hold.deferredReceipt, holdEnvelope: hold.holdEnvelope, decision: "DENY",
  });

  // The attacker touches no signature. It makes two fields unstable, in OPPOSITE directions,
  // because each is read in the opposite order relative to its own signature check:
  //   `decision`          — read #1 feeds the signature check (DENY), later reads authorize (APPROVE)
  //   `governance.verdict` — read #1 is the live authorization read (ALLOWED), later the chain
  //                          re-serialization (BLOCKED)
  const da = poisonKey(decisionArtifact, "decision", "DENY", "APPROVE");
  const gov = poisonKey(receipt.governance as unknown as Record<string, unknown>, "verdict", "ALLOWED", "BLOCKED");
  const rView = Object.create(Object.getPrototypeOf(receipt) as object) as Record<string, unknown>;
  for (const k of Object.keys(receipt)) {
    if (k === "governance") continue;
    Object.defineProperty(rView, k, { value: (receipt as unknown as Record<string, unknown>)[k], enumerable: true, writable: true, configurable: true });
  }
  Object.defineProperty(rView, "governance", { value: gov.view, enumerable: true, writable: true, configurable: true });

  // ONE serialization. This is the whole architectural change: the caller commits to bytes, and the
  // bytes are what the gate verifies and authorizes from.
  const res = fx.engine.decide(holdId, body({ receipt: rView, decisionArtifact: da.view }));
  const after = fx.store.getHold(holdId);

  assert.ok(da.reads() >= 1 && gov.reads() >= 1,
    `poison never fired (decision reads=${da.reads()}, verdict reads=${gov.reads()}) — inconclusive, not a pass`);
  // THE NEW TRUTH, asserted exactly: a two-faced field cannot survive encoding, because it is read
  // once. Any number above 1 means a caller-owned value reached a second read inside the trusted
  // path, which is the defect class this whole ADR exists to remove.
  assert.equal(da.reads(), 1,
    `decisionArtifact.decision was read ${da.reads()} times. Bytes-in must read a caller value EXACTLY ` +
      "once — a second read is the M3 defect regardless of what the two reads happen to return.");
  assert.equal(gov.reads(), 1,
    `receipt.governance.verdict was read ${gov.reads()} times; the same rule applies to the receipt.`);
  assert.notEqual(after?.status, "APPROVED", "a human DENY must never resolve to APPROVED");
  assert.notEqual(after?.reasonCode, "HUMAN_APPROVED", "a human DENY must never claim HUMAN_APPROVED");
  assert.equal((res.body as Record<string, unknown> | undefined)?.["executionGrant"], undefined,
    "no ExecutionGrant may be issued for a denied action");
});

test("M3 anti-vacuity: an honest APPROVE still resolves to APPROVED", () => {
  const fx = setupGate({ approverRole: "approve-critical" });
  const created = fx.engine.createHold(fx.agent, "idem-m3-av", body({
    action: ACTION, params: sampleCommandParams(), chain: "chain-m3-av",
  }));
  assert.equal(created.status, 201);
  const holdId = (created.body as { holdId: string }).holdId;
  const hold = fx.store.getHold(holdId)!;

  const { receipt, decisionArtifact } = signPhoneDecision({
    trust: fx.trust, deferredReceipt: hold.deferredReceipt, holdEnvelope: hold.holdEnvelope, decision: "APPROVE",
  });
  const res = fx.engine.decide(holdId, body({ receipt, decisionArtifact }));

  assert.equal(res.status, 200, "the honest approval path must still work");
  assert.equal(fx.store.getHold(holdId)?.status, "APPROVED");
});

test("M3 anti-vacuity: an honest DENY resolves cleanly, not as an error", () => {
  const fx = setupGate({ approverRole: "approve-critical" });
  const created = fx.engine.createHold(fx.agent, "idem-m3-deny", body({
    action: ACTION, params: sampleCommandParams(), chain: "chain-m3-deny",
  }));
  assert.equal(created.status, 201);
  const holdId = (created.body as { holdId: string }).holdId;
  const hold = fx.store.getHold(holdId)!;

  const { receipt, decisionArtifact } = signPhoneDecision({
    trust: fx.trust, deferredReceipt: hold.deferredReceipt, holdEnvelope: hold.holdEnvelope, decision: "DENY",
  });
  const res = fx.engine.decide(holdId, body({ receipt, decisionArtifact }));

  assert.equal(res.status, 200, "an honest denial is a valid outcome, not a failure");
  assert.notEqual(fx.store.getHold(holdId)?.status, "APPROVED");
});

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// M7 — the display the human reads and the hash the grant binds must describe the same action.
//
// Measured pre-fix: `projections.ts:74` puts the caller's `argv` array into the snapshot as a
// REFERENCE, not a copy. `:82` hashes the snapshot and `:90` renders `display.Args` — two separate
// reads of a caller-owned array. NO CALLER DISPLAY FIELD IS INVOLVED, which is why neither
// ADR-0003 nor ADR-0004 would have closed this: both were of the form "stop accepting the caller's
// display", and M7 supplies none.
// ─────────────────────────────────────────────────────────────────────────────────────────────────

test("M7: a mutable argv cannot show one command and authorize another", () => {
  const fx = setupGate({ approverRole: "approve-critical" });

  // argv[0] flips after the reads that build the snapshot. If any later stage re-reads the caller's
  // array, the hash and the display describe different commands.
  const face = twoFaced("-rf", "--help", 2);
  const unstable: unknown[] = ["placeholder"];
  Object.defineProperty(unstable, "0", { get: face.get, enumerable: true, configurable: true });

  const a = fx.engine.createHold(fx.agent, "idem-m7", body({
    action: ACTION, params: sampleCommandParams({ argv: unstable }), chain: "chain-m7",
  }));

  // ⚠ THIS PRECONDITION WAS INVERTED BY ADR-0005 SLICE 1, AND THE INVERSION IS THE POINT.
  //
  // It read `assert.ok(face.reads() >= 2, "argv read fewer than twice — inconclusive")`, which was
  // correct while the entry point took a live object: the attack NEEDED two reads, so fewer than two
  // meant the fixture had stopped reproducing it. With `createHold(… Uint8Array)` the caller
  // serializes once and the gate parses those bytes, so TWO READS ARE NO LONGER CONSTRUCTIBLE — and
  // the old assertion would fail on a CORRECT implementation, which is the worst kind of test.
  //
  // Kept and inverted rather than deleted (owner instruction): the fixture still builds the identical
  // unstable array, and `=== 1` now pins the property that closed the defect. A refactor that
  // reintroduces a second read of a caller-owned array breaks this line.
  assert.equal(face.reads(), 1,
    `argv[0] was read ${face.reads()} times. A caller-owned array must be read EXACTLY once — at the ` +
      "single serialization — after which every stage reads the parsed snapshot. Two reads is M7.");
  if (a.status !== 201) return; // refusing the unstable input outright is also a secure outcome

  // THE SECURITY OUTCOME: whatever value the boundary captured, EVERY stage must have used that same
  // value. Build a second hold from a STABLE array holding the first-read value; if the snapshot is
  // taken once, the two paramsHashes are identical. A split read produces different digests.

  // Decode what the human will actually read. `testSealer` base64s the display JSON into
  // `payload.ciphertext`, so the plaintext IS observable in tests — which is what makes the real
  // security assertion possible.
  const holdA = fx.store.getHold((a.body as { holdId: string }).holdId)!;
  const encA = holdA.encryptedDisplay as unknown as { payload: { ciphertext: string } };
  const shown = JSON.parse(Buffer.from(encA.payload.ciphertext, "base64").toString("utf8")) as Record<string, string>;
  const shownArgs = String(shown["Args"] ?? "");

  // Build a reference hold from EXACTLY what the human was shown. If the display and the authorized
  // digest describe the same command, the two paramsHashes are identical. If argv was re-read, the
  // human saw one command and the grant bound another, and the digests diverge.
  //
  // ⚠ TWO EARLIER VERSIONS OF THIS ASSERTION WERE NOT CONTROLS. The first demanded the gate REFUSE an
  // unstable argv — a policy I invented, which would have failed a correct implementation. The second
  // compared the digest against a hard-coded "-rf" reference, which SURVIVED ITS OWN KNOCKOUT: sharing
  // the caller's array by reference left the hash unchanged, because the split lands between the HASH
  // and the DISPLAY, not between validation and the hash. Only comparing the SHOWN text against the
  // digest detects it.
  const fx2 = setupGate({ approverRole: "approve-critical" });
  const b = fx2.engine.createHold(fx2.agent, "idem-m7-ref", body({
    action: ACTION, params: sampleCommandParams({ argv: [shownArgs] }), chain: "chain-m7-ref",
  }));
  assert.equal(b.status, 201, "reference hold must be creatable");
  const hashB = fx2.store.getHold((b.body as { holdId: string }).holdId)!.action.paramsHash;

  assert.equal(holdA.action.paramsHash, hashB,
    `the human is shown Args="${shownArgs}" but the authorized digest commits to a different command: ` +
      "argv was read more than once, so the display and the signed paramsHash describe different actions");
});

test("M7 anti-vacuity: a stable argv produces an ordinary hold", () => {
  const fx = setupGate({ approverRole: "approve-critical" });
  const created = fx.engine.createHold(fx.agent, "idem-m7-av", body({
    action: ACTION, params: sampleCommandParams({ argv: ["--help"] }), chain: "chain-m7-av",
  }));
  assert.equal(created.status, 201, "the honest path must still produce a hold");
  assert.ok(fx.store.getHold((created.body as { holdId: string }).holdId), "an honest hold must exist");
});

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// M2 — the caller must not choose its own enforcement tier or its own approver.
//
// Measured pre-fix: `engine.ts:171` reads `rawAction["riskClass"]`, `:174` validates SET MEMBERSHIP
// ONLY — never against what the action actually does — and `:453` feeds it to `verifyArtifact`,
// which derives the required approver role (`approval-artifacts/src/verify.ts:133-138`). Measured:
// the identical destructive action gave 422 at CRITICAL and 200 + grant at LOW.
// ─────────────────────────────────────────────────────────────────────────────────────────────────

test("M2: a caller cannot downgrade riskClass to obtain a weaker approver", () => {
  // The approver device holds ONLY `approve-high`. A CRITICAL action must be refused for it.
  const fx = setupGate({ approverRole: "approve-high" });
  const destructive = sampleCommandParams({ executable: "/bin/rm", argv: ["-rf", "/srv"] });

  const created = fx.engine.createHold(fx.agent, "idem-m2", body({
    action: { canonical: "noa.command.exec", riskClass: "LOW", reversible: false }, // <- the lie
    params: destructive,
    chain: "chain-m2",
  }));
  assert.equal(created.status, 201, `fixture precondition: hold created (got ${created.status})`);
  const holdId = (created.body as { holdId: string }).holdId;
  const hold = fx.store.getHold(holdId)!;

  const { receipt, decisionArtifact } = signPhoneDecision({
    trust: fx.trust, deferredReceipt: hold.deferredReceipt, holdEnvelope: hold.holdEnvelope, decision: "APPROVE",
  });
  fx.engine.decide(holdId, body({ receipt, decisionArtifact }));
  const after = fx.store.getHold(holdId);

  assert.notEqual(
    after?.reasonCode, "HUMAN_APPROVED",
    "an `rm -rf /srv` labelled LOW must not obtain HUMAN_APPROVED from an approve-high device: " +
      "the enforcement tier must be derived from what the action does, not from the caller's label",
  );
});

test("M2 anti-vacuity: an honestly-labelled action still succeeds for a sufficient approver", () => {
  const fx = setupGate({ approverRole: "approve-critical" });
  const created = fx.engine.createHold(fx.agent, "idem-m2-av", body({
    action: ACTION, params: sampleCommandParams(), chain: "chain-m2-av",
  }));
  assert.equal(created.status, 201);
  const holdId = (created.body as { holdId: string }).holdId;
  const hold = fx.store.getHold(holdId)!;

  const { receipt, decisionArtifact } = signPhoneDecision({
    trust: fx.trust, deferredReceipt: hold.deferredReceipt, holdEnvelope: hold.holdEnvelope, decision: "APPROVE",
  });
  const res = fx.engine.decide(holdId, body({ receipt, decisionArtifact }));
  assert.equal(res.status, 200, "a correctly-labelled CRITICAL action with a critical approver must work");
  assert.equal(fx.store.getHold(holdId)?.reasonCode, "HUMAN_APPROVED");
});

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// M2b — the required APPROVER ROLE must not be selectable by the caller.
//
// Distinct vector from the tier downgrade above: here the SAME destructive action is submitted twice
// with two different labels, and the two runs must reach the same authorization outcome. If they
// differ, the caller — not the policy — chose who was allowed to approve.
// ─────────────────────────────────────────────────────────────────────────────────────────────────

test("M2b: the same action must require the same approver regardless of the caller's label", () => {
  const destructive = sampleCommandParams({ executable: "/bin/rm", argv: ["-rf", "/srv"] });

  const attempt = (label: string, idem: string): number => {
    const fx = setupGate({ approverRole: "approve-high" });
    const created = fx.engine.createHold(fx.agent, idem, body({
      mode: "ENFORCED",
      action: { canonical: "noa.command.exec", riskClass: label, reversible: false },
      params: destructive,
      chain: "chain-" + idem,
    }));
    if (created.status !== 201) return created.status;
    const holdId = (created.body as { holdId: string }).holdId;
    const hold = fx.store.getHold(holdId)!;
    const { receipt, decisionArtifact } = signPhoneDecision({
      trust: fx.trust, deferredReceipt: hold.deferredReceipt, holdEnvelope: hold.holdEnvelope, decision: "APPROVE",
    });
    return fx.engine.decide(holdId, body({ receipt, decisionArtifact })).status;
  };

  const asCritical = attempt("CRITICAL", "idem-m2b-crit");
  const asLow = attempt("LOW", "idem-m2b-low");

  assert.equal(asCritical, asLow,
    `identical \`rm -rf /srv\` reached different outcomes purely by relabelling: ` +
      `CRITICAL -> ${asCritical}, LOW -> ${asLow}. The approver requirement must be derived from ` +
      `what the action does, not from a caller-supplied label.`);
});

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// M1 — a caller-supplied encryptedDisplay must never become the approved representation.
//
// Measured pre-fix: `engine.ts:269-271` accepts `input["encryptedDisplay"]` if it is a record whose
// `spec` matches, assigns it with an `as` cast, and those lines sit OUTSIDE the RAW/ENFORCED branch
// (which closes at `:210`). The pinned projection still runs and still derives a display — and that
// derived display is discarded, because `display` is only consumed at `:282`, inside the `else`.
// ─────────────────────────────────────────────────────────────────────────────────────────────────

test("M1: a caller-supplied encryptedDisplay cannot survive ENFORCED mode", () => {
  const fx = setupGate({ approverRole: "approve-critical" });

  const LIE = { Action: "Read a config file", Command: "/bin/cat", Args: "/etc/motd", Cwd: "/tmp", Env: "dev" };
  const forged = {
    spec: "noa.encrypted-display/0.1",
    tenant: "alpha-tenant",
    holdId: "attacker-chosen",
    deferredReceiptHash: "sha256:" + "0".repeat(64),
    expiresAt: "2099-01-01T00:00:00Z",
    suite: { kem: 32, kdf: 1, aead: 3 },
    payload: { nonce: "AAAAAAAAAAAAAAAA", ciphertext: Buffer.from(JSON.stringify(LIE), "utf8").toString("base64") },
    recipients: [{ kid: "attacker-key-1", enc: "ZW5j", wrappedCek: "d3JhcA" }],
    aadHash: "sha256:" + "1".repeat(64),
  };

  const created = fx.engine.createHold(fx.agent, "idem-m1", body({
    action: ACTION,
    params: sampleCommandParams({ executable: "/bin/rm", argv: ["-rf", "/"] }),
    encryptedDisplay: forged,
    chain: "chain-m1",
  }));

  if (created.status !== 201) return; // refused at the boundary: the secure outcome

  const hold = fx.store.getHold((created.body as { holdId: string }).holdId)!;
  const stored = hold.encryptedDisplay as unknown as Record<string, unknown>;
  const recipients = stored["recipients"] as Array<{ kid: string }> | undefined;

  assert.notEqual(recipients?.[0]?.kid, "attacker-key-1",
    "the gate sealed the ATTACKER's display: a caller-supplied encryptedDisplay must never become " +
      "the approved representation, and in ENFORCED mode the gate must seal only what it derived");
});

test("M1 anti-vacuity: with no encryptedDisplay supplied, the gate seals to the real approver", () => {
  const fx = setupGate({ approverRole: "approve-critical" });
  const created = fx.engine.createHold(fx.agent, "idem-m1-av", body({
    action: ACTION, params: sampleCommandParams(), chain: "chain-m1-av",
  }));
  assert.equal(created.status, 201, "the honest path must still produce a hold");
  const hold = fx.store.getHold((created.body as { holdId: string }).holdId)!;
  const recipients = (hold.encryptedDisplay as unknown as Record<string, unknown>)["recipients"] as Array<{ kid: string }>;
  assert.notEqual(recipients?.[0]?.kid, "attacker-key-1", "sanity: the honest path has no attacker recipient");
});

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// RAW downgrade — the caller must not select its own security mode.
//
// Measured pre-fix: `engine.ts:164` reads `mode` from CALLER INPUT, so registering an ENFORCED
// projection does not constrain the action — the caller simply asks for RAW, supplies its own
// paramsHash and its own display, and the two are never bound to each other.
// ─────────────────────────────────────────────────────────────────────────────────────────────────

test("RAW: a caller cannot select RAW for a critical action to escape derivation", () => {
  const fx = setupGate({ approverRole: "approve-critical" });
  // ⚠ ISOLATION MATTERS, AND MY FIRST VERSION DID NOT HAVE IT. The original request omitted `params`
  // and supplied its own `paramsHash`, so it was refused by TWO independent mechanisms. When the mode
  // check was knocked out, the request was still refused (missing params) and the test still PASSED —
  // meaning it survived its own knockout and, by this repository's own standard
  // (`wrapper.ts:266-277`: "an equality check that survives its own knockout is not a control"), it
  // was NOT a control. Valid params are now supplied so the ONLY remaining reason to refuse is the
  // caller trying to select the mode.
  const created = fx.engine.createHold(fx.agent, "idem-raw", body({
    mode: "RAW",
    action: { canonical: "noa.command.exec", riskClass: "CRITICAL", reversible: false },
    params: sampleCommandParams(),
    chain: "chain-raw",
  }));

  // Owner decision 2026-07-30 closed this at the strongest point available: `mode` is no longer a
  // request field at all. It is DERIVED from the projection registry, and a request that carries one
  // is refused outright rather than ignored — because accepting a field is the vulnerability, not
  // disagreeing with its value. This test therefore now passes on MODE_NOT_CALLER_SELECTABLE.
  assert.notEqual(created.status, 201,
    "a CRITICAL action was accepted with a caller-selected mode, where the display and the " +
      "paramsHash are unrelated caller assertions. A registered projection exists for this action " +
      "type; the caller must not be able to opt out of it by naming a mode.");
});

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// paramsHash substitution — the digest must be derived, never accepted.
// ─────────────────────────────────────────────────────────────────────────────────────────────────

test("digest: a caller-supplied paramsHash must be REFUSED even when it matches", async () => {
  const fx = setupGate({ approverRole: "approve-critical" });
  const honest = sampleCommandParams();

  // Compute the hash the gate itself would derive, and supply exactly that.
  //
  // ⚠ WHY A MATCHING HASH AND NOT A MISMATCHING ONE. A mismatching hash is already refused today
  // (`422 PARAMS_HASH_MISMATCH — ENFORCED: gate-computed paramsHash != caller-supplied`), which is a
  // real control and is why the first version of this test passed. But rejecting on MISMATCH is not
  // the same as rejecting on PRESENCE: a field accepted today with a matching value is accepted
  // tomorrow with a mismatching one, and the check that catches it is one refactor from being
  // reordered. ACCEPTANCE is the vulnerability.
  const { canonicalize, sha256Prefixed } = await import("noa-approval-artifacts") as {
    canonicalize: (v: unknown) => string; sha256Prefixed: (s: string) => string;
  };
  const matching = sha256Prefixed(canonicalize({
    executable: honest["executable"], argv: honest["argv"], cwd: honest["cwd"],
    targetEnv: honest["targetEnv"], allowedEnvHash: honest["allowedEnvHash"], stdinHash: honest["stdinHash"],
  }));

  const created = fx.engine.createHold(fx.agent, "idem-digest", body({
    action: { ...ACTION, paramsHash: matching },
    params: honest,
    chain: "chain-digest",
  }));

  assert.notEqual(created.status, 201,
    "a caller-supplied paramsHash was ACCEPTED because it happened to match. The digest must be " +
      "derived inside the boundary and the request field must not exist: supplying it at all is the " +
      "defect, not supplying a wrong one");
});

test("digest anti-vacuity: the same params with NO caller hash are accepted", () => {
  const fx = setupGate({ approverRole: "approve-critical" });
  const created = fx.engine.createHold(fx.agent, "idem-digest-av", body({
    action: ACTION, params: sampleCommandParams(), chain: "chain-digest-av",
  }));
  assert.equal(created.status, 201, "the honest path — no caller-supplied digest — must still work");
});

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// Registry — the projection registry must not be mutable at runtime from the caller's realm.
//
// Measured pre-fix: `projections.ts:98-106` is a module-level mutable Map and `registerProjection`
// is an EXPORTED public setter using `REGISTRY.set` (overwrite, no freeze, no guard), re-exported at
// `index.ts:28`, with ZERO callers repo-wide. One call from any dependency running as the app's uid
// replaces a reviewed adapter while the envelope still advertises the reviewed identity.
// ─────────────────────────────────────────────────────────────────────────────────────────────────

test("registry: a reviewed projection cannot be replaced at runtime", async () => {
  const projections = await import("../src/projections.js") as Record<string, unknown>;
  const register = projections["registerProjection"] as ((p: unknown) => void) | undefined;
  const get = projections["getProjection"] as ((c: string) => unknown) | undefined;

  assert.ok(get, "fixture precondition: getProjection is available");
  const before = get!("noa.command.exec");
  assert.ok(before, "fixture precondition: the reviewed adapter is registered");

  if (!register) return; // no public setter exists: the secure outcome

  // ⚠ THIS TEST POISONS A PROCESS-WIDE REGISTRY, so it MUST restore it. An earlier version did not,
  // and the overwritten adapter made every LATER test in this file unable to create a hold — the
  // execute() pair then failed with "no hold appeared" and looked like a security finding. The suite
  // was a victim of the exact defect this test demonstrates. That is the strongest available argument
  // for B-3: a registry any code can overwrite has no isolation, not even from its own test suite.
  let threw = false;
  try {
    register({
      canonical: "noa.command.exec",
      run: () => ({ ok: false, error: "attacker" }),
    });
  } catch {
    threw = true;
  }

  const after = get!("noa.command.exec");

  // Restore before asserting, so a failing assertion cannot leak the poison either.
  if (!threw && before) { try { register(before); } catch { /* sealed: nothing to restore */ } }
  assert.ok(threw || after === before,
    "a public exported setter overwrote a reviewed projection at runtime. The registry is the root " +
      "of display trust: it must be sealed after construction, or installed only through an " +
      "authenticated administrative path — never via an exported function reachable by any dependency");
});

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// Projection identity — the pinned identity must change when behaviour changes.
//
// Measured pre-fix: `projections.ts:41-48` hashes `{id, version, kind}` — three self-declared
// strings. It does NOT cover the adapter's `run()`, so a totally different implementation reproduces
// the reviewed identity byte-for-byte, and the envelope pins a renderer that never ran.
// ─────────────────────────────────────────────────────────────────────────────────────────────────

test("projection identity: a different implementation must not reproduce the reviewed identity", async () => {
  const projections = await import("../src/projections.js") as Record<string, unknown>;
  const get = projections["getProjection"] as ((c: string) => Record<string, unknown> | undefined) | undefined;
  const honest = get?.("noa.command.exec");
  assert.ok(honest, "fixture precondition: the reviewed adapter is registered");

  const dp = honest!["displayProjection"] as { id: string; version: number; hash: string } | undefined;
  assert.ok(dp?.hash, "fixture precondition: the adapter carries a displayProjection identity hash");

  // Reconstruct the identity the way the source does — from {id, version, kind} alone. If that
  // reproduces the shipped hash, the identity is independent of the implementation.
  const { canonicalize, sha256Prefixed } = await import("noa-approval-artifacts") as {
    canonicalize: (v: unknown) => string; sha256Prefixed: (s: string) => string;
  };
  const reconstructed = sha256Prefixed(canonicalize({ id: dp!.id, version: dp!.version, kind: "displayProjection" }));

  assert.notEqual(reconstructed, dp!.hash,
    "the projection identity hash is reproducible from {id, version, kind} alone, so an adapter with " +
      "entirely different behaviour pins the reviewed identity. The identity must commit to the " +
      "implementation artifact, not to its labels");
});

/** ADR-0006-A PART A — the POSITIVE property, which the test above cannot establish.
 *
 *  "Labels alone do not reproduce the hash" is satisfied by a hash over ANY extra bytes — a build
 *  timestamp, a random nonce, a constant. It would go green while the identity still committed to
 *  nothing about `run()`. So the test above is necessary and NOT sufficient, and on its own it is
 *  exactly the shape this repository has been burned by three times: a control that passes for a
 *  reason other than the one claimed.
 *
 *  This test names the formula. The FIRST assertion is the anti-vacuity control: reconstructing the
 *  identity WITH the real implementation's artifact digest must reproduce the shipped hash exactly.
 *  If it does not, the reconstruction below is measuring something other than what ships and the
 *  second assertion proves nothing. */
test("projection identity: the identity COMMITS to the implementation artifact — a different run() cannot reproduce it", async () => {
  const projections = await import("../src/projections.js");
  const honest = projections.getProjection("noa.command.exec");
  assert.ok(honest, "fixture precondition: the reviewed adapter is registered");

  const { canonicalize, sha256Prefixed } = await import("noa-approval-artifacts") as {
    canonicalize: (v: unknown) => string; sha256Prefixed: (s: string) => string;
  };
  const artifactDigest = (fn: unknown): string => sha256Prefixed(Function.prototype.toString.call(fn));
  const identity = (kind: string, id: string, version: number, impl: unknown): string =>
    sha256Prefixed(canonicalize({ id, version, kind, implementation: artifactDigest(impl) }));

  // CONTROL — the shipped hashes must be reproducible from labels + the REAL run()'s artifact digest.
  // This is what makes the assertions below meaningful rather than accidentally true.
  assert.equal(identity("displayProjection", honest!.displayProjection.id, honest!.displayProjection.version, honest!.run),
    honest!.displayProjection.hash,
    "anti-vacuity: the shipped displayProjection identity is NOT sha256 over {id,version,kind,implementation-digest}. " +
      "Whatever it does commit to, this test is not measuring it");
  assert.equal(identity("actionSchema", honest!.actionSchema.id, honest!.actionSchema.version, honest!.run),
    honest!.actionSchema.hash,
    "anti-vacuity: the shipped actionSchema identity does not commit to the implementation either. " +
      "The schema validation lives INSIDE run(), so leaving this one on labels alone would fix a site " +
      "and not its neighbour — the exact pattern that produced a CRITICAL in three consecutive releases");

  // ATTACK — the same labels, a different implementation. Must NOT reproduce the reviewed identity.
  const impostor = (): { ok: false; error: string } => ({ ok: false, error: "attacker" });
  assert.notEqual(identity("displayProjection", honest!.displayProjection.id, honest!.displayProjection.version, impostor),
    honest!.displayProjection.hash,
    "an adapter with entirely different behaviour reproduced the reviewed displayProjection identity");
  assert.notEqual(identity("actionSchema", honest!.actionSchema.id, honest!.actionSchema.version, impostor),
    honest!.actionSchema.hash,
    "an adapter with entirely different behaviour reproduced the reviewed actionSchema identity");
});

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// execute() — the boundary must not hand authorization to an opaque caller closure.
//
// Measured pre-fix: `wrapper.ts:122` declares `execute: () => Promise<{ok, detail?}>` — NO ARGUMENTS.
// The gate hashes a params snapshot, compares it to the grant, then calls a function the caller wrote,
// which does whatever it likes. `wrapper.ts:5-10` calls this "the load-bearing guarantee ... D14
// exact-execution binding" and asserts "approve action A, run action B is refused". The type signature
// 113 lines below makes that structurally impossible in EVERY mode, including ENFORCED. Confirmed
// independently by codex (C-01) and the Fable QA seat (F-2, with an executed PoC).
// ─────────────────────────────────────────────────────────────────────────────────────────────────

// ⚠ FIXTURE INCOMPLETE — READ BEFORE TRUSTING THE TWO TESTS BELOW.
//
// The DEFECT is confirmed and not in doubt: `wrapper.ts:122` declares `execute: () => Promise<...>`
// with NO ARGUMENTS, so the executed command is never compared to the granted one. codex (C-01) and
// the Fable QA seat (F-2, executed PoC) each reproduced it independently, and the lead verified the
// signature at source.
//
// What is incomplete is MY FIXTURE. `approveFirstPending()` below does not observe the PENDING hold
// that `guard()` demonstrably creates — a direct probe shows the hold present and PENDING within
// 50 ms, yet the poll exhausts. So BOTH tests below currently fail, INCLUDING THE ANTI-VACUITY
// CONTROL — and a failing anti-vacuity control invalidates the attack test above it. Neither result
// may be counted as evidence of anything until the fixture works.
//
// Recorded rather than deleted or quietly left looking like a real RED: 9 of the 10 attacks in this
// file are pinned with passing controls; this is the tenth and it is NOT yet pinned. Fixing the
// harness is a Phase 2 remainder, not a Phase 4 dependency.

test("execute(): the wrapper must not report success for an action it cannot verify", async () => {
  const { guard, InProcessGateClient } = await import("../src/wrapper.js");
  const fx = setupGate({ approverRole: "approve-critical" });
  const client = new InProcessGateClient(fx.engine, fx.agent);

  // What actually happens at the target, recorded independently of anything the caller reports.
  const sideEffects: Array<Record<string, unknown>> = [];
  const approved = sampleCommandParams();

  const run = guard({
    client,
    action: { canonical: "noa.command.exec", riskClass: "CRITICAL", reversible: false },
    params: approved,
    idempotencyKey: "idem-exec",
    chain: "chain-exec",
    waitMs: 2000,
    // The grant binds `approved`. This closure performs something else entirely, and the gate is
    // never told what it did, because `execute` takes no arguments and returns only a boolean.
    execute: async () => {
      sideEffects.push({ executable: "/bin/rm", argv: ["-rf", "/"] });
      return { ok: true };
    },
  });

  await approveFirstPending(fx);
  const outcome = await run;

  const performed = sideEffects[0];
  assert.ok(performed !== undefined && performed["executable"] !== approved["executable"],
    `fixture precondition: the closure must have run a DIFFERENT action (got ${JSON.stringify(performed)})`);

  assert.notEqual(outcome.outcome, "EXECUTED",
    "the wrapper reported EXECUTED for an action it has no way to observe: `execute` takes no " +
      "arguments, so the executed command is never compared to the granted one. The boundary must " +
      "accept a typed execution command it constructs, not an opaque caller-supplied closure");
});

test("execute() anti-vacuity: an honest closure performing the approved action reports success", async () => {
  const { guard, InProcessGateClient } = await import("../src/wrapper.js");
  const fx = setupGate({ approverRole: "approve-critical" });
  const client = new InProcessGateClient(fx.engine, fx.agent);
  const approved = sampleCommandParams();
  const sideEffects: Array<Record<string, unknown>> = [];

  const run = guard({
    client,
    action: { canonical: "noa.command.exec", riskClass: "CRITICAL", reversible: false },
    params: approved,
    idempotencyKey: "idem-exec-av",
    chain: "chain-exec-av",
    waitMs: 2000,
    execute: async () => { sideEffects.push(approved); return { ok: true }; },
  });

  await approveFirstPending(fx);
  const outcome = await run;

  assert.equal(sideEffects.length, 1, "the honest closure must have run exactly once");
  assert.equal(outcome.outcome, "EXECUTED", "the honest approved path must report EXECUTED");
});

/** Approve the first PENDING hold out-of-band, waking guard()'s long-poll.
 *
 *  ⚠ FIXTURE HISTORY, PRESERVED PER OWNER INSTRUCTION. An earlier version of this helper polled
 *  `listHolds({ status: "PENDING" })[0]` and never observed the hold, so BOTH execute() tests failed
 *  — including the anti-vacuity control, which invalidated the attack test above it. A direct probe
 *  inside the same test runner proved the hold IS present and PENDING at iteration 0 and that
 *  `decide()` returns 200, so the defect was in the helper, not in the gate. This version is built
 *  from that probe: poll for ANY hold first, then select the pending one. The distinction matters
 *  because a fixture that cannot observe its own precondition produces a failure that looks exactly
 *  like a security finding. */
async function approveFirstPending(fx: ReturnType<typeof setupGate>): Promise<void> {
  for (let i = 0; i < 200; i++) {
    const all = fx.store.listHolds({});
    if (all.length > 0) {
      const pending = all.find((h) => h.status === "PENDING");
      if (pending) {
        const { receipt, decisionArtifact } = signPhoneDecision({
          trust: fx.trust, deferredReceipt: pending.deferredReceipt,
          holdEnvelope: pending.holdEnvelope, decision: "APPROVE",
        });
        const d = fx.engine.decide(pending.id, body({ receipt, decisionArtifact }));
        if (d.status !== 200) {
          throw new Error(`fixture broken, not a security result: decide -> ${d.status} ${JSON.stringify(d.body)}`);
        }
        return;
      }
    }
    await new Promise((r) => setTimeout(r, 2));
  }
  throw new Error("no hold appeared at all — fixture broken, not a security result");
}

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// F-3 (codex adjudication, HIGH, lead-reproduced) — the risk default must FAIL CLOSED.
//
// `docs/OWNER-DECISION-REGISTER.md:79-80`, which I wrote myself, requires an unmatched action to
// "classify to the HIGHEST tier and fail closed — otherwise the default is the vulnerability". The
// first implementation was a DENYLIST of nine binaries returning HIGH for everything else, and I
// documented that as an accepted "lower bound" as if disclosure discharged the requirement. It did
// not: wrapping deletion in any interpreter evaded it.
// ─────────────────────────────────────────────────────────────────────────────────────────────────

test("F-3: an unreviewed executable classifies to the highest tier, not to HIGH", () => {
  const fx = setupGate({ approverRole: "approve-critical" });
  const created = fx.engine.createHold(fx.agent, "idem-f3", body({
    action: { canonical: "noa.command.exec", riskClass: "LOW", reversible: false }, // the lie
    params: sampleCommandParams({
      executable: "/usr/bin/python3",
      argv: ["-c", "import shutil; shutil.rmtree('/srv')"],
    }),
    chain: "chain-f3",
  }));
  assert.equal(created.status, 201, "fixture precondition: the hold must be creatable");
  const risk = fx.store.getHold((created.body as { holdId: string }).holdId)!.action.riskClass;

  assert.ok(risk === "CRITICAL" || risk === "IRREVERSIBLE",
    `an interpreter invocation that recursively deletes /srv classified as ${risk}. A denylist cannot ` +
      "fail closed: its default is \"unrecognised, therefore fine\". Node, Perl, BusyBox and " +
      "`find -delete` evade it identically.");
});

test("F-3 anti-vacuity: a REVIEWED executable still gets its lower reviewed floor", () => {
  const fx = setupGate({ approverRole: "approve-high" });
  const created = fx.engine.createHold(fx.agent, "idem-f3-av", body({
    action: { canonical: "noa.command.exec", riskClass: "HIGH", reversible: false },
    params: sampleCommandParams(), // /usr/local/bin/deploy — on the reviewed allowlist
    chain: "chain-f3-av",
  }));
  assert.equal(created.status, 201, "the reviewed deploy path must still work");
  assert.equal(fx.store.getHold((created.body as { holdId: string }).holdId)!.action.riskClass, "HIGH",
    "the allowlist must still grant its reviewed floor — otherwise everything is CRITICAL and the " +
      "classifier is not a classifier, it is a refusal");
});

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// ADR-0005 SLICE 1 — THE BYTE BOUNDARY IS THE ENTRY SIGNATURE.
//
// The tests above prove the ATTACKS are closed. These prove WHY they are closed, which is a different
// claim and the one that survives a refactor: a trusted entry point does not accept a live object at
// all, so the two-reads precondition cannot be reconstructed by any caller.
//
// Measured on the tree immediately before this slice (`engine.ts:635`, the APPROVE branch of the Hold
// Resolution, one line above a correct use of the `rDoc` snapshot):
//
//     gate-SIGNED holdResolution.decisionArtifactHash : sha256:8efd3224...
//     refHash(the VERIFIED snapshot)                  : sha256:0141ca02...
//     signed hash commits to the VERIFIED doc?        false
//     signed hash commits to the ATTACKER's doc?      true
//
// The gate signed a commitment to a document it never verified. Nothing was forged. The fix is that
// the identifier holding the live object no longer exists in that scope, so `tsc` rejects the line.
// ─────────────────────────────────────────────────────────────────────────────────────────────────

/** Every trusted entry point, with a body that is a live object rather than bytes. */
const LIVE_OBJECT_ENTRIES: Array<{ name: string; call: (fx: ReturnType<typeof setupGate>) => { status: number; body: unknown } }> = [
  {
    name: "createHold",
    call: (fx) => fx.engine.createHold(fx.agent, "idem-bytes", { action: ACTION, params: sampleCommandParams() } as unknown as Uint8Array),
  },
  {
    name: "decide",
    call: (fx) => {
      const created = fx.engine.createHold(fx.agent, "idem-bytes-d", body({ action: ACTION, params: sampleCommandParams(), chain: "chain-bytes-d" }));
      const holdId = (created.body as { holdId: string }).holdId;
      const hold = fx.store.getHold(holdId)!;
      const { receipt, decisionArtifact } = signPhoneDecision({
        trust: fx.trust, deferredReceipt: hold.deferredReceipt, holdEnvelope: hold.holdEnvelope, decision: "APPROVE",
      });
      return fx.engine.decide(holdId, { receipt, decisionArtifact } as unknown as Uint8Array);
    },
  },
  {
    name: "report",
    call: (fx) => {
      const created = fx.engine.createHold(fx.agent, "idem-bytes-r", body({ action: ACTION, params: sampleCommandParams(), chain: "chain-bytes-r" }));
      const holdId = (created.body as { holdId: string }).holdId;
      const hold = fx.store.getHold(holdId)!;
      const { receipt, decisionArtifact } = signPhoneDecision({
        trust: fx.trust, deferredReceipt: hold.deferredReceipt, holdEnvelope: hold.holdEnvelope, decision: "APPROVE",
      });
      const decided = fx.engine.decide(holdId, body({ receipt, decisionArtifact }));
      const grantId = (decided.body as { grantId: string }).grantId;
      fx.engine.reserve(grantId, fx.agent);
      return fx.engine.report(grantId, { result: "DISPATCHED" } as unknown as Uint8Array, fx.agent);
    },
  },
];

for (const entry of LIVE_OBJECT_ENTRIES) {
  test(`bytes-in: ${entry.name}() refuses a live object WITH A REASON, and runs none of its code`, () => {
    const fx = setupGate({ approverRole: "approve-critical" });
    const res = entry.call(fx);

    // 422, not 500 and not a throw. A trusted boundary that throws hands the caller an exception whose
    // own `message` getter the attacker controls; every refusal here is a returned, reasoned status.
    assert.equal(res.status, 422,
      `${entry.name}() accepted a live JavaScript object as a document (status ${res.status}). The whole ` +
        "ADR-0005 defect class requires exactly that: a caller reference in scope alongside its parsed " +
        `snapshot. Got body: ${JSON.stringify(res.body)}`);
    const b0 = res.body as { error?: string; detail?: string };
    assert.equal(b0.error, "BODY_NOT_STRICT_JSON", "the refusal is the parse boundary's, not an ad-hoc check");
    assert.match(String(b0.detail), /Uint8Array/,
      "the refusal must carry the parser's own reason saying what a document IS — a bare error code " +
        "leaves an integrator guessing, and this detail is built from the parser's literals, never " +
        "from anything the caller owns");
  });
}

test("bytes-in anti-vacuity: the identical documents AS BYTES complete the whole flow", () => {
  // If the three refusals above were caused by anything other than the input not being bytes — a
  // broken fixture, a stale hold, a missing sealer — this control would fail too, and the refusals
  // would prove nothing.
  const fx = setupGate({ approverRole: "approve-critical" });
  const created = fx.engine.createHold(fx.agent, "idem-bytes-av", body({
    action: ACTION, params: sampleCommandParams(), chain: "chain-bytes-av",
  }));
  assert.equal(created.status, 201, "createHold with BYTES must work");
  const holdId = (created.body as { holdId: string }).holdId;
  const hold = fx.store.getHold(holdId)!;

  const { receipt, decisionArtifact } = signPhoneDecision({
    trust: fx.trust, deferredReceipt: hold.deferredReceipt, holdEnvelope: hold.holdEnvelope, decision: "APPROVE",
  });
  const decided = fx.engine.decide(holdId, body({ receipt, decisionArtifact }));
  assert.equal(decided.status, 200, "decide with BYTES must work");
  assert.equal(fx.store.getHold(holdId)?.reasonCode, "HUMAN_APPROVED");

  const grantId = (decided.body as { grantId: string }).grantId;
  assert.equal(fx.engine.reserve(grantId, fx.agent).status, 200);
  assert.equal(fx.engine.report(grantId, body({ result: "DISPATCHED" }), fx.agent).status, 200,
    "report with BYTES must work — the honest end-to-end path is intact");
});

test("bytes-in: an EMPTY body is 422 with a reason, not a synthesized {}", () => {
  // `server.ts` used to turn a zero-length body into `{}` before the engine saw it, which is the shim
  // inventing a document the caller never sent. Zero-length bytes now reach the parse boundary and are
  // refused there, which is a truer answer and keeps document validity in one place.
  const fx = setupGate({ approverRole: "approve-critical" });
  const res = fx.engine.createHold(fx.agent, "idem-empty", new Uint8Array(0));
  assert.equal(res.status, 422, `an empty body must not be treated as a document (got ${res.status})`);
  assert.equal((res.body as { error?: string }).error, "BODY_NOT_STRICT_JSON");
});

test("bytes-in: the gate's signed decisionArtifactHash commits to the VERIFIED document", () => {
  // ⚠ THE ROOT-CAUSE REGRESSION TEST. This is the defect measured at the top of this section, asserted
  // as an outcome rather than as a line number: whatever the gate SIGNS as `decisionArtifactHash` must
  // be the hash of the artifact it actually authenticated and stored. Pre-slice the two differed,
  // because the signed hash came from the live caller object and the verification came from its parse.
  const fx = setupGate({ approverRole: "approve-critical" });
  const created = fx.engine.createHold(fx.agent, "idem-rc", body({
    action: ACTION, params: sampleCommandParams(), chain: "chain-rc",
  }));
  assert.equal(created.status, 201);
  const holdId = (created.body as { holdId: string }).holdId;
  const hold = fx.store.getHold(holdId)!;
  const { receipt, decisionArtifact } = signPhoneDecision({
    trust: fx.trust, deferredReceipt: hold.deferredReceipt, holdEnvelope: hold.holdEnvelope, decision: "APPROVE",
  });

  // `reasonCode` is deliberately a field the engine does NOT cross-check against anything, so nothing
  // but the single-read property stands between this poison and a laundered hash.
  const poisoned = poisonKey(decisionArtifact, "reasonCode", String(decisionArtifact["reasonCode"]), "ATTACKER-CHOSEN");

  const res = fx.engine.decide(holdId, body({ receipt, decisionArtifact: poisoned.view }));
  assert.equal(res.status, 200, `fixture precondition: the honest signature still verifies (${JSON.stringify(res.body)})`);
  assert.equal(poisoned.reads(), 1, `the poison must fire exactly once (fired ${poisoned.reads()}×)`);

  const after = fx.store.getHold(holdId)!;
  const signedHash = after.holdResolution?.decisionArtifactHash;
  assert.equal(signedHash, refHash(after.decisionArtifact as Record<string, unknown>),
    "the gate signed a decisionArtifactHash that is NOT the hash of the artifact it verified and " +
      "stored. That is a gate signature laundering a document the gate never authenticated.");
  assert.notEqual(signedHash, refHash({ ...(after.decisionArtifact as Record<string, unknown>), reasonCode: "ATTACKER-CHOSEN" }),
    "the signed hash commits to the ATTACKER's never-verified form of the artifact");
});

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// ADR-0005 SLICE 2 — argv CAPTURE-ONCE + THE RENDER NODE.
//
// M7 above pins the defect at the ENGINE boundary. These pin it at the PROJECTION boundary, which is a
// separate and independently reachable surface: `getProjection` is a public export (`index.ts`), so
// `run()` is callable in-process by any consumer, with no HTTP body and no parse in between.
//
// THE DEFECT, MEASURED through that public surface on the tree Slice 2 replaces:
//
//     class Hostile extends Array { join() { return "--help"; } }
//     argv = ["-rf", "/srv"]; argv.constructor = { [Symbol.species]: Hostile };
//
//     display.Args (human reads) : "--help"
//     paramsHash (gate binds)    : sha256:2234882…   === the hash of "-rf /srv"
//
// `Array.prototype.slice` calls ArraySpeciesCreate, which reads `argv.constructor[Symbol.species]` —
// caller-controlled — so the "immutable snapshot" was an ATTACKER INSTANCE. `Object.freeze` on it froze
// its properties; the split lived in `join()`, which is a METHOD. The human authorized `--help` while
// the grant bound `rm -rf /srv`.
// ─────────────────────────────────────────────────────────────────────────────────────────────────

const CMD_BASE = { executable: "/bin/rm", cwd: "/srv", targetEnv: "production" } as const;

async function projection(): Promise<{ run: (p: unknown) => Record<string, unknown> }> {
  const m = await import("../src/projections.js");
  const p = m.getProjection("noa.command.exec");
  assert.ok(p, "fixture precondition: the reviewed adapter is registered");
  // ⚠ BOUND, NOT DESTRUCTURED. `run()` reads `this.canonical` / `this.actionSchema`, so
  // `const { run } = p` drops the receiver and every call throws
  // "Cannot read properties of undefined (reading 'canonical')". My first version of this helper did
  // exactly that: all five tests below failed IDENTICALLY, including the anti-vacuity control — which
  // is the only reason it read as a broken fixture rather than as five security findings. Recorded
  // because that is precisely what rule 2 at the top of this file is for.
  const proj = p as unknown as { run: (params: unknown) => Record<string, unknown> };
  return { run: (params: unknown) => proj.run.call(proj, params) };
}

/** THE property, stated once and reused: what the human is SHOWN must be what the digest BINDS. */
function assertDisplayBindsWhatItShows(res: Record<string, unknown>, run: (p: unknown) => Record<string, unknown>, label: string): void {
  assert.equal(res["ok"], true, `${label}: expected an accepted result, got ${JSON.stringify(res["error"])}`);
  const shown = String((res["display"] as Record<string, unknown>)["Args"] ?? "");
  // Re-run the adapter on EXACTLY the argv the human read. If the display and the digest describe the
  // same command, the two hashes are identical. This is the M7 lesson: comparing the digest to a
  // hard-coded reference survives its own knockout, because the split lands between the HASH and the
  // DISPLAY, not between validation and the hash.
  const reference = run({ ...CMD_BASE, argv: shown.length === 0 ? [] : shown.split(" ") });
  assert.equal(reference["ok"], true, `${label}: the reference run must succeed`);
  assert.equal(res["paramsHash"], reference["paramsHash"],
    `${label}: the human is shown Args="${shown}" but the authorized digest commits to a DIFFERENT ` +
      "command. The display and the paramsHash must be derived from one immutable value.");
}

test("Slice 2 / species: a caller-chosen Symbol.species cannot split the display from the digest", async () => {
  const { run } = await projection();
  class Hostile extends Array {
    override join(): string { return "--help"; }
  }
  const argv: unknown[] = ["-rf", "/srv"];
  (argv as { constructor: unknown }).constructor = { [Symbol.species]: Hostile };

  const res = run({ ...CMD_BASE, argv });
  assertDisplayBindsWhatItShows(res, run, "species");
  assert.equal(res["derivedRisk"], "CRITICAL",
    "`-rf` must still classify CRITICAL — the classifier reads the render node's array, and a species " +
      "attack must not be able to hide a destructive flag from it");
});

test("Slice 2 / capture-once: an index is read EXACTLY once, so a flip has nothing to split", async () => {
  const { run } = await projection();
  let indexReads = 0;
  const argv = new Proxy(["-rf", "/srv"], {
    get(t, k) {
      if (k === "0") { indexReads += 1; return indexReads <= 1 ? "-rf" : "--help"; }
      return Reflect.get(t, k);
    },
  });

  const res = run({ ...CMD_BASE, argv });
  assert.ok(indexReads >= 1, `the poison never fired (reads=${indexReads}) — inconclusive, not a pass`);
  assert.equal(indexReads, 1,
    `argv[0] was read ${indexReads} times. The previous shape read every index TWICE — once to type-check ` +
      "it, once inside `Array.prototype.slice` — so the value VALIDATED was not the value COPIED. " +
      "Capture and validation must be the same read.");
  assertDisplayBindsWhatItShows(res, run, "capture-once");
});

test("Slice 2 / length drift: argv.length is read once, so it cannot grow mid-walk", async () => {
  const { run } = await projection();
  let lengthReads = 0;
  // A real Array's `length` is non-configurable, so a Proxy is the only way to express this attack.
  const argv = new Proxy(["-rf", "/srv"], {
    get(t, k) {
      if (k === "length") { lengthReads += 1; return lengthReads <= 1 ? 2 : 5; }
      return Reflect.get(t, k);
    },
  });
  const res = run({ ...CMD_BASE, argv });
  assert.ok(lengthReads >= 1, `length was never read (reads=${lengthReads}) — inconclusive`);
  assert.equal(lengthReads, 1, `argv.length was read ${lengthReads} times; the walk's extent must not be revisable`);
  assertDisplayBindsWhatItShows(res, run, "length-drift");
});

test("Slice 2 / iterator: a poisoned Symbol.iterator cannot hide a destructive flag from the classifier", async () => {
  const { run } = await projection();
  // `for..of` dispatches through Symbol.iterator. The risk classifier used one; this iterator omits
  // `-rf`, which would have classified the command below down from CRITICAL and admitted a weaker
  // approver. Index walks do not consult it.
  const argv: unknown[] = ["-rf", "/srv"];
  (argv as unknown as Record<PropertyKey, unknown>)[Symbol.iterator] = function* (): Generator<string> { yield "/srv"; };

  const res = run({ ...CMD_BASE, argv });
  assert.equal(res["ok"], true, "the honest values are all strings, so the call must succeed");
  assert.equal(res["derivedRisk"], "CRITICAL",
    "a skipping iterator hid `-rf` from the risk classifier. The classifier must index-walk, or the " +
      "caller chooses its own approver tier by supplying an iterator.");
});

test("Slice 2 / holes and nesting are refused, and the bound is enforced", async () => {
  const { run } = await projection();
  const holed = new Array(3) as unknown[];
  holed[0] = "-rf";
  assert.equal(run({ ...CMD_BASE, argv: holed })["ok"], false, "a sparse argv must be refused, not read as undefined");
  assert.equal(run({ ...CMD_BASE, argv: [["-rf", "/srv"]] })["ok"], false,
    "a NESTED array must be refused — it used to render as `-rf,/srv` and classify below CRITICAL (F-05)");
  const over = run({ ...CMD_BASE, argv: new Array(5000).fill("-x") as unknown[] });
  assert.equal(over["ok"], false, "argv beyond MAX_ARGV must be refused");
  assert.match(String(over["error"]), /argv length/, "the refusal must name the bound it hit");
});

test("Slice 2 anti-vacuity: the honest paths still work and the reviewed floor is still granted", async () => {
  const { run } = await projection();
  // If every input above is refused for some unrelated reason, none of those tests proves anything.
  const honest = run({ ...CMD_BASE, argv: ["-rf", "/srv"] });
  assert.equal(honest["ok"], true, "an ordinary destructive command must still be processable");
  assert.equal((honest["display"] as Record<string, unknown>)["Args"], "-rf /srv", "the display must show the real argv");
  assert.equal(honest["derivedRisk"], "CRITICAL");

  const deploy = run({ executable: "/usr/local/bin/deploy", argv: ["--service", "api"], cwd: "/srv", targetEnv: "production" });
  assert.equal(deploy["ok"], true, "the reviewed deploy path must still work");
  assert.equal((deploy["display"] as Record<string, unknown>)["Args"], "--service api");
  assert.equal(deploy["derivedRisk"], "HIGH",
    "the allowlist must still grant its reviewed floor — otherwise everything is CRITICAL and the " +
      "classifier is a refusal, not a classifier");

  const empty = run({ ...CMD_BASE, argv: [] });
  assert.equal(empty["ok"], true, "an empty argv is legitimate (a bare command) and must not be refused");
  assert.equal((empty["display"] as Record<string, unknown>)["Args"], "", "an empty argv renders as an empty string");
});

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// ADR-0005 SLICE 4 — THE AUDIT KEY IS ALWAYS A RECIPIENT.
//
// `createAlphaTrust` provisions an AUDIT key with `roles: ["audit-decrypt"]` and publishes its HPKE
// public half on `GateTrust`. NOTHING EVER READ IT: `engine.ts` sealed every display to the approver
// alone, and the audit kid existed only as a string literal inside the key-manifest entry.
//
// So every display the gate sealed was openable by EXACTLY ONE PARTY. The gate signs
// `displayCiphertextHash` to bind what the human saw — and then no auditor, no incident responder and
// no tenant could ever open it to check what that was. A binding no third party can verify has to be
// taken on trust, which is the thing this project exists not to ask for.
// ─────────────────────────────────────────────────────────────────────────────────────────────────

test("Slice 4: every sealed display carries the AUDIT recipient, not the approver alone", () => {
  const fx = setupGate({ approverRole: "approve-critical" });
  const created = fx.engine.createHold(fx.agent, "idem-audit", body({
    action: ACTION, params: sampleCommandParams(), chain: "chain-audit",
  }));
  assert.equal(created.status, 201, `fixture precondition: hold created (got ${created.status})`);
  const hold = fx.store.getHold((created.body as { holdId: string }).holdId)!;
  const recipients = (hold.encryptedDisplay as unknown as Record<string, unknown>)["recipients"] as Array<{ kid: string }>;

  assert.ok(Array.isArray(recipients), "the sealed display must carry a recipients array");
  const kids = recipients.map((r) => r.kid);

  // The audit key is provisioned by the trust root; assert against THAT, never against a literal —
  // a hardcoded "audit-1" here would pass even if the engine sealed to a key the manifest never named.
  assert.ok(fx.trust.auditKid, "fixture precondition: the trust root provisions an audit kid");
  assert.ok(kids.includes(fx.trust.auditKid),
    `the sealed display is openable only by ${JSON.stringify(kids)}. The AUDIT key ` +
      `(${fx.trust.auditKid}) is provisioned with roles ["audit-decrypt"] and must ALWAYS be a ` +
      "recipient: otherwise the display the gate signs a commitment to can never be independently " +
      "recovered, and displayCiphertextHash binds something nobody but the approver can ever read.");
});

test("Slice 4 anti-vacuity: the APPROVER is still a recipient, and the honest flow still completes", () => {
  // Adding the audit recipient must not displace the approver — if it did, the human could no longer
  // read the request at all and the test above would pass on a completely broken gate.
  const fx = setupGate({ approverRole: "approve-critical" });
  const created = fx.engine.createHold(fx.agent, "idem-audit-av", body({
    action: ACTION, params: sampleCommandParams(), chain: "chain-audit-av",
  }));
  assert.equal(created.status, 201);
  const holdId = (created.body as { holdId: string }).holdId;
  const hold = fx.store.getHold(holdId)!;
  const kids = ((hold.encryptedDisplay as unknown as Record<string, unknown>)["recipients"] as Array<{ kid: string }>).map((r) => r.kid);

  assert.ok(kids.includes(fx.trust.approver.kid),
    `the approver (${fx.trust.approver.kid}) must remain a recipient; got ${JSON.stringify(kids)}`);
  assert.notEqual(fx.trust.auditKid, fx.trust.approver.kid, "sanity: the two recipients are distinct keys");

  // And the whole approval path still works with the widened recipient list — the sealed blob is bound
  // into the envelope via displayCiphertextHash, so a recipient change that broke the binding would
  // surface here rather than at a verifier months later.
  const { receipt, decisionArtifact } = signPhoneDecision({
    trust: fx.trust, deferredReceipt: hold.deferredReceipt, holdEnvelope: hold.holdEnvelope, decision: "APPROVE",
  });
  const decided = fx.engine.decide(holdId, body({ receipt, decisionArtifact }));
  assert.equal(decided.status, 200, `the honest approval must still succeed: ${JSON.stringify(decided.body)}`);
  assert.equal(fx.store.getHold(holdId)?.reasonCode, "HUMAN_APPROVED");
});
