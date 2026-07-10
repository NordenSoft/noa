import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPair } from "../src/keys.js";
import { buildReceipt, buildCheckpoint, BuilderError, type BuildInput, type Signer } from "../src/builder.js";
import { verifyChain, verifyCheckpoint } from "../src/verify.js";
import { sha256Prefixed } from "../src/hash.js";
import type { Receipt } from "../src/index.js";

function mkInput(seqId: string, ts: string): BuildInput {
  return {
    id: `rcpt_${seqId}`,
    ts,
    scope: { tenant: "t", chain: "c1" },
    agent: { id: "a1", model: null, principal: "SERVICE" },
    action: {
      id: "db.delete",
      canonical: "db.delete",
      riskClass: "CRITICAL",
      paramsHash: sha256Prefixed("table=orders;id=1"),
      reversible: true,
      rollbackRef: "snap_1",
    },
    governance: { mode: "on", verdict: "EXECUTED", ruleId: "r", approval: null, sandboxed: false },
  };
}

function mkSigner(): Signer {
  const kp = generateKeyPair("k1");
  return { kid: kp.kid, privateKey: kp.privateKey };
}

// ── A3: buildReceipt must refuse to hand back a signed-but-MALFORMED receipt ──────────────

test("A3 happy path: valid input -> buildReceipt -> verifyChain is VALID", () => {
  const pair = generateKeyPair("k2");
  const signer: Signer = { kid: pair.kid, privateKey: pair.privateKey };
  const keyring = { [pair.kid]: pair.publicKey };

  const r = buildReceipt(mkInput("0", "2026-06-20T00:00:00.000Z"), null, signer);
  const res = verifyChain([r], { keyring });
  assert.equal(res.status, "VALID", res.reason);
});

test("A3 PoC: id over the 128-code-point cap throws BuilderError (never returns a signed receipt)", () => {
  const signer = mkSigner();
  const bad = mkInput("0", "2026-06-20T00:00:00.000Z");
  bad.id = "x".repeat(129); // exceeds receipt.id: non-empty string <=128 code points
  assert.throws(() => buildReceipt(bad, null, signer), BuilderError);
  try {
    buildReceipt(bad, null, signer);
    assert.fail("expected buildReceipt to throw");
  } catch (e) {
    assert.ok(e instanceof BuilderError);
    assert.match((e as BuilderError).message, /receipt\.id/);
    assert.ok((e as BuilderError).errors.some((m) => /receipt\.id/.test(m)));
  }
});

test("A3 PoC: malformed paramsHash throws BuilderError (never returns a signed receipt)", () => {
  const signer = mkSigner();
  const bad = mkInput("0", "2026-06-20T00:00:00.000Z");
  bad.action.paramsHash = "not-a-valid-hash";
  assert.throws(() => buildReceipt(bad, null, signer), BuilderError);
  try {
    buildReceipt(bad, null, signer);
    assert.fail("expected buildReceipt to throw");
  } catch (e) {
    assert.ok(e instanceof BuilderError);
    assert.match((e as BuilderError).message, /paramsHash/);
  }
});

test("A3 PoC: an untyped caller smuggling an unknown field is rejected, not silently signed", () => {
  const signer = mkSigner();
  const bad = mkInput("0", "2026-06-20T00:00:00.000Z") as BuildInput & { action: Record<string, unknown> };
  (bad.action as unknown as Record<string, unknown>)["secretPII"] = "victim@example.com";
  assert.throws(() => buildReceipt(bad, null, signer), BuilderError);
});

test("A3 mutation-safety: mutating the caller's input object after build does NOT corrupt the signed receipt", () => {
  const pair = generateKeyPair("k3");
  const signer: Signer = { kid: pair.kid, privateKey: pair.privateKey };
  const keyring = { [pair.kid]: pair.publicKey };

  const input = mkInput("0", "2026-06-20T00:00:00.000Z");
  const r = buildReceipt(input, null, signer);

  // Mutate every caller-supplied nested object AFTER the call.
  input.scope.chain = "TAMPERED-CHAIN";
  input.agent.id = "TAMPERED-AGENT";
  input.action.riskClass = "LOW";
  input.governance.verdict = "BLOCKED";

  assert.equal(r.scope.chain, "c1", "receipt must not alias caller's scope object");
  assert.equal(r.agent.id, "a1", "receipt must not alias caller's agent object");
  assert.equal(r.action.riskClass, "CRITICAL", "receipt must not alias caller's action object");
  assert.equal(r.governance.verdict, "EXECUTED", "receipt must not alias caller's governance object");

  const res = verifyChain([r], { keyring });
  assert.equal(res.status, "VALID", res.reason);
});

// ── A3: buildCheckpoint must refuse to hand back a signed-but-MALFORMED checkpoint ────────

test("A3 checkpoint happy path: valid head -> buildCheckpoint -> verifyCheckpoint is ok", () => {
  const pair = generateKeyPair("k4");
  const signer: Signer = { kid: pair.kid, privateKey: pair.privateKey };
  const keyring = { [pair.kid]: pair.publicKey };

  const head = buildReceipt(mkInput("0", "2026-06-20T00:00:00.000Z"), null, signer);
  const cp = buildCheckpoint(head, "2026-06-20T06:00:00.000Z", signer);
  assert.equal(verifyCheckpoint(cp, keyring), "ok");
});

test("A3 checkpoint PoC: malformed ts throws BuilderError (never returns a signed checkpoint)", () => {
  const pair = generateKeyPair("k5");
  const signer: Signer = { kid: pair.kid, privateKey: pair.privateKey };
  const head = buildReceipt(mkInput("0", "2026-06-20T00:00:00.000Z"), null, signer);

  assert.throws(() => buildCheckpoint(head, "not-a-timestamp", signer), BuilderError);
  try {
    buildCheckpoint(head, "not-a-timestamp", signer);
    assert.fail("expected buildCheckpoint to throw");
  } catch (e) {
    assert.ok(e instanceof BuilderError);
    assert.match((e as BuilderError).message, /checkpoint\.ts/);
  }
});

test("A3 checkpoint PoC: empty signer.kid throws BuilderError", () => {
  const pair = generateKeyPair("");
  const signer: Signer = { kid: "", privateKey: pair.privateKey };
  const head = buildReceipt(mkInput("0", "2026-06-20T00:00:00.000Z"), null, { kid: "k6", privateKey: pair.privateKey });

  assert.throws(() => buildCheckpoint(head, "2026-06-20T06:00:00.000Z", signer), BuilderError);
});

test("A3 checkpoint mutation-safety: mutating `head` after buildCheckpoint does NOT corrupt the signed checkpoint", () => {
  const pair = generateKeyPair("k7");
  const signer: Signer = { kid: pair.kid, privateKey: pair.privateKey };
  const keyring = { [pair.kid]: pair.publicKey };

  const head: Receipt = buildReceipt(mkInput("0", "2026-06-20T00:00:00.000Z"), null, signer);
  const cp = buildCheckpoint(head, "2026-06-20T06:00:00.000Z", signer);

  // Mutate `head` AFTER the checkpoint was built.
  head.scope.chain = "TAMPERED-CHAIN";
  (head.chain as { seq: number }).seq = 999;
  (head.chain as { hash: string }).hash = "sha256:" + "0".repeat(64);

  assert.equal(cp.chain, "c1", "checkpoint must not alias caller's head.scope object");
  assert.equal(cp.highestSeq, 0, "checkpoint must not alias caller's head.chain object");
  assert.notEqual(cp.headHash, "sha256:" + "0".repeat(64));
  assert.equal(verifyCheckpoint(cp, keyring), "ok");
});
