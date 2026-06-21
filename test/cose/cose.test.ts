import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPair } from "../../src/keys.js";
import { buildReceipt, type BuildInput, type Signer } from "../../src/builder.js";
import { receiptToCose, receiptFromCose } from "../../src/cose/receipt-cose.js";
import { coseSign1, coseSign1Verify } from "../../src/cose/cose-sign1.js";
import { encInt, encBstr, encTstr, encArray, encMap, decode, CborError } from "../../src/cose/cbor.js";
import { sha256Prefixed } from "../../src/hash.js";
import { canonicalize } from "../../src/jcs.js";

function mkReceipt(signer: Signer) {
  const input: BuildInput = {
    id: "rcpt_cose_0",
    ts: "2026-06-21T10:00:00.000Z",
    scope: { tenant: "t", chain: "c1" },
    agent: { id: "a1", model: null, principal: "SERVICE" },
    action: { id: "payment.refund", canonical: "payment.refund", riskClass: "HIGH", paramsHash: sha256Prefixed("x"), reversible: false, rollbackRef: null },
    governance: { mode: "on", verdict: "EXECUTED", ruleId: "r", approval: null, sandboxed: false },
  };
  return buildReceipt(input, null, signer);
}

test("CBOR: deterministic canonical encoding round-trips (int/bstr/tstr/array/map)", () => {
  const m = encMap([[encInt(4), encBstr(Buffer.from("kid"))], [encInt(1), encInt(-8)]]);
  const d = decode(m);
  assert.equal(d.t, "map");
  // canonical: key 1 must sort before key 4 regardless of insertion order
  if (d.t === "map") {
    const firstKey = d.v[0]![0];
    assert.equal(firstKey.t === "int" ? firstKey.v : NaN, 1);
  }
  assert.deepEqual(decode(encArray([encTstr("Signature1"), encInt(0)])), {
    t: "array", v: [{ t: "tstr", v: "Signature1" }, { t: "int", v: 0 }],
  });
});

test("receipt → COSE_Sign1 → verify round-trips, returns the receipt", () => {
  const kp = generateKeyPair("noa-key-1");
  const signer: Signer = { kid: kp.kid, privateKey: kp.privateKey };
  const keyring = { [kp.kid]: kp.publicKey };
  const receipt = mkReceipt(signer);

  const cose = receiptToCose(receipt, { kid: kp.kid, privateKey: kp.privateKey });
  assert.ok(Buffer.isBuffer(cose) && cose.length > 0);
  assert.equal(cose[0], 0xd2); // CBOR tag 18 (0xc0|18=0xd2) — a real COSE_Sign1 tag

  const r = receiptFromCose(cose, keyring);
  assert.equal(r.ok, true, r.reason);
  assert.equal(r.kid, "noa-key-1");
  // canonical-equivalence (safeParse yields null-prototype objects; bytes are what matter)
  assert.equal(canonicalize(r.receipt), canonicalize(receipt));
});

test("COSE_Sign1: tampered payload fails verification", () => {
  const kp = generateKeyPair("k");
  const keyring = { k: kp.publicKey };
  const cose = coseSign1(Buffer.from("hello", "utf8"), { kid: "k", privateKey: kp.privateKey });
  assert.equal(coseSign1Verify(cose, keyring).ok, true);
  const tampered = Buffer.from(cose);
  // flip a byte inside the payload region (find 'hello')
  const idx = tampered.indexOf(Buffer.from("hello"));
  tampered[idx] = tampered[idx]! ^ 0x01;
  assert.equal(coseSign1Verify(tampered, keyring).ok, false);
});

test("COSE_Sign1: unknown kid / no keyring entry ⇒ not verified (never throws)", () => {
  const kp = generateKeyPair("k");
  const cose = coseSign1(Buffer.from("x"), { kid: "k", privateKey: kp.privateKey });
  const r = coseSign1Verify(cose, {}); // empty keyring
  assert.equal(r.ok, false);
  assert.match(r.reason ?? "", /unknown kid/);
});

test("COSE_Sign1: malformed CBOR ⇒ ok:false, no throw", () => {
  assert.equal(coseSign1Verify(Buffer.from([0xff, 0x00, 0x13]), { k: "x" }).ok, false);
  assert.equal(coseSign1Verify(Buffer.from([0x80]), { k: "x" }).ok, false); // empty array, not tag 18
});

test("ROUND-3: decoder REJECTS non-canonical CBOR (shortest-form + sorted/unique map keys)", () => {
  // non-minimal int heads (a strict COSE/SCITT verifier rejects these; so must NOA)
  assert.throws(() => decode(Buffer.from([0x19, 0x00, 0x05])), CborError); // 5 in 2 bytes
  assert.throws(() => decode(Buffer.from([0x18, 0x05])), CborError); // 5 in 1 byte
  assert.throws(() => decode(Buffer.from([0x1a, 0x00, 0x00, 0x00, 0x05])), CborError); // 5 in 4 bytes
  // duplicate + out-of-order map keys
  assert.throws(() => decode(Buffer.from([0xa2, 0x01, 0x00, 0x01, 0x01])), CborError); // dup key 1
  assert.throws(() => decode(Buffer.from([0xa2, 0x02, 0x00, 0x01, 0x00])), CborError); // keys 2,1 out of order
  // canonical forms still decode
  assert.equal((decode(Buffer.from([0x05])) as { v: number }).v, 5);
  assert.equal((decode(Buffer.from([0xa2, 0x01, 0x00, 0x02, 0x00])) as { t: string }).t, "map"); // 1,2 sorted
});

test("alg-confusion: a COSE_Sign1 whose protected header isn't {alg:EdDSA} is rejected", () => {
  // hand-build a tag-18 with protected = {1: -7} (ES256, not EdDSA) → must reject
  const kp = generateKeyPair("k");
  const badProtected = encMap([[encInt(1), encInt(-7)]]);
  const body = encArray([encBstr(badProtected), encMap([[encInt(4), encBstr(Buffer.from("k"))]]), encBstr(Buffer.from("x")), encBstr(Buffer.alloc(64))]);
  const cose = Buffer.concat([Buffer.from([0xd2]), body]);
  const r = coseSign1Verify(cose, { k: kp.publicKey });
  assert.equal(r.ok, false);
  assert.match(r.reason ?? "", /EdDSA/);
});

test("ROUND-6: a truncated multi-byte CBOR head throws typed CborError (not raw RangeError) — contract + DoS guard", () => {
  // Every truncated head width must surface the DOCUMENTED CborError, never Node's raw RangeError (which
  // would crash a contract-following `catch (e) { if (e instanceof CborError) …; throw e }` consumer).
  for (const b of [[0x18], [0x19, 0x00], [0x1a, 0x00, 0x00], [0x1b, 0, 0, 0, 0, 0, 0, 0], [0x58], [0x78]]) {
    assert.throws(() => decode(Buffer.from(b)), CborError);
  }
  // nested truncation (inside an array / a COSE-shaped prefix) — the RangeError paths the fuzz surfaced
  assert.throws(() => decode(Buffer.from([0x81, 0x19, 0x00])), CborError);
  assert.throws(() => decode(Buffer.from([0xd2, 0x84, 0x5a, 0x00, 0x00])), CborError);
});

test("ROUND-8: receiptFromCose identity binding — impersonation on the COSE path is caught + kid-level warned", () => {
  const alice = generateKeyPair("alice-key");
  const bob = generateKeyPair("bob-key");
  const keyring = { [alice.kid]: alice.publicKey, [bob.kid]: bob.publicKey };
  const manifest = { alice: ["alice-key"], bob: ["bob-key"] };
  // impersonation: agent.id=alice, signed by bob
  const input: BuildInput = {
    id: "rcpt_imp", ts: "2026-06-21T10:00:00.000Z", scope: { tenant: "t", chain: "c1" },
    agent: { id: "alice", model: null, principal: "SERVICE" },
    action: { id: "payment.refund", canonical: "payment.refund", riskClass: "HIGH", paramsHash: sha256Prefixed("x"), reversible: false, rollbackRef: null },
    governance: { mode: "on", verdict: "EXECUTED", ruleId: "r", approval: null, sandboxed: false },
  };
  const imp = buildReceipt(input, null, { kid: bob.kid, privateKey: bob.privateKey });
  const cose = receiptToCose(imp, { kid: bob.kid, privateKey: bob.privateKey });
  // no manifest → ok:true (COSE sig valid) BUT an explicit kid-level-attribution warning (no longer silent)
  const weak = receiptFromCose(cose, keyring);
  assert.equal(weak.ok, true);
  assert.ok(weak.warnings.some((w) => /attribution is kid-level/.test(w)));
  // with manifest → impersonation rejected (alice not authorized for bob-key)
  const strong = receiptFromCose(cose, keyring, manifest);
  assert.equal(strong.ok, false);
  assert.match(strong.reason ?? "", /not authorized for signing key/);
});

test("ROUND-11 HIGH: receiptFromCose identity binding is TOCTOU-safe — a flipping accessor manifest entry → ok:false (read-once snapshot)", () => {
  const alice = generateKeyPair("alice-key");
  const bob = generateKeyPair("bob-key");
  const keyring = { [alice.kid]: alice.publicKey, [bob.kid]: bob.publicKey };
  // impersonation: agent.id=alice signed by bob, wrapped as COSE
  const input: BuildInput = {
    id: "rcpt_imp_toctou", ts: "2026-06-21T10:00:00.000Z", scope: { tenant: "t", chain: "c1" },
    agent: { id: "alice", model: null, principal: "SERVICE" },
    action: { id: "payment.refund", canonical: "payment.refund", riskClass: "HIGH", paramsHash: sha256Prefixed("x"), reversible: false, rollbackRef: null },
    governance: { mode: "on", verdict: "EXECUTED", ruleId: "r", approval: null, sandboxed: false },
  };
  const imp = buildReceipt(input, null, { kid: bob.kid, privateKey: bob.privateKey });
  const cose = receiptToCose(imp, { kid: bob.kid, privateKey: bob.privateKey });

  // a getter that returns ['alice-key'] to validation then ['bob-key'] to enforcement would, pre-fix,
  // "authorize" alice→bob-key (ok:true). The COSE-path snapshot reads the entry exactly once → ok:false.
  let reads = 0;
  const manifest: Record<string, string[]> = { bob: ["bob-key"] };
  Object.defineProperty(manifest, "alice", {
    enumerable: true, configurable: true,
    get() { return (++reads === 1 ? ["alice-key"] : ["bob-key"]) as string[]; },
  });
  const r = receiptFromCose(cose, keyring, manifest);
  assert.equal(r.ok, false, "the flipping accessor must not authorize the impersonation");
  assert.match(r.reason ?? "", /not authorized for signing key/);
  assert.equal(reads, 1, "the COSE-path manifest entry must be read EXACTLY ONCE (snapshot)");
});
