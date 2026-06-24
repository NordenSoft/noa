import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, sign as cryptoSign } from "node:crypto";
import { generateKeyPair, signEd25519 } from "../../src/keys.js";
import { buildReceipt, type BuildInput, type Signer } from "../../src/builder.js";
import { receiptToCose, receiptFromCose } from "../../src/cose/receipt-cose.js";
import { coseSign1, coseSign1Verify } from "../../src/cose/cose-sign1.js";
import { encInt, encBstr, encTstr, encArray, encMap, encTag, decode, CborError } from "../../src/cose/cbor.js";
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

test("alg-confusion: a COSE_Sign1 whose protected header isn't {alg:Ed25519} is rejected", () => {
  const kp = generateKeyPair("k");
  // hand-build a tag-18 with protected = {1: alg} → must reject for any alg != -19 (Ed25519, RFC 9864),
  // INCLUDING the now-deprecated generic EdDSA (-8) and ES256 (-7). Pinning the curve-specific -19
  // (rather than -8, which also admits Ed448) closes the alg-id-layer confusion surface.
  for (const badAlg of [-7 /* ES256 */, -8 /* generic EdDSA, deprecated */, -35 /* ES384 */]) {
    const badProtected = encMap([[encInt(1), encInt(badAlg)]]);
    const body = encArray([encBstr(badProtected), encMap([[encInt(4), encBstr(Buffer.from("k"))]]), encBstr(Buffer.from("x")), encBstr(Buffer.alloc(64))]);
    const cose = Buffer.concat([Buffer.from([0xd2]), body]);
    const r = coseSign1Verify(cose, { k: kp.publicKey });
    assert.equal(r.ok, false, `alg ${badAlg} must be rejected`);
    assert.match(r.reason ?? "", /Ed25519/);
  }
});

test("curve-pin: an Ed448 key + {1:-19} protected + genuine Ed448 signature is REJECTED (defends past the alg-id check)", () => {
  // The alg-id check ({1:-19}) closes the registry-layer confusion; this test proves the SECOND,
  // deeper defense — the node:crypto curve-type pin in verifyEd25519. We construct a COSE_Sign1 that
  // PASSES isEd25519Protected (protected = {1:-19}, the very alg we accept) yet is signed by a real
  // Ed448 key whose SPKI sits in the keyring under the kid. If verification dispatched on the key type
  // (cryptoVerify(null, …) does), this Ed448 signature would verify TRUE under alg "Ed25519" —
  // algorithm/key confusion (CWE-347). The asymmetricKeyType !== "ed25519" pin must reject it.
  const { publicKey, privateKey } = generateKeyPairSync("ed448");
  const kid = "ed448-key";
  const pubB64 = (publicKey.export({ type: "spki", format: "der" }) as Buffer).toString("base64");

  // hand-build the COSE_Sign1 exactly as cose-sign1.ts does, but sign with the Ed448 key:
  const prot = encMap([[encInt(1), encInt(-19)]]); // {1:-19} — accepted by isEd25519Protected
  const payload = Buffer.from("ed448-attack-payload", "utf8");
  const sigStructure = encArray([encTstr("Signature1"), encBstr(prot), encBstr(Buffer.alloc(0)), encBstr(payload)]);
  const sig = cryptoSign(null, sigStructure, privateKey); // a GENUINE Ed448 signature over the Sig_structure
  const unprotected = encMap([[encInt(4), encBstr(Buffer.from(kid, "utf8"))]]);
  const body = encArray([encBstr(prot), unprotected, encBstr(payload), encBstr(sig)]);
  const cose = encTag(18, body);

  const r = coseSign1Verify(cose, { [kid]: pubB64 });
  assert.equal(r.ok, false, "an Ed448 key/sig must be rejected even when the protected header says Ed25519 (curve pin)");
  assert.match(r.reason ?? "", /bad signature/); // reaches the verify step; rejected by the curve-type pin
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

test("ROUND-16 #5: a non-object keyring (null / array / non-object) ⇒ clean ok:false, never throws (COSE path)", () => {
  const kp = generateKeyPair("k");
  const cose = coseSign1(Buffer.from("x"), { kid: "k", privateKey: kp.privateKey });

  // coseSign1Verify: null / array / non-object keyring → clean ok:false, doesNotThrow (round-15 #7 parity)
  for (const bad of [null, [], "x", 5]) {
    let r!: ReturnType<typeof coseSign1Verify>;
    assert.doesNotThrow(() => { r = coseSign1Verify(cose, bad as never); });
    assert.equal(r.ok, false, `coseSign1Verify must fail-closed on keyring=${JSON.stringify(bad)}`);
    assert.match(r.reason ?? "", /keyring must be an object/);
  }

  // receiptFromCose: same guard at its own entry, before any manifest work
  const receipt = mkReceipt({ kid: kp.kid, privateKey: kp.privateKey });
  const wrapped = receiptToCose(receipt, { kid: kp.kid, privateKey: kp.privateKey });
  for (const bad of [null, [], "x"]) {
    let r!: ReturnType<typeof receiptFromCose>;
    assert.doesNotThrow(() => { r = receiptFromCose(wrapped, bad as never); });
    assert.equal(r.ok, false, `receiptFromCose must fail-closed on keyring=${JSON.stringify(bad)}`);
    assert.match(r.reason ?? "", /keyring must be an object/);
  }

  // sanity: a genuine keyring still verifies (no happy-path regression)
  assert.equal(coseSign1Verify(cose, { k: kp.publicKey }).ok, true);
  assert.equal(receiptFromCose(wrapped, { [kp.kid]: kp.publicKey }).ok, true);
});

// ── FORWARD-COMPAT relaxation (verifier accepts draft-conformant peers; alg-pin preserved) ──────────
// helper: hand-build a COSE_Sign1 with an ARBITRARY protected map + unprotected map, signed by `priv`.
function buildCose(protectedMap: Buffer, unprotectedMap: Buffer, payload: Buffer, privB64: string): Buffer {
  const sigStruct = encArray([encTstr("Signature1"), encBstr(protectedMap), encBstr(Buffer.alloc(0)), encBstr(payload)]);
  const sig = Buffer.from(signEd25519(privB64, sigStruct), "base64");
  return encTag(18, encArray([encBstr(protectedMap), unprotectedMap, encBstr(payload), encBstr(sig)]));
}

test("FWD-COMPAT (a): kid in the PROTECTED header {1:-19, 4:kid} is accepted AND verifies", () => {
  const kp = generateKeyPair("k-prot");
  const payload = Buffer.from("kid-in-protected-payload", "utf8");
  // protected = {1:-19, 4:"k-prot"} (kid signed-in); unprotected = {} (empty)
  const prot = encMap([[encInt(1), encInt(-19)], [encInt(4), encBstr(Buffer.from("k-prot", "utf8"))]]);
  const cose = buildCose(prot, encMap([]), payload, kp.privateKey);
  const r = coseSign1Verify(cose, { "k-prot": kp.publicKey });
  assert.equal(r.ok, true, r.reason); // former exact-{1:-19} gate REJECTED this; now accepted
  assert.equal(r.kid, "k-prot"); // resolved from the protected (signed) bucket
  assert.equal(r.payload?.toString("utf8"), "kid-in-protected-payload");
});

test("FWD-COMPAT (a'): protected kid is preferred over a DIFFERENT unprotected kid (signed copy wins)", () => {
  const kp = generateKeyPair("signer-key");
  const payload = Buffer.from("x", "utf8");
  const prot = encMap([[encInt(1), encInt(-19)], [encInt(4), encBstr(Buffer.from("signer-key", "utf8"))]]);
  // unprotected carries a DECOY kid; the protected (signed) one must win → keyring lookup uses signer-key
  const unprot = encMap([[encInt(4), encBstr(Buffer.from("attacker-decoy-kid", "utf8"))]]);
  const cose = buildCose(prot, unprot, payload, kp.privateKey);
  const r = coseSign1Verify(cose, { "signer-key": kp.publicKey });
  assert.equal(r.ok, true, r.reason);
  assert.equal(r.kid, "signer-key");
});

test("FWD-COMPAT (a''): a protected kid (label 4) that is NOT a bstr fails CLOSED — no downgrade to the unsigned unprotected kid", () => {
  const kp = generateKeyPair("real-key");
  const payload = Buffer.from("x", "utf8");
  // protected kid is mistyped (an int, not a bstr); a DECOY valid kid sits in the UNSIGNED unprotected
  // bucket. The verifier must REJECT — never silently fall through to the unsigned kid. (cross-family QA, surface B)
  const prot = encMap([[encInt(1), encInt(-19)], [encInt(4), encInt(42)]]);
  const unprot = encMap([[encInt(4), encBstr(Buffer.from("real-key", "utf8"))]]);
  const cose = buildCose(prot, unprot, payload, kp.privateKey);
  const r = coseSign1Verify(cose, { "real-key": kp.publicKey });
  assert.equal(r.ok, false, "a non-bstr protected kid must fail closed, not downgrade to the unsigned bucket");
  assert.match(r.reason ?? "", /protected kid .*must be a bstr/i);
});

test("FWD-COMPAT (b): an UNKNOWN critical header (crit lists a label we don't process) is REJECTED (fail-closed)", () => {
  const kp = generateKeyPair("k-crit");
  const payload = Buffer.from("crit-payload", "utf8");
  // protected = {1:-19, 2:[3], 3:0} — crit declares content-type (label 3) critical, which we do NOT
  // process → reject. (We process only alg(1) + kid(4); anything else critical is fail-closed.)
  const prot = encMap([
    [encInt(1), encInt(-19)],
    [encInt(2), encArray([encInt(3)])],
    [encInt(3), encInt(0)],
    [encInt(4), encBstr(Buffer.from("k-crit", "utf8"))],
  ]);
  const cose = buildCose(prot, encMap([]), payload, kp.privateKey);
  const r = coseSign1Verify(cose, { "k-crit": kp.publicKey });
  assert.equal(r.ok, false, "a crit label the verifier cannot process must fail-closed");
  assert.match(r.reason ?? "", /critical/);
});

test("FWD-COMPAT (b''): a crit listing the kid label {2:[4]} is accepted — we DO process kid (key resolution)", () => {
  const kp = generateKeyPair("k-crit-kid");
  const payload = Buffer.from("p", "utf8");
  // crit declares kid (4) critical. We read+use kid for key resolution → we process it → accept
  // (closes the over-rejection of a draft-conformant kid-critical peer; cross-family QA, surface B).
  const prot = encMap([
    [encInt(1), encInt(-19)],
    [encInt(2), encArray([encInt(4)])],
    [encInt(4), encBstr(Buffer.from("k-crit-kid", "utf8"))],
  ]);
  const cose = buildCose(prot, encMap([]), payload, kp.privateKey);
  const r = coseSign1Verify(cose, { "k-crit-kid": kp.publicKey });
  assert.equal(r.ok, true, r.reason);
  assert.equal(r.kid, "k-crit-kid");
});

test("FWD-COMPAT (b'): a crit listing ONLY the alg label {2:[1]} is accepted (we DO process alg)", () => {
  const kp = generateKeyPair("k-crit-ok");
  const payload = Buffer.from("p", "utf8");
  const prot = encMap([[encInt(1), encInt(-19)], [encInt(2), encArray([encInt(1)])]]);
  const cose = buildCose(prot, encMap([[encInt(4), encBstr(Buffer.from("k-crit-ok", "utf8"))]]), payload, kp.privateKey);
  const r = coseSign1Verify(cose, { "k-crit-ok": kp.publicKey });
  assert.equal(r.ok, true, r.reason);
});

test("FWD-COMPAT (c): alg-confusion STILL closed — {1:-8} (deprecated EdDSA) is rejected post-relaxation", () => {
  const kp = generateKeyPair("k8");
  const payload = Buffer.from("p", "utf8");
  // even with a GENUINE Ed25519 signature, alg=-8 in the protected header must be rejected (alg pin).
  const prot = encMap([[encInt(1), encInt(-8)], [encInt(4), encBstr(Buffer.from("k8", "utf8"))]]);
  const cose = buildCose(prot, encMap([]), payload, kp.privateKey);
  const r = coseSign1Verify(cose, { k8: kp.publicKey });
  assert.equal(r.ok, false, "alg -8 must remain rejected after the forward-compat relaxation");
  assert.match(r.reason ?? "", /Ed25519/);
});

test("FWD-COMPAT (c'): an extra UNKNOWN non-critical protected label is IGNORED, envelope still verifies (RFC 9052 §3.1)", () => {
  const kp = generateKeyPair("k-extra");
  const payload = Buffer.from("p", "utf8");
  // protected = {1:-19, 4:kid, 15:bstr(CWT_Claims placeholder), 99:bstr(future/private label)} — none critical.
  const prot = encMap([
    [encInt(1), encInt(-19)],
    [encInt(4), encBstr(Buffer.from("k-extra", "utf8"))],
    [encInt(15), encBstr(Buffer.from("cwt", "utf8"))],
    [encInt(99), encBstr(Buffer.from("future", "utf8"))],
  ]);
  const cose = buildCose(prot, encMap([]), payload, kp.privateKey);
  const r = coseSign1Verify(cose, { "k-extra": kp.publicKey });
  assert.equal(r.ok, true, r.reason); // unknown non-critical labels ignored, not rejected (forward-compat)
  assert.equal(r.kid, "k-extra");
});

test("FWD-COMPAT (d): the legacy kid-in-UNPROTECTED envelope NOA itself emits STILL verifies (no regression)", () => {
  const kp = generateKeyPair("k-legacy");
  const cose = coseSign1(Buffer.from("legacy", "utf8"), { kid: "k-legacy", privateKey: kp.privateKey });
  const r = coseSign1Verify(cose, { "k-legacy": kp.publicKey });
  assert.equal(r.ok, true, r.reason);
  assert.equal(r.kid, "k-legacy");
});

test("round-17 #5: receiptFromCose with a throwing-accessor identityManifest → clean ok:false, never throws", () => {
  const kp = generateKeyPair("k");
  const receipt = mkReceipt({ kid: kp.kid, privateKey: kp.privateKey });
  const wrapped = receiptToCose(receipt, { kid: kp.kid, privateKey: kp.privateKey });
  const keyring = { [kp.kid]: kp.publicKey };

  // a manifest whose ENTRY getter throws — pre-fix the COSE path had no try/catch, so it escaped as a raw
  // throw (unlike verifyChain). The guard makes it a clean ok:false.
  const evilEntry: Record<string, unknown> = {};
  Object.defineProperty(evilEntry, "a1", { enumerable: true, configurable: true, get() { throw new Error("boom"); } });
  let r1!: ReturnType<typeof receiptFromCose>;
  assert.doesNotThrow(() => { r1 = receiptFromCose(wrapped, keyring, evilEntry as never); });
  assert.equal(r1.ok, false);

  // a manifest entry that IS an array but whose element getter throws — same fail-closed contract.
  const arr: string[] = [];
  Object.defineProperty(arr, "0", { enumerable: true, configurable: true, get() { throw new Error("boom"); } });
  arr.length = 1;
  let r2!: ReturnType<typeof receiptFromCose>;
  assert.doesNotThrow(() => { r2 = receiptFromCose(wrapped, keyring, { a1: arr } as never); });
  assert.equal(r2.ok, false);

  // sanity: a genuine manifest still binds (no regression) — a1 authorized for k.
  assert.equal(receiptFromCose(wrapped, keyring, { a1: ["k"] }).ok, true);
});
