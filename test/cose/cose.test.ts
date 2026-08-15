import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, sign as cryptoSign } from "node:crypto";
import { generateKeyPair, signEd25519 } from "../../src/keys.js";
import { buildReceipt, type BuildInput, type Signer } from "../../src/builder.js";
import { receiptToCose, receiptFromCose } from "../../src/cose/receipt-cose.js";
import { coseSign1, coseSign1Verify } from "../../src/cose/cose-sign1.js";
import { encInt, encBstr, encTstr, encArray, encMap, encTag, decode, CborError } from "../../src/cose/cbor.js";
import { sha256Prefixed } from "../../src/hash.js";
import { isInertArray } from "../../src/inert.js";
import { canonicalize } from "../../src/jcs.js";
import { b } from "../helpers/bytes.js";

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
  const rt = decode(encArray([encTstr("Signature1"), encInt(0)]));
  assert.equal(rt.t, "array");
  // `Array.from` because the decoder re-roots its arrays onto INERT_ARRAY_PROTOTYPE (T19) and
  // `deepStrictEqual` compares prototypes. The re-rooting is what stops a substituting
  // `Array.prototype[Symbol.iterator]` from rewriting the protected header's alg at CHECK time; the
  // rooting itself is asserted below so this test measures the property rather than tolerating it.
  assert.deepEqual(Array.from(rt.t === "array" ? rt.v : []), [{ t: "tstr", v: "Signature1" }, { t: "int", v: 0 }]);
  assert.equal(isInertArray(rt.t === "array" ? rt.v : null), true, "decoded arrays must be inert-rooted");
  assert.equal(isInertArray(d.t === "map" ? d.v : null), true, "decoded maps must be inert-rooted");
  assert.equal(isInertArray(d.t === "map" ? d.v[0] : null), true, "each decoded map PAIR must be inert-rooted too — destructuring dispatches through the pair's own iterator");
});

test("receipt → COSE_Sign1 → verify round-trips, returns the receipt", () => {
  const kp = generateKeyPair("noa-key-1");
  const signer: Signer = { kid: kp.kid, privateKey: kp.privateKey };
  const keyring = { [kp.kid]: kp.publicKey };
  const receipt = mkReceipt(signer);

  const cose = receiptToCose(receipt, { kid: kp.kid, privateKey: kp.privateKey });
  assert.ok(Buffer.isBuffer(cose) && cose.length > 0);
  assert.equal(cose[0], 0xd2); // CBOR tag 18 (0xc0|18=0xd2) — a real COSE_Sign1 tag

  const r = receiptFromCose(cose, b(keyring));
  assert.equal(r.ok, true, r.reason ?? "");
  assert.equal(r.kid, "noa-key-1");
  // canonical-equivalence (safeParse yields null-prototype objects; bytes are what matter)
  assert.equal(canonicalize(r.receipt), canonicalize(receipt));
});

test("P0-14: both public COSE verification surfaces refuse a lifecycle-retired signer outright", () => {
  const retired = generateKeyPair("cose-retired");
  const current = generateKeyPair("cose-current");
  const retiredReceipt = mkReceipt({ kid: retired.kid, privateKey: retired.privateKey });
  const currentReceipt = mkReceipt({ kid: current.kid, privateKey: current.privateKey });
  const retiredEnvelope = receiptToCose(retiredReceipt, { kid: retired.kid, privateKey: retired.privateKey });
  const currentEnvelope = receiptToCose(currentReceipt, { kid: current.kid, privateKey: current.privateKey });
  const lifecycle = b({
    spec: "noa.signing-key-lifecycle/0.1",
    keys: {
      [retired.kid]: { publicKey: retired.publicKey, retiredAt: "2026-08-01T08:36:12.643Z" },
      [current.kid]: { publicKey: current.publicKey, retiredAt: null },
    },
  });

  assert.equal(coseSign1Verify(currentEnvelope, lifecycle).ok, true, "current-key control must verify");
  assert.equal(receiptFromCose(currentEnvelope, lifecycle).ok, true, "receipt current-key control must verify");

  const rawAttack = coseSign1Verify(retiredEnvelope, lifecycle);
  const receiptAttack = receiptFromCose(retiredEnvelope, lifecycle);
  assert.equal(rawAttack.ok, false, "raw COSE verifier accepted a lifecycle-retired key");
  assert.match(rawAttack.reason ?? "", /retired/i);
  assert.equal(receiptAttack.ok, false, "receipt COSE verifier accepted a lifecycle-retired key");
  assert.match(receiptAttack.reason ?? "", /retired/i);
});

test("P0-14 (enveloped): a CURRENT emitter cannot re-present a receipt signed by a RETIRED agent key", () => {
  // The test above retires the key that signs BOTH layers, so the outer check alone answers it. Here
  // the two keys differ: the envelope is signed by a live relay key and the retired key is only the
  // receipt's own. Nothing on the outer layer can see that, and an enveloped receipt is exactly how a
  // superseded key would be re-presented after its retirement.
  const retired = generateKeyPair("agent-retired");
  const current = generateKeyPair("agent-current");
  const relay = generateKeyPair("relay-live");
  const lifecycle = b({
    spec: "noa.signing-key-lifecycle/0.1",
    keys: {
      [retired.kid]: { publicKey: retired.publicKey, retiredAt: "2026-08-01T08:36:12.643Z" },
      [current.kid]: { publicKey: current.publicKey, retiredAt: null },
      [relay.kid]: { publicKey: relay.publicKey, retiredAt: null },
    },
  });

  const staleReceipt = mkReceipt({ kid: retired.kid, privateKey: retired.privateKey });
  const relayed = receiptToCose(staleReceipt, { kid: relay.kid, privateKey: relay.privateKey });
  const attack = receiptFromCose(relayed, lifecycle);
  assert.equal(attack.ok, false, "a live envelope must not resurrect a retired agent key");
  assert.equal(attack.agentClaim, "FAILED");
  assert.equal(attack.nativeKid, retired.kid);
  assert.equal(attack.envelopeClaim, "VERIFIED", "the relay's own signature is genuine — the two claims are separate");
  assert.match(attack.reason ?? "", /retired/i);

  // CONTROL: the identical shape with a live agent key verifies, so the refusal above is about
  // retirement and not about relaying.
  const liveReceipt = mkReceipt({ kid: current.kid, privateKey: current.privateKey });
  const ok = receiptFromCose(receiptToCose(liveReceipt, { kid: relay.kid, privateKey: relay.privateKey }), lifecycle);
  assert.equal(ok.ok, true, ok.reason ?? "");
  assert.equal(ok.agentClaim, "UNBOUND");
});

test("COSE_Sign1: tampered payload fails verification", () => {
  const kp = generateKeyPair("k");
  const keyring = { k: kp.publicKey };
  const cose = coseSign1(Buffer.from("hello", "utf8"), { kid: "k", privateKey: kp.privateKey });
  assert.equal(coseSign1Verify(cose, b(keyring)).ok, true);
  const tampered = Buffer.from(cose);
  // flip a byte inside the payload region (find 'hello')
  const idx = tampered.indexOf(Buffer.from("hello"));
  tampered[idx] = tampered[idx]! ^ 0x01;
  assert.equal(coseSign1Verify(tampered, b(keyring)).ok, false);
});

test("COSE_Sign1: unknown kid / no keyring entry ⇒ not verified (never throws)", () => {
  const kp = generateKeyPair("k");
  const cose = coseSign1(Buffer.from("x"), { kid: "k", privateKey: kp.privateKey });
  const r = coseSign1Verify(cose, b({})); // empty keyring
  assert.equal(r.ok, false);
  assert.match(r.reason ?? "", /unknown kid/);
});

test("COSE_Sign1: malformed CBOR ⇒ ok:false, no throw", () => {
  assert.equal(coseSign1Verify(Buffer.from([0xff, 0x00, 0x13]), b({ k: "x" })).ok, false);
  assert.equal(coseSign1Verify(Buffer.from([0x80]), b({ k: "x" })).ok, false); // empty array, not tag 18
});

test("decoder REJECTS non-canonical CBOR (shortest-form + sorted/unique map keys)", () => {
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
    const r = coseSign1Verify(cose, b({ k: kp.publicKey }));
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

  const r = coseSign1Verify(cose, b({ [kid]: pubB64 }));
  assert.equal(r.ok, false, "an Ed448 key/sig must be rejected even when the protected header says Ed25519 (curve pin)");
  assert.match(r.reason ?? "", /bad signature/); // reaches the verify step; rejected by the curve-type pin
});

test("a truncated multi-byte CBOR head throws typed CborError (not raw RangeError) — contract + DoS guard", () => {
  // Every truncated head width must surface the DOCUMENTED CborError, never Node's raw RangeError (which
  // would crash a contract-following `catch (e) { if (e instanceof CborError) …; throw e }` consumer).
  for (const b of [[0x18], [0x19, 0x00], [0x1a, 0x00, 0x00], [0x1b, 0, 0, 0, 0, 0, 0, 0], [0x58], [0x78]]) {
    assert.throws(() => decode(Buffer.from(b)), CborError);
  }
  // nested truncation (inside an array / a COSE-shaped prefix) — the RangeError paths the fuzz surfaced
  assert.throws(() => decode(Buffer.from([0x81, 0x19, 0x00])), CborError);
  assert.throws(() => decode(Buffer.from([0xd2, 0x84, 0x5a, 0x00, 0x00])), CborError);
});

test("receiptFromCose identity binding — impersonation on the COSE path is caught + kid-level warned", () => {
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
  const weak = receiptFromCose(cose, b(keyring));
  assert.equal(weak.ok, true);
  assert.ok(weak.warnings.some((w) => /attribution is kid-level/.test(w)));
  // with manifest → impersonation rejected (alice not authorized for bob-key)
  const strong = receiptFromCose(cose, b(keyring), b(manifest));
  assert.equal(strong.ok, false);
  assert.match(strong.reason ?? "", /not authorized for signing key/);
});

test("receiptFromCose identity binding is TOCTOU-safe — a flipping accessor manifest entry → ok:false, read ZERO times", () => {
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
  // "authorize" alice→bob-key (ok:true). The old fix read the entry EXACTLY ONCE into a private Map.
  let reads = 0;
  const manifest: Record<string, string[]> = { bob: ["bob-key"] };
  Object.defineProperty(manifest, "alice", {
    enumerable: true, configurable: true,
    get() { return (++reads === 1 ? ["alice-key"] : ["bob-key"]) as string[]; },
  });
  // ASSERTION CHANGED on two lines, both in the strict direction:
  //   • `reads === 1` → `reads === 0`. The manifest is a DOCUMENT now, so a live object is refused at
  //     the boundary rather than being read once into a snapshot. "Read once" was the best available
  //     guarantee while the object was traversed; "never read" is what replaces it.
  //   • the reason regex moves from the authorization failure to the boundary's own refusal, because
  //     the refusal happens before any (agent.id, kid) lookup. ok:false is unchanged, and the
  //     authorization path is re-asserted immediately below over the same manifest as BYTES.
  const r = receiptFromCose(cose, b(keyring), manifest as never);
  assert.equal(r.ok, false, "the flipping accessor must not authorize the impersonation");
  assert.match(r.reason ?? "", /expected Uint8Array or string/);
  assert.equal(reads, 0, "the COSE-path manifest entry must never be read from a caller object");

  // BOTH halves of the split as fixed documents — the only forms an attacker has left. The restrictive
  // manifest rejects the impersonation; the permissive one is what the flip was trying to smuggle in,
  // and supplying it openly is a caller decision, not a bypass.
  const restrictive = receiptFromCose(cose, b(keyring), b({ alice: ["alice-key"], bob: ["bob-key"] }));
  assert.equal(restrictive.ok, false);
  assert.match(restrictive.reason ?? "", /not authorized for signing key/);
  assert.equal(receiptFromCose(cose, b(keyring), b({ alice: ["alice-key", "bob-key"], bob: ["bob-key"] })).ok, true);
});

test("a non-object keyring (null / array / non-object) ⇒ clean ok:false, never throws (COSE path)", () => {
  const kp = generateKeyPair("k");
  const cose = coseSign1(Buffer.from("x"), { kid: "k", privateKey: kp.privateKey });

  // coseSign1Verify: a trust-root DOCUMENT that parses to null / array / non-object → clean ok:false,
  // doesNotThrow, same reason as before (parity with verifyChain).
  const receipt = mkReceipt({ kid: kp.kid, privateKey: kp.privateKey });
  const wrapped = receiptToCose(receipt, { kid: kp.kid, privateKey: kp.privateKey });
  for (const bad of [null, [], "x", 5]) {
    let r!: ReturnType<typeof coseSign1Verify>;
    assert.doesNotThrow(() => { r = coseSign1Verify(cose, b(bad as never)); });
    assert.equal(r.ok, false, `coseSign1Verify must fail-closed on keyring=${JSON.stringify(bad)}`);
    assert.match(r.reason ?? "", /keyring must be an object/);
    // receiptFromCose: same guard at its own entry, before any manifest work
    let r2!: ReturnType<typeof receiptFromCose>;
    assert.doesNotThrow(() => { r2 = receiptFromCose(wrapped, b(bad as never)); });
    assert.equal(r2.ok, false, `receiptFromCose must fail-closed on keyring=${JSON.stringify(bad)}`);
    assert.match(r2.reason ?? "", /keyring must be an object/);
  }

  // …and the same values as raw JavaScript, refused at the byte boundary. Fail-closed on both routes.
  for (const bad of [null, [], 5, {}]) {
    let r!: ReturnType<typeof coseSign1Verify>;
    assert.doesNotThrow(() => { r = coseSign1Verify(cose, bad as never); });
    assert.equal(r.ok, false, `coseSign1Verify must fail-closed on raw keyring=${JSON.stringify(bad)}`);
    assert.match(r.reason ?? "", /expected Uint8Array or string/);
    let r2!: ReturnType<typeof receiptFromCose>;
    assert.doesNotThrow(() => { r2 = receiptFromCose(wrapped, bad as never); });
    assert.equal(r2.ok, false, `receiptFromCose must fail-closed on raw keyring=${JSON.stringify(bad)}`);
    assert.match(r2.reason ?? "", /expected Uint8Array or string/);
  }

  // sanity: a genuine keyring still verifies (no happy-path regression)
  assert.equal(coseSign1Verify(cose, b({ k: kp.publicKey })).ok, true);
  assert.equal(receiptFromCose(wrapped, b({ [kp.kid]: kp.publicKey })).ok, true);
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
  const r = coseSign1Verify(cose, b({ "k-prot": kp.publicKey }));
  assert.equal(r.ok, true, r.reason ?? ""); // former exact-{1:-19} gate REJECTED this; now accepted
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
  const r = coseSign1Verify(cose, b({ "signer-key": kp.publicKey }));
  assert.equal(r.ok, true, r.reason ?? "");
  assert.equal(r.kid, "signer-key");
});

test("FWD-COMPAT (a''): a protected kid (label 4) that is NOT a bstr fails CLOSED — no downgrade to the unsigned unprotected kid", () => {
  const kp = generateKeyPair("real-key");
  const payload = Buffer.from("x", "utf8");
  // protected kid is mistyped (an int, not a bstr); a DECOY valid kid sits in the UNSIGNED unprotected
  // bucket. The verifier must REJECT — never silently fall through to the unsigned kid.
  const prot = encMap([[encInt(1), encInt(-19)], [encInt(4), encInt(42)]]);
  const unprot = encMap([[encInt(4), encBstr(Buffer.from("real-key", "utf8"))]]);
  const cose = buildCose(prot, unprot, payload, kp.privateKey);
  const r = coseSign1Verify(cose, b({ "real-key": kp.publicKey }));
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
  const r = coseSign1Verify(cose, b({ "k-crit": kp.publicKey }));
  assert.equal(r.ok, false, "a crit label the verifier cannot process must fail-closed");
  assert.match(r.reason ?? "", /critical/);
});

test("FWD-COMPAT (b''): a crit listing the kid label {2:[4]} is accepted — we DO process kid (key resolution)", () => {
  const kp = generateKeyPair("k-crit-kid");
  const payload = Buffer.from("p", "utf8");
  // crit declares kid (4) critical. We read+use kid for key resolution → we process it → accept
  // (closes the over-rejection of a draft-conformant kid-critical peer).
  const prot = encMap([
    [encInt(1), encInt(-19)],
    [encInt(2), encArray([encInt(4)])],
    [encInt(4), encBstr(Buffer.from("k-crit-kid", "utf8"))],
  ]);
  const cose = buildCose(prot, encMap([]), payload, kp.privateKey);
  const r = coseSign1Verify(cose, b({ "k-crit-kid": kp.publicKey }));
  assert.equal(r.ok, true, r.reason ?? "");
  assert.equal(r.kid, "k-crit-kid");
});

test("FWD-COMPAT (b'): a crit listing ONLY the alg label {2:[1]} is accepted (we DO process alg)", () => {
  const kp = generateKeyPair("k-crit-ok");
  const payload = Buffer.from("p", "utf8");
  const prot = encMap([[encInt(1), encInt(-19)], [encInt(2), encArray([encInt(1)])]]);
  const cose = buildCose(prot, encMap([[encInt(4), encBstr(Buffer.from("k-crit-ok", "utf8"))]]), payload, kp.privateKey);
  const r = coseSign1Verify(cose, b({ "k-crit-ok": kp.publicKey }));
  assert.equal(r.ok, true, r.reason ?? "");
});

test("FWD-COMPAT (c): alg-confusion STILL closed — {1:-8} (deprecated EdDSA) is rejected post-relaxation", () => {
  const kp = generateKeyPair("k8");
  const payload = Buffer.from("p", "utf8");
  // even with a GENUINE Ed25519 signature, alg=-8 in the protected header must be rejected (alg pin).
  const prot = encMap([[encInt(1), encInt(-8)], [encInt(4), encBstr(Buffer.from("k8", "utf8"))]]);
  const cose = buildCose(prot, encMap([]), payload, kp.privateKey);
  const r = coseSign1Verify(cose, b({ k8: kp.publicKey }));
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
  const r = coseSign1Verify(cose, b({ "k-extra": kp.publicKey }));
  assert.equal(r.ok, true, r.reason ?? ""); // unknown non-critical labels ignored, not rejected (forward-compat)
  assert.equal(r.kid, "k-extra");
});

test("FWD-COMPAT (d): a legacy kid-in-UNPROTECTED envelope STILL verifies, but its kid is NOT authenticated", () => {
  // NOA's own producer now emits the kid in the PROTECTED header (H4), so this envelope is hand-built
  // to preserve the interop guarantee: an external/legacy peer that puts kid in the UNPROTECTED header
  // still verifies. Its `kid` resolves and the signature checks — but kidAuthenticated is FALSE, since
  // the unprotected header is not covered by the signature.
  const kp = generateKeyPair("k-legacy");
  const payload = Buffer.from("legacy", "utf8");
  const prot = encMap([[encInt(1), encInt(-19)]]); // {1:-19} — alg only, NO kid in the signed header
  const cose = buildCose(prot, encMap([[encInt(4), encBstr(Buffer.from("k-legacy", "utf8"))]]), payload, kp.privateKey);
  const r = coseSign1Verify(cose, b({ "k-legacy": kp.publicKey }));
  assert.equal(r.ok, true, r.reason ?? "");
  assert.equal(r.kid, "k-legacy");
  assert.equal(r.kidAuthenticated, false, "an unprotected-header kid is not covered by the signature — not authenticated");
});

test("receiptFromCose with a throwing-accessor identityManifest → clean ok:false, never throws", () => {
  const kp = generateKeyPair("k");
  const receipt = mkReceipt({ kid: kp.kid, privateKey: kp.privateKey });
  const wrapped = receiptToCose(receipt, { kid: kp.kid, privateKey: kp.privateKey });
  const keyring = { [kp.kid]: kp.publicKey };

  // a manifest whose ENTRY getter throws — pre-fix the COSE path had no try/catch, so it escaped as a raw
  // throw (unlike verifyChain). ok:false is unchanged; the added counters prove the getters never ran.
  let entryFired = 0;
  const evilEntry: Record<string, unknown> = {};
  Object.defineProperty(evilEntry, "a1", { enumerable: true, configurable: true, get() { entryFired++; throw new Error("boom"); } });
  let r1!: ReturnType<typeof receiptFromCose>;
  assert.doesNotThrow(() => { r1 = receiptFromCose(wrapped, b(keyring), evilEntry as never); });
  assert.equal(r1.ok, false);
  assert.equal(entryFired, 0, "the manifest entry getter fired inside the boundary");

  // a manifest entry that IS an array but whose element getter throws — same fail-closed contract.
  let elemFired = 0;
  const arr: string[] = [];
  Object.defineProperty(arr, "0", { enumerable: true, configurable: true, get() { elemFired++; throw new Error("boom"); } });
  arr.length = 1;
  let r2!: ReturnType<typeof receiptFromCose>;
  assert.doesNotThrow(() => { r2 = receiptFromCose(wrapped, b(keyring), { a1: arr } as never); });
  assert.equal(r2.ok, false);
  assert.equal(elemFired, 0, "the manifest element getter fired inside the boundary");

  // A manifest that IS a document but carries a non-string kid — the shape guard the getters used to
  // reach. It must still fail closed, or the checks above would be the only thing keeping it out.
  const nonString = receiptFromCose(wrapped, b(keyring), b({ a1: [1, 2] }));
  assert.equal(nonString.ok, false);
  assert.match(nonString.reason ?? "", /must be an array of kid strings/);

  // sanity: a genuine manifest still binds (no regression) — a1 authorized for k.
  assert.equal(receiptFromCose(wrapped, b(keyring), b({ a1: ["k"] })).ok, true);
});

// ── H4 — the kid used for attribution MUST be signed (protected header) ────────────────────────────
test("H4: NOA's producer now puts the kid in the PROTECTED (signed) header — attribution is authenticated", () => {
  const kp = generateKeyPair("prod-kid");
  const receipt = mkReceipt({ kid: kp.kid, privateKey: kp.privateKey });
  const cose = receiptToCose(receipt, { kid: kp.kid, privateKey: kp.privateKey });
  const r = coseSign1Verify(cose, b({ [kp.kid]: kp.publicKey }));
  assert.equal(r.ok, true, r.reason ?? "");
  assert.equal(r.kid, kp.kid);
  assert.equal(r.kidAuthenticated, true, "the producer's kid is in the signed header");
});

// ⚠ REWRITTEN 2026-08-15 with the two-signature attribution fix, and the assertions got STRICTER,
// not looser. The old body asserted `ok:false` on the last case for a reason that has stopped being
// true: the manifest used to bind the OUTER kid, so an unprotected outer kid sank the whole receipt.
// The manifest now binds the receipt's NATIVE sig.kid, which lives inside the signed payload and is
// covered by two signatures — an unsigned emitter label cannot reach it. So H4's rule is unchanged
// ("never present an identifier no signature covers as an identity") and it is now enforced where
// it belongs: the unprotected kid is not REPORTED as an identity (envelopeKid stays null), while the
// agent claim is decided on its own evidence. The laundering half is asserted below in the same
// test, which the old body could not express at all.
test("H4: an UNPROTECTED-only outer kid is never REPORTED as an identity — and cannot bind, nor sink, the agent claim", () => {
  const kp = generateKeyPair("unsigned-kid");
  const rogue = generateKeyPair("rogue-kid");
  const receipt = mkReceipt({ kid: kp.kid, privateKey: kp.privateKey }); // agent.id = "a1"
  const payload = Buffer.from(canonicalize(receipt), "utf8");
  // hand-build an envelope with kid ONLY in the unprotected header (a legacy/external peer).
  const protNoKid = encMap([[encInt(1), encInt(-19)]]);
  const unprotKid = encMap([[encInt(4), encBstr(Buffer.from(kp.kid, "utf8"))]]);
  const cose = buildCose(protNoKid, unprotKid, payload, kp.privateKey);
  const keyring = { [kp.kid]: kp.publicKey, [rogue.kid]: rogue.publicKey };

  // no manifest → ok:true (a keyring-trusted key signed) + the existing kid-level-attribution warning.
  const weak = receiptFromCose(cose, b(keyring));
  assert.equal(weak.ok, true, weak.reason ?? "");
  assert.ok(weak.warnings.some((w) => /attribution is kid-level/.test(w)));

  // THE H4 RULE, at the claim it governs: the unprotected kid resolved the key (`kid` says so) but is
  // NOT reported as an identity — `envelopeKid` is null and the disposition names the reason.
  const strong = receiptFromCose(cose, b(keyring), b({ a1: [kp.kid] }));
  assert.equal(strong.kid, kp.kid, "the unprotected kid MAY resolve a key, and the result says which one did");
  assert.equal(strong.envelopeKid, null, "an unsigned kid must never be reported as an identity");
  assert.equal(strong.envelopeClaim, "UNAUTHENTICATED");
  assert.ok(strong.warnings.some((w) => /not in the signed \(protected\) header/.test(w)));
  // …and it does not sink the agent claim, which rides on the native signature the emitter label
  // cannot touch (spec §6: MUST NOT reject solely because of the outer signer).
  assert.equal(strong.ok, true, strong.reason ?? "");
  assert.equal(strong.nativeKid, kp.kid);
  assert.equal(strong.agentClaim, "VERIFIED");

  // AND the unprotected envelope still cannot launder: a receipt natively signed by the ROGUE key,
  // enveloped under a kid the manifest authorizes for a1, is refused on the native pairing.
  const laundered = mkReceipt({ kid: rogue.kid, privateKey: rogue.privateKey }); // agent.id = "a1"
  const launderedCose = buildCose(protNoKid, unprotKid, Buffer.from(canonicalize(laundered), "utf8"), kp.privateKey);
  const bad = receiptFromCose(launderedCose, b(keyring), b({ a1: [kp.kid] }));
  assert.equal(bad.ok, false, "an authorized envelope key must not launder a rogue native signature");
  assert.equal(bad.agentClaim, "UNAUTHORIZED");
  assert.equal(bad.nativeKid, rogue.kid);

  // contrast: the SAME receipt produced with a protected kid DOES report the emitter (no over-correction).
  const good = receiptToCose(receipt, { kid: kp.kid, privateKey: kp.privateKey });
  const goodResult = receiptFromCose(good, b(keyring), b({ a1: [kp.kid] }));
  assert.equal(goodResult.ok, true);
  assert.equal(goodResult.envelopeKid, kp.kid);
  assert.equal(goodResult.envelopeClaim, "VERIFIED");
});

test("H4: swapping the unprotected kid on a protected-kid envelope does NOT change attribution", () => {
  const signer = generateKeyPair("real-signer");
  const victim = generateKeyPair("victim");
  const receipt = mkReceipt({ kid: signer.kid, privateKey: signer.privateKey });
  const payload = Buffer.from(canonicalize(receipt), "utf8");
  // protected {1:-19, 4:real-signer} (signed), unprotected {4:victim} (a swapped decoy).
  const prot = encMap([[encInt(1), encInt(-19)], [encInt(4), encBstr(Buffer.from(signer.kid, "utf8"))]]);
  const unprot = encMap([[encInt(4), encBstr(Buffer.from(victim.kid, "utf8"))]]);
  const cose = buildCose(prot, unprot, payload, signer.privateKey);
  const r = coseSign1Verify(cose, b({ [signer.kid]: signer.publicKey, [victim.kid]: victim.publicKey }));
  assert.equal(r.ok, true, r.reason ?? "");
  assert.equal(r.kid, signer.kid, "the SIGNED protected kid wins — the unprotected decoy is ignored");
  assert.equal(r.kidAuthenticated, true);
});

// ── H5 — the returned receipt must re-canonicalize to the SIGNED bytes ─────────────────────────────
test("H5: an invalid-UTF-8 / non-canonical payload with a VALID outer signature is rejected", () => {
  const kp = generateKeyPair("h5-kid");
  const input: BuildInput = {
    id: "rcpt_h5", ts: "2026-06-21T10:00:00.000Z", scope: { tenant: "t", chain: "c1" },
    agent: { id: "Zaphod", model: null, principal: "SERVICE" },
    action: { id: "payment.refund", canonical: "payment.refund", riskClass: "HIGH", paramsHash: sha256Prefixed("x"), reversible: false, rollbackRef: null },
    governance: { mode: "on", verdict: "EXECUTED", ruleId: "r", approval: null, sandboxed: false },
  };
  const receipt = buildReceipt(input, null, { kid: kp.kid, privateKey: kp.privateKey });
  const payload = Buffer.from(canonicalize(receipt), "utf8");
  const idx = payload.indexOf(Buffer.from("Zaphod"));
  assert.ok(idx > 0, "the unique agent id must appear as a string value in the canonical payload");
  const corrupted = Buffer.from(payload);
  corrupted[idx] = 0x80; // replace 'Z' with a lone continuation byte → invalid UTF-8 → U+FFFD on decode
  // Sign over the CORRUPTED bytes, so the OUTER signature is valid over the non-canonical payload.
  const prot = encMap([[encInt(1), encInt(-19)], [encInt(4), encBstr(Buffer.from(kp.kid, "utf8"))]]);
  const cose = buildCose(prot, encMap([]), corrupted, kp.privateKey);
  const r = receiptFromCose(cose, b({ [kp.kid]: kp.publicKey }));
  assert.equal(r.ok, false, "a receipt that does not re-canonicalize to the signed bytes must be rejected");
  assert.match(r.reason ?? "", /canonical|re-canonicalize/i);
});

test("H5: a genuine receipt round-trips (the canonical check does not over-reject)", () => {
  const kp = generateKeyPair("h5-ok");
  const receipt = mkReceipt({ kid: kp.kid, privateKey: kp.privateKey });
  const cose = receiptToCose(receipt, { kid: kp.kid, privateKey: kp.privateKey });
  const r = receiptFromCose(cose, b({ [kp.kid]: kp.publicKey }));
  assert.equal(r.ok, true, r.reason ?? "");
  assert.equal(canonicalize(r.receipt), canonicalize(receipt));
});
