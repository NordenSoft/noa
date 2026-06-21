/**
 * CROSS-IMPLEMENTATION conformance: the universality proof.
 *
 * "Universal" only holds if an INDEPENDENT implementation verifies NOA's COSE_Sign1 — otherwise it
 * is just another bespoke format that claims to be COSE. Here an independent CBOR library (cbor2,
 * dev-only) + node:crypto Ed25519 (a path that does NOT use NOA's own cbor/cose code) verify a
 * NOA-produced receipt-as-COSE_Sign1, and confirm NOA's canonical CBOR is byte-identical to cbor2's.
 * cbor2 is a devDependency; the shipped library stays zero-runtime-dependency.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { decode as cbor2Decode, encode as cbor2Encode } from "cbor2";
import { generateKeyPair } from "../../src/keys.js";
import { buildReceipt, type Signer } from "../../src/builder.js";
import { receiptToCose } from "../../src/cose/receipt-cose.js";
import { sha256Prefixed } from "../../src/hash.js";

test("an INDEPENDENT impl (cbor2 + node:crypto) verifies NOA's COSE_Sign1 — universality proof", () => {
  const kp = generateKeyPair("noa-universal-key");
  const signer: Signer = { kid: kp.kid, privateKey: kp.privateKey };
  const receipt = buildReceipt(
    {
      id: "rcpt_x",
      ts: "2026-06-21T11:00:00.000Z",
      scope: { tenant: "t", chain: "c" },
      agent: { id: "a", model: null, principal: "SERVICE" },
      action: { id: "payment.refund", canonical: "payment.refund", riskClass: "HIGH", paramsHash: sha256Prefixed("p"), reversible: false, rollbackRef: null },
      governance: { mode: "on", verdict: "EXECUTED", ruleId: "r", approval: null, sandboxed: false },
    },
    null,
    signer,
  );

  const cose = receiptToCose(receipt, { kid: kp.kid, privateKey: kp.privateKey });

  // 1. Independent CBOR decode: it IS a COSE_Sign1 (tag 18, 4-element array)
  const tag = cbor2Decode(cose) as { tag: number; contents: Uint8Array[] | unknown[] };
  assert.equal(tag.tag, 18, "must decode as COSE_Sign1 tag 18 in an independent CBOR lib");
  const [prot, , pl, sig] = tag.contents as Uint8Array[];

  // 2. Independent canonical re-encode of the RFC 9052 Sig_structure (must byte-match NOA's)
  const sigStructure = Buffer.from(
    cbor2Encode(["Signature1", new Uint8Array(prot!), new Uint8Array(0), new Uint8Array(pl!)]),
  );

  // 3. Independent Ed25519 verify via node:crypto (no NOA cose/cbor code in this path)
  const pub = crypto.createPublicKey({ key: Buffer.from(kp.publicKey, "base64"), format: "der", type: "spki" });
  const ok = crypto.verify(null, sigStructure, pub, Buffer.from(sig!));
  assert.equal(ok, true, "an off-the-shelf COSE verification path must accept NOA's COSE_Sign1");

  // 4. The protected header is exactly {1: -8} (alg EdDSA) per the COSE registry
  assert.equal(Buffer.from(prot!).toString("hex"), "a10127");
});

test("cross-impl: a tampered NOA COSE_Sign1 is rejected by the independent verifier too", () => {
  const kp = generateKeyPair("k");
  const receipt = buildReceipt(
    { id: "r", ts: "2026-06-21T11:00:00.000Z", scope: { tenant: "t", chain: "c" }, agent: { id: "a", model: null, principal: "SERVICE" }, action: { id: "x", canonical: "x", riskClass: "LOW", paramsHash: sha256Prefixed("p"), reversible: true, rollbackRef: null }, governance: { mode: "on", verdict: "EXECUTED", ruleId: null, approval: null, sandboxed: false } },
    null,
    { kid: kp.kid, privateKey: kp.privateKey },
  );
  const cose = receiptToCose(receipt, { kid: kp.kid, privateKey: kp.privateKey });
  const tag = cbor2Decode(cose) as { contents: Uint8Array[] };
  const [prot, , pl, sig] = tag.contents;
  // flip a byte in the payload, re-derive the Sig_structure → signature must NOT verify
  const tampered = Buffer.from(pl!);
  tampered[0] = tampered[0]! ^ 0x01;
  const sigStructure = Buffer.from(cbor2Encode(["Signature1", new Uint8Array(prot!), new Uint8Array(0), new Uint8Array(tampered)]));
  const pub = crypto.createPublicKey({ key: Buffer.from(kp.publicKey, "base64"), format: "der", type: "spki" });
  assert.equal(crypto.verify(null, sigStructure, pub, Buffer.from(sig!)), false);
});
