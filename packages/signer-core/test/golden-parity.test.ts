/**
 * G2 — golden-receipt parity gate (parent build spec §3 "PARITY GATES", kill-gate #2).
 *
 * Builds a receipt (and a follow-on chained receipt) with THIS package's `buildReceipt` and
 * with `noa-receipt`'s own `buildReceipt`/`signEd25519`, for the SAME `BuildInput` + the SAME
 * Ed25519 keypair (produced by `noa-receipt`'s own `generateKeyPair`, so the private key is the
 * exact `Signer.privateKey` shape both packages accept). Asserts:
 *
 *   1. The two produced `Receipt` objects are byte-identical (deep-equal AND identical JCS
 *      canonical bytes — deep-equal alone could theoretically hide a key-order difference that
 *      JCS's own sort would mask; checking both is strictly stronger).
 *   2. `noa-receipt`'s own `verifyChain` accepts BOTH outputs as VALID against the same keyring.
 *   3. The raw Ed25519 public key noble derives from the DER-extracted seed matches the raw
 *      public key extracted from noa-receipt's own SPKI-DER public key (proves the DER
 *      extraction in `../src/der.ts` is itself correct, not just "the signature happened to
 *      match").
 *
 * `noa-receipt` is a devDependency here ONLY (see package.json) — used exclusively as the
 * reference implementation this test compares against; the shipped `src/` never imports it.
 *
 * A ONE-BYTE divergence anywhere in this test is a failed build (parent build spec §3).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  generateKeyPair,
  buildReceipt as referenceBuildReceipt,
  verifyChain,
  canonicalize as referenceCanonicalize,
  type BuildInput as ReferenceBuildInput,
  type Receipt as ReferenceReceipt,
  type Signer as ReferenceSigner,
} from "noa-receipt";

import { buildReceipt, canonicalize, spkiEd25519ToRawPublicKey, pkcs8Ed25519ToRawSeed, generateKeyPair as ourGenerateKeyPair } from "../src/index.js";
import type { BuildInput, Receipt } from "../src/index.js";
import { ed25519 } from "@noble/curves/ed25519.js";
import { bytesToHex } from "../src/bytes.js";

// ── Compile-time type-parity check (in addition to the runtime byte check below) ───────────
// If this package's local `Receipt`/`BuildInput` types (src/types.ts, src/builder.ts) ever
// silently diverge from noa-receipt's own (an added/removed/renamed field), ONE of these two
// assignments fails to typecheck — independent of, and in addition to, the runtime assertions
// below. Never called; existence-and-compiles is the assertion.
function _assertReceiptShapeParity(a: Receipt): ReferenceReceipt {
  return a;
}
function _assertReceiptShapeParityReverse(a: ReferenceReceipt): Receipt {
  return a;
}
function _assertBuildInputShapeParity(a: BuildInput): ReferenceBuildInput {
  return a;
}
function _assertBuildInputShapeParityReverse(a: ReferenceBuildInput): BuildInput {
  return a;
}
void _assertReceiptShapeParity;
void _assertReceiptShapeParityReverse;
void _assertBuildInputShapeParity;
void _assertBuildInputShapeParityReverse;

function mkInput(id: string, ts: string): BuildInput {
  return {
    id: `rcpt_g2_${id}`,
    ts,
    scope: { tenant: "g2-tenant", chain: "g2-chain" },
    agent: { id: "g2-agent", model: "example-provider/llm-v1", principal: "SERVICE" },
    action: {
      id: "payment.refund",
      canonical: "payment.refund",
      riskClass: "HIGH",
      paramsHash: "sha256:" + "0".repeat(64),
      reversible: false,
      rollbackRef: null,
    },
    governance: { mode: "on", verdict: "EXECUTED", ruleId: "g2-rule", approval: null, sandboxed: false },
  };
}

test("G2: noa-signer buildReceipt is byte-identical to noa-receipt buildReceipt (genesis)", () => {
  const pair = generateKeyPair("g2-signer-1");
  const referenceSigner: ReferenceSigner = { kid: pair.kid, privateKey: pair.privateKey };
  const ourSigner = { kid: pair.kid, privateKey: pair.privateKey };

  const input = mkInput("0", "2026-07-12T00:00:00.000Z");

  const referenceReceipt = referenceBuildReceipt(input, null, referenceSigner);
  const ourReceipt = buildReceipt(input, null, ourSigner);

  assert.deepEqual(ourReceipt, referenceReceipt, "structural deep-equal: every field must match exactly");

  const referenceBytes = referenceCanonicalize(referenceReceipt);
  const ourBytes = canonicalize(ourReceipt);
  assert.equal(ourBytes, referenceBytes, "JCS-canonical byte form must be identical (not just deep-equal)");

  const keyring = { [pair.kid]: pair.publicKey };
  const refVerify = verifyChain([referenceReceipt], { keyring });
  const oursVerify = verifyChain([ourReceipt], { keyring });
  assert.equal(refVerify.status, "VALID", "reference-built receipt must verify VALID");
  assert.equal(oursVerify.status, "VALID", "noa-signer-built receipt must verify VALID under the SAME verifier");
});

test("G2: noa-signer buildReceipt is byte-identical to noa-receipt buildReceipt (chained, seq>0)", () => {
  const pair = generateKeyPair("g2-signer-2");
  const referenceSigner: ReferenceSigner = { kid: pair.kid, privateKey: pair.privateKey };
  const ourSigner = { kid: pair.kid, privateKey: pair.privateKey };

  const genesisInput = mkInput("chain-0", "2026-07-12T00:00:00.000Z");
  const referenceGenesis = referenceBuildReceipt(genesisInput, null, referenceSigner);
  const ourGenesis = buildReceipt(genesisInput, null, ourSigner);
  assert.deepEqual(ourGenesis, referenceGenesis);

  const nextInput = mkInput("chain-1", "2026-07-12T00:01:00.000Z");
  const referenceNext = referenceBuildReceipt(nextInput, referenceGenesis, referenceSigner);
  const ourNext = buildReceipt(nextInput, ourGenesis, ourSigner);

  assert.deepEqual(ourNext, referenceNext, "chained receipt (seq=1, prevHash set) must be byte-identical too");
  assert.equal(ourNext.chain.seq, 1);
  assert.equal(ourNext.chain.prevHash, referenceGenesis.chain.hash);

  const keyring = { [pair.kid]: pair.publicKey };
  const refChain = verifyChain([referenceGenesis, referenceNext], { keyring });
  const ourChain = verifyChain([ourGenesis, ourNext], { keyring });
  assert.equal(refChain.status, "VALID");
  assert.equal(ourChain.status, "VALID");
});

test("G2 supporting proof: DER-extracted raw seed derives the SAME public key noa-receipt's own keygen produced", () => {
  const pair = generateKeyPair("g2-signer-3");
  const seed = pkcs8Ed25519ToRawSeed(pair.privateKey);
  const derivedPub = ed25519.getPublicKey(seed);
  const referencePubRaw = spkiEd25519ToRawPublicKey(pair.publicKey);
  assert.equal(bytesToHex(derivedPub), bytesToHex(referencePubRaw), "noble-derived public key must equal the raw key inside noa-receipt's own SPKI DER");
});

test("G2 negative control: a tampered field changes the hash (proves the test isn't vacuously true)", () => {
  const pair = generateKeyPair("g2-signer-4");
  const signer = { kid: pair.kid, privateKey: pair.privateKey };
  const input = mkInput("tamper", "2026-07-12T00:00:00.000Z");

  const r1 = buildReceipt(input, null, signer);
  const tamperedInput = mkInput("tamper", "2026-07-12T00:00:00.000Z");
  tamperedInput.action.riskClass = "CRITICAL";
  const r2 = buildReceipt(tamperedInput, null, signer);

  assert.notEqual(r1.chain.hash, r2.chain.hash, "a changed field must change chain.hash");
  assert.notEqual(r1.sig.value, r2.sig.value, "a changed field must change the signature");
});

test("G2 end-to-end: a key noa-signer itself generated signs a receipt noa-receipt's own verifyChain accepts VALID", () => {
  // Closes the loop the rest of this file doesn't cover: every other test uses a key
  // noa-receipt's generateKeyPair produced. This one uses OUR OWN generateKeyPair (WebCrypto
  // entropy + noble derivation, see src/keygen.ts) end to end, proving a noa-signer-native key
  // is a fully interoperable drop-in — not just "our signature math matches", but "a whole key
  // lifecycle originating in this package produces a receipt the reference verifier accepts".
  const pair = ourGenerateKeyPair("g2-native-keygen");
  const signer = { kid: pair.kid, privateKey: pair.privateKey };
  const input = mkInput("native-keygen", "2026-07-12T00:00:00.000Z");

  const receipt = buildReceipt(input, null, signer);
  const keyring = { [pair.kid]: pair.publicKey };
  const result = verifyChain([receipt], { keyring });
  assert.equal(result.status, "VALID");
});
