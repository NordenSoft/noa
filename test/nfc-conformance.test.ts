/**
 * NFC conformance — producer enforced, verifier asymmetric.
 *
 * The profile says every receipt string MUST be Unicode NFC, and nothing enforced it at any layer:
 * `src/jcs.ts` deliberately does not normalize (correct — normalizing there would MASK a
 * producer/verifier disagreement), and neither builder nor verifier checked. A receipt carrying an
 * NFD `agent.id` verified VALID in TypeScript, Python, Go and Rust alike. The exposure was latent
 * rather than active — all four implementations agreed, because none of them normalized — but an
 * unenforced MUST is exactly how two conforming implementations drift apart later, and how a
 * canonicalization-map folding stops being a paper problem.
 *
 * The shape of the fix is asymmetric on purpose:
 *   PRODUCE — hard failure. Nothing this package signs can be non-NFC again. Zero compatibility
 *             cost: a producer emitting non-NFC was already violating the profile.
 *   VERIFY  — report by default, reject only on `requireNFC: true`. Rejecting by default would
 *             break receipts already issued and signed, which is the worse failure.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { verifyChain } from "../src/verify.js";
import { generateKeyPair } from "../src/keys.js";
import { buildReceipt, BuilderError, type BuildInput } from "../src/builder.js";
import { isNFC, nonNfcPaths } from "../src/nfc.js";
import { receiptHashInput } from "../src/canonicalize.js";
import { sha256Hex } from "../src/hash.js";
import { signEd25519 } from "../src/keys.js";
import { signingMessage, RECEIPT_SIG_DOMAIN } from "../src/signing.js";
import type { Keyring, Receipt } from "../src/index.js";

const kp = generateKeyPair("nfc-key");
const keyring: Keyring = { [kp.kid]: kp.publicKey };

const NFC = "café";          // é as U+00E9 (precomposed)
const NFD = "café";         // e + U+0301 COMBINING ACUTE ACCENT

function mkInput(over: Partial<BuildInput> = {}): BuildInput {
  return {
    id: "rcpt_nfc_0001",
    ts: "2026-07-27T10:00:00Z",
    scope: { tenant: "t1", chain: "c1" },
    agent: { id: "agent-1", model: null, principal: "SERVICE" },
    action: {
      id: "a.b", canonical: "a.b", riskClass: "LOW",
      paramsHash: "sha256:" + "11".repeat(32), reversible: true, rollbackRef: null,
    },
    governance: { mode: "on", verdict: "EXECUTED", ruleId: "r1", approval: null, sandboxed: false },
    ...over,
  };
}

test("the two spellings really are byte-distinct and NFC-equivalent (the premise of everything below)", () => {
  assert.notEqual(NFC, NFD, "the fixtures must differ as JS strings");
  assert.equal(NFD.normalize("NFC"), NFC, "NFD must normalize to the NFC fixture");
  assert.equal(isNFC(NFC), true);
  assert.equal(isNFC(NFD), false);
});

test("PRODUCE: the builder refuses to sign a non-NFC payload, and names the offending path", () => {
  assert.throws(
    () => buildReceipt(mkInput({ agent: { id: NFD, model: null, principal: "SERVICE" } }), null, { kid: kp.kid, privateKey: kp.privateKey }),
    (e: unknown) => {
      assert.ok(e instanceof BuilderError, "must be a typed BuilderError, never a bare throw");
      assert.match(e.message, /non-NFC/);
      assert.deepEqual(e.errors, ["agent.id"], "the error must identify WHICH field");
      return true;
    },
  );
});

test("PRODUCE: the equivalent NFC payload signs normally (the check constrains spelling, not content)", () => {
  const r = buildReceipt(mkInput({ agent: { id: NFC, model: null, principal: "SERVICE" } }), null, { kid: kp.kid, privateKey: kp.privateKey });
  assert.equal(verifyChain([r], { keyring }).status, "VALID");
});

test("PRODUCE: a non-NFC value nested deeper is caught too (approval.by), before anything is signed", () => {
  assert.throws(
    () => buildReceipt(
      mkInput({ governance: { mode: "on", verdict: "EXECUTED", ruleId: "r1", approval: { by: NFD, at: "2026-07-27T09:00:00Z" }, sandboxed: false } }),
      null, { kid: kp.kid, privateKey: kp.privateKey },
    ),
    (e: unknown) => e instanceof BuilderError && (e.errors as string[]).includes("governance.approval.by"),
  );
});

test("VERIFY: an already-issued non-NFC receipt still VERIFIES by default, and is reported in warnings", () => {
  // Mint one the only way still possible: build NFC, then rewrite the field and re-hash/re-sign
  // exactly as a non-conforming third-party producer would have. This is what a receipt signed
  // before the producer check existed looks like.
  const legacy = mintNonNfcLegacyReceipt();
  const res = verifyChain([legacy], { keyring });

  assert.equal(res.status, "VALID", "receipts already in the wild must not stop verifying");
  const flagged = res.warnings.filter((w) => w.startsWith("non-nfc:"));
  assert.equal(flagged.length, 1, `expected exactly one non-nfc warning, got ${JSON.stringify(res.warnings)}`);
  assert.match(flagged[0]!, /agent\.id/);
});

test("VERIFY: requireNFC:true rejects the same receipt as MALFORMED, naming the field", () => {
  const legacy = mintNonNfcLegacyReceipt();
  const res = verifyChain([legacy], { keyring, requireNFC: true });
  assert.equal(res.status, "MALFORMED");
  assert.match(res.reason ?? "", /non-NFC/);
  assert.match(res.reason ?? "", /agent\.id/);
  assert.equal(res.badSeq, 0);
});

test("VERIFY: requireNFC:true is a no-op on a conforming chain (no false positives)", () => {
  const r = buildReceipt(mkInput(), null, { kid: kp.kid, privateKey: kp.privateKey });
  const res = verifyChain([r], { keyring, requireNFC: true });
  assert.equal(res.status, "VALID", res.reason);
  assert.equal(res.warnings.some((w) => w.startsWith("non-nfc:")), false);
});

test("nonNfcPaths reports member NAMES as well as values, and caps its output", () => {
  assert.deepEqual(nonNfcPaths({ [NFD]: "ok" }), [`${NFD} (member name)`]);
  assert.deepEqual(nonNfcPaths({ a: { b: [NFD] } }), ["a.b[0]"]);
  const many = Object.fromEntries(Array.from({ length: 50 }, (_, i) => [`k${i}`, NFD]));
  assert.equal(nonNfcPaths(many).length, 16, "output must be capped so a hostile payload cannot blow up the diagnostic");
});

/**
 * Produce a validly-signed receipt carrying a non-NFC string, WITHOUT going through the builder's
 * new producer check — i.e. exactly what a receipt signed by an older or third-party producer looks
 * like. Built by hand from the same primitives the builder uses, so the signature and chain hash
 * are genuine and the only non-conformance is the spelling.
 */
function mintNonNfcLegacyReceipt(): Receipt {
  const conforming = buildReceipt(mkInput({ agent: { id: NFC, model: null, principal: "SERVICE" } }), null, { kid: kp.kid, privateKey: kp.privateKey });
  const draft = structuredClone(conforming) as Receipt;
  draft.agent.id = NFD;
  // Re-derive the hash and signature over the rewritten payload, as the original producer would.
  draft.chain.hash = "";
  draft.sig.value = "";
  const hashInput = receiptHashInput(draft);
  draft.chain.hash = "sha256:" + sha256Hex(hashInput);
  draft.sig.value = signEd25519(kp.privateKey, signingMessage(RECEIPT_SIG_DOMAIN, hashInput));
  return draft;
}
