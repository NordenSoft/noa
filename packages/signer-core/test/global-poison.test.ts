/**
 * C-01 SIBLING — PERMANENT REGRESSION. The receipt pre-image must not be built through a writable
 * global.
 *
 * THE DEFECT: `receiptHashInput` was `structuredClone(receipt)` plus two `delete`s.
 * `structuredClone` is a writable global. The root package measured what that costs and recorded
 * the reproduction in `src/canonicalize.ts`:
 *
 *     globalThis.structuredClone = () => genuineReceipt;
 *     verifyChain(bytesOfForgedReceipt, { keyring })   // => VALID
 *
 * The root then closed its OWN sink and left this one — the sibling — in place. The existing
 * exploit fixture missed it because its poison was shaped for the old sink.
 *
 * THIS SINK SITS ON BOTH SIDES, which is why it is worse than the root's was: the relay's only
 * cryptographic check reaches it through `relay/src/crypto.ts`, and this package's own `sign()`
 * reaches it when PRODUCING a receipt. Poisoned on the producer side, the signature would cover
 * bytes the returned receipt does not contain.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { receiptHashInput } from "../src/receipt-hash.js";
import type { Receipt } from "../src/types.js";
import { signReceipt } from "../src/sign.js";
import { generateKeyPair } from "../src/keygen.js";


function receipt(canonical: string): Receipt {
  return {
    spec: "noa.receipt/0.1",
    id: "rcpt-poison",
    ts: "2026-07-30T12:00:00.000Z",
    scope: { chain: "chain-poison" },
    agent: { id: "agent-1", model: null, principal: "HUMAN" },
    action: { id: "act-1", canonical, riskClass: "HIGH", paramsHash: "sha256:" + "a".repeat(64), reversible: false, rollbackRef: null },
    governance: { mode: "approvals_on", verdict: "ALLOWED", sandboxed: false, approval: { by: "kid-1", at: "2026-07-30T12:00:00.000Z" } },
    chain: { prev: null, hash: "sha256:" + "b".repeat(64) },
    sig: { alg: "ed25519", kid: "kid-1", value: "SIGNATURE" },
  } as unknown as Receipt;
}

test("C-01 sibling: poisoning globalThis.structuredClone cannot change what gets hashed", () => {
  const honest = receipt("infra.deploy");
  const attacker = receipt("wire.transfer.to-attacker");

  const before = receiptHashInput(honest);

  const original = globalThis.structuredClone;
  let poisonFired = 0;
  try {
    // The exact shape the root documented: the global returns a DIFFERENT receipt entirely.
    (globalThis as { structuredClone: unknown }).structuredClone = () => {
      poisonFired += 1;
      return attacker;
    };

    const during = receiptHashInput(honest);
    assert.equal(during, before,
      "the pre-image changed while `structuredClone` was poisoned — the hashed bytes are still " +
      "being routed through a writable global, so an attacker who can set one property decides " +
      "what a signature covers");

    // And the attacker's own receipt must still hash to something DIFFERENT — i.e. the function is
    // reading its argument, not a captured constant that happens to be immune to the poison.
    assert.notEqual(receiptHashInput(attacker), before,
      "two materially different receipts hashed to the same pre-image — that would be a far worse " +
      "defect than the one under test");
  } finally {
    (globalThis as { structuredClone: unknown }).structuredClone = original;
  }

  assert.equal(poisonFired, 0,
    `the poisoned global was invoked ${poisonFired} time(s); the pre-image must not reach it at all`);
});

test("C-01 sibling ANTI-VACUITY: the exclusions are still exactly chain.hash and sig.value", () => {
  // Without this, a `receiptHashInput` that returned a constant — or that omitted half the receipt —
  // would pass the test above while destroying the signature scheme.
  const r = receipt("infra.deploy");
  const input = receiptHashInput(r);

  assert.ok(input.includes("infra.deploy"), "the action must be inside the hashed bytes");
  assert.ok(input.includes("kid-1"), "sig.kid MUST be hashed — it is what binds the key identity (key-swap defence)");
  assert.ok(input.includes("ed25519"), "sig.alg must be hashed");
  assert.ok(!input.includes("SIGNATURE"), "sig.value must be EXCLUDED");
  assert.ok(!input.includes("b".repeat(64)), "chain.hash must be EXCLUDED");

  // Changing an excluded field must not move the pre-image; changing an included one must.
  const otherSig = receipt("infra.deploy");
  (otherSig as unknown as { sig: { value: string } }).sig.value = "DIFFERENT-SIGNATURE";
  assert.equal(receiptHashInput(otherSig), input, "sig.value is excluded, so it cannot move the hash");

  assert.notEqual(receiptHashInput(receipt("wire.transfer")), input,
    "the action IS included, so changing it must move the hash");
});

test("C-01 sibling: a receipt with a non-object chain or sig is refused, not silently hashed", () => {
  const bad = receipt("infra.deploy") as unknown as Record<string, unknown>;
  bad["chain"] = "not-an-object";
  assert.throws(() => receiptHashInput(bad as unknown as Receipt), /chain must be an object/);

  const bad2 = receipt("infra.deploy") as unknown as Record<string, unknown>;
  bad2["sig"] = null;
  assert.throws(() => receiptHashInput(bad2 as unknown as Receipt), /sig must be an object/);
});

/**
 * C-01 SIBLING, PRODUCER HALF. `signReceipt` and `buildReceiptDraft` used `structuredClone` to
 * snapshot caller data. On a producer path that separates WHAT WAS SIGNED from WHAT IS RETURNED:
 *
 *     const hashInput = receiptHashInput(core);   // the signature covers THIS
 *     const signed    = structuredClone(core);    // the caller receives THIS
 *
 * Poisoned, those are two different documents — a receipt carrying a genuine Ed25519 signature over
 * content it does not contain.
 */
test("C-01 sibling (producer): what is signed is what is returned, even with the global poisoned", () => {
  const kp = generateKeyPair("kid-prod", new Uint8Array(32).fill(11));
  const core = receipt("infra.deploy");
  (core as unknown as { sig: { value: string; kid: string } }).sig.value = "";
  (core as unknown as { sig: { value: string; kid: string } }).sig.kid = "kid-prod";

  const decoy = receipt("wire.transfer.to-attacker");
  (decoy as unknown as { sig: { value: string; kid: string } }).sig.value = "";
  (decoy as unknown as { sig: { value: string; kid: string } }).sig.kid = "kid-prod";

  const original = globalThis.structuredClone;
  let signed: Receipt;
  try {
    (globalThis as { structuredClone: unknown }).structuredClone = () => decoy;
    signed = signReceipt(core, { kid: "kid-prod", privateKey: kp.privateKey });
  } finally {
    (globalThis as { structuredClone: unknown }).structuredClone = original;
  }

  assert.equal(signed.action.canonical, "infra.deploy",
    "the RETURNED receipt is the attacker's document — a real signature now certifies content the " +
    "caller never submitted");

  // The returned receipt must hash to the SAME pre-image that was signed. `sig.value` is excluded
  // from the pre-image, so this compares the signed content against what the caller actually got —
  // which is exactly the property the poison was trying to break.
  assert.equal(receiptHashInput(signed), receiptHashInput(core),
    "the returned receipt hashes differently from the document that was signed");

  // ANTI-VACUITY: the input is still not mutated (the documented contract the clone existed for).
  assert.equal(core.sig.value, "", "signReceipt must not write the signature back into the caller's input");
});

test("C-01 sibling (producer) ANTI-VACUITY: an accessor on a signing path is REFUSED, not read", () => {
  // Without this, `inertDeepCopy` could be silently invoking getters and the test above would still
  // pass — the poison there is a global, not an accessor.
  const kp = generateKeyPair("kid-acc", new Uint8Array(32).fill(12));
  const core = receipt("infra.deploy") as unknown as Record<string, unknown>;
  (core as unknown as { sig: { value: string; kid: string } }).sig.value = "";
  (core as unknown as { sig: { value: string; kid: string } }).sig.kid = "kid-acc";

  let reads = 0;
  const action = core["action"] as Record<string, unknown>;
  const twoFaced: Record<string, unknown> = {};
  for (const k of Object.keys(action)) if (k !== "canonical") twoFaced[k] = action[k];
  Object.defineProperty(twoFaced, "canonical", {
    enumerable: true, configurable: true,
    get() { reads += 1; return reads === 1 ? "infra.deploy" : "wire.transfer"; },
  });
  core["action"] = twoFaced;

  assert.throws(
    () => signReceipt(core as unknown as Receipt, { kid: "kid-acc", privateKey: kp.privateKey }),
    /accessor at/,
    "a getter reached a signing path and was not refused — that is how one value gets signed and a " +
    "different one returned",
  );
});
