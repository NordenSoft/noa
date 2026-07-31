/**
 * #77-A — THE SIGNATURE MUST BE A FUNCTION OF THE RECEIPT, AND OF NOTHING ELSE.
 *
 * ─── THE DEFECT ─────────────────────────────────────────────────────────────────────────────────
 *
 * `signingMessageBytes` assembled the exact Ed25519 message with two LIVE inherited method calls:
 *
 *     const out = new Uint8Array(domainBytes.length + digest.length);
 *     out.set(domainBytes, 0);              // Uint8Array.prototype.set — writable, global
 *     out.set(digest, domainBytes.length);  // same
 *
 * `Uint8Array.prototype.set` is a writable slot. Replace it with a no-op and `out` stays all
 * zeroes, so the "message" is a CONSTANT: the domain tag is gone and the receipt digest is gone.
 * MEASURED against the pre-fix source, with a live control in the same run:
 *
 *     CONTROL  two different receipts -> different signatures        (content-bound)
 *     ATTACK   sig("infra.deploy")          = AAAAAAAAAAAAAAAAAAAA…
 *              sig("production.delete.all") = AAAAAAAAAAAAAAAAAAAA…   IDENTICAL
 *              signed message = 00000000…00  (53 zero bytes: tag AND digest both absent)
 *     POST     restored -> different again
 *
 * A second sink in the same family reaches the same outcome one file over: `hash.ts` builds what
 * gets hashed with `encoder.encode(...)`, and `TextEncoder.prototype.encode` is equally live.
 *
 * ─── ATTACKER · VICTIM · CAPABILITY · OUTCOME ───────────────────────────────────────────────────
 *
 *   attacker    any code running in the same realm BEFORE the signing call — a dependency earlier
 *               in the import graph, or anything that has already achieved script execution
 *   victim      the tenant whose approval evidence is being produced
 *   capability  prototype pollution ONLY. No key material, no network position, no signature forgery
 *   outcome     one signature covers every document. The binding between a signature and the action
 *               it authorises is destroyed at the producer
 *
 * HONEST SCOPE, stated because overstating it is a defect in itself (CORRECTIONS.md C-5): a receipt
 * produced under this poison FAILS CLOSED at a clean verifier — the constant message does not match
 * the digest a clean verifier computes. The realised harm is (a) a producer that emits garbage
 * evidence for real approvals, and (b) a verifier running in the SAME poisoned realm, which accepts
 * anything. It is not a path to a forged approval accepted by an honest remote verifier.
 *
 * ─── WHY INDEX WRITES ARE THE FIX ───────────────────────────────────────────────────────────────
 *
 * A typed array's integer-indexed writes are handled by the exotic object's own internal method and
 * do NOT consult the prototype chain for a setter. MEASURED separately: with an accessor installed
 * on `Uint8Array.prototype["0"]`, `hexToBytes` was unaffected and the setter fired 0 times.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { buildReceipt } from "../src/builder.js";
import { generateKeyPair } from "../src/keygen.js";
import { receiptHashInput } from "../src/receipt-hash.js";
import { signingMessageBytes, RECEIPT_SIG_DOMAIN } from "../src/signing.js";
import type { Receipt } from "../src/types.js";
import { verifyChain } from "noa-receipt";

const kp = generateKeyPair("kid-A", new Uint8Array(32).fill(3));
const signer = { kid: kp.kid, privateKey: kp.privateKey };
const bytes = (v: unknown): Uint8Array => new TextEncoder().encode(JSON.stringify(v));

function input(canonical: string) {
  return {
    id: "rcpt_0",
    ts: "2026-07-31T12:00:00.000Z",
    scope: { chain: "chain-A" },
    agent: { id: "agent-1", model: null, principal: "HUMAN" as const },
    action: {
      id: "act-1",
      canonical,
      riskClass: "CRITICAL" as const,
      paramsHash: ("sha256:" + "a".repeat(64)) as `sha256:${string}`,
      reversible: false,
      rollbackRef: null,
    },
    governance: { mode: "approvals_on" as const, verdict: "ALLOWED" as const, sandboxed: false, approval: null },
  };
}
const sign = (canonical: string): string => buildReceipt(input(canonical) as never, null, signer).sig.value;

/** Save a prototype method, run `body`, restore the EXACT prior descriptor. */
function withPoison<T>(target: object, key: string, replacement: unknown, body: () => T): T {
  const prior = Object.getOwnPropertyDescriptor(target, key);
  Object.defineProperty(target, key, { value: replacement, writable: true, configurable: true });
  try {
    return body();
  } finally {
    if (prior === undefined) delete (target as Record<string, unknown>)[key];
    else Object.defineProperty(target, key, prior);
  }
}

// ────────────────────────────────────────────────────────────────────────────────────────────────
// ATTACK — the signature must stay a function of the receipt under each live-slot poison.
// ────────────────────────────────────────────────────────────────────────────────────────────────

test("#77-A: a poisoned `Uint8Array.prototype.set` cannot make the signature context-independent", () => {
  // PROOF THE VEHICLE IS LIVE, before relying on it: the poison must actually be reachable.
  let fired = 0;
  withPoison(Uint8Array.prototype, "set", function (this: Uint8Array) { fired++; }, () => {
    const probe = new Uint8Array(2);
    probe.set(new Uint8Array([1, 1]), 0);
    assert.ok(fired > 0, "`Uint8Array.prototype.set` was not consulted by a plain `.set()` call — the fixture is not hostile");
    assert.equal(probe[0], 0, "the poisoned set still wrote — the fixture is not hostile");
  });

  const clean = [sign("infra.deploy"), sign("production.delete.all")] as const;
  assert.notEqual(clean[0], clean[1], "two different receipts already share a signature — the control is broken, not the fix");

  // THE CORRECT OUTCOME HERE IS A REFUSAL, NOT A DISTINCT SIGNATURE, and the reason is worth
  // stating because it changed the shape of this test. Hardening `signing.ts` to assemble by index
  // closed THIS PACKAGE's use of `.set()` — and the attack still worked, because `@noble/hashes`
  // builds its blocks with `.set()` too (`_md.js:94`). With it poisoned, `sha256("A") === sha256("B")`:
  // SHA-256 itself is neutralised beneath us. No edit to this package can prevent that.
  // So the guarantee is fail-closed: the signing path runs a known-answer test on the primitive and
  // REFUSES rather than emitting a receipt whose digest is not a digest of its contents.
  const outcome = withPoison(Uint8Array.prototype, "set", function () { /* swallow */ }, () => {
    try {
      return { threw: false as const, sigs: [sign("infra.deploy"), sign("production.delete.all")] as const };
    } catch (e) {
      return { threw: true as const, err: e as Error };
    }
  });

  if (!outcome.threw) {
    assert.notEqual(
      outcome.sigs[0], outcome.sigs[1],
      "TWO DIFFERENT RECEIPTS PRODUCED THE SAME SIGNATURE while `Uint8Array.prototype.set` was a " +
      "no-op, and signing did not refuse. Every signature covers the same constant",
    );
  } else {
    assert.equal(outcome.err.name, "HashPrimitiveError",
      `signing failed under the poison, but not through the primitive check — got ${outcome.err.name}: ${outcome.err.message}`);
    assert.match(outcome.err.message, /FIPS 180-4 vector/, "the refusal did not name the check that fired");
  }

  // AND the guarantee must be restored afterwards, not merely absent during the attack.
  assert.deepEqual([sign("infra.deploy"), sign("production.delete.all")], clean,
    "signing did not return to its clean behaviour after the poison was removed");
});

test("#77-A: the message assembly itself survives a poison TARGETED at its exact length", () => {
  // ── WHY THIS TEST EXISTS: the broad poison was not a control for the assembly ────────────────
  // Registering a knockout for the index-write change returned DETECTOR_DID_NOT_TRIGGER: reverting
  // `out[i] = …` back to `out.set(…)` broke nothing, because the SHA-256 known-answer test fires
  // first under a blanket `.set` poison and the suite accepts that refusal either way. So the
  // blanket poison measures the KAT, not the assembly — two different controls, one of them
  // unproven. Rather than delete the change or claim it untested, this isolates it.
  //
  // The message is `"NOA-Receipt-v0.1-sig:"` (21 bytes) ++ a 32-byte digest = 53 bytes. `@noble`'s
  // internal `.set()` calls operate on its own block buffers, which are a different size. Poisoning
  // ONLY length-53 targets therefore leaves SHA-256 fully working — the KAT passes — and attacks
  // nothing but the assembly.
  const MSG_LEN = new TextEncoder().encode(RECEIPT_SIG_DOMAIN + ":").length + 32;
  assert.equal(MSG_LEN, 53, "the message length changed; this test's isolation argument depends on it");

  const realSet = Uint8Array.prototype.set;
  let targeted = 0;
  const clean = [sign("infra.deploy"), sign("production.delete.all")] as const;

  const poisoned = withPoison(
    Uint8Array.prototype,
    "set",
    function (this: Uint8Array, src: ArrayLike<number>, off?: number) {
      if (this.length === MSG_LEN) { targeted++; return; }        // swallow ONLY the assembly
      return (realSet as (s: ArrayLike<number>, o?: number) => void).call(this, src, off);
    },
    () => [sign("infra.deploy"), sign("production.delete.all")] as const,
  );

  // ANTI-VACUITY: SHA-256 must still be intact under this targeted poison, otherwise the test has
  // silently become the blanket one again and proves nothing about the assembly.
  assert.doesNotThrow(() => sign("infra.deploy"), "the targeted poison broke hashing too — the isolation failed");

  assert.notEqual(
    poisoned[0], poisoned[1],
    "with `.set()` swallowed at exactly the message length, two different receipts produced the " +
    "same signature — the domain-separated message is being assembled through a writable global",
  );
  assert.deepEqual(poisoned, clean, "the signature moved under a poison the assembly should be immune to");
  assert.equal(targeted, 0,
    `the assembly called \`.set()\` ${targeted} time(s) at the message length — it must write by index`);
});

test("#77-A: a poisoned `TextEncoder.prototype.encode` cannot decide what gets hashed", () => {
  let fired = 0;
  withPoison(TextEncoder.prototype, "encode", function () { fired++; return new Uint8Array(0); }, () => {
    new TextEncoder().encode("probe");
    assert.ok(fired > 0, "`TextEncoder.prototype.encode` was not consulted — the fixture is not hostile");
  });

  const clean = [sign("infra.deploy"), sign("production.delete.all")] as const;
  const poisoned = withPoison(TextEncoder.prototype, "encode", function () { return new Uint8Array(0); }, () =>
    [sign("infra.deploy"), sign("production.delete.all")] as const);

  assert.notEqual(
    poisoned[0], poisoned[1],
    "with `TextEncoder.prototype.encode` returning nothing, two different receipts hashed to the " +
    "same value — what gets hashed is attacker-controlled",
  );
  assert.deepEqual(poisoned, clean, "the signature moved under the poison — the hash input must not reach a writable global");
});

// ────────────────────────────────────────────────────────────────────────────────────────────────
// BINDING MATRIX — the owner's signature requirement, proven by MEASUREMENT.
//
// For each element: two receipts differing in ONLY that element must produce DIFFERENT signed
// bytes. An element whose change does not move the bytes is NOT committed, and the test says so by
// failing rather than by being quietly omitted.
// ────────────────────────────────────────────────────────────────────────────────────────────────

const reference = buildReceipt(input("finance.wire.transfer") as never, null, signer);
const msgOf = (r: Receipt, domain: string = RECEIPT_SIG_DOMAIN): string =>
  Buffer.from(signingMessageBytes(domain, receiptHashInput(r))).toString("hex");
const REFERENCE_MSG = msgOf(reference);
const mutate = (f: (r: Receipt) => void): Receipt => {
  const r = structuredClone(reference);
  f(r);
  return r;
};

const COMMITTED: Array<[string, () => string]> = [
  ["protocol/version — spec", () => msgOf(mutate((r) => { (r as unknown as Record<string, unknown>)["spec"] = "noa.receipt/0.2"; }))],
  ["tenant — scope.tenant", () => msgOf(mutate((r) => { r.scope.tenant = "acme-tenant"; }))],
  ["action type — action.canonical", () => msgOf(mutate((r) => { r.action.canonical = "production.delete.all"; }))],
  ["action type — action.riskClass", () => msgOf(mutate((r) => { r.action.riskClass = "LOW"; }))],
  ["canonical payload — action.paramsHash", () => msgOf(mutate((r) => { r.action.paramsHash = ("sha256:" + "b".repeat(64)) as typeof r.action.paramsHash; }))],
  ["signer identity — sig.kid", () => msgOf(mutate((r) => { r.sig.kid = "kid-B"; }))],
  ["intended purpose — the domain tag", () => msgOf(reference, "NOA-Receipt-v0.1-OTHER")],
  ["ordering/nonce — chain.seq", () => msgOf(mutate((r) => { r.chain.seq = 7; }))],
  ["ordering/nonce — chain.prevHash", () => msgOf(mutate((r) => { r.chain.prevHash = "sha256:" + "c".repeat(64); }))],
  ["artifact identity — id", () => msgOf(mutate((r) => { (r as unknown as Record<string, unknown>)["id"] = "rcpt_other"; }))],
  ["agent identity — agent.id", () => msgOf(mutate((r) => { r.agent.id = "agent-evil"; }))],
  ["decision — governance.verdict", () => msgOf(mutate((r) => { r.governance.verdict = "BLOCKED"; }))],
  ["timestamp — ts", () => msgOf(mutate((r) => { (r as unknown as Record<string, unknown>)["ts"] = "2026-08-01T00:00:00.000Z"; }))],
];

test("#77-A: the signed bytes COMMIT to every element a signature must be scoped by", () => {
  for (const [name, produce] of COMMITTED) {
    assert.notEqual(
      produce(), REFERENCE_MSG,
      `changing "${name}" did NOT move the signed bytes — a signature valid for one value of it is ` +
      `equally valid for another, so the signature is not scoped by it`,
    );
  }
});

test("#77-A: the two spec-EXCLUDED fields are excluded, and nothing else is", () => {
  // `sig.value` cannot be inside its own pre-image, and `chain.hash` is derived FROM it. Both
  // exclusions are deliberate; asserting them keeps the matrix above honest, because a pre-image
  // that included everything would pass every "COMMITTED" case while breaking the scheme.
  assert.equal(msgOf(mutate((r) => { r.sig.value = "A-DIFFERENT-SIGNATURE"; })), REFERENCE_MSG,
    "`sig.value` entered its own pre-image — the signature would have to cover itself");
  assert.equal(msgOf(mutate((r) => { r.chain.hash = "sha256:" + "d".repeat(64); })), REFERENCE_MSG,
    "`chain.hash` entered the pre-image it is derived from");
});

// ────────────────────────────────────────────────────────────────────────────────────────────────
// ANTI-VACUITY — these must hold in the same run, including under the knockout.
// ────────────────────────────────────────────────────────────────────────────────────────────────

test("#77-A ANTI-VACUITY: identical receipts produce IDENTICAL signed bytes", () => {
  // Without this, a `signingMessageBytes` that mixed in a random nonce would satisfy every
  // "COMMITTED" assertion above while making signatures unverifiable.
  const a = buildReceipt(input("finance.wire.transfer") as never, null, signer);
  const b = buildReceipt(input("finance.wire.transfer") as never, null, signer);
  assert.equal(msgOf(a), msgOf(b), "the same receipt hashed to two different pre-images — signing is not deterministic");
  assert.equal(a.sig.value, b.sig.value, "the same receipt signed to two different signatures");
});

test("#77-A ANTI-VACUITY: an honest receipt still verifies VALID at the ROOT kernel", () => {
  const r = buildReceipt(input("finance.wire.transfer") as never, null, signer);
  const v = verifyChain(bytes([r]), { keyring: bytes({ [kp.kid]: kp.publicKey }) });
  assert.equal(v.status, "VALID", `an honest receipt did not verify at the root: ${v.reason}`);
});

test("#77-A ANTI-VACUITY: the domain tag is present in the signed message, not merely mixed in", () => {
  // A "domain separation" that produced the same bytes for two different tags would pass the
  // COMMITTED case above only by accident of the digest; this pins the tag itself.
  const msg = signingMessageBytes(RECEIPT_SIG_DOMAIN, receiptHashInput(reference));
  const tag = new TextEncoder().encode(RECEIPT_SIG_DOMAIN + ":");
  assert.equal(msg.length, tag.length + 32, "the message is not <tag>:<32-byte digest>");
  for (let i = 0; i < tag.length; i++) {
    assert.equal(msg[i], tag[i], `the domain tag is not the literal prefix of the signed message at byte ${i}`);
  }
  assert.ok(msg.slice(tag.length).some((b) => b !== 0), "the digest half of the message is all zeroes");
});
