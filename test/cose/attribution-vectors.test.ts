/**
 * CONFORMANCE: two-signature attribution on the COSE entry point.
 * Spec: draft-noa-scitt-ai-agent-receipt-01 §6 ("Identity binding"), published 2026-08-15.
 *
 * An enveloped receipt carries TWO identifiers and they answer DIFFERENT questions. The native
 * `sig.kid` attributes the AGENT — it is the key that signed the receipt into its chain, and the one
 * `agent.id` makes a claim about. The outer COSE kid attributes the party that EMITTED the envelope.
 * The identity manifest answers only the first question.
 *
 * WHY THE VECTORS POINT IN OPPOSITE DIRECTIONS, and why one of them alone would prove nothing.
 * `receiptFromCose` used to check the manifest against the OUTER kid, so it got BOTH answers exactly
 * backwards — and each error is the other's mirror:
 *
 *   • LAUNDERING: a receipt natively signed by a rogue key, claiming `agent.id: "alice"`, wrapped in
 *     an envelope signed by a key the manifest authorizes FOR alice, returned `ok:true`. The rogue
 *     key was never bound to anything.
 *   • LEGITIMATE RELAY: a receipt properly signed by alice's own key, presented by a relay, returned
 *     `ok:false` — "agent alice is not authorized for signing key k-relay".
 *
 * A verifier that only refuses the first case can do it by refusing everything; one that only accepts
 * the second can do it by accepting everything. Only the pair pins the rule, so the pair is the
 * conformance artifact, and this file fails if either direction regresses.
 *
 * The vectors are FIXED BYTES read from `conformance/cose-attribution/vectors.json`, not rebuilt
 * here: a test that re-derives its own input from the code under test measures self-consistency.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { receiptFromCose } from "../../src/cose/receipt-cose.js";
import { b } from "../helpers/bytes.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const VECTOR_FILE = join(__dirname, "..", "..", "..", "conformance", "cose-attribution", "vectors.json");

interface Expectation {
  ok: boolean;
  nativeKid: string | null;
  agentClaim: string;
  envelopeKid: string | null;
  envelopeClaim: string;
  reasonMatches?: string;
}
interface Vector {
  name: string;
  note: string;
  coseHex: string;
  expect: Expectation;
}
interface VectorFile {
  spec: string;
  keyring: Record<string, string>;
  identityManifest: Record<string, string[]>;
  vectors: Vector[];
}

const file = JSON.parse(readFileSync(VECTOR_FILE, "utf8")) as VectorFile;

// ANTI-VACUITY. A vector file that failed to load, or lost its entries in a bad merge, would make
// every assertion below vacuous and the suite would still be green. Pin what must be present.
test("the attribution vector file carries BOTH directions of the rule", () => {
  assert.equal(file.spec, "noa.receipt-cose-attribution/0.1");
  assert.ok(file.vectors.length >= 6, `expected at least 6 vectors, found ${file.vectors.length}`);
  const accepted = file.vectors.filter((v) => v.expect.ok === true);
  const refused = file.vectors.filter((v) => v.expect.ok === false);
  assert.ok(refused.length >= 1, "no REFUSED vector: the laundering direction is unmeasured");
  assert.ok(accepted.length >= 1, "no ACCEPTED vector: the legitimate-relay direction is unmeasured");
  // Every control by name, so deleting a vector cannot quietly shrink the corpus and leave the
  // knockout entry that cites it reporting a green suite.
  const names = file.vectors.map((v) => v.name);
  for (const required of [
    "laundering",
    "legitimate-relay",
    "verifier-does-not-hold",
    "unprotected-outer-kid",
    "does-not-verify-under-the-kid-it-claims",
    "forged-chain-hash",
  ]) {
    assert.ok(
      names.some((n) => n.includes(required)),
      `the "${required}" vector is missing (have: ${names.join(", ")})`,
    );
  }
});

for (const v of file.vectors) {
  test(`COSE attribution vector: ${v.name}`, () => {
    const r = receiptFromCose(
      Buffer.from(v.coseHex, "hex"),
      b(file.keyring),
      b(file.identityManifest),
    );
    assert.equal(r.ok, v.expect.ok, `${v.name}: ok — ${r.reason ?? "(no reason)"}\n  ${v.note}`);
    assert.equal(r.nativeKid, v.expect.nativeKid, `${v.name}: nativeKid (the AGENT claim's identifier)`);
    assert.equal(r.agentClaim, v.expect.agentClaim, `${v.name}: agentClaim`);
    assert.equal(r.envelopeKid, v.expect.envelopeKid, `${v.name}: envelopeKid (the EMITTER's identifier)`);
    assert.equal(r.envelopeClaim, v.expect.envelopeClaim, `${v.name}: envelopeClaim`);
    if (v.expect.reasonMatches !== undefined) {
      assert.ok(
        (r.reason ?? "").includes(v.expect.reasonMatches),
        `${v.name}: reason ${JSON.stringify(r.reason)} must contain ${JSON.stringify(v.expect.reasonMatches)}`,
      );
    }
  });
}

// ── The two dispositions must be independently readable, not derivable from `ok` ───────────────────
test("the laundering refusal and the relay acceptance disagree on ok, and agree on the envelope", () => {
  const launder = file.vectors.find((v) => v.name.includes("laundering"))!;
  const relayed = file.vectors.find((v) => v.name.includes("legitimate-relay"))!;
  const l = receiptFromCose(Buffer.from(launder.coseHex, "hex"), b(file.keyring), b(file.identityManifest));
  const g = receiptFromCose(Buffer.from(relayed.coseHex, "hex"), b(file.keyring), b(file.identityManifest));

  // The envelope claim is VERIFIED in both: the laundering envelope's signature is genuine. If the
  // verdict were a single merged value, that fact would be indistinguishable from the agent claim.
  assert.equal(l.envelopeClaim, "VERIFIED");
  assert.equal(g.envelopeClaim, "VERIFIED");
  assert.notEqual(l.agentClaim, g.agentClaim);
  assert.equal(l.ok, false);
  assert.equal(g.ok, true);

  // The refused one is refused on the NATIVE kid — naming the outer kid here would be the old bug's
  // error message surviving its fix.
  assert.ok((l.reason ?? "").includes(l.nativeKid!), "the refusal must name the native kid it judged");
  assert.ok(!(l.reason ?? "").includes("k-alice"), "the refusal must not blame the (genuine) envelope signer");
});

// ── ok:true may never mean "one of the two signatures verified" ────────────────────────────────────
test("a relayed receipt whose OWN key the verifier does not hold is refused, not accepted on the envelope's authority", () => {
  const v = file.vectors.find((x) => x.name.includes("verifier-does-not-hold"))!;
  const withManifest = receiptFromCose(Buffer.from(v.coseHex, "hex"), b(file.keyring), b(file.identityManifest));
  assert.equal(withManifest.ok, false);
  assert.equal(withManifest.agentClaim, "FAILED");

  // …and WITHOUT a manifest too. The manifest decides WHICH AGENT; it is not what makes the native
  // signature get verified, so dropping it must not turn an unverifiable receipt into ok:true.
  const noManifest = receiptFromCose(Buffer.from(v.coseHex, "hex"), b(file.keyring));
  assert.equal(noManifest.ok, false, "no-manifest mode must not accept an unverifiable native signature");
  assert.equal(noManifest.agentClaim, "FAILED");
});
