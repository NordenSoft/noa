// Generates the two-signature attribution vectors that `test/cose/attribution-vectors.test.ts`
// judges. Spec: draft-noa-scitt-ai-agent-receipt-01 §6 ("Identity binding").
//
// An enveloped receipt carries TWO identifiers that answer DIFFERENT questions — the native
// `sig.kid` attributes the AGENT, the outer COSE kid attributes whoever EMITTED the envelope — and
// the two failures below are what happens when a verifier substitutes one for the other. They point
// in OPPOSITE directions, which is why one vector cannot cover them: a verifier that only refuses
// the laundering case can do so by refusing everything, and a verifier that only accepts the relay
// case can do so by accepting everything. Both are committed so neither cheat passes.
//
// The generator lives beside its vectors (the `cose-3rd-party/` precedent) rather than in
// `scripts/`, because the artifact and the code that produces it belong together — an artifact whose
// generator is missing cannot be regenerated, only trusted.
//
// Run from the repository root, after `npm run build`:
//   node conformance/cose-attribution/gen-vectors.mjs
//
// Keys are generated fresh on every run, so re-running rewrites the committed file with different
// (equivalent) bytes. The committed vector is the fixed artifact the suite reads; regeneration is a
// maintenance operation, not part of the test run. Nothing outside this directory pins these bytes.
import { generateKeyPair } from "../../dist/src/keys.js";
import { buildReceipt } from "../../dist/src/builder.js";
import { receiptToCose, receiptFromCose } from "../../dist/src/cose/receipt-cose.js";
import { coseSign1 } from "../../dist/src/cose/cose-sign1.js";
import { signEd25519 } from "../../dist/src/keys.js";
import { encInt, encBstr, encTstr, encArray, encMap, encTag } from "../../dist/src/cose/cbor.js";
import { canonicalize } from "../../dist/src/jcs.js";
import { sha256Prefixed } from "../../dist/src/hash.js";
import { writeFileSync } from "node:fs";

const alice = generateKeyPair("k-alice");
const relay = generateKeyPair("k-relay");
const rogue = generateKeyPair("k-rogue");
const stranger = generateKeyPair("k-stranger");

const keyring = {
  [alice.kid]: alice.publicKey,
  [relay.kid]: relay.publicKey,
  [rogue.kid]: rogue.publicKey,
};
// `k-stranger` is deliberately ABSENT from the keyring: it is the agent key a verifier does not hold.
const identityManifest = { alice: ["k-alice"] };

/** A receipt claiming `agent.id: "alice"`, signed natively by whichever key is handed in. */
function receiptForAlice(id, signer) {
  return buildReceipt(
    {
      id,
      ts: "2026-08-15T10:00:00.000Z",
      scope: { tenant: "tenant-acme", chain: "chain-acme-1" },
      agent: { id: "alice", model: null, principal: "SERVICE" },
      action: {
        id: "payment.refund",
        canonical: "payment.refund",
        riskClass: "HIGH",
        paramsHash: sha256Prefixed("params"),
        reversible: false,
        rollbackRef: null,
      },
      governance: { mode: "on", verdict: "EXECUTED", ruleId: "rule-1", approval: null, sandboxed: false },
    },
    null,
    signer,
  );
}

/** An envelope whose kid sits ONLY in the UNPROTECTED bucket (a legacy/external emitter). */
function envelopeWithUnprotectedKid(payload, kid, privB64) {
  const prot = encMap([[encInt(1), encInt(-19)]]);
  const unprot = encMap([[encInt(4), encBstr(Buffer.from(kid, "utf8"))]]);
  const sigStruct = encArray([encTstr("Signature1"), encBstr(prot), encBstr(Buffer.alloc(0)), encBstr(payload)]);
  const sig = Buffer.from(signEd25519(privB64, sigStruct), "base64");
  return encTag(18, encArray([encBstr(prot), unprot, encBstr(payload), encBstr(sig)]));
}

const vectors = [];

// ── 1. LAUNDERING — the envelope must not lend its authorization to the receipt inside it ─────────
{
  const receipt = receiptForAlice("rcpt_launder", { kid: rogue.kid, privateKey: rogue.privateKey });
  const cose = receiptToCose(receipt, { kid: alice.kid, privateKey: alice.privateKey });
  vectors.push({
    name: "laundering-authorized-envelope-over-a-rogue-native-signature",
    note:
      "A receipt natively signed by k-rogue and claiming agent.id 'alice', wrapped in an envelope " +
      "signed by k-alice — a key the manifest DOES authorize for alice. The envelope signature is " +
      "genuine; it says nothing about who signed the receipt inside it. MUST be refused: an " +
      "authorized outer kid may not satisfy the agent check (§6).",
    coseHex: cose.toString("hex"),
    expect: {
      ok: false,
      nativeKid: "k-rogue",
      agentClaim: "UNAUTHORIZED",
      envelopeKid: "k-alice",
      envelopeClaim: "VERIFIED",
      reasonMatches: "is not authorized for signing key \"k-rogue\"",
    },
  });
}

// ── 2. LEGITIMATE RELAY — a relay presenting someone else's receipt is not an impersonation ───────
{
  const receipt = receiptForAlice("rcpt_relayed", { kid: alice.kid, privateKey: alice.privateKey });
  const cose = receiptToCose(receipt, { kid: relay.kid, privateKey: relay.privateKey });
  vectors.push({
    name: "legitimate-relay-of-an-agent-signed-receipt",
    note:
      "A receipt properly signed by alice's own key, presented by relay key k-relay, which the " +
      "manifest does NOT list for alice. MUST be accepted: this profile defines no authorization " +
      "list for emitters, and the agent claim rides on the native signature the relay never touched " +
      "(§6). The two results are reported separately.",
    coseHex: cose.toString("hex"),
    expect: {
      ok: true,
      nativeKid: "k-alice",
      agentClaim: "VERIFIED",
      envelopeKid: "k-relay",
      envelopeClaim: "VERIFIED",
    },
  });
}

// ── 3. The envelope never authenticates the agent inside it ───────────────────────────────────────
{
  const receipt = receiptForAlice("rcpt_unknown_agent_key", { kid: stranger.kid, privateKey: stranger.privateKey });
  const cose = receiptToCose(receipt, { kid: relay.kid, privateKey: relay.privateKey });
  vectors.push({
    name: "relayed-receipt-whose-own-key-the-verifier-does-not-hold",
    note:
      "A perfectly valid envelope from a trusted relay, around a receipt signed by k-stranger — a " +
      "key absent from the keyring. MUST be refused rather than accepted on the envelope's " +
      "authority: ok:true would tell a caller both signatures verified when only the outer one did.",
    coseHex: cose.toString("hex"),
    expect: {
      ok: false,
      nativeKid: "k-stranger",
      agentClaim: "FAILED",
      envelopeKid: "k-relay",
      envelopeClaim: "VERIFIED",
      reasonMatches: "is not in the keyring",
    },
  });
}

// ── 4. An unprotected outer kid resolves a key, and is not an identity ────────────────────────────
{
  const receipt = receiptForAlice("rcpt_unprotected_emitter", { kid: alice.kid, privateKey: alice.privateKey });
  const payload = Buffer.from(canonicalize(receipt), "utf8");
  const cose = envelopeWithUnprotectedKid(payload, relay.kid, relay.privateKey);
  vectors.push({
    name: "unprotected-outer-kid-resolves-a-key-but-is-not-an-identity",
    note:
      "The same relayed receipt, emitted by a peer that puts its kid ONLY in the unprotected header. " +
      "The kid MAY resolve the key, and MUST NOT be reported as an identity (§6): envelopeKid is " +
      "null. The agent claim is unaffected — it is carried by the native signature.",
    coseHex: cose.toString("hex"),
    expect: {
      ok: true,
      nativeKid: "k-alice",
      agentClaim: "VERIFIED",
      envelopeKid: null,
      envelopeClaim: "UNAUTHENTICATED",
    },
  });
}

// ── 5. A genuine-looking signature under a MISLABELLED native kid ─────────────────────────────────
{
  // sig.kid says "k-alice"; the bytes were signed by k-rogue. chain.hash is correct (sig.kid is part
  // of the hash input, so the hash cannot be what catches this) — only verifying the native signature
  // does. This is the vector that goes red if the verification is removed but the kid check is kept.
  const receipt = receiptForAlice("rcpt_mislabelled_kid", { kid: alice.kid, privateKey: rogue.privateKey });
  const cose = receiptToCose(receipt, { kid: relay.kid, privateKey: relay.privateKey });
  vectors.push({
    name: "native-signature-does-not-verify-under-the-kid-it-claims",
    coseHex: cose.toString("hex"),
    note:
      "The receipt names k-alice as its signer and the manifest authorizes k-alice for alice, so " +
      "the (agent.id, sig.kid) PAIRING is perfect. The signature was produced by k-rogue. Checking " +
      "the pairing without verifying the signature under it authorizes a string, not a key.",
    expect: {
      ok: false,
      nativeKid: "k-alice",
      agentClaim: "FAILED",
      envelopeKid: "k-relay",
      envelopeClaim: "VERIFIED",
      reasonMatches: "does not verify under its kid",
    },
  });
}

// ── 6. A forged chain.hash riding a genuine native signature ──────────────────────────────────────
{
  // `chain.hash` is EXCLUDED from the receipt's hash input, so the native signature does not pin it.
  // The next receipt in the chain links to it, which is why it has to be re-derived here.
  const genuine = receiptForAlice("rcpt_forged_chain_hash", { kid: alice.kid, privateKey: alice.privateKey });
  const forged = JSON.parse(JSON.stringify(genuine));
  forged.chain.hash = "sha256:" + "0".repeat(64);
  const cose = coseSign1(Buffer.from(canonicalize(forged), "utf8"), { kid: relay.kid, privateKey: relay.privateKey });
  vectors.push({
    name: "forged-chain-hash-under-a-genuine-native-signature",
    coseHex: cose.toString("hex"),
    note:
      "Every signature here is real: alice signed the receipt, the relay signed the envelope. Only " +
      "chain.hash was rewritten, and no signature covers it. Accepting this hands the caller a " +
      "receipt whose successor link is attacker-chosen.",
    expect: {
      ok: false,
      nativeKid: "k-alice",
      agentClaim: "FAILED",
      envelopeKid: "k-relay",
      envelopeClaim: "VERIFIED",
      reasonMatches: "chain.hash is not a hash of its own contents",
    },
  });
}

// SELF-CHECK: the generator refuses to write a vector whose expectation the kernel does not already
// produce. A vector file written without running it is a wish, not a conformance artifact.
const keyringBytes = Buffer.from(JSON.stringify(keyring), "utf8");
const manifestBytes = Buffer.from(JSON.stringify(identityManifest), "utf8");
for (const v of vectors) {
  const got = receiptFromCose(Buffer.from(v.coseHex, "hex"), keyringBytes, manifestBytes);
  for (const [field, want] of Object.entries(v.expect)) {
    if (field === "reasonMatches") {
      if (!String(got.reason ?? "").includes(want)) {
        throw new Error(`[${v.name}] reason ${JSON.stringify(got.reason)} does not contain ${JSON.stringify(want)}`);
      }
      continue;
    }
    if (got[field] !== want) {
      throw new Error(`[${v.name}] ${field}: expected ${JSON.stringify(want)}, kernel produced ${JSON.stringify(got[field])}`);
    }
  }
}

const OUT = new URL("vectors.json", import.meta.url);
writeFileSync(
  OUT,
  JSON.stringify(
    {
      spec: "noa.receipt-cose-attribution/0.1",
      normative: "draft-noa-scitt-ai-agent-receipt-01 §6 (Identity binding)",
      generatedFrom: "conformance/cose-attribution/gen-vectors.mjs",
      note:
        "Two signatures carry two different claims. The native sig.kid attributes the AGENT; the " +
        "outer COSE kid attributes the party that EMITTED the envelope. A verifier MUST check the " +
        "identity manifest against the NATIVE kid, MUST NOT let an authorized outer kid satisfy the " +
        "agent check, and MUST NOT reject a receipt solely because its outer signer is not one of " +
        "the agent's keys. Each vector is verified against the kernel by the generator before it is " +
        "written, and again by test/cose/attribution-vectors.test.ts on every run.",
      keyring,
      identityManifest,
      vectors,
    },
    null,
    2,
  ) + "\n",
);
console.log(`wrote ${vectors.length} vectors to ${OUT.pathname}`);
