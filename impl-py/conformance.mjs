#!/usr/bin/env node
/**
 * Cross-implementation conformance proof.
 *
 * The TypeScript reference (../dist, node:crypto/OpenSSL) EMITS a signed receipt chain + keyring;
 * the independent Python verifier (noa_verify.py — its own JCS + from-scratch RFC 8032 Ed25519,
 * ZERO shared crypto) RE-VERIFIES it. Agreement proves the canonical bytes + signing preimage are
 * unambiguous across two independent stacks — the interoperability bar for an IETF/AAIF profile.
 *
 * Asserts: VALID (with keyring, exit 0) · UNVERIFIED (no keyring, exit 1) · TAMPERED (flip a byte, exit 2).
 * Run: node impl-py/conformance.mjs   (after `npm run build`)
 */
import { generateKeyPair, signEd25519 } from "../dist/src/keys.js";
import { buildReceipt, buildCheckpoint } from "../dist/src/builder.js";
import { sha256Prefixed, sha256Hex } from "../dist/src/hash.js";
import { receiptHashInput } from "../dist/src/canonicalize.js";
import { signingMessage, RECEIPT_SIG_DOMAIN } from "../dist/src/signing.js";
import { verifyChain } from "../dist/src/index.js";
import { writeFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFileSync } from "node:child_process";

const dir = mkdtempSync(join(tmpdir(), "noa-conf-"));
const kp = generateKeyPair("agent-key-1");

function mk(seq, prev) {
  const input = {
    id: `rcpt_${seq}`,
    ts: `2026-06-21T10:0${seq}:00.000Z`,
    scope: { tenant: "acme", chain: "chain-1" },
    agent: { id: "agent-7", model: "vendor/model-x", principal: "SERVICE" },
    action: { id: "payment.refund", canonical: "payment.refund", riskClass: "CRITICAL", paramsHash: sha256Prefixed(`p${seq}`), reversible: false, rollbackRef: null },
    governance: { mode: "on", verdict: "EXECUTED", ruleId: "r1", approval: null, sandboxed: false },
    // a non-ASCII string + an astral character exercise the JCS string + UTF-16 key-sort paths
    note: `refund éç 😀 ${seq}`,
  };
  return buildReceipt(input, prev, { kid: kp.kid, privateKey: kp.privateKey });
}

const r0 = mk(0, null);
const r1 = mk(1, r0);
const chain = [r0, r1];
const keyring = { [kp.kid]: kp.publicKey };

const chainPath = join(dir, "receipts.json");
const keyringPath = join(dir, "keyring.json");
writeFileSync(chainPath, JSON.stringify(chain));
writeFileSync(keyringPath, JSON.stringify(keyring));

const PY = join(import.meta.dirname, "noa_verify.py");
function pyVerify(args) {
  try {
    const out = execFileSync("python3", [PY, ...args], { encoding: "utf8" });
    return { code: 0, out };
  } catch (e) {
    return { code: e.status, out: (e.stdout || "") + (e.stderr || "") };
  }
}

let failures = 0;
function expect(label, got, want) {
  const ok = got === want;
  console.log(`${ok ? "✓" : "✗"} ${label}: exit ${got} (want ${want})`);
  if (!ok) failures++;
}

// 1. VALID — Python re-verifies the TS-signed chain against the keyring.
expect("VALID  (TS-signed chain, Python verifies w/ keyring)", pyVerify([chainPath, keyringPath]).code, 0);
// 2. UNVERIFIED — no keyring → signatures not authenticated.
expect("UNVERIFIED (no keyring)", pyVerify([chainPath]).code, 1);
// 3. TAMPERED — flip a field in a receipt; the recomputed hash must diverge.
const tampered = JSON.parse(JSON.stringify(chain));
tampered[1].action.riskClass = "LOW";
const tPath = join(dir, "tampered.json");
writeFileSync(tPath, JSON.stringify(tampered));
expect("TAMPERED (content altered)", pyVerify([tPath, keyringPath]).code, 2);
// 4. TAMPERED — keep content, break the signature only (wrong key in keyring).
const otherKp = generateKeyPair("agent-key-1"); // same kid, different key
writeFileSync(join(dir, "wrong-keyring.json"), JSON.stringify({ [kp.kid]: otherKp.publicKey }));
expect("TAMPERED (sig fails under wrong pubkey)", pyVerify([chainPath, join(dir, "wrong-keyring.json")]).code, 2);

// ── Attack vectors: Python must match the TS reference's SECURITY verdicts, not just the happy path ──
// 5. Cross-agent impersonation: agent.id=alice signed by bob → UNTRUSTED with a manifest (exit 5).
const bob = generateKeyPair("agent-key-2");
const imp = buildReceipt({
  id: "imp_0", ts: "2026-06-21T10:00:00.000Z", scope: { tenant: "acme", chain: "chain-1" },
  agent: { id: "alice", model: null, principal: "SERVICE" },
  action: { id: "payment.refund", canonical: "payment.refund", riskClass: "CRITICAL", paramsHash: sha256Prefixed("x"), reversible: false, rollbackRef: null },
  governance: { mode: "on", verdict: "EXECUTED", ruleId: "r", approval: null, sandboxed: false },
}, null, { kid: bob.kid, privateKey: bob.privateKey });
const impPath = join(dir, "imp.json");
const krBoth = join(dir, "kr-both.json");
const manPath = join(dir, "manifest.json");
writeFileSync(impPath, JSON.stringify([imp]));
writeFileSync(krBoth, JSON.stringify({ [kp.kid]: kp.publicKey, [bob.kid]: bob.publicKey, "alice-key": kp.publicKey }));
writeFileSync(manPath, JSON.stringify({ alice: ["alice-key"], "agent-key-2": ["agent-key-2"] }));
expect("UNTRUSTED (impersonation, with identity manifest)", pyVerify([impPath, krBoth, "--identity", manPath]).code, 5);
expect("VALID    (impersonation, NO manifest — kid-level, matches TS)", pyVerify([impPath, krBoth]).code, 0);

// 6. Tail-truncation: checkpoint asserts head=seq1, but only [seq0] is presented → TAMPERED (exit 2).
const cp = buildCheckpoint(r1, "2026-06-21T11:00:00.000Z", { kid: kp.kid, privateKey: kp.privateKey });
const truncPath = join(dir, "trunc.json");
const cpPath = join(dir, "cp.json");
writeFileSync(truncPath, JSON.stringify([r0]));
writeFileSync(cpPath, JSON.stringify(cp));
expect("TAMPERED (tail-truncation, checkpoint detects)", pyVerify([truncPath, keyringPath, "--checkpoint", cpPath]).code, 2);

// 7. Duplicate-key receipt (raw text) → MALFORMED via strict parse (exit 3).
const dupText = JSON.stringify([r0]).replace('"agent":', '"agent":' + JSON.stringify(r0.agent) + ',"agent":');
const dupPath = join(dir, "dup.json");
writeFileSync(dupPath, dupText);
expect("MALFORMED (duplicate JSON key, strict parse)", pyVerify([dupPath, keyringPath]).code, 3);

// ── STRUCTURAL parity (round-9 audit): receipts that are STRUCTURALLY-INVALID but CRYPTO-CONSISTENT ──
// The hashed surface covers ALL fields, so a keyring-trusted producer can sign a receipt with a
// smuggled field / bad enum / sig.alg!="ed25519" / wrong spec. The TS reference runs validateReceiptShape
// as step 1 of verifyChain → MALFORMED. The independent Python verifier MUST agree (was VALID before the
// port — the divergence this audit closes). Each vector mutates a VALID receipt, then re-hashes + re-signs
// so chain integrity + Ed25519 signature stay GENUINE (only the STRUCTURE is out-of-spec).
function reseal(obj) {
  // RE-COMPUTE chain.hash and RE-SIGN over the canonical hash-input so the receipt is crypto-consistent.
  obj.chain.hash = "sha256:" + sha256Hex(receiptHashInput(obj));
  obj.sig.value = signEd25519(kp.privateKey, signingMessage(RECEIPT_SIG_DOMAIN, receiptHashInput(obj)));
  return obj;
}
function structParity(label, mutate) {
  const m = JSON.parse(JSON.stringify(r0)); // a genuine, valid base receipt at seq 0 (genesis)
  mutate(m);
  reseal(m);
  const p = join(dir, `struct-${label.replace(/[^a-z0-9]+/gi, "-")}.json`);
  writeFileSync(p, JSON.stringify([m]));
  // TS reference must call it MALFORMED…
  const tsStatus = verifyChain([m], { keyring }).status;
  const tsOk = tsStatus === "MALFORMED";
  console.log(`${tsOk ? "✓" : "✗"} ${label} [TS verifyChain]: ${tsStatus} (want MALFORMED)`);
  if (!tsOk) failures++;
  // …and the independent Python verifier must exit 3 (MALFORMED) — the parity this port establishes.
  expect(`${label} [PY verifier]`, pyVerify([p, keyringPath]).code, 3);
}

// 7b. RE-HEADING truncation (round-10 audit): a scope.chain is a SHARED partition with no opener/
// ownership binding, so a co-trusted key can APPEND its own receipt onto a victim's prefix, BECOME the
// head, DROP the victim's incriminating tail, and forge a checkpoint over its OWN head. The old §5b
// head-binding "validated" the attacker against its OWN authorized agent.id → VALID + tailChecked while
// the victim's tail was erased. Genesis-binding (checkpoint authority = the chain OPENER, seq 0) closes
// it. Both impls MUST return UNTRUSTED (TS) / exit 5 (Python).
{
  const aliceK = generateKeyPair("rh-alice-key");
  const bobK = generateKeyPair("rh-bob-key");
  const krRH = { [aliceK.kid]: aliceK.publicKey, [bobK.kid]: bobK.publicKey };
  const manRH = { "rh-alice": ["rh-alice-key"], "rh-bob": ["rh-bob-key"] };
  const mkRH = (id, agentId, actId, risk, prev, signer) => buildReceipt({
    id, ts: "2026-06-21T10:00:00.000Z", scope: { tenant: "acme", chain: "chain-rh" },
    agent: { id: agentId, model: null, principal: "SERVICE" },
    action: { id: actId, canonical: actId, riskClass: risk, paramsHash: sha256Prefixed("x"), reversible: false, rollbackRef: null },
    governance: { mode: "on", verdict: "EXECUTED", ruleId: "r", approval: null, sandboxed: false },
  }, prev, signer);
  const aS = { kid: aliceK.kid, privateKey: aliceK.privateKey };
  const bS = { kid: bobK.kid, privateKey: bobK.privateKey };
  const a0 = mkRH("rh_a0", "rh-alice", "login", "LOW", null, aS);
  mkRH("rh_a1", "rh-alice", "payment.refund", "CRITICAL", a0, aS); // alice's dropped tail (built, not presented)
  const b1 = mkRH("rh_b1", "rh-bob", "noop", "LOW", a0, bS);       // bob re-heads
  const bobCp = buildCheckpoint(b1, "2026-06-21T11:00:00.000Z", bS);

  const rhPath = join(dir, "reheading.json");
  const krRHPath = join(dir, "kr-rh.json");
  const manRHPath = join(dir, "man-rh.json");
  const cpRHPath = join(dir, "cp-rh.json");
  writeFileSync(rhPath, JSON.stringify([a0, b1]));
  writeFileSync(krRHPath, JSON.stringify(krRH));
  writeFileSync(manRHPath, JSON.stringify(manRH));
  writeFileSync(cpRHPath, JSON.stringify(bobCp));

  // TS reference must return UNTRUSTED (not VALID).
  const tsRH = verifyChain([a0, b1], { keyring: krRH, checkpoint: bobCp, identityManifest: manRH });
  const tsRHok = tsRH.status === "UNTRUSTED" && tsRH.tailChecked === false;
  console.log(`${tsRHok ? "✓" : "✗"} UNTRUSTED (re-heading truncation, genesis-binding) [TS verifyChain]: ${tsRH.status} tailChecked=${tsRH.tailChecked} (want UNTRUSTED / false)`);
  if (!tsRHok) failures++;
  // independent Python verifier must exit 5 (UNTRUSTED).
  expect("UNTRUSTED (re-heading truncation, genesis-binding) [PY verifier]", pyVerify([rhPath, krRHPath, "--identity", manRHPath, "--checkpoint", cpRHPath]).code, 5);

  // and the LEGIT opener checkpoint over alice's own chain stays VALID (exit 0) — no false-positive break.
  const la0 = mkRH("rh_l0", "rh-alice", "login", "LOW", null, aS);
  const la1 = mkRH("rh_l1", "rh-alice", "payment.refund", "CRITICAL", la0, aS);
  const goodCp = buildCheckpoint(la1, "2026-06-21T11:00:00.000Z", aS);
  const legitPath = join(dir, "reheading-legit.json");
  const goodCpPath = join(dir, "cp-rh-good.json");
  writeFileSync(legitPath, JSON.stringify([la0, la1]));
  writeFileSync(goodCpPath, JSON.stringify(goodCp));
  const tsLegit = verifyChain([la0, la1], { keyring: krRH, checkpoint: goodCp, identityManifest: manRH });
  const tsLegitOk = tsLegit.status === "VALID" && tsLegit.tailChecked === true;
  console.log(`${tsLegitOk ? "✓" : "✗"} VALID    (legit opener checkpoint, no false-positive) [TS verifyChain]: ${tsLegit.status} tailChecked=${tsLegit.tailChecked} (want VALID / true)`);
  if (!tsLegitOk) failures++;
  expect("VALID    (legit opener checkpoint, no false-positive) [PY verifier]", pyVerify([legitPath, krRHPath, "--identity", manRHPath, "--checkpoint", goodCpPath]).code, 0);
}

// 8. Smuggled unknown field carrying fake PII (the "smuggle PII in an unrecognized field" channel).
structParity("MALFORMED (smuggled unknown field w/ fake PII)", (m) => { m.note = "ssn=123-45-6789"; });
// 9. Out-of-spec enum (riskClass not in the frozen set).
structParity("MALFORMED (bad enum: action.riskClass)", (m) => { m.action.riskClass = "ULTRA"; });
// 10. sig.alg != "ed25519" (algorithm-confusion surface — must be rejected structurally).
structParity('MALFORMED (sig.alg="rsa")', (m) => { m.sig.alg = "rsa"; });
// 11. Wrong spec string.
structParity("MALFORMED (wrong spec)", (m) => { m.spec = "noa.receipt/9.9"; });

if (failures) { console.error(`\nCROSS-IMPL CONFORMANCE FAILED: ${failures} mismatch(es)`); process.exit(1); }
console.log("\nCROSS-IMPL CONFORMANCE PASS: the independent Python verifier agrees with the TS reference on every vector (incl. impersonation/truncation/dup-key security verdicts).");
