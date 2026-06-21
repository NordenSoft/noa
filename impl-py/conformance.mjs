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
import { verifyChain, verifyChainText, complianceCommit } from "../dist/src/index.js";
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
// NOTE (round-11 HIGH, identityManifest TOCTOU): the TS in-process API can be handed a manifest that is a
// LIVE object with accessor (getter) entries — or an array whose element getter flips on the second read —
// returning ['alice-key'] to the validation pass and ['bob-key'] to enforcement (cross-agent impersonation
// that would verify VALID/ok:true). The TS verifier defends this by SNAPSHOTTING the manifest into a plain
// Map at validation (each entry read EXACTLY ONCE, arrays copied by value via slice) and reading only the
// snapshot at every enforcement point. This CLI/Python conformance path is IMMUNE BY CONSTRUCTION: the
// manifest is loaded via JSON.parse from a file, and JSON has no accessors — every value is already a plain,
// non-flipping array. The read-once invariant therefore only matters for the JS object API; it is documented
// here so a re-implementer of the in-process library reproduces it (a re-implementer of the CLI need not).
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
// 12. round-14 #1 — trailing-newline in an OPAQUE regex-validated field. Python's re `$` matched before a
// single trailing \n (.match), accepting "value\n" that TS + the JSON Schema reject → VALID(PY)/MALFORMED(TS)
// on identical SIGNED bytes. .fullmatch now makes both reject. (reseal keeps the receipt crypto-genuine.)
structParity("MALFORMED (trailing-newline paramsHash, regex fullmatch)", (m) => { m.action.paramsHash = sha256Prefixed("z") + "\n"; });
structParity("MALFORMED (trailing-newline ts, regex fullmatch)", (m) => { m.ts = "2026-06-21T10:00:00.000Z\n"; });

// ── B4 on-receipt compliance WITH verdict (round-12 #5/#8): a receipt carrying governance.compliance
// (incl. the optional `verdict`) is NOA's OWN B4 output. Both verifiers MUST accept it. Before the port fix
// the Python validator omitted `verdict` from the optional-key list, so an authentic NOA B4 receipt verified
// VALID in TS but MALFORMED in Python — a verifier that rejects its own producer's receipts. ──
{
  const POLICY = { spec: "noa.policy/0.2", id: "refund-guard-v1", requiredPaths: ["action", "amountMinor"],
    rules: [{ id: "allow", when: { op: "lt", path: "amountMinor", value: 100000000 }, then: "ALLOW" }] };
  const cr = buildReceipt({
    id: "comp_0", ts: "2026-06-21T10:00:00.000Z", scope: { tenant: "acme", chain: "chain-comp" },
    agent: { id: "agent-7", model: null, principal: "POLICY" },
    action: { id: "payment.refund", canonical: "payment.refund", riskClass: "HIGH", paramsHash: sha256Prefixed("x"), reversible: false, rollbackRef: null },
    governance: { mode: "on", verdict: "EXECUTED", ruleId: "allow", approval: null, sandboxed: false, compliance: complianceCommit(POLICY, { action: "payment.refund", amountMinor: 4200 }) },
  }, null, { kid: kp.kid, privateKey: kp.privateKey });
  const compPath = join(dir, "compliance.json");
  writeFileSync(compPath, JSON.stringify([cr]));
  const tsComp = verifyChain([cr], { keyring }).status;
  const tsCompOk = tsComp === "VALID";
  console.log(`${tsCompOk ? "✓" : "✗"} VALID    (B4 compliance receipt w/ verdict) [TS verifyChain]: ${tsComp} (want VALID)`);
  if (!tsCompOk) failures++;
  expect("VALID    (B4 compliance receipt w/ verdict) [PY verifier]", pyVerify([compPath, keyringPath]).code, 0);
}

// ── Signature canonicality (round-12 #2 malleability, #3 non-canonical base64). sig.value is NOT covered by
// the receipt hash, so these mutate ONLY the signature encoding (hash + content stay intact); both verifiers
// MUST reject (TAMPERED). Before the fixes the Python verifier accepted a malleated S (no S<L check) and
// rejected non-canonical base64 that TS accepted — two consensus divergences on identical input bytes. ──
{
  const _L = 2n ** 252n + 27742317777372353535851937790883648493n;
  const sb = Buffer.from(r0.sig.value, "base64"); // 64 bytes: R(32) || S(32, little-endian)
  let S = 0n; for (let i = 31; i >= 0; i--) S = (S << 8n) | BigInt(sb[32 + i]);
  let Sp = S + _L; const spb = Buffer.alloc(32); for (let i = 0; i < 32; i++) { spb[i] = Number(Sp & 0xffn); Sp >>= 8n; }
  const malleated = JSON.parse(JSON.stringify(r0));
  malleated.sig.value = Buffer.concat([sb.subarray(0, 32), spb]).toString("base64");
  const malPath = join(dir, "malleated.json");
  writeFileSync(malPath, JSON.stringify([malleated]));
  const tsMal = verifyChain([malleated], { keyring }).status;
  const tsMalOk = tsMal === "TAMPERED";
  console.log(`${tsMalOk ? "✓" : "✗"} TAMPERED (Ed25519 S-malleability, S+L) [TS verifyChain]: ${tsMal} (want TAMPERED)`);
  if (!tsMalOk) failures++;
  expect("TAMPERED (Ed25519 S-malleability, S+L) [PY verifier]", pyVerify([malPath, keyringPath]).code, 2);

  const nc = JSON.parse(JSON.stringify(r0)); // embedded space: decodes leniently to the same 64 bytes, non-canonical
  nc.sig.value = r0.sig.value.slice(0, 4) + " " + r0.sig.value.slice(4);
  const ncPath = join(dir, "noncanon-b64.json");
  writeFileSync(ncPath, JSON.stringify([nc]));
  const tsNc = verifyChain([nc], { keyring }).status;
  const tsNcOk = tsNc === "TAMPERED";
  console.log(`${tsNcOk ? "✓" : "✗"} TAMPERED (non-canonical base64 sig) [TS verifyChain]: ${tsNc} (want TAMPERED)`);
  if (!tsNcOk) failures++;
  expect("TAMPERED (non-canonical base64 sig) [PY verifier]", pyVerify([ncPath, keyringPath]).code, 2);
}

// ── round-13 cross-impl parity: base64 canonicality (sig + key) + non-object keyring ──
{
  // #6 keyring as a JSON list (non-object) → MALFORMED in both, never a crash/traceback.
  const listKrPath = join(dir, "keyring-list.json");
  writeFileSync(listKrPath, JSON.stringify([kp.publicKey]));
  expect("MALFORMED (keyring is a JSON list, not an object) [PY verifier]", pyVerify([chainPath, listKrPath]).code, 3);

  // #5 non-canonical keyring SPKI base64 (embedded space): decodes leniently to the same key, but is not
  // canonical → both reject (was TS-VALID / PY-TAMPERED divergence).
  const ncKr = { [kp.kid]: kp.publicKey.slice(0, 4) + " " + kp.publicKey.slice(4) };
  const ncKrPath = join(dir, "keyring-noncanon.json");
  writeFileSync(ncKrPath, JSON.stringify(ncKr));
  const tsNcKr = verifyChain(chain, { keyring: ncKr }).status;
  const tsNcKrOk = tsNcKr === "TAMPERED";
  console.log(`${tsNcKrOk ? "✓" : "✗"} TAMPERED (non-canonical keyring SPKI base64) [TS verifyChain]: ${tsNcKr} (want TAMPERED)`);
  if (!tsNcKrOk) failures++;
  expect("TAMPERED (non-canonical keyring SPKI base64) [PY verifier]", pyVerify([chainPath, ncKrPath]).code, 2);

  // #2 trailing-bits non-canonical signature: a base64 string that decodes to the SAME 64 bytes but is not
  // canonical (the final data char carries unused bits). Python's b64decode(validate=True) ACCEPTED these
  // (consensus break + sig malleability); now both reject via canonical round-trip.
  const ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  const sigBytes = Buffer.from(r0.sig.value, "base64");
  const ci = r0.sig.value.length - 3; // final data char (before "==")
  let trailing = null;
  for (const ch of ALPHA) {
    const cand = r0.sig.value.slice(0, ci) + ch + r0.sig.value.slice(ci + 1);
    if (cand !== r0.sig.value && Buffer.from(cand, "base64").equals(sigBytes)) { trailing = cand; break; }
  }
  if (trailing) {
    const tb = JSON.parse(JSON.stringify(r0));
    tb.sig.value = trailing;
    const tbPath = join(dir, "trailing-bits-sig.json");
    writeFileSync(tbPath, JSON.stringify([tb]));
    const tsTb = verifyChain([tb], { keyring }).status;
    const tsTbOk = tsTb === "TAMPERED";
    console.log(`${tsTbOk ? "✓" : "✗"} TAMPERED (trailing-bits non-canonical sig base64) [TS verifyChain]: ${tsTb} (want TAMPERED)`);
    if (!tsTbOk) failures++;
    expect("TAMPERED (trailing-bits non-canonical sig base64) [PY verifier]", pyVerify([tbPath, keyringPath]).code, 2);
  } else {
    console.log("⚠ (skipped trailing-bits vector: no same-bytes base64 variant for this signature)");
  }
}

// ── round-14 #2: strict_load_text parity with safeParse — oversized ints (> 2^53-1) + NaN/Infinity. Python's
// json defaults parsed these (then graded TAMPERED); TS safeParse rejects (MALFORMED). Both must now reach
// the SAME verdict class (MALFORMED) at the parser. ──
{
  const bigText = JSON.stringify([r0]).replace('"seq":0', '"seq":9007199254740993');
  const bigPath = join(dir, "oversized-int.json");
  writeFileSync(bigPath, bigText);
  const tsBig = verifyChainText(bigText, { keyring }).status;
  const tsBigOk = tsBig === "MALFORMED";
  console.log(`${tsBigOk ? "✓" : "✗"} MALFORMED (oversized int > 2^53-1, strict parse) [TS verifyChainText]: ${tsBig} (want MALFORMED)`);
  if (!tsBigOk) failures++;
  expect("MALFORMED (oversized int > 2^53-1, strict parse) [PY verifier]", pyVerify([bigPath, keyringPath]).code, 3);

  const nanText = JSON.stringify([r0]).replace('"seq":0', '"seq":NaN');
  const nanPath = join(dir, "nan-literal.json");
  writeFileSync(nanPath, nanText);
  const tsNan = verifyChainText(nanText, { keyring }).status;
  const tsNanOk = tsNan === "MALFORMED";
  console.log(`${tsNanOk ? "✓" : "✗"} MALFORMED (NaN literal, strict parse) [TS verifyChainText]: ${tsNan} (want MALFORMED)`);
  if (!tsNanOk) failures++;
  expect("MALFORMED (NaN literal, strict parse) [PY verifier]", pyVerify([nanPath, keyringPath]).code, 3);
}

if (failures) { console.error(`\nCROSS-IMPL CONFORMANCE FAILED: ${failures} mismatch(es)`); process.exit(1); }
console.log("\nCROSS-IMPL CONFORMANCE PASS: the independent Python verifier agrees with the TS reference on every vector (incl. impersonation/truncation/dup-key security verdicts).");
