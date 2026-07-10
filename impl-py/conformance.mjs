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
import { receiptHashInput, checkpointHashInput } from "../dist/src/canonicalize.js";
import { signingMessage, RECEIPT_SIG_DOMAIN, CHECKPOINT_SIG_DOMAIN } from "../dist/src/signing.js";
import { verifyChain, verifyChainText, complianceCommit } from "../dist/src/index.js";
import { safeParse } from "../dist/src/safe-json.js";
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
// NOTE (identityManifest TOCTOU hardening): the TS in-process API can be handed a manifest that is a
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

// ── STRUCTURAL parity: receipts that are STRUCTURALLY-INVALID but CRYPTO-CONSISTENT ──
// The hashed surface covers ALL fields, so a keyring-trusted producer can sign a receipt with a
// smuggled field / bad enum / sig.alg!="ed25519" / wrong spec. The TS reference runs validateReceiptShape
// as step 1 of verifyChain → MALFORMED. The independent Python verifier MUST agree. Each vector mutates
// a VALID receipt, then re-hashes + re-signs
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

// 7b. RE-HEADING truncation: a scope.chain is a SHARED partition with no opener/
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
// 12. trailing-newline in an OPAQUE regex-validated field. Python's re `$` matched before a
// single trailing \n (.match), accepting "value\n" that TS + the JSON Schema reject → VALID(PY)/MALFORMED(TS)
// on identical SIGNED bytes. .fullmatch now makes both reject. (reseal keeps the receipt crypto-genuine.)
structParity("MALFORMED (trailing-newline paramsHash, regex fullmatch)", (m) => { m.action.paramsHash = sha256Prefixed("z") + "\n"; });
structParity("MALFORMED (trailing-newline ts, regex fullmatch)", (m) => { m.ts = "2026-06-21T10:00:00.000Z\n"; });

// ── B4 on-receipt compliance WITH verdict: a receipt carrying governance.compliance
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

// ── Signature canonicality (S-malleability + non-canonical base64). sig.value is NOT covered by
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

// ── cross-impl parity: base64 canonicality (sig + key) + non-object keyring ──
{
  // keyring as a JSON list (non-object) → MALFORMED in both. (This comment used to claim
  // "in both" while asserting ONLY the Python side — and TS verifyChain did NOT actually validate the keyring;
  // an array `keyring[kid]` returned undefined → an unknown-kid TAMPERED, NOT MALFORMED. Now TS rejects a
  // non-object keyring up front (verify.ts), so BOTH reach MALFORMED, and BOTH sides are asserted here.)
  const listKrPath = join(dir, "keyring-list.json");
  writeFileSync(listKrPath, JSON.stringify([kp.publicKey]));
  const tsListKr = verifyChain(chain, { keyring: [kp.publicKey] }).status;
  const tsListKrOk = tsListKr === "MALFORMED";
  console.log(`${tsListKrOk ? "✓" : "✗"} MALFORMED (keyring is a JSON list, not an object) [TS verifyChain]: ${tsListKr} (want MALFORMED)`);
  if (!tsListKrOk) failures++;
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

// ── strict_load_text parity with safeParse — oversized ints (> 2^53-1) + NaN/Infinity. Python's
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

// ── Unicode-digit RFC-3339 regex divergence. The RFC-3339 patterns (ts / approval.at, and the
// checkpoint ts) used bare `\d`. Python's `re` `\d` matches the ENTIRE Unicode decimal-number category (Nd)
// — Arabic-Indic ٢٠٢٦, fullwidth ２０２６, etc. — while ECMA-262 `\d` (the dialect the normative JSON-Schema
// `pattern` uses, and src/schema.ts/verify.ts) is ASCII [0-9] ONLY. A crypto-genuine receipt/checkpoint
// carrying a Unicode-digit timestamp therefore verified VALID in Python but MALFORMED/TAMPERED in the TS
// reference — a consensus split on IDENTICAL signed bytes. Spelling the classes as [0-9] in noa_verify.py
// makes both ASCII-only. reseal() keeps the receipts crypto-genuine, so this exercises the regex, not the hash.
structParity("MALFORMED (Arabic-Indic digits in ts)", (m) => { m.ts = "٢٠٢٦-06-21T10:00:00.000Z"; });
structParity("MALFORMED (fullwidth digits in ts frac-seconds)", (m) => { m.ts = "2026-06-21T10:00:00.１２３Z"; });
structParity("MALFORMED (Arabic-Indic digits in ts tz offset)", (m) => { m.ts = "2026-06-21T10:00:00+٠٢:00"; });
structParity("MALFORMED (Unicode digits in approval.at)", (m) => { m.governance.approval = { by: "u", at: "２０２６-06-21T10:00:00Z" }; });
{
  // Checkpoint ts with fullwidth digits: re-sign so the checkpoint is crypto-genuine. TS → TAMPERED
  // (checkpoint invalid), Python must agree (exit 2), not VALID.
  const cpU = buildCheckpoint(r1, "2026-06-21T11:00:00.000Z", { kid: kp.kid, privateKey: kp.privateKey });
  cpU.ts = "２０２６-06-21T11:00:00Z";
  cpU.sig.value = signEd25519(kp.privateKey, signingMessage(CHECKPOINT_SIG_DOMAIN, checkpointHashInput(cpU)));
  const cpUPath = join(dir, "cp-unicode-digits.json");
  writeFileSync(cpUPath, JSON.stringify(cpU));
  const tsCpU = verifyChain(chain, { keyring, checkpoint: cpU }).status;
  const tsCpUOk = tsCpU === "TAMPERED";
  console.log(`${tsCpUOk ? "✓" : "✗"} TAMPERED (Unicode-digit checkpoint ts) [TS verifyChain]: ${tsCpU} (want TAMPERED)`);
  if (!tsCpUOk) failures++;
  expect("TAMPERED (Unicode-digit checkpoint ts) [PY verifier]", pyVerify([chainPath, keyringPath, "--checkpoint", cpUPath]).code, 2);
}

// ── Python over-accepted vs the TS safeParse / in-process API on exotic-but-malformed
// AUXILIARY trust files (keyring / identity / checkpoint), not just receipts. The TS CLI parses EVERY file
// with safeParse (lone-surrogate reject) and the in-process API treats `opts.X !== undefined` as PRESENT
// (so a null identity/checkpoint is "present but not an object" → MALFORMED). Python's json.loads + CLI
// loaded these leniently. These vectors pin both impls to the SAME verdict at the file/option boundary. ──

// #3 — a LONE UTF-16 surrogate in a keyring KID. TS safeParse rejects an unpaired surrogate in EVERY string
// of EVERY file (src/safe-json.ts isWellFormed) → CLI MALFORMED; Python json.loads decoded a \uD800 escape
// into a lone surrogate (over-accept) until strict_load_text's recursive _reject_lone_surrogate pass.
{
  // Raw text with a \uD800 escape as a keyring key (a lone high surrogate).
  const surKrText = '{"\\uD800": ' + JSON.stringify(kp.publicKey) + '}';
  const surKrPath = join(dir, "keyring-lone-surrogate-kid.json");
  writeFileSync(surKrPath, surKrText);
  let tsSurKrThrew = false;
  try { safeParse(surKrText); } catch { tsSurKrThrew = true; } // TS CLI parses keyring files via safeParse → MALFORMED
  console.log(`${tsSurKrThrew ? "✓" : "✗"} MALFORMED (lone surrogate in keyring kid) [TS safeParse]: ${tsSurKrThrew ? "rejected" : "accepted"} (want rejected)`);
  if (!tsSurKrThrew) failures++;
  expect("MALFORMED (lone surrogate in keyring kid) [PY verifier]", pyVerify([chainPath, surKrPath]).code, 3);
}

// #4 — a LONE UTF-16 surrogate in an (unknown) CHECKPOINT field. Same boundary: TS safeParse rejects the
// file; Python must too (recursive surrogate pass), not parse-then-lenient.
{
  // Genuine checkpoint object, then inject a 𝄞? no — a LONE low surrogate \uDC00 in an extra field.
  const cpObj = buildCheckpoint(r1, "2026-06-21T11:00:00.000Z", { kid: kp.kid, privateKey: kp.privateKey });
  // Serialize then splice in a smuggled field carrying a lone surrogate escape (raw text, like an attacker file).
  const cpText = JSON.stringify(cpObj).replace(/}$/, ',"x":"\\uDC00"}');
  const surCpPath = join(dir, "cp-lone-surrogate-field.json");
  writeFileSync(surCpPath, cpText);
  let tsSurCpThrew = false;
  try { safeParse(cpText); } catch { tsSurCpThrew = true; } // TS CLI parses checkpoint files via safeParse → MALFORMED
  console.log(`${tsSurCpThrew ? "✓" : "✗"} MALFORMED (lone surrogate in checkpoint field) [TS safeParse]: ${tsSurCpThrew ? "rejected" : "accepted"} (want rejected)`);
  if (!tsSurCpThrew) failures++;
  expect("MALFORMED (lone surrogate in checkpoint field) [PY verifier]", pyVerify([chainPath, keyringPath, "--checkpoint", surCpPath]).code, 3);
}

// #6 — an identity file that is literally `null` (a valid JSON value, but NOT a manifest object). The TS
// in-process API treats `opts.identityManifest !== undefined` as PRESENT → null is not an object → MALFORMED
// (keeps the impersonation defense; a null manifest must NOT silently degrade to "no manifest"). The Python
// CLI loaded `null` → None → verify_chain read it as "not supplied" → VALID (silent drop) until the _main
// guard. Both must now reject a given-but-null identity. (checkpoint=null mirrors this.)
{
  const nullIdentPath = join(dir, "identity-null.json");
  writeFileSync(nullIdentPath, "null");
  // TS in-process: passing identityManifest:null is "present but not an object" → MALFORMED.
  const tsNullId = verifyChain(chain, { keyring, identityManifest: null }).status;
  const tsNullIdOk = tsNullId === "MALFORMED";
  console.log(`${tsNullIdOk ? "✓" : "✗"} MALFORMED (identity provided as null) [TS verifyChain]: ${tsNullId} (want MALFORMED)`);
  if (!tsNullIdOk) failures++;
  expect("MALFORMED (identity file = null) [PY verifier]", pyVerify([chainPath, keyringPath, "--identity", nullIdentPath]).code, 3);

  const nullCpPath = join(dir, "checkpoint-null.json");
  writeFileSync(nullCpPath, "null");
  const tsNullCp = verifyChain(chain, { keyring, checkpoint: null }).status;
  // checkpoint:null → opts.checkpoint !== undefined is TRUE → the non-object guard → MALFORMED.
  const tsNullCpOk = tsNullCp === "MALFORMED";
  console.log(`${tsNullCpOk ? "✓" : "✗"} MALFORMED (checkpoint provided as null) [TS verifyChain]: ${tsNullCp} (want MALFORMED)`);
  if (!tsNullCpOk) failures++;
  expect("MALFORMED (checkpoint file = null) [PY verifier]", pyVerify([chainPath, keyringPath, "--checkpoint", nullCpPath]).code, 3);
}

// a NON-OBJECT (but valid-JSON) checkpoint: a JSON array / number / string. TS used to route it
// into verifyCheckpoint → "malformed checkpoint" → TAMPERED (exit 2); Python's _main returns MALFORMED (exit 3)
// on a non-dict checkpoint. A non-object checkpoint is STRUCTURALLY malformed → MALFORMED is canonical. Both
// impls must now agree on MALFORMED for the SAME malformed input. (null is covered just above; this pins the
// array/number/string shapes.)
{
  const arrCpPath = join(dir, "checkpoint-array.json");
  writeFileSync(arrCpPath, "[]");
  const tsArrCp = verifyChain(chain, { keyring, checkpoint: [] }).status;
  const tsArrCpOk = tsArrCp === "MALFORMED";
  console.log(`${tsArrCpOk ? "✓" : "✗"} MALFORMED (checkpoint is a JSON array, not an object) [TS verifyChain]: ${tsArrCp} (want MALFORMED)`);
  if (!tsArrCpOk) failures++;
  expect("MALFORMED (checkpoint is a JSON array) [PY verifier]", pyVerify([chainPath, keyringPath, "--checkpoint", arrCpPath]).code, 3);

  const numCpPath = join(dir, "checkpoint-number.json");
  writeFileSync(numCpPath, "7");
  const tsNumCp = verifyChain(chain, { keyring, checkpoint: 7 }).status;
  const tsNumCpOk = tsNumCp === "MALFORMED";
  console.log(`${tsNumCpOk ? "✓" : "✗"} MALFORMED (checkpoint is a JSON number, not an object) [TS verifyChain]: ${tsNumCp} (want MALFORMED)`);
  if (!tsNumCpOk) failures++;
  expect("MALFORMED (checkpoint is a JSON number) [PY verifier]", pyVerify([chainPath, keyringPath, "--checkpoint", numCpPath]).code, 3);
}

// a TRAILING `--checkpoint` / `--identity` with NO following path. Silently dropping the
// control would FAIL-OPEN (the verifier returns VALID/exit 0 over an unchecked tail / unbound identity),
// whereas the TS CLI returns usage (exit 4). The Python _main must mirror the TS CLI: emit usage + exit 4.
expect("USAGE (trailing --checkpoint, no path) [PY verifier]", pyVerify([chainPath, keyringPath, "--checkpoint"]).code, 4);
expect("USAGE (trailing --identity, no path) [PY verifier]", pyVerify([chainPath, keyringPath, "--identity"]).code, 4);
// the flag as the SOLE trailing token (no keyring either) must also be usage, never a silent VALID.
expect("USAGE (--checkpoint is the last token, no keyring) [PY verifier]", pyVerify([chainPath, "--checkpoint"]).code, 4);
expect("USAGE (--identity is the last token, no keyring) [PY verifier]", pyVerify([chainPath, "--identity"]).code, 4);

// ── id length is bounded in CODE POINTS, not UTF-16 code units. An astral char is 1 code point
// but 2 UTF-16 units. The TS schema used to read r.id.length (units), falsely rejecting an astral id at the
// boundary that the Python verifier (len() = code points) + the normative schema (maxLength = code points)
// accept — a consensus split on identical SIGNED bytes. Now BOTH measure code points. reseal keeps it genuine.
{
  const EMOJI = String.fromCodePoint(0x1f600);
  // 128 astral chars = 128 code points (≤128) but 256 UTF-16 units → must be VALID in BOTH (the bug would have
  // made TS MALFORMED here while Python stayed VALID).
  const ok128 = JSON.parse(JSON.stringify(r0));
  ok128.id = EMOJI.repeat(128);
  reseal(ok128);
  const ok128Path = join(dir, "astral-id-128.json");
  writeFileSync(ok128Path, JSON.stringify([ok128]));
  const tsOk128 = verifyChain([ok128], { keyring }).status;
  const tsOk128Ok = tsOk128 === "VALID";
  console.log(`${tsOk128Ok ? "✓" : "✗"} VALID    (id = 128 astral chars = 128 code points, code-point cap) [TS verifyChain]: ${tsOk128} (want VALID)`);
  if (!tsOk128Ok) failures++;
  expect("VALID    (id = 128 astral chars, code-point cap) [PY verifier]", pyVerify([ok128Path, keyringPath]).code, 0);

  // 129 astral chars = 129 code points (>128) → MALFORMED in BOTH (the cap still bites, measured consistently).
  const bad129 = JSON.parse(JSON.stringify(r0));
  bad129.id = EMOJI.repeat(129);
  reseal(bad129);
  const bad129Path = join(dir, "astral-id-129.json");
  writeFileSync(bad129Path, JSON.stringify([bad129]));
  const tsBad129 = verifyChain([bad129], { keyring }).status;
  const tsBad129Ok = tsBad129 === "MALFORMED";
  console.log(`${tsBad129Ok ? "✓" : "✗"} MALFORMED (id = 129 astral chars = 129 code points, over cap) [TS verifyChain]: ${tsBad129} (want MALFORMED)`);
  if (!tsBad129Ok) failures++;
  expect("MALFORMED (id = 129 astral chars, over cap) [PY verifier]", pyVerify([bad129Path, keyringPath]).code, 3);
}

// ── low-order / non-canonical PUBLIC KEY consensus pin. node:crypto/OpenSSL verify is cofactored
// and ACCEPTS a small-subgroup public key; the independent strict-equation Python reference can reject it →
// VALID(TS)/TAMPERED(PY) on identical signed bytes. Both impls now reject the 8 canonical small-order point
// encodings AND any non-canonical y ≥ q encoding. A keyring whose pubkey is a low-order point → both TAMPERED
// (the receipt is genuinely structured/hashed; only the keyring key is a low-order point → signature unauthable).
{
  const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
  const rawToSpkiB64 = (rawHex) => Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(rawHex, "hex")]).toString("base64");
  const SMALL_ORDER_RAW = [
    "0100000000000000000000000000000000000000000000000000000000000000", // order 1
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // order 2
    "0000000000000000000000000000000000000000000000000000000000000000", // order 4
    "0000000000000000000000000000000000000000000000000000000000000080", // order 4
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05", // order 8
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85", // order 8
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a", // order 8
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa", // order 8
  ];
  SMALL_ORDER_RAW.forEach((rawHex, i) => {
    // keyring maps the chain's REAL kid to a LOW-ORDER pubkey: the receipt is genuine, only the trusted key is
    // a low-order point → the signature cannot authenticate under it → TAMPERED in both impls (never VALID).
    const loKr = { [kp.kid]: rawToSpkiB64(rawHex) };
    const loKrPath = join(dir, `keyring-low-order-${i}.json`);
    writeFileSync(loKrPath, JSON.stringify(loKr));
    const tsLo = verifyChain(chain, { keyring: loKr }).status;
    const tsLoOk = tsLo === "TAMPERED";
    console.log(`${tsLoOk ? "✓" : "✗"} TAMPERED (low-order pubkey #${i} in keyring) [TS verifyChain]: ${tsLo} (want TAMPERED)`);
    if (!tsLoOk) failures++;
    expect(`TAMPERED (low-order pubkey #${i} in keyring) [PY verifier]`, pyVerify([chainPath, loKrPath]).code, 2);
  });
  // non-canonical (y ≥ q) encoding of a low-order point: OpenSSL accepts + re-exports unchanged (canonical-SPKI
  // round-trip misses it); the y < q strict check now rejects it in BOTH, matching Python's _decodepoint guard.
  const ncLoKr = { [kp.kid]: rawToSpkiB64("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f") };
  const ncLoKrPath = join(dir, "keyring-noncanon-low-order.json");
  writeFileSync(ncLoKrPath, JSON.stringify(ncLoKr));
  const tsNcLo = verifyChain(chain, { keyring: ncLoKr }).status;
  const tsNcLoOk = tsNcLo === "TAMPERED";
  console.log(`${tsNcLoOk ? "✓" : "✗"} TAMPERED (non-canonical y≥q low-order pubkey in keyring) [TS verifyChain]: ${tsNcLo} (want TAMPERED)`);
  if (!tsNcLoOk) failures++;
  expect("TAMPERED (non-canonical y≥q low-order pubkey in keyring) [PY verifier]", pyVerify([chainPath, ncLoKrPath]).code, 2);
}

if (failures) { console.error(`\nCROSS-IMPL CONFORMANCE FAILED: ${failures} mismatch(es)`); process.exit(1); }
console.log("\nCROSS-IMPL CONFORMANCE PASS: the independent Python verifier agrees with the TS reference on every vector (incl. impersonation/truncation/dup-key security verdicts).");
