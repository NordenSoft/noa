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
import { generateKeyPair } from "../dist/src/keys.js";
import { buildReceipt, buildCheckpoint } from "../dist/src/builder.js";
import { sha256Prefixed } from "../dist/src/hash.js";
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

if (failures) { console.error(`\nCROSS-IMPL CONFORMANCE FAILED: ${failures} mismatch(es)`); process.exit(1); }
console.log("\nCROSS-IMPL CONFORMANCE PASS: the independent Python verifier agrees with the TS reference on every vector (incl. impersonation/truncation/dup-key security verdicts).");
