#!/usr/bin/env node
/**
 * @noa/receipt — KILLER DEMO
 * ============================================================================
 * Hash-only, OFFLINE-verifiable provenance for an AI-agent $-refund decision.
 *
 *   1. EMIT   a HASH-ONLY receipt for a $42.00 refund. The receipt carries a
 *             SHA-256 of the decision params — the raw amount is nowhere on it.
 *   2. VERIFY it OFFLINE using ONLY the public lib + a keyring: the signed
 *             hash-chain (verifyChain) AND the deterministic policy re-run
 *             (verifyReceiptCompliance) both pass → "VALID".
 *   3. TAMPER one hashed field (relabel $42.00 → $1,000,000.00) and re-verify:
 *             chain.hash was computed over the ORIGINAL field, so swapping it
 *             makes the recomputed hash diverge → "TAMPERED" (the signature,
 *             over that original digest, is now stale too — but the hash
 *             check trips first).
 *
 * Uses ONLY @noa/receipt's public API surface (../dist/src/index.js). No
 * reinvented crypto, no dependency beyond the Node >=20 stdlib.
 *
 * Run:   node examples/killer-demo.mjs   (dist/ ships built — run `npm run build`
 *        first only if you have changed src/)
 * ============================================================================
 */
import {
  generateKeyPair,
  buildReceipt,
  verifyChain,
  complianceCommit,
  verifyReceiptCompliance,
  validatePolicy,
  evaluate,
  policyHash,
  readSet,
  readSetHash,
  canonicalize,
  sha256Prefixed,
} from "../dist/src/index.js";

// ── display helpers (display only — never touch the hashed surface) ─────────
const HR = "═".repeat(74);
const hr = (s) => console.log(`\n${HR}\n${s}`);
// Truncate only genuinely long strings (the base64 signature) so the receipt
// preview stays readable; full 71-char sha256 digests are shown in full.
const short = (v) => (typeof v === "string" && v.length > 80 ? `${v.slice(0, 24)}…(${v.length} chars)` : v);
const preview = (obj) => JSON.parse(JSON.stringify(obj, (_k, v) => short(v)));
const usd = (minor) =>
  "$" + (minor / 100).toLocaleString("en-US", { minimumFractionDigits: 2, maximumFractionDigits: 2 });

// ── 0. TRUST ROOT ───────────────────────────────────────────────────────────
// The ONLY thing an offline verifier needs besides the receipts: a keyring
// (kid -> base64 SPKI public key). The matching private key stays with the issuer.
hr("0 · TRUST ROOT — Ed25519 keyring (the verifier's only trust input)");
const kp = generateKeyPair("refund-issuer-2026");
const signer = { kid: kp.kid, privateKey: kp.privateKey };
const keyring = { [kp.kid]: kp.publicKey };
console.log(`issuer kid  : ${kp.kid}`);
console.log(`public key  : ${short(kp.publicKey)}   (base64 DER SPKI; private key never leaves the issuer)`);

// ── 1. THE DECISION (raw params — these stay OFF the receipt) ───────────────
hr("1 · THE DECISION — what the agent actually did (raw params; never on-receipt)");
// Money is INTEGER minor units: 4200 = $42.00. No floats (jcs.ts rejects them),
// so producer/verifier byte-serialization can never diverge.
const decision = { amount_minor: 4200, currency: "USD" }; // $42.00
const decisionHash = sha256Prefixed(canonicalize(decision)); // the ONLY thing about it on the receipt
console.log(`decision     : ${JSON.stringify(decision)}   =  ${usd(decision.amount_minor)}`);
console.log(`decisionHash : ${decisionHash}   (sha256 over JCS-canonical params)`);

// ── 2. THE PUBLISHED POLICY (deterministic, re-runnable offline) ────────────
hr("2 · THE POLICY — published rule: auto-ALLOW refunds ≤ $50.00 USD, else DENY");
const AUTO_ALLOW_CAP_MINOR = 5000; // $50.00
const policy = {
  spec: "noa.policy/0.2",
  id: "refund-auto-allow-usd-50",
  requiredPaths: ["amount_minor", "currency"],
  rules: [
    {
      id: "within-usd-cap",
      when: {
        op: "and",
        clauses: [
          { op: "le", path: "amount_minor", value: AUTO_ALLOW_CAP_MINOR },
          { op: "eq", path: "currency", value: "USD" },
        ],
      },
      then: "ALLOW",
    },
    // Anything else (over cap / non-USD / …) matches no rule → default-DENY.
  ],
};
const policyValidation = validatePolicy(policy);
if (!policyValidation.ok) {
  console.error("policy invalid:", policyValidation.errors);
  process.exit(1);
}
console.log(`policy id    : ${policy.id}`);
console.log(`policyHash   : ${policyHash(policy)}   (the policy's published, hash-pinned identity)`);
console.log(`read-set     : ${JSON.stringify(readSet(policy))}   → readSetHash ${short(readSetHash(policy))}`);
const evalResult = evaluate(policy, decision);
console.log(`evaluate()   : verdict=${evalResult.verdict}  ruleFired=${evalResult.ruleFired}   (re-runs byte-identically on any machine)`);

// ── 3. L2 COMMITMENT — bind (policy, inputs) by hash; record the verdict ────
hr("3 · L2 COMMITMENT — complianceCommit(policy, decision)");
const commit = complianceCommit(policy, decision);
console.log(preview(commit)); // { policyHash, readSetHash, inputsHash, verdict:"ALLOW" }

// ── 4. EMIT A HASH-ONLY RECEIPT ─────────────────────────────────────────────
hr("4 · EMIT — a HASH-ONLY receipt (paramsHash + compliance hashes; NO raw amount)");
const receipt = buildReceipt(
  {
    id: "rcpt_refund_demo_0",
    ts: "2026-06-22T09:00:00.000Z",
    scope: { tenant: "store_demo", chain: "store_demo:usd-refunds" },
    agent: { id: "refund-agent", model: "vendor/refund-bot-v1", principal: "SERVICE" },
    action: {
      id: "payment.refund",
      canonical: "payment.refund",
      riskClass: "LOW",
      paramsHash: decisionHash, // ← HASH ONLY: commits to the params by digest, not by value
      reversible: false,
      rollbackRef: null,
    },
    governance: {
      mode: "on",
      verdict: "EXECUTED", // action lifecycle (the refund ran); compliance.verdict is the policy decision
      ruleId: "within-usd-cap",
      approval: null,
      sandboxed: false,
      compliance: commit, // ← L2 block: policyHash + readSetHash + inputsHash + verdict
    },
  },
  null, // genesis (first receipt in this chain)
  signer,
);
console.log(preview(receipt));
console.log(`\n↳ The receipt carries only HASHES of the decision (action.paramsHash + compliance.inputsHash).`);
console.log(`  The literal ${usd(decision.amount_minor)} / 4200 is not a field on it — provenance without exposing params.`);

// ── 5. VERIFY OFFLINE ───────────────────────────────────────────────────────
hr("5 · VERIFY OFFLINE — verifyChain + verifyReceiptCompliance (public lib + keyring only)");
const chainResult = verifyChain([receipt], { keyring });
console.log("verifyChain([receipt], { keyring }) →");
console.log(preview(chainResult));

const compliance = verifyReceiptCompliance(receipt, policy, decision, { keyring });
console.log("\nverifyReceiptCompliance(receipt, policy, decision, { keyring }) →");
console.log(preview(compliance));

if (chainResult.status === "VALID" && compliance.ok) {
  console.log("\n✅  VALID  — signed hash-chain intact AND the recorded policy decision reproduces over the supplied inputs.");
} else {
  console.error("\nUNEXPECTED: the honest receipt did not verify.");
  process.exit(1);
}

// ── 6. TAMPER — relabel the $42.00 refund as $1,000,000.00 ──────────────────
hr("6 · TAMPER — attacker swaps action.paramsHash to the digest of a $1,000,000.00 refund");
const fraud = { amount_minor: 100_000_000, currency: "USD" }; // $1,000,000.00
const fraudHash = sha256Prefixed(canonicalize(fraud));
const tampered = structuredClone(receipt); // keep chain.hash + sig.value EXACTLY as issued
tampered.action.paramsHash = fraudHash; // …and silently rewrite what the receipt "proves"

console.log(`  honest    action.paramsHash = ${decisionHash}   (digest of ${JSON.stringify(decision)}  =  ${usd(decision.amount_minor)})`);
console.log(`  tampered  action.paramsHash = ${fraudHash}   (digest of ${JSON.stringify(fraud)}  =  ${usd(fraud.amount_minor)})`);
console.log(`  chain.hash + sig.value     = UNCHANGED  (attacker cannot re-sign without the issuer's private key)`);

const tamperedChain = verifyChain([tampered], { keyring });
const tamperedCompliance = verifyReceiptCompliance(tampered, policy, decision, { keyring });
console.log("\nverifyChain([tampered], { keyring }) →");
console.log(preview(tamperedChain));
console.log("\nverifyReceiptCompliance(tampered, …, { keyring }) →");
console.log(preview(tamperedCompliance));

if (tamperedChain.status === "TAMPERED" && !tamperedCompliance.ok) {
  console.log(`\n🚫  TAMPERED  — ${tamperedChain.reason}`);
  console.log("   chain.hash was computed over the ORIGINAL action.paramsHash; with that one field swapped, the recomputed hash no longer matches → instant detection.");
  console.log("   (The Ed25519 signature is over that original digest too, so it is now stale as well — and the attacker cannot re-sign it without the issuer's private key. The hash-integrity check simply trips first.)");
  console.log("   Hash-only + signed = tamper-evident provenance: you can prove WHAT was decided without ever storing it in the clear.");
} else {
  console.error("\nUNEXPECTED: the tampered receipt was NOT rejected.");
  process.exit(1);
}

console.log(`\n${HR}\nDemo complete: hash-only receipt → offline VALID → tamper → TAMPERED. Zero deps; public lib only.`);
