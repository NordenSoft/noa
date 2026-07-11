#!/usr/bin/env node
/**
 * Mock-shell dev harness (parent build spec §3: "Add a build check + a 'mock shell' dev
 * harness: if the core cannot run in a clean Node/Bun context without a shell SDK, the build
 * fails.").
 *
 * This script is deliberately a BARE Node script — no test framework, no bundler, no DOM
 * shim, no React-Native/Telegram SDK of any kind. It imports ONLY the package's own compiled
 * output (`dist/src/index.js`) plus its two runtime dependencies (`@noble/curves`,
 * `@noble/hashes`) and exercises the full sign+verify round trip end to end. If this script
 * can run to completion in plain `node scripts/mock-shell-harness.mjs`, that is direct,
 * executable proof the core has no hidden platform-SDK dependency — the compile-time boundary
 * (tsconfig `lib` excludes `"dom"`, see README.md) proves the SAME thing at the type level;
 * this proves it at the runtime level too.
 */
import assert from "node:assert/strict";
import {
  buildReceipt,
  canonicalize,
  receiptHashInput,
  signingMessageBytes,
  RECEIPT_SIG_DOMAIN,
} from "../dist/src/index.js";

// A throwaway Ed25519 keypair generated via node:crypto ONLY to produce a base64(PKCS8 DER)
// private key in the exact shape noa-signer's SignerKey expects — this harness script itself
// runs under Node so node:crypto is fine HERE (it is not part of the shipped package). The
// package under test (dist/src/*) never imports node:crypto.
const { generateKeyPairSync } = await import("node:crypto");
const { publicKey, privateKey } = generateKeyPairSync("ed25519");
const kid = "mock-shell-harness-key";
const privateKeyB64 = privateKey.export({ type: "pkcs8", format: "der" }).toString("base64");
const publicKeyB64 = publicKey.export({ type: "spki", format: "der" }).toString("base64");

const input = {
  id: "rcpt_mock_shell_0",
  ts: "2026-07-12T00:00:00.000Z",
  scope: { chain: "mock-shell-chain" },
  agent: { id: "mock-shell-agent", model: null, principal: "SERVICE" },
  action: {
    id: "noop.probe",
    canonical: "noop.probe",
    riskClass: "LOW",
    paramsHash: "sha256:" + "0".repeat(64),
    reversible: true,
    rollbackRef: null,
  },
  governance: { mode: "on", verdict: "EXECUTED", sandboxed: false },
};

const receipt = buildReceipt(input, null, { kid, privateKey: privateKeyB64 });

assert.equal(receipt.chain.seq, 0);
assert.equal(receipt.sig.kid, kid);
assert.ok(receipt.sig.value.length > 0, "sig.value must be populated");
assert.ok(receipt.chain.hash.startsWith("sha256:"));

// Prove receiptHashInput/canonicalize/signingMessageBytes are independently callable too (the
// full internal pipeline this harness's own buildReceipt call used under the hood).
const hashInput = receiptHashInput({ ...receipt, chain: { ...receipt.chain, hash: "" }, sig: { ...receipt.sig, value: "" } });
assert.equal(typeof canonicalize({ a: 1, b: [1, 2, 3] }), "string");
assert.ok(signingMessageBytes(RECEIPT_SIG_DOMAIN, hashInput).length > 0);

// Independently verify with node:crypto (harness-only, not package code) that the signature
// this bare-Node run of the package produced is a genuine, valid Ed25519 signature.
const { verify: cryptoVerify, createPublicKey } = await import("node:crypto");
const pubKeyObj = createPublicKey({ key: Buffer.from(publicKeyB64, "base64"), format: "der", type: "spki" });
const domainTag = Buffer.from(RECEIPT_SIG_DOMAIN + ":", "utf8");
const { createHash } = await import("node:crypto");
const digest = createHash("sha256").update(Buffer.from(hashInput, "utf8")).digest();
const message = Buffer.concat([domainTag, digest]);
const sigBytes = Buffer.from(receipt.sig.value, "base64");
const valid = cryptoVerify(null, message, pubKeyObj, sigBytes);
assert.equal(valid, true, "node:crypto must independently verify the signature noa-signer produced in this clean-Node context");

console.log("MOCK-SHELL HARNESS: PASS — noa-signer built + signed a receipt in a bare Node context (no platform SDK), and node:crypto independently verified the signature.");
console.log(JSON.stringify({ receiptId: receipt.id, chainHash: receipt.chain.hash, sigLen: sigBytes.length }, null, 2));
