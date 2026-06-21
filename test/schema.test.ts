import { test } from "node:test";
import assert from "node:assert/strict";
import { validateReceiptShape } from "../src/schema.js";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const VEC = join(__dirname, "..", "..", "conformance", "vectors");

function loadValidReceipt(): Record<string, unknown> {
  const chain = JSON.parse(readFileSync(join(VEC, "valid-chain.json"), "utf8"));
  return structuredClone(chain[0]);
}

test("accepts a valid receipt", () => {
  const r = validateReceiptShape(loadValidReceipt());
  assert.equal(r.ok, true, r.errors.join("; "));
});

test("REJECTS unknown top-level field (PII smuggle)", () => {
  const bad = loadValidReceipt();
  bad["customerEmail"] = "victim@example.com";
  const r = validateReceiptShape(bad);
  assert.equal(r.ok, false);
  assert.match(r.errors.join(" "), /unknown field "customerEmail"/);
});

test("REJECTS unknown nested field", () => {
  const bad = loadValidReceipt();
  (bad.action as Record<string, unknown>)["secret"] = "x";
  const r = validateReceiptShape(bad);
  assert.equal(r.ok, false);
  assert.match(r.errors.join(" "), /unknown field "secret"/);
});

test("REJECTS invalid enum", () => {
  const bad = loadValidReceipt();
  (bad.action as Record<string, unknown>)["riskClass"] = "SUPER_HIGH";
  assert.equal(validateReceiptShape(bad).ok, false);
});

test("REJECTS missing required field", () => {
  const bad = loadValidReceipt();
  delete bad["sig"];
  const r = validateReceiptShape(bad);
  assert.equal(r.ok, false);
  assert.match(r.errors.join(" "), /missing required field "sig"|object required/);
});

test("REJECTS bad hash format", () => {
  const bad = loadValidReceipt();
  (bad.chain as Record<string, unknown>)["hash"] = "sha256:nothex";
  assert.equal(validateReceiptShape(bad).ok, false);
});

test("REJECTS non-ed25519 sig alg", () => {
  const bad = loadValidReceipt();
  (bad.sig as Record<string, unknown>)["alg"] = "rsa";
  assert.equal(validateReceiptShape(bad).ok, false);
});

// ── round-18 #1: id length is bounded in CODE POINTS, not UTF-16 code units (cross-impl with Python len()). ──
// An astral character is 1 code point but 2 UTF-16 units. `r.id.length` (units) would falsely reject an id at
// the boundary that the Python verifier (len() = code points) + the normative schema (maxLength = code points)
// accept — a consensus split on identical signed bytes. [...r.id].length (code points) makes all three agree.
test("round-18 #1: id of 128 astral chars (= 128 code points, 256 UTF-16 units) is ACCEPTED (code-point cap)", () => {
  const r = loadValidReceipt();
  r.id = "😀".repeat(128); // 128 code points (≤128), but .length === 256
  assert.equal("😀".repeat(128).length, 256); // sanity: UTF-16 unit count would over-count
  assert.equal(validateReceiptShape(r).ok, true, "128 code points must pass the ≤128 cap");
});

test("round-18 #1: id of 129 astral chars (= 129 code points) is REJECTED at the boundary", () => {
  const r = loadValidReceipt();
  r.id = "😀".repeat(129); // 129 code points (>128)
  const res = validateReceiptShape(r);
  assert.equal(res.ok, false);
  assert.match(res.errors.join(" "), /receipt\.id/);
});
