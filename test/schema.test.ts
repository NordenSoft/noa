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
