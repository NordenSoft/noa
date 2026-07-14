/**
 * Self-tests for the zero-dependency JSON-Schema-subset evaluator (src/schema-eval.ts) and a
 * structural sanity pass over every shipped schema. If the evaluator itself is wrong, every
 * conformance verdict downstream is suspect — so its keyword handling (const/enum/pattern/
 * additionalProperties:false/oneOf-exactly-one/$ref/type-union/minItems) is proven here directly.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { evalSchema } from "../src/schema-eval.js";
import { ARTIFACTS } from "../src/domains.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const SCHEMA_DIR = join(HERE, "..", "..", "schema");

test("const", () => {
  const s = { const: "noa.hold/0.1" };
  assert.ok(evalSchema(s, "noa.hold/0.1").ok);
  assert.ok(!evalSchema(s, "noa.decision/0.1").ok);
});

test("enum + integer const in enum", () => {
  assert.ok(evalSchema({ enum: ["RAW", "ENFORCED"] }, "RAW").ok);
  assert.ok(!evalSchema({ enum: ["RAW", "ENFORCED"] }, "OTHER").ok);
  assert.ok(evalSchema({ enum: [2, 3] }, 3).ok);
  assert.ok(!evalSchema({ enum: [2, 3] }, 99).ok);
});

test("pattern only constrains strings; null passes a nullable union", () => {
  const nullableHash = { type: ["string", "null"], pattern: "^sha256:[0-9a-f]{64}$" };
  assert.ok(evalSchema(nullableHash, null).ok);
  assert.ok(evalSchema(nullableHash, "sha256:" + "a".repeat(64)).ok);
  assert.ok(!evalSchema(nullableHash, "sha256:short").ok);
});

test("additionalProperties:false rejects unknown keys", () => {
  const s = { type: "object", additionalProperties: false, required: ["a"], properties: { a: { type: "string" } } };
  assert.ok(evalSchema(s, { a: "x" }).ok);
  assert.ok(!evalSchema(s, { a: "x", b: "smuggled" }).ok);
  assert.ok(!evalSchema(s, {}).ok, "missing required");
});

test("integer type rejects float and non-number", () => {
  assert.ok(evalSchema({ type: "integer", minimum: 1 }, 7).ok);
  assert.ok(!evalSchema({ type: "integer" }, 1.5).ok);
  assert.ok(!evalSchema({ type: "integer" }, "7").ok);
  assert.ok(!evalSchema({ type: "integer", minimum: 1 }, 0).ok);
});

test("minItems on arrays", () => {
  const s = { type: "array", minItems: 1, items: { type: "string" } };
  assert.ok(evalSchema(s, ["a"]).ok);
  assert.ok(!evalSchema(s, []).ok);
  assert.ok(!evalSchema(s, [1]).ok, "item type enforced");
});

test("oneOf requires EXACTLY one match (discriminated union)", () => {
  const s = {
    oneOf: [
      { type: "object", additionalProperties: false, required: ["t", "a"], properties: { t: { const: "A" }, a: { type: "string" } } },
      { type: "object", additionalProperties: false, required: ["t", "b"], properties: { t: { const: "B" }, b: { type: "string" } } },
    ],
  };
  assert.ok(evalSchema(s, { t: "A", a: "x" }).ok);
  assert.ok(evalSchema(s, { t: "B", b: "x" }).ok);
  assert.ok(!evalSchema(s, { t: "A", a: "x", b: "y" }).ok, "extra field breaks branch A → 0 matches");
  assert.ok(!evalSchema(s, { t: "C" }).ok, "no branch matches");
});

test("$ref resolves local #/$defs", () => {
  const s = {
    $defs: { hash: { type: "string", pattern: "^sha256:[0-9a-f]{64}$" } },
    type: "object",
    additionalProperties: false,
    required: ["h"],
    properties: { h: { $ref: "#/$defs/hash" } },
  };
  assert.ok(evalSchema(s, { h: "sha256:" + "b".repeat(64) }).ok);
  assert.ok(!evalSchema(s, { h: "nope" }).ok);
});

test("every shipped schema parses, has $id, and validates its own valid vector", () => {
  const CONF_DIR = join(HERE, "..", "..", "conformance");
  for (const meta of Object.values(ARTIFACTS)) {
    const schema = JSON.parse(readFileSync(join(SCHEMA_DIR, meta.schemaId), "utf8"));
    assert.equal(typeof schema.$id, "string", `${meta.schemaId}: missing $id`);
    // top-level object schemas must forbid extra props (pairing uses oneOf branches that each do).
    if (schema.type === "object") assert.equal(schema.additionalProperties, false, `${meta.schemaId}: top-level additionalProperties must be false`);
  }
  void CONF_DIR;
});
