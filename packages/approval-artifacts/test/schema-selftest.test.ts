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

/* ─── P1-6: THREE FROZEN SCHEMAS ADVERTISED A CIPHER SUITE NOBODY IMPLEMENTS ───────────────────────
 *
 * `noa-encrypted-display`, `noa-decision` and `noa-encrypted-reason` all declared
 * `aead: { "enum": [2, 3] }`, and `noa-decision`'s own description called AES-256-GCM=2 an
 * "accepted alternate". Nothing accepts it: the sole sealer emits `HPKE_SUITE` (aead 3,
 * `signer-core/src/encrypted-display.ts:180`) and the sole opener throws on anything else (`:212`,
 * "unsupported HPKE suite (decrypter never guesses)"). A schema-valid document with aead:2 was
 * therefore refused by the only implementation that exists — the schema was advertising a promise
 * no code could keep.
 *
 * NARROWED IN PLACE rather than version-bumped, on four measured grounds:
 *   1. the correction is FAIL-CLOSED — it rejects more, never accepts more. A frozen artifact may be
 *      corrected in place only in this direction; a widening erratum would be refused outright.
 *   2. zero blast radius — no emitter of aead:2 exists anywhere in the repo, and this artifact
 *      family has no presence in impl-py/go/rust/csharp and no conformance vectors.
 *   3. the spec-bump trigger is "an already-issued document verifies differently", and no aead:2
 *      document has ever existed. Hypothetical aead:2 input was rejected before and is rejected
 *      now; the refusal merely moves earlier, from open-time to schema-time.
 *   4. for `decision` and `encrypted-reason` nothing validates the suite at RUNTIME at all — both
 *      type it as a bare `number` — so the JSON schema is the only machine gate on aead. A prose
 *      non-claim would have reached no validator.
 *
 * These vectors run BOTH directions per schema. A schema narrowed without a passing case is a
 * schema nobody proved still accepts real documents, and one narrowed without a failing case is a
 * narrowing nobody proved happened.
 */
test("P1-6: all three HPKE schemas REFUSE aead:2 and still ACCEPT aead:3", () => {
  const HPKE_SCHEMAS = [
    "noa-encrypted-display-0.1.schema.json",
    "noa-decision-0.1.schema.json",
    "noa-encrypted-reason-0.1.schema.json",
  ];
  for (const file of HPKE_SCHEMAS) {
    // Untyped, matching the shipped-schema test above: `SchemaNode` is internal to schema-eval.ts,
    // and these are external JSON documents whose shape is exactly what is under test.
    const schema = JSON.parse(readFileSync(join(SCHEMA_DIR, file), "utf8"));
    const suite = schema.$defs.suite;

    assert.ok(evalSchema(suite, { kem: 32, kdf: 1, aead: 3 }).ok,
      `${file}: the narrowing rejected the ONLY suite any implementation emits — this would refuse ` +
        `every real sealed document, which is an outage, not a hardening`);

    assert.ok(!evalSchema(suite, { kem: 32, kdf: 1, aead: 2 }).ok,
      `${file}: aead:2 (AES-256-GCM) still validates. No sealer emits it and the opener throws on ` +
        `it (signer-core/src/encrypted-display.ts:212), so the schema is promising a cipher suite ` +
        `that does not exist — the exact defect P1-6 recorded`);

    assert.ok(!evalSchema(suite, { kem: 32, kdf: 1, aead: 1 }).ok,
      `${file}: aead:1 (AES-128-GCM) validates — the constraint is not a bound, it is a hole`);
  }
});

test("P1-6: the decision schema's PROSE no longer offers AES-256-GCM either", () => {
  // The sharpest false claim was not the enum — it was the sentence beside it. A reader integrating
  // against this schema would have implemented AES-256-GCM on the strength of the words "accepted
  // alternate" and produced documents nothing can open. Narrowing the enum while leaving the prose
  // would have left the schema self-contradictory, which is worse than either half alone.
  const raw = readFileSync(join(SCHEMA_DIR, "noa-decision-0.1.schema.json"), "utf8");
  assert.ok(!/accepted alternate/.test(raw),
    "the schema still describes AES-256-GCM as an accepted alternate while its enum refuses it");
  assert.ok(/ChaCha20Poly1305=0x0003=3 \(locked/.test(raw),
    "the locked suite must stay named — deleting the description entirely removes the reader's " +
      "only statement of what IS supported");
});
