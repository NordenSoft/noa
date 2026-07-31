/**
 * P0-6 — `Date.parse` IS NOT A SECURITY PARSER.
 *
 * ─── WHY THIS FILE EXISTS, AND WHY IT LIVES HERE ────────────────────────────────────────────────
 *
 * A previous test of this same defect (`packages/evidence/test/root-activation-window.test.ts`) was
 * named *"a MALFORMED validFrom is carried through and fails CLOSED at the verifier"* and **never
 * invoked the verifier** — it asserted field carriage only. The name claimed an end-to-end property
 * the body did not measure. Every assertion below therefore runs the REAL `verifyArtifact` against
 * the REAL shipped conformance vector and asserts the FINAL authorization result.
 *
 * ─── THE DEFECT ─────────────────────────────────────────────────────────────────────────────────
 *
 * `parseTime` returned `Date.parse(v)` for any string. `Date.parse` does not reject malformed input;
 * it NORMALISES it into a plausible instant, which every comparison then treats as the declared one.
 * MEASURED against the shipped decision vector, with the unmodified vector ACCEPTED in the same run:
 *
 *     validFrom "0"          -> Date.parse => 1999-12-31  -> ACCEPTED (a past instant)
 *     validFrom "2026-02-30" -> Date.parse => 2026-03-02  -> ACCEPTED (that day does not exist)
 *
 * HONEST SEVERITY: exploiting this requires authoring the key record, which is already a trusted
 * position — an attacker who can write a keyring can simply declare a past activation instead. The
 * realised risk is an OPERATOR who declares a future activation and mistypes it, and whose key is
 * then silently active already. Recorded at that severity rather than inflated to a bypass.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { verifyArtifact } from "../src/verify.js";
import { ARTIFACTS } from "../src/domains.js";
import type { KeyEntry } from "../src/verify.js";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const enc = (v: unknown): Uint8Array => new TextEncoder().encode(JSON.stringify(v));

const schemas: Record<string, unknown> = {};
for (const meta of Object.values(ARTIFACTS)) {
  schemas[meta.spec] = JSON.parse(readFileSync(join(ROOT, "schema", meta.schemaId), "utf8"));
}
const keyring = JSON.parse(readFileSync(join(ROOT, "conformance", "keyring.json"), "utf8")) as Record<string, KeyEntry>;
const fx = JSON.parse(readFileSync(join(ROOT, "conformance", "decision", "valid.json"), "utf8")) as {
  artifact: Record<string, unknown>;
  context: Record<string, unknown>;
};
const SIGNER = (fx.artifact["sig"] as { kid: string }).kid;

/** Verify the REAL vector with the signer's `validFrom` replaced. Returns the FINAL result. */
function verifyWithValidFrom(validFrom: unknown): { ok: boolean; reason: string } {
  const kr = JSON.parse(JSON.stringify(keyring)) as Record<string, KeyEntry>;
  kr[SIGNER] = { ...(kr[SIGNER] as KeyEntry), validFrom: validFrom as string | null };
  const r = verifyArtifact(enc(fx.artifact), enc({ ...fx.context, schemas, keyring: kr }));
  return { ok: r.ok, reason: r.ok ? "" : String(r.reason) };
}

// ────────────────────────────────────────────────────────────────────────────────────────────────
// ANTI-VACUITY FIRST — if the harness cannot produce an acceptance, nothing below means anything.
// ────────────────────────────────────────────────────────────────────────────────────────────────

test("P0-6 ANTI-VACUITY: the unmodified conformance vector VERIFIES", () => {
  const r = verifyArtifact(enc(fx.artifact), enc({ ...fx.context, schemas, keyring }));
  assert.equal(r.ok, true, `the shipped vector does not verify (${r.ok ? "" : r.reason}) — every refusal below would be meaningless`);
});

test("P0-6 ANTI-VACUITY: activation IS enforced for a canonical FUTURE time", () => {
  // If this passed, the activation check would not be running at all and the malformed cases below
  // would be refused for some unrelated reason.
  const r = verifyWithValidFrom("2099-01-01T00:00:00.000Z");
  assert.equal(r.ok, false, "a key that activates in 2099 verified a signature made now");
  assert.match(r.reason, /before its validFrom/, `refused for the wrong reason: ${r.reason}`);
});

// ────────────────────────────────────────────────────────────────────────────────────────────────
// THE DEFECT — a malformed declared activation must NEVER become a usable past instant.
// ────────────────────────────────────────────────────────────────────────────────────────────────

test("P0-6: a malformed `validFrom` cannot be normalised into a past instant", () => {
  for (const bad of [
    "0",                      // Date.parse => 1999-12-31
    "2026-02-30",             // a day that does not exist; Date.parse rolls it to 2026-03-02
    "2026-13-01",             // month 13
    "2026-01-01",             // date only, no time or zone — ambiguous
    "2026-01-01T00:00:00",    // no zone designator
    "2026-01-01t00:00:00z",   // lowercase, non-canonical
    "2026-01-01T00:00:00+01:00", // an offset form this project never emits
    " 2026-01-01T00:00:00Z",  // leading whitespace
  ]) {
    const r = verifyWithValidFrom(bad);
    assert.equal(r.ok, false,
      `validFrom ${JSON.stringify(bad)} was ACCEPTED. A declared activation the verifier cannot ` +
      `evaluate EXACTLY must fail closed — normalising it into a plausible instant means an ` +
      `operator who mistypes a future activation gets a key that is silently active already`);
    assert.match(r.reason, /cannot evaluate activation time/,
      `${JSON.stringify(bad)} was refused, but not by the activation parser: ${r.reason}`);
  }
});

test("P0-6: values that were ALREADY refused stay refused, by the same rule", () => {
  for (const bad of ["", "   ", "not-a-timestamp", "99999999999999"]) {
    const r = verifyWithValidFrom(bad);
    assert.equal(r.ok, false, `${JSON.stringify(bad)} became acceptable`);
    assert.match(r.reason, /cannot evaluate activation time/, `wrong refusal reason for ${JSON.stringify(bad)}: ${r.reason}`);
  }
  // A non-string is refused by the type guard, not by the format check — both fail closed.
  assert.equal(verifyWithValidFrom(0).ok, false, "a numeric validFrom was accepted");
});

// ────────────────────────────────────────────────────────────────────────────────────────────────
// THE RULES THAT MUST NOT CHANGE — legacy compatibility and the boundary semantics.
// ────────────────────────────────────────────────────────────────────────────────────────────────

test("P0-6: the documented legacy rule holds — an ABSENT validFrom is always-active", () => {
  assert.equal(verifyWithValidFrom(null).ok, true,
    "a key with no declared activation stopped verifying — this is the documented legacy behaviour " +
    "(`KeyEntry.validFrom`: an entry without it is treated as always-active) and 1727 shipped " +
    "timestamps depend on it");
});

test("P0-6: a canonical PAST activation still verifies, in both accepted spellings", () => {
  assert.equal(verifyWithValidFrom("2000-01-01T00:00:00.000Z").ok, true, "millisecond form rejected");
  assert.equal(verifyWithValidFrom("2000-01-01T00:00:00Z").ok, true, "second-precision form rejected");
});

test("P0-6: the boundary is INCLUSIVE — signing exactly AT validFrom is allowed", () => {
  // `verify.ts:242` compares `at < from`, so equality is accepted. Pinned explicitly so a future
  // change to `<=` is a test failure rather than a silent semantic shift.
  //
  // The comparand is the ARTIFACT's own time, not `context.now`. My first version of this test used
  // `context.now` (12:00:00Z) while the vector's `decidedAt` is 11:56:00Z, so it asserted the wrong
  // boundary and failed — the test was wrong, not the code. Reading the comparand from the artifact
  // is what makes this pin meaningful.
  const at = String((fx.artifact as Record<string, unknown>)["decidedAt"] ?? (fx.artifact as Record<string, unknown>)["ts"]);
  assert.match(at, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3})?Z$/, "the fixture's artifact time is not canonical — this pin cannot be trusted");
  assert.equal(verifyWithValidFrom(at).ok, true, "a key activating at exactly the artifact time was refused — the boundary flipped to exclusive");
});
