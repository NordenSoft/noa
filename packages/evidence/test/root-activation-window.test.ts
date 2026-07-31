/**
 * P0-1 — A TRUST-ROOT KEY'S ACTIVATION WINDOW WAS OPEN AT ONE END.
 *
 * ─── THE DEFECT ─────────────────────────────────────────────────────────────────────────────────
 *
 * `asRootKeyEntryMap` (`trust.ts:68-78`) built ROOT entries carrying `revokedAt` but NOT
 * `validFrom`. `KeyEntry.validFrom` is OPTIONAL and `verify.ts:234` enforces activation only when it
 * is non-null — so a signature dated BEFORE a trust root's own declared activation verified clean.
 *
 * `KeyEntry`'s own docstring already describes this class:
 *     "Manifests already carried this field; `KeyEntry` did not, so every keyring resolver silently
 *      dropped it and pre-activation signatures verified clean."
 * The manifest resolver was fixed for exactly this (`trust.ts:154-156`, with a comment saying so).
 * The ROOT resolver 80 lines above it was not. The fix landed on one sibling.
 *
 * MEASURED before the fix, with a control that proves the parser was otherwise working:
 *     ROOT entry as parsed : {publicKey, type, roles, revokedAt}      <- no validFrom
 *     revokedAt carried    : true                                     <- the parser IS populating
 *
 * ─── COMPATIBILITY, MEASURED BEFORE THE FIX WAS WRITTEN ─────────────────────────────────────────
 *
 * Carrying the field through invalidates NO existing record:
 *     string shorthand `{"kid":"<spki>"}`  -> no validFrom, unchanged
 *     object without validFrom             -> no validFrom, unchanged   (treated as always-active)
 *     object WITH validFrom                -> was silently discarded, now enforced  <- the defect
 * Absent stays absent. No default activation time is invented — inventing one would fabricate
 * history for keys whose activation was never declared.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { asRootKeyEntryMap } from "../src/trust.js";

const enc = (o: unknown): Uint8Array => new TextEncoder().encode(JSON.stringify(o));
const PUB = "aa".repeat(32);
/** Parse a single ROOT record and REQUIRE it to resolve — a missing entry is a fixture bug, not a result. */
function root(extra: Record<string, unknown>) {
  const e = asRootKeyEntryMap(enc({ "root-a": { type: "ROOT", publicKey: PUB, roles: [], ...extra } }))["root-a"];
  if (e === undefined) throw new Error("fixture: the ROOT record did not resolve at all");
  return e;
}

// ────────────────────────────────────────────────────────────────────────────────────────────────
// THE DEFECT — the field must survive the parse, or nothing downstream can enforce it.
// ────────────────────────────────────────────────────────────────────────────────────────────────

test("P0-1: a ROOT entry's validFrom SURVIVES parsing", () => {
  const e = root({ validFrom: "2026-01-01T00:00:00.000Z", revokedAt: null });
  assert.equal(
    e.validFrom, "2026-01-01T00:00:00.000Z",
    "validFrom was dropped while building the ROOT key entry. `verify.ts:234` enforces activation " +
    "only when the field is non-null, so dropping it means a trust-root signature dated BEFORE its " +
    "own activation verifies clean — the window is open at one end",
  );
});

test("P0-1 ANTI-VACUITY: the parser is otherwise working, so the omission is SPECIFIC", () => {
  // Without this, a parser that returned `undefined` for everything would satisfy nothing above but
  // could be mistaken for the defect. `revokedAt` is the sibling field on the same branch.
  const e = root({ validFrom: "2026-01-01T00:00:00.000Z", revokedAt: "2027-01-01T00:00:00.000Z" });
  assert.equal(e.revokedAt, "2027-01-01T00:00:00.000Z", "revokedAt is not carried either — the parser is broken, not the field");
  assert.equal(e.publicKey, PUB, "the public key is not carried");
  assert.equal(e.type, "ROOT", "the type is not carried");
});

// ────────────────────────────────────────────────────────────────────────────────────────────────
// THE COMPATIBILITY RULE — explicit, and it must stay explicit.
// ────────────────────────────────────────────────────────────────────────────────────────────────

test("P0-1: an ABSENT validFrom stays absent — legacy roots are always-active, no default invented", () => {
  // The documented rule (`KeyEntry.validFrom`): "an entry without it (a root key, a test fixture) is
  // treated as always-active, so this is additive for existing callers." Inventing a default would
  // fabricate an activation time for keys whose activation was never declared.
  const obj = root({ revokedAt: null });
  assert.equal(obj.validFrom ?? null, null, "an absent validFrom was given a value — history invented");

  const shorthand = asRootKeyEntryMap(enc({ "root-b": PUB }))["root-b"];
  if (shorthand === undefined) throw new Error("the string-shorthand root form no longer parses — legacy records broken");
  assert.equal(shorthand.validFrom ?? null, null, "the shorthand form gained an activation time it never declared");
  assert.equal(shorthand.publicKey, PUB);
});

test("P0-1: a MALFORMED validFrom is carried through and fails CLOSED at the verifier", () => {
  // One rule, enforced in ONE place. The parser does not invent a second activation rule: it carries
  // what the record declared, and `verify.ts:236-239` refuses with "cannot evaluate activation time"
  // when the value will not parse. Silently dropping a malformed value would fail OPEN, which is the
  // defect this test exists to prevent recurring in a new disguise.
  const e = root({ validFrom: "not-a-timestamp", revokedAt: null });
  assert.equal(e.validFrom, "not-a-timestamp",
    "a malformed validFrom was silently dropped — the activation check would then be SKIPPED and " +
    "the record would verify clean, which fails OPEN");
});

// ────────────────────────────────────────────────────────────────────────────────────────────────
// REPRESENTATION — the same instant written two ways must compare equal.
// ────────────────────────────────────────────────────────────────────────────────────────────────

test("P0-1: timestamp representation cannot bypass the comparison", () => {
  // `Date.parse` is what `verify.ts` uses. These are THE SAME INSTANT written differently; if the
  // parser or the comparison were string-based, an offset form would slip past a Z-form boundary.
  const zForm = "2026-01-01T00:00:00.000Z";
  const offsetForm = "2026-01-01T01:00:00.000+01:00";
  assert.equal(Date.parse(zForm), Date.parse(offsetForm),
    "the two representations do not resolve to the same instant — the fixture is wrong, not the code");

  const a = root({ validFrom: zForm, revokedAt: null });
  const b = root({ validFrom: offsetForm, revokedAt: null });
  assert.equal(Date.parse(a.validFrom as string), Date.parse(b.validFrom as string),
    "the parser altered the instant a timestamp denotes");
});

// ────────────────────────────────────────────────────────────────────────────────────────────────
// CONSISTENCY — the ROOT path and the manifest path must not have two different activation rules.
// ────────────────────────────────────────────────────────────────────────────────────────────────

test("P0-1: the ROOT path and the MANIFEST path carry activation the SAME way", () => {
  // The manifest resolver (`trust.ts:156`) does `validFrom: k.validFrom ?? null`. The ROOT resolver
  // must produce a field the same downstream check can read, or the system has two activation rules
  // and only one of them is enforced — which is precisely how this defect arose.
  const rootEntry = root({ validFrom: "2026-06-01T00:00:00.000Z", revokedAt: null });
  assert.equal(typeof rootEntry.validFrom, "string", "the ROOT path does not expose validFrom as the verifier expects");
  assert.ok("revokedAt" in rootEntry, "the ROOT path does not expose revokedAt");
  // Both window ends present on the same entry: the check at verify.ts:234 (activation) and :243
  // (revocation) read the same shape from either resolver.
  const windowed = root({ validFrom: "2026-06-01T00:00:00.000Z", revokedAt: "2026-12-01T00:00:00.000Z" });
  assert.equal(windowed.validFrom, "2026-06-01T00:00:00.000Z");
  assert.equal(windowed.revokedAt, "2026-12-01T00:00:00.000Z");
});
