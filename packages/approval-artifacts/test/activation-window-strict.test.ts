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
import { generateKeyPair } from "../src/crypto.js";
import { signArtifact } from "../src/sign.js";
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

const BATCH_N_SIGNER = generateKeyPair(SIGNER);

function verifyBatchNDecision(
  decidedAt: string,
  options: {
    validFrom?: string | null;
    revokedAt?: string | null;
    now?: string | null;
    authorizationTime?: string | null;
    timeSchema?: Record<string, unknown>;
  } = {},
): { ok: boolean; reason: string } {
  const unsigned: Record<string, unknown> = {
    ...fx.artifact,
    decidedAt,
    approverKid: BATCH_N_SIGNER.kid,
  };
  delete unsigned.sig;
  const signed = signArtifact(
    enc(unsigned),
    ARTIFACTS["noa.decision/0.1"]!.domain!,
    BATCH_N_SIGNER,
  );
  const kr = JSON.parse(JSON.stringify(keyring)) as Record<string, KeyEntry>;
  const entry = kr[SIGNER]!;
  entry.publicKey = BATCH_N_SIGNER.publicKey;
  entry.type = "APPROVER";
  entry.roles = ["approve-high"];
  entry.validFrom = options.validFrom === undefined ? "2026-07-14T11:55:00.000Z" : options.validFrom;
  entry.revokedAt = options.revokedAt ?? null;
  const now = options.now === undefined ? "2026-07-14T12:00:00.000Z" : options.now;
  const authorizationTime = options.authorizationTime === undefined
    ? "2026-07-14T12:00:00.000Z"
    : options.authorizationTime;
  let selectedSchemas = schemas;
  if (options.timeSchema !== undefined) {
    const decisionSchema = JSON.parse(JSON.stringify(schemas["noa.decision/0.1"])) as Record<string, unknown>;
    const defs = decisionSchema["$defs"] as Record<string, unknown>;
    defs["rfc3339"] = options.timeSchema;
    selectedSchemas = { ...schemas, "noa.decision/0.1": decisionSchema };
  }
  const r = verifyArtifact(enc(signed), enc({
    schemas: selectedSchemas,
    keyring: kr,
    riskClass: "HIGH",
    mustBeWithin: [{
      path: "decidedAt",
      min: "2026-07-14T11:00:00.000Z",
      max: "2026-07-14T12:05:00.000Z",
    }],
    ...(now === null ? {} : { now }),
    ...(authorizationTime === null ? {} : { authorizationTime }),
  }));
  return { ok: r.ok, reason: r.ok ? "" : String(r.reason) };
}

/** Verify the REAL vector with the signer's `validFrom`; null deliberately omits trusted historical time. */
function verifyWithValidFrom(
  validFrom: unknown,
  authorizationTime: string | null = String(fx.context["now"]),
): { ok: boolean; reason: string } {
  const kr = JSON.parse(JSON.stringify(keyring)) as Record<string, KeyEntry>;
  kr[SIGNER] = { ...(kr[SIGNER] as KeyEntry), validFrom: validFrom as string | null };
  const r = verifyArtifact(enc(fx.artifact), enc({
    ...fx.context,
    schemas,
    keyring: kr,
    ...(authorizationTime === null ? {} : { authorizationTime }),
  }));
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
  assert.equal(r.ok, false, "a key that activates in 2099 verified at an earlier trusted caller time");
  assert.match(r.reason, /before its validFrom/, `refused for the wrong reason: ${r.reason}`);
});

test("P0-14 activation asymmetry: signer time may only move the verdict toward REFUSE", () => {
  const decidedAt = String(fx.artifact["decidedAt"]);
  const now = String(fx.context["now"]);
  const validFromAfterClaim = new Date(Date.parse(decidedAt) + 60_000).toISOString();
  assert.ok(Date.parse(now) > Date.parse(validFromAfterClaim), "fixture: verifier now must be after activation");

  // ATTACK: caller omits authorizationTime. Verifier-owned `now` permits acceptance, but the
  // signer's own claim says the signature predates its key. That contradiction can only REFUSE.
  const attack = verifyWithValidFrom(validFromAfterClaim, null);
  assert.equal(attack.ok, false, "a self-contradicting pre-activation artifact verified after the key activated");
  assert.match(attack.reason, /before its validFrom/, `refused for the wrong reason: ${attack.reason}`);

  // CONTROL, same run: an independently trusted historical authorization time inside the key's
  // activation window still accepts the unchanged, genuinely historical signed artifact.
  const validFromBeforeClaim = new Date(Date.parse(decidedAt) - 60_000).toISOString();
  const historical = verifyWithValidFrom(validFromBeforeClaim, decidedAt);
  assert.equal(historical.ok, true, `trusted historical control stopped verifying: ${historical.reason}`);

  // CONTROL, same run: a genuinely static entry has no activation assertion and is unaffected.
  const staticEntry = verifyWithValidFrom(null, null);
  assert.equal(staticEntry.ok, true, `static non-rotating control stopped verifying: ${staticEntry.reason}`);
});

test("Batch N: every published Decision timestamp spelling verifies while lifecycle time stays asymmetric", () => {
  const spellings = [
    "2026-07-14T11:56:00.000Z",
    "2026-07-14t11:56:00.000z",
    "2026-07-14T11:56:00.1Z",
    "2026-07-14T11:56:00.123456789Z",
    "2026-07-14T13:56:00.000+02:00",
  ];
  const compatibility = spellings.map((decidedAt) => ({
    decidedAt,
    outcome: verifyBatchNDecision(decidedAt),
  }));

  const contradictionWithoutAnyTrustedTime = verifyBatchNDecision(
    "2026-07-14T11:56:00.000Z",
    { validFrom: "2026-07-14T11:57:00.000Z", now: null, authorizationTime: null },
  );
  const rejectOnlyContradiction = verifyBatchNDecision(
    "2026-07-14T11:56:00.000Z",
    { validFrom: "2026-07-14T11:57:00.000Z", authorizationTime: null },
  );
  const futureDatedBeforeActivation = verifyBatchNDecision(
    "2026-07-14T20:00:00.000Z",
    { validFrom: "2026-07-14T13:00:00.000Z" },
  );
  const retired = verifyBatchNDecision(
    "2026-07-14T11:56:00.000Z",
    { validFrom: null, revokedAt: "2026-07-14T11:59:00.000Z" },
  );
  const unparseableSignerClaim = verifyBatchNDecision(
    "2026-02-30T11:56:00.000Z",
  );
  const subMillisecondContradiction = verifyBatchNDecision(
    "2026-07-14T11:56:00.123456788Z",
    { validFrom: "2026-07-14T11:56:00.123456789Z" },
  );
  // A raw throw fails this test before the returned-verdict assertions run.
  const permissiveSchemaOutcome = verifyBatchNDecision(
    "2026-07-14T11:56:00Q",
    { timeSchema: { type: "string" } },
  );
  const staticConsumer = verifyBatchNDecision(
    "2026-07-14T11:56:00.000Z",
    { validFrom: null, now: null, authorizationTime: null },
  );

  for (const row of compatibility) {
    assert.equal(row.outcome.ok, true,
      `${row.decidedAt} is permitted by the published Decision schema but was refused: ${row.outcome.reason}`);
  }
  assert.equal(contradictionWithoutAnyTrustedTime.ok, false,
    "a lifecycle-bearing key verified without verifier-controlled time");
  assert.match(contradictionWithoutAnyTrustedTime.reason, /trusted activation time/,
    `missing trusted time was refused for the wrong reason: ${contradictionWithoutAnyTrustedTime.reason}`);
  assert.equal(rejectOnlyContradiction.ok, false,
    "a signer-claimed time before validFrom verified after the key activated");
  assert.match(rejectOnlyContradiction.reason, /before its validFrom/,
    `the self-contradiction was refused for the wrong reason: ${rejectOnlyContradiction.reason}`);
  assert.equal(futureDatedBeforeActivation.ok, false,
    "a future-dated artifact activated a key before verifier-controlled time reached validFrom");
  assert.match(futureDatedBeforeActivation.reason, /evaluated at trusted time.*before its validFrom/,
    `the future-dated artifact was refused for the wrong reason: ${futureDatedBeforeActivation.reason}`);
  assert.equal(retired.ok, false, "a retired signer verified on the Decision surface");
  assert.match(retired.reason, /was revoked at/, `the retired signer was refused for the wrong reason: ${retired.reason}`);
  assert.equal(unparseableSignerClaim.ok, false,
    "a signer-claimed timestamp with a non-existent calendar date was accepted");
  assert.match(unparseableSignerClaim.reason, /cannot evaluate signer-claimed activation time/,
    `the unparseable signer claim was refused for the wrong reason: ${unparseableSignerClaim.reason}`);
  assert.equal(subMillisecondContradiction.ok, false,
    "a signer claim one nanosecond before validFrom was rounded into the activation window");
  assert.match(subMillisecondContradiction.reason, /before its validFrom/,
    `the nanosecond contradiction was refused for the wrong reason: ${subMillisecondContradiction.reason}`);
  assert.equal(permissiveSchemaOutcome.ok, false,
    "a timestamp the semantic parser cannot decode was accepted under a permissive supplied schema");
  assert.match(permissiveSchemaOutcome.reason, /cannot evaluate signer-claimed activation time/,
    `the permissive-schema timestamp was refused for the wrong reason: ${permissiveSchemaOutcome.reason}`);
  assert.equal(staticConsumer.ok, true,
    `a static non-rotating consumer stopped verifying: ${staticConsumer.reason}`);
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

test("P0-6: every published PAST activation spelling reaches the same semantic parser", () => {
  assert.equal(verifyWithValidFrom("2000-01-01T00:00:00.000Z").ok, true, "millisecond form rejected");
  assert.equal(verifyWithValidFrom("2000-01-01T00:00:00Z").ok, true, "second-precision form rejected");
  assert.equal(verifyWithValidFrom("2000-01-01t00:00:00.1z").ok, true, "lowercase/fractional form rejected");
  assert.equal(verifyWithValidFrom("2000-01-01T00:00:00.123456789Z").ok, true, "nanosecond form rejected");
  // Accepted grammar comes from the published schema; emit stays uppercase `T`/`Z`.
  assert.equal(verifyWithValidFrom("2026-01-01T00:00:00+01:00").ok, true, "RFC 3339 offset form rejected");
});

// ────────────────────────────────────────────────────────────────────────────────────────────────
// P0-12 — ROOT IS NOT EXEMPT. Every activation test above probes the DECISION vector, whose signer
// is an APPROVER. MEASURED (2026-07-31): exempting ROOT from the activation branch
// (`entry.validFrom != null && entry.type !== "ROOT"`) introduced NO NEW FAILURE across five suites
// (1040 tests: 1038 passed, the 2 known-red owner-deferred ADR-0006 gate tests unchanged) —
// [corrected 2026-07-31: this line first said "left 1040 tests GREEN", stating the total as a pass
// count and denying two real failures — the same claim-precision defect this file polices] —
// P0-1 proved a ROOT's `validFrom` is CARRIED, and nothing proved it is ENFORCED. These tests probe
// the artifact a ROOT key actually signs (the key-delegation, signerType ROOT), so that exact
// mutation turns them RED while the APPROVER tests above stay green — the failure names the
// exemption, not a broken harness. Twin through the real §13 consumer:
// packages/evidence/test/root-activation-window.test.ts. Knockout: `p12-root-activation-enforced`.
// ────────────────────────────────────────────────────────────────────────────────────────────────

const dfx = JSON.parse(readFileSync(join(ROOT, "conformance", "key-delegation", "valid.json"), "utf8")) as {
  artifact: Record<string, unknown>;
  context: Record<string, unknown>;
};
const ROOT_SIGNER = (dfx.artifact["sig"] as { kid: string }).kid;

/** Verify the REAL root-signed delegation vector at a trusted caller time. */
function verifyDelegationWithRootValidFrom(validFrom: unknown): { ok: boolean; reason: string } {
  const kr = JSON.parse(JSON.stringify(keyring)) as Record<string, KeyEntry>;
  kr[ROOT_SIGNER] = { ...(kr[ROOT_SIGNER] as KeyEntry), validFrom: validFrom as string | null };
  const r = verifyArtifact(enc(dfx.artifact), enc({ ...dfx.context, schemas, keyring: kr, authorizationTime: dfx.context["now"] }));
  return { ok: r.ok, reason: r.ok ? "" : String(r.reason) };
}

test("P0-12 [PROOF:RES-PAR-ROOT-ENFORCED]: a trust ROOT is NOT exempt from its own activation window", () => {
  // Control 1 (harness): the unmodified delegation vector verifies through the same call.
  const ctl = verifyArtifact(enc(dfx.artifact), enc({ ...dfx.context, schemas, keyring }));
  assert.equal(ctl.ok, true, `the shipped delegation vector does not verify (${ctl.ok ? "" : ctl.reason}) — the probe below would refuse for the wrong reason`);

  // Control 2 (specificity): the SAME future instant on a NON-ROOT signer is refused. Under the
  // ROOT-exemption mutation this still passes, so only the probe below flips — the RED names ROOT.
  const nonRoot = verifyWithValidFrom("2099-01-01T00:00:00.000Z");
  assert.equal(nonRoot.ok, false, "non-ROOT activation stopped being enforced — the branch itself is broken, not the ROOT case");

  // The probe: a ROOT that activates in 2099 must not vouch at the earlier trusted caller time.
  const r = verifyDelegationWithRootValidFrom("2099-01-01T00:00:00.000Z");
  assert.equal(r.ok, false,
    "a trust ROOT with a declared FUTURE activation vouched for a delegation NOW. The trust anchor " +
    "is the one key whose window matters most, and an exemption here re-opens P0-1 one layer up");
  assert.match(r.reason, /before its validFrom/, `refused, but not by the activation check: ${r.reason}`);
});

test("P0-12: ROOT compatibility + fail-closed follow the SAME rules as every signer", () => {
  // A canonical PAST activation still vouches (the P0-1 compatibility rule, now at the verifier).
  assert.equal(verifyDelegationWithRootValidFrom("2000-01-01T00:00:00.000Z").ok, true,
    "a ROOT with a canonical past activation stopped vouching — compatibility broke");
  // An ABSENT activation stays always-active (documented legacy; asRootKeyEntryMap terse form).
  assert.equal(verifyDelegationWithRootValidFrom(null).ok, true,
    "a ROOT with no declared activation stopped vouching — the documented legacy rule broke");
  // A MALFORMED declared activation fails CLOSED by the same parser rule as P0-6.
  const mal = verifyDelegationWithRootValidFrom("not-a-timestamp");
  assert.equal(mal.ok, false, "a malformed ROOT validFrom was accepted — the check was skipped (fail OPEN)");
  assert.match(mal.reason, /cannot evaluate activation time/, `wrong refusal reason: ${mal.reason}`);
});

test("P0-6: the boundary is INCLUSIVE — verification exactly AT validFrom is allowed", () => {
  // `verify.ts:242` compares `at < from`, so equality is accepted. Pinned explicitly so a future
  // change to `<=` is a test failure rather than a silent semantic shift.
  //
  // The comparand is explicitly caller-controlled. Using the artifact's decidedAt as an implicit
  // fallback would reopen the activation-mirror attack.
  const at = String((fx.artifact as Record<string, unknown>)["decidedAt"] ?? (fx.artifact as Record<string, unknown>)["ts"]);
  assert.match(at, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3})?Z$/, "the fixture's artifact time is not canonical — this pin cannot be trusted");
  assert.equal(verifyWithValidFrom(at, at).ok, true, "a key evaluated exactly at activation was refused — the boundary flipped to exclusive");
});

test("P0-10 ANTI-VACUITY: mustBeWithin runs against the verifying decision vector", () => {
  const control = verifyArtifact(enc(fx.artifact), enc({ ...fx.context, schemas, keyring }));
  assert.equal(control.ok, true,
    `the shipped decision vector does not verify (${control.ok ? "" : control.reason}) — the window probe would be meaningless`);

  const excluded = verifyArtifact(enc(fx.artifact), enc({
    ...fx.context,
    schemas,
    keyring,
    mustBeWithin: [{ path: "decidedAt", min: "2099-01-01T00:00:00.000Z", max: "2100-01-01T00:00:00.000Z" }],
  }));
  assert.equal(excluded.ok, false, "a decision outside a well-formed mustBeWithin window was accepted");
  assert.match(String(excluded.reason), /time check failed: decidedAt must be within/,
    `the well-formed window was refused for the wrong reason: ${excluded.reason}`);
});

test("P0-10: mustBeWithin refuses every malformed window bound", () => {
  for (const window of [
    { label: "both bounds", min: "not-a-time", max: "also-not-a-time" },
    { label: "min only", min: "not-a-time", max: "2100-01-01T00:00:00.000Z" },
    { label: "max only", min: "2000-01-01T00:00:00.000Z", max: "not-a-time" },
  ]) {
    const r = verifyArtifact(enc(fx.artifact), enc({
      ...fx.context,
      schemas,
      keyring,
      mustBeWithin: [{ path: "decidedAt", min: window.min, max: window.max }],
    }));
    assert.equal(r.ok, false, `mustBeWithin accepted malformed ${window.label}: [${window.min}, ${window.max}]`);
    assert.match(String(r.reason), /time check failed: decidedAt must be within/,
      `malformed ${window.label} was refused for the wrong reason: ${r.reason}`);
  }
});

test("P0-9: a targeted Date.prototype.toISOString poison cannot admit a non-existent activation date", () => {
  const impossible = "2026-02-30T00:00:00.000Z";
  const rolled = "2026-03-02T00:00:00.000Z";

  const clean = verifyWithValidFrom(impossible);
  assert.equal(clean.ok, false, "a non-existent activation date was accepted without the poison");
  assert.match(clean.reason, /cannot evaluate activation time/,
    `the clean non-existent date was refused for the wrong reason: ${clean.reason}`);

  const originalToISOString = Date.prototype.toISOString;
  try {
    Date.prototype.toISOString = function targetedToISOStringPoison(): string {
      const actual = originalToISOString.call(this);
      return actual === rolled ? impossible : actual;
    };

    const control = verifyArtifact(enc(fx.artifact), enc({ ...fx.context, schemas, keyring }));
    assert.equal(control.ok, true,
      `the unmodified conformance vector failed while the targeted poison was installed (${control.ok ? "" : control.reason})`);

    const attacked = verifyWithValidFrom(impossible);
    assert.equal(attacked.ok, false,
      "a targeted Date.prototype.toISOString poison admitted a non-existent activation date");
    assert.match(attacked.reason, /cannot evaluate activation time/,
      `the poisoned non-existent date was refused for the wrong reason: ${attacked.reason}`);
  } finally {
    Date.prototype.toISOString = originalToISOString;
  }
});

test("P0-11: equivalent RFC 3339 instant spellings produce the same activation outcome", () => {
  const control = verifyArtifact(enc(fx.artifact), enc({ ...fx.context, schemas, keyring }));
  assert.equal(control.ok, true,
    `the unmodified conformance vector does not verify (${control.ok ? "" : control.reason}) — the equivalence probe would be meaningless`);

  for (const malformed of [
    "2026-07-14T13:56:00.000+99:00",
    "2026-07-14T13:56:00.000+02:60",
    "2026-07-14T13:56:00.000+2:00",
    "2026-07-14T13:56:00.000+02",
  ]) {
    const refused = verifyWithValidFrom(malformed);
    assert.equal(refused.ok, false, `malformed offset ${JSON.stringify(malformed)} was accepted`);
    assert.match(refused.reason, /cannot evaluate activation time/,
      `malformed offset ${JSON.stringify(malformed)} was refused for the wrong reason: ${refused.reason}`);
  }

  const boundary = "2026-07-14T11:56:00.000Z";
  const outsideWindow = verifyWithValidFrom("2026-07-14T14:56:00.000+02:00", boundary);
  assert.equal(outsideWindow.ok, false,
    "a well-formed offset activation instant one hour after the trusted time was accepted");

  const spellings = [
    "2026-07-14T11:56:00.000Z",
    "2026-07-14T13:56:00.000+02:00",
    "2026-07-14T06:56:00.000-05:00",
  ];
  const outcomes = spellings.map((spelling) => verifyWithValidFrom(spelling, boundary));
  assert.equal(outcomes[0]!.ok, true, "the Z spelling at the activation boundary was refused");
  for (let i = 1; i < outcomes.length; i += 1) {
    assert.deepEqual(outcomes[i], outcomes[0],
      `${spellings[i]} and ${spellings[0]} denote the same instant but produced different verification outcomes`);
  }
});
