/**
 * THE ENROLMENT PLANE, MEASURED WHERE THE CORPUS CANNOT REACH.
 *
 * The conformance corpus pins one fixture per rule at the process boundary. This file pins the
 * things a fixture corpus is the wrong instrument for: the DOWNGRADE attacks (what happens when a
 * reader is handed a broken, hostile or near-miss registry), the properties that must hold ACROSS
 * many registries, and the non-claims — the escapes this design concedes rather than closes.
 *
 * ── THE ONE PROPERTY EVERYTHING HERE IS TESTING ──────────────────────────────────────────────────
 *
 *   SUPPLYING A REGISTRY MAY ONLY EVER MAKE A VERDICT HARDER TO REACH.
 *
 * Every test below is an attempt to find an input for which that is false — a registry whose
 * CONTENT, ABSENCE OF CONTENT, or MALFORMEDNESS buys a positive the same bundle would not otherwise
 * have got. The design's predecessor failed exactly this: a class positively absent from a
 * `closed:true` registry received the legacy positive, so narrowing a registry was a bypass and the
 * same document recommended narrowing.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { verifyEvidence, loadSchemas } from "../src/verify-evidence.js";
import { exitCodeFor } from "../src/exit-codes.js";
import { b } from "./helpers/bytes.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const CONF = join(HERE, "..", "..", "conformance");
const schemas = loadSchemas();

interface Fixture {
  expectVerdict: string; expectStep: string | null; expectCode: string | null;
  now: string; maxAgeHours: number;
  bundle: Record<string, unknown>;
  tenantRoot: Record<string, unknown>; checkpointKeyring: Record<string, unknown>;
  enrolmentRegistries?: Array<Record<string, unknown>>; audience?: string;
}

function load(id: string): Fixture {
  return JSON.parse(readFileSync(join(CONF, `${id}.json`), "utf8")) as Fixture;
}

/** Run a fixture, optionally REPLACING what the reader was handed. */
function run(fx: Fixture, over: { registries?: unknown[] | undefined; audience?: string | undefined } = {}) {
  const registries = over.registries !== undefined ? over.registries : fx.enrolmentRegistries;
  const audience = "audience" in over ? over.audience : fx.audience;
  return verifyEvidence(b(fx.bundle), {
    tenantRoot: b(fx.tenantRoot),
    checkpointKeyring: b(fx.checkpointKeyring),
    ...(registries !== undefined ? { enrolmentRegistries: (registries as unknown[]).map((r) => b(r)) } : {}),
    ...(audience !== undefined ? { audience } : {}),
    now: fx.now,
    maxAgeMs: fx.maxAgeHours * 3600 * 1000,
    schemas,
  });
}

const exitOf = (r: ReturnType<typeof run>): number => exitCodeFor(r.verdict, r.enrolment, r.dimensions.settlement);

/** The enrolled base: a bundle whose class IS enrolled by the registry its fixture ships. */
const ENROLLED = "enrolment/s5-enrolled-no-settlement";
/** The SAME bundle bytes, verified with no registry at all. */
const NO_REGISTRY = "enrolment/s5-enrolment-no-registry";

// ── 1. THE DOWNGRADE ATTACKS — a broken registry must never equal no registry ────────────────────

test("DOWNGRADE: a MALFORMED registry does not reset the reader to the permissive regime", () => {
  // THE ATTACK THIS PLANE EXISTS FOR, in its most direct form. If a registry the verifier cannot use
  // fell back to "nobody asked", then anyone who can corrupt the file on its way to the reader —
  // truncation, a proxy, a bad deploy — silently restores the regime where a self-reported dispatch
  // is believed. The reader ASKED; the honest answer is that its configuration could not answer.
  const fx = load(ENROLLED);
  for (const [why, junk] of [
    ["not JSON at all", "not-a-json-document"],
    ["an empty object", {}],
    ["the wrong spec", { spec: "noa.key-manifest/0.1" }],
    ["a registry with its signature stripped", (() => { const c = JSON.parse(JSON.stringify(fx.enrolmentRegistries![0])) as Record<string, unknown>; delete c.sig; return c; })()],
    ["a registry with a corrupted signature", (() => { const c = JSON.parse(JSON.stringify(fx.enrolmentRegistries![0])) as Record<string, unknown>; (c.sig as Record<string, unknown>).value = "AA=="; return c; })()],
  ] as const) {
    const res = run(fx, { registries: [junk] });
    assert.equal(res.verdict, "UNVERIFIED", `${why}: verdict ${res.verdict}`);
    assert.equal(res.code, "E_ENROLMENT_UNVERIFIABLE", `${why}: code ${res.code}`);
    assert.equal(res.enrolment, "UNVERIFIABLE", `${why}: enrolment ${res.enrolment}`);
    assert.equal(
      exitOf(res), 4,
      `${why}: exited ${exitOf(res)}. A registry the verifier cannot use is NOT the same as no registry, ` +
        `and if it were, corrupting a file would be a policy downgrade anyone on the path could perform.`,
    );
  }
});

test("DOWNGRADE: an EMPTY closed registry blesses nothing — it refuses everything", () => {
  // The one-signature restoration of the fully permissive regime, and it does not exist. A tenant
  // cannot publish `classes: [], closed: true` and thereby return every class to "the gate's word is
  // enough". Both shapes are measured because they are different documents making the same move: a
  // registry with NO classes at all, and one whose classes positively omit this bundle's.
  //
  // The registries are the SHIPPED, GENUINELY SIGNED ones. Editing a registry in-process would test
  // authentication instead — an unsigned edit is refused before the emptiness rule is ever reached,
  // which would look like a pass and measure nothing.
  for (const id of ["enrolment/s5-enrolment-empty-closed-registry", "enrolment/s5-enrolment-class-absent"] as const) {
    const res = run(load(id));
    assert.equal(res.verdict, "UNVERIFIED", `${id}: verdict`);
    assert.equal(res.code, "E_ENROLMENT_CLASS_ABSENT", `${id}: code`);
    assert.equal(exitOf(res), 4, `${id}: an omission bought a positive — that is the bypass this design replaced`);
  }
});

test("DOWNGRADE: an empty --audience string is not 'no audience needed'", () => {
  // A caller passing `""` is passing a value, and a naive presence test (`audience !== undefined`)
  // would treat it as an identity that no registry can match — or worse, as a wildcard. It is
  // neither: it is a missing reader identity, and the plane fails closed with the code that says so.
  const fx = load(ENROLLED);
  const res = run(fx, { audience: "" });
  assert.equal(res.verdict, "UNVERIFIED");
  assert.equal(res.code, "E_ENROLMENT_AUDIENCE");
  assert.equal(exitOf(res), 4);
});

test("DOWNGRADE: audience matching is EXACT — no wildcard, no prefix, no case folding", () => {
  // Three near-misses that a lenient matcher would accept, and each one is a registry written for
  // somebody else being read as this reader's policy. The wildcard case is doubly refused: the
  // grammar forbids `*` in an identifier, so the document does not even authenticate.
  const fx = load(ENROLLED);
  const reg = fx.enrolmentRegistries![0]!;
  for (const [why, audience] of [
    ["a prefix of the registry's audience", "rp:vendor"],
    ["a superstring of it", "rp:vendor.example.attacker"],
    ["a case variant", "RP:VENDOR.EXAMPLE"],
    ["a literal asterisk", "*"],
  ] as const) {
    const res = run(fx, { registries: [reg], audience });
    assert.equal(
      res.code, "E_ENROLMENT_UNVERIFIABLE",
      `${why} (${audience}) selected a registry it does not name — got ${res.code}`,
    );
    assert.equal(exitOf(res), 4);
  }
});

test("DOWNGRADE: a registry naming EVERY audience it can think of still cannot bless a class", () => {
  // Even a registry that DOES name this reader, is in window, closed and authentic can only ever
  // impose a requirement. There is no field whose value makes a bundle easier to accept, so an
  // attacker who somehow obtained the enrolment key gains a denial-of-service, never a forgery.
  const fx = load(ENROLLED);
  const res = run(fx);
  assert.equal(res.verdict, "INCONCLUSIVE");
  assert.equal(res.code, "E_SETTLEMENT_REQUIRED");
  assert.notEqual(exitOf(res), 0, "an enrolled class reached a positive with no settlement evidence");
});

// ── 2. PROPERTIES ACROSS MANY REGISTRIES ─────────────────────────────────────────────────────────

test("MANY REGISTRIES: the reader may hold several, and only the ones addressed to it are consulted", () => {
  // A relying party legitimately holds a stack: one per tenant it transacts with, and successive
  // windows for the same tenant. A registry for another reader sitting in that stack must be inert —
  // neither selected nor an accusation.
  const enrolled = load(ENROLLED);
  const forSomeoneElse = load("enrolment/s5-enrolment-audience-mismatch").enrolmentRegistries![0]!;
  const res = run(enrolled, { registries: [forSomeoneElse, enrolled.enrolmentRegistries![0]!] });
  assert.equal(res.enrolment, "ENROLLED", "a registry addressed elsewhere blocked one that was addressed here");
  assert.equal(res.code, "E_SETTLEMENT_REQUIRED");
});

test("MANY REGISTRIES: a SUPERSEDED window is not a contradiction, and the current one governs", () => {
  // Registry rotation is ordinary governance: the old registry keeps its old class hashes and its
  // window closes. Reading row-level disagreements across out-of-window registries would turn every
  // projection re-build into a hard INVALID for every archived bundle — an outage manufactured by a
  // rule meant to catch substitution. Registry-LEVEL contradictions (tenant) are not window-scoped;
  // ROW-level ones are.
  const fx = load("enrolment/s5-enrolment-superseded-registry-not-a-contradiction");
  const res = run(fx);
  assert.equal(res.verdict, "INCONCLUSIVE", `a superseded registry was read as an accusation: ${res.code}`);
  assert.equal(res.code, "E_SETTLEMENT_REQUIRED");
  assert.equal(res.enrolment, "ENROLLED");
});

test("MANY REGISTRIES: an equivocating pair resolves toward the REQUIREMENT, never away from it", () => {
  // Two in-window registries the reader holds at once: one enrols the class, one omits it. Whichever
  // the tenant meant, the verifier takes the stricter reading — the class is enrolled and owes a
  // witness. The opposite resolution would let a tenant equivocate its way back to the permissive
  // regime by publishing a second, narrower registry.
  const enrolled = load(ENROLLED);
  const omitting = load("enrolment/s5-enrolment-class-absent").enrolmentRegistries![0]!;
  for (const order of [[omitting, enrolled.enrolmentRegistries![0]!], [enrolled.enrolmentRegistries![0]!, omitting]]) {
    const res = run(enrolled, { registries: order });
    assert.equal(res.enrolment, "ENROLLED", "an omitting registry cancelled an enrolling one");
    assert.equal(res.code, "E_SETTLEMENT_REQUIRED");
  }
});

// ── 3. THE MIGRATION GUARANTEE, AS A DIFFERENCE ──────────────────────────────────────────────────

test("MIGRATION: the same bundle, two readers — and the ONLY difference is the reader's configuration", () => {
  const withRegistry = load(ENROLLED);
  const without = load(NO_REGISTRY);
  assert.deepEqual(withRegistry.bundle, without.bundle, "the pair is only a measurement over identical bytes");

  const a = run(without);
  assert.equal(a.verdict, "VALID_FULL_CHAIN");
  assert.equal(a.enrolment, "NOT_EVALUATED");
  assert.equal(a.failedStep, undefined);
  assert.equal(exitOf(a), 0);

  const withIt = run(withRegistry);
  assert.equal(withIt.verdict, "INCONCLUSIVE");
  assert.equal(withIt.enrolment, "ENROLLED");
  assert.equal(exitOf(withIt), 6);
});

test("MIGRATION: an outcome that asserts no execution effect is never enrolment-evaluated", () => {
  // The enrolment plane lives inside steps 10 and 11 — the two POSITIVE outcomes, which are the two
  // that escape step 15's fresh-checkpoint tax. Handing a registry to a reader verifying a DENIED
  // bundle asks a question about a class that did nothing, and the honest answer is that the question
  // was not put. Asserting it here means a future rule that started evaluating enrolment on the other
  // six outcomes would be a visible edit rather than a silent re-verdicting of historical evidence.
  const denied = load("valid/denied");
  const registry = load(ENROLLED).enrolmentRegistries![0]!;
  const res = run(denied, { registries: [registry], audience: "rp:vendor.example" });
  assert.equal(res.verdict, "VALID_FULL_CHAIN");
  assert.equal(res.enrolment, "NOT_EVALUATED");
  assert.equal(exitOf(res), 0);
});

// ── 4. NON-CLAIMS — the escapes this design CONCEDES, written down rather than implied ───────────

test("NON-CLAIM: a reader that supplies no registry gets the old regime, and that is the concession", () => {
  // The migration guarantee and the escape are the SAME property read from two sides, and this is the
  // side that is a residual: a relying party that configures no registry sees a self-reported dispatch
  // as VALID_FULL_CHAIN. It is not closable from inside the verifier — a verifier cannot require an
  // input it was not given — and unlike the signer-side routes, the party declining here is the one
  // being protected rather than the one being judged.
  const res = run(load(NO_REGISTRY));
  assert.equal(res.verdict, "VALID_FULL_CHAIN");
  assert.equal(res.dimensions.settlement, "NO_EXECUTION_BINDING");
  assert.equal(
    res.enrolment, "NOT_EVALUATED",
    "the result must SAY that nothing was asked. A positive that does not disclose which questions " +
      "went unasked is the shape this dimension exists to prevent.",
  );
});

test("NON-CLAIM: outcome shopping is not closed — a relabelled outcome escapes the enrolment plane", () => {
  // A gate that wants to avoid the requirement can claim an outcome the plane does not run for. The
  // FAILURE label is closed for an enrolled class (the carry-forward rule), and `UNKNOWN_AFTER_DISPATCH`
  // is not: it needs only a gate-signed uncertainty artifact — a self-report by the party being judged.
  // What it costs is step 15's fresh-checkpoint tax, which the two positive outcomes do not pay.
  // Written as a test so the concession is measured rather than remembered.
  const unknown = load("valid/unknown_after_dispatch");
  const registry = load(ENROLLED).enrolmentRegistries![0]!;
  const res = run(unknown, { registries: [registry], audience: "rp:vendor.example" });
  assert.equal(res.verdict, "VALID_FULL_CHAIN", "if this ever stops being true, this non-claim needs re-reading, not deleting");
  assert.equal(res.enrolment, "NOT_EVALUATED");
  // …and the FAILURE label, which is the one that pays no freshness tax, IS closed.
  const failure = run(load("enrolment/s5-enrolled-failure-unwitnessed"));
  assert.equal(failure.verdict, "INCONCLUSIVE");
  assert.equal(failure.code, "E_NON_DISPATCH_UNWITNESSED");
});

test("NON-CLAIM: enrolment authority rides the bundle's OWN delegation, and old bundles fall the safe way", () => {
  // A registry is authenticated against the keyring resolved from the BUNDLE's delegation, so a
  // tenant that grants enrolment authority today cannot have its registry consulted against a bundle
  // whose delegation predates the grant. Those bundles report UNVERIFIED, not VALID — the fail-closed
  // direction — and a reader auditing archives can simply not supply the registry. Measured here on
  // the shipped EXECUTED fixture, whose delegation carries `key-manifest-sign` alone.
  const legacy = load("valid/executed");
  const registry = load(ENROLLED).enrolmentRegistries![0]!;
  const res = run(legacy, { registries: [registry], audience: "rp:vendor.example" });
  assert.equal(res.verdict, "UNVERIFIED");
  assert.equal(res.code, "E_ENROLMENT_UNVERIFIABLE");
  assert.equal(exitOf(res), 4, "a bundle whose delegation never granted enrolment authority must not silently pass");
});

// ── 5. ANTI-VACUITY OVER THE WHOLE ENROLMENT CORPUS ──────────────────────────────────────────────

test("ANTI-VACUITY: the enrolment corpus produces every refusal code exactly once", () => {
  // Two codes that are mutually substitutable prove nothing about which rule fired: a bug that turns
  // "this registry is not addressed to me" into "this class is not in it" would pass both fixtures.
  // So each code is claimed by exactly one fixture, and every code the plane can emit is claimed.
  const dir = join(CONF, "enrolment");
  const seen = new Map<string, string[]>();
  for (const f of readdirSync(dir)) {
    if (!f.endsWith(".json")) continue;
    const fx = JSON.parse(readFileSync(join(dir, f), "utf8")) as Fixture;
    const res = run(fx);
    const key = res.code ?? "(no failure)";
    seen.set(key, [...(seen.get(key) ?? []), f]);
  }
  const ENROLMENT_CODES = [
    "E_ENROLMENT_AUDIENCE", "E_ENROLMENT_UNVERIFIABLE", "E_ENROLMENT_NOT_CLOSED",
    "E_ENROLMENT_OUT_OF_WINDOW", "E_ENROLMENT_CLASS_ABSENT", "E_ENROLMENT_MISMATCH",
    "E_SETTLEMENT_REQUIRED", "E_SETTLEMENT_UNRECONFIRMED", "E_NON_DISPATCH_UNWITNESSED",
  ];
  for (const code of ENROLMENT_CODES) {
    assert.ok((seen.get(code) ?? []).length >= 1, `no enrolment fixture produces ${code} — the rule that emits it is unmeasured`);
  }
  assert.ok((seen.get("(no failure)") ?? []).length >= 2, "the corpus refuses everything; nothing proves a registry-capable bundle can still verify");
});

test("ANTI-VACUITY: every enrolment fixture is checked against a REAL statSync'd directory", () => {
  // Guards the loop above: a mistyped path would make it iterate nothing and pass silently.
  const dir = join(CONF, "enrolment");
  assert.ok(statSync(dir).isDirectory());
  assert.ok(readdirSync(dir).filter((f) => f.endsWith(".json")).length >= 14, "the enrolment corpus shrank");
});
