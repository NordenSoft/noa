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
  // `in` rather than `!== undefined`, so a caller can say "hand this reader NOTHING" and mean it.
  // With a `??` fallback, passing `undefined` would silently restore the fixture's own registries —
  // and the test that most needs to express "no registries" is the one about the permissive regime.
  const registries = "registries" in over ? over.registries : fx.enrolmentRegistries;
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

// ── 1a. THE COLLECTION ITSELF — a supplied registry must never normalize to "none supplied" ──────

/** Verify with a caller-supplied registry collection of an arbitrary shape. */
function runWithCollection(fx: Fixture, supplied: unknown) {
  return verifyEvidence(b(fx.bundle), {
    tenantRoot: b(fx.tenantRoot),
    checkpointKeyring: b(fx.checkpointKeyring),
    enrolmentRegistries: supplied as never,
    audience: fx.audience!,
    now: fx.now,
    maxAgeMs: fx.maxAgeHours * 3600 * 1000,
    schemas,
  });
}

test("DOWNGRADE: a SUPPLIED registry collection this verifier cannot read as a list is REFUSED", () => {
  // THE HIGH FINDING, and the most dangerous shape in the plane because it skips the plane entirely.
  // The option was normalized as `Array.isArray(x) ? [...x] : undefined`, so ANYTHING not recognised
  // as an array became `undefined` — the NO-REGISTRY branch — and a reader that DID supply governance
  // got VALID_FULL_CHAIN / NOT_EVALUATED / exit 0.
  //
  // "An unrecognised trust-input shape must never soften to 'not supplied'" is the rule, and it is
  // the one the tenant root and the checkpoint keyring already follow: an input the verifier cannot
  // read is a refusal, never a permission. TypeScript does not make malformed JavaScript calls
  // impossible, and this is a PUBLISHED runtime entry point.
  const fx = load(ENROLLED);
  const registry = b(fx.enrolmentRegistries![0]!);
  for (const [why, supplied] of [
    ["the registry bytes handed over directly, not wrapped in a list", registry],
    ["an array-LIKE object", { 0: registry, length: 1 }],
    ["a string", "not-a-list"],
    ["a number", 1],
    ["null", null],
    ["a Set of registries", new Set([registry])],
    // FOUND WHILE SELF-REFUTING THE FIX ABOVE, and it is the same defect one layer out: a PROXY over
    // a real array passes `Array.isArray` (which unwraps to the target) while every read — `length`
    // included — runs the handler. Trapping `length` to 0 snapshotted an empty list over a full one
    // and exited 0 with a registry supplied. The "`length` cannot be an accessor" argument is true of
    // real arrays and of nothing else, so a programmable stand-in is refused rather than read.
    ["a Proxy whose length trap reports an empty list", new Proxy([registry], { get(t, k, rc) { return k === "length" ? 0 : Reflect.get(t, k, rc); } })],
    ["a transparent Proxy over a real array", new Proxy([registry], {})],
  ] as const) {
    const res = runWithCollection(fx, supplied);
    assert.equal(
      res.verdict, "INVALID",
      `${why}: verdict ${res.verdict} / enrolment ${res.enrolment}. A supplied collection this verifier ` +
        `cannot read as a list must be REFUSED — softening it into the unconfigured branch returns a ` +
        `positive verdict to a reader that did supply governance.`,
    );
    assert.equal(res.enrolment, "NOT_EVALUATED", `${why}: the plane never ran, so it has nothing to report`);
    assert.equal(exitOf(res), 2, `${why}: exit ${exitOf(res)}`);
  }
});

test("DOWNGRADE: the copy is taken BY INDEX — a poisoned own iterator cannot empty the list", () => {
  // The second half of the same finding. `[...caller]` runs the CALLER'S iterator, so a genuine array
  // — one `Array.isArray` calls an array — carrying an own `Symbol.iterator` that yields nothing
  // copied to `[]`: the no-registry branch and exit 0 again. Snapshotting by index through `length`
  // closes it, because on a real array `length` is a non-configurable data property — there is no
  // accessor to lie and no iterator to run.
  const fx = load(ENROLLED);
  const hostile: unknown[] = [b(fx.enrolmentRegistries![0]!)];
  Object.defineProperty(hostile, Symbol.iterator, { value: function* () { /* yields nothing */ }, configurable: true });
  const res = runWithCollection(fx, hostile);
  assert.equal(res.enrolment, "ENROLLED", `enrolment ${res.enrolment}: the registry was dropped by its own iterator`);
  assert.equal(res.code, "E_SETTLEMENT_REQUIRED");
  assert.equal(exitOf(res), 6, "an array whose iterator yields nothing reached the permissive branch");
});

test("DOWNGRADE: an index ACCESSOR is read exactly once, and cannot answer two different things", () => {
  // The remaining caller-owned surface on a real array: element slots CAN be accessors even though
  // `length` cannot. Read twice, one could authenticate as a valid registry and then be consumed as
  // something else. The snapshot reads each slot ONCE, and the count is the evidence.
  const fx = load(ENROLLED);
  const registry = b(fx.enrolmentRegistries![0]!);
  let reads = 0;
  const probing: unknown[] = [];
  Object.defineProperty(probing, "0", { get() { reads += 1; return registry; }, enumerable: true, configurable: true });
  probing.length = 1;
  const res = runWithCollection(fx, probing);
  assert.equal(reads, 1, `the caller's element accessor fired ${reads} times — it must be read exactly once`);
  assert.equal(res.enrolment, "ENROLLED");
  assert.equal(exitOf(res), 6);
});

test("DOWNGRADE: the BYTE BOUNDARY holds for the registry too — it is a document, not an object", () => {
  // The registry joins the trust root and the checkpoint keyring as a DOCUMENT, so the same boundary
  // rules apply to it: a live object is refused rather than traversed (its getters could answer one
  // thing to the signature check and another to the field read), a duplicate key is refused rather
  // than last-wins (producer and verifier must not be able to disagree about which value is "the"
  // value), and `__proto__` is refused rather than applied.
  //
  // These are exercised HERE rather than assumed from the kernel, because a new caller of the parser
  // is a new place to get it wrong: the bytes that get AUTHENTICATED and the bytes that get READ have
  // to be the same bytes, and this file is where that is measured for the newest input.
  const fx = load(ENROLLED);
  const registry = fx.enrolmentRegistries![0]!;
  const cases: ReadonlyArray<readonly [string, unknown]> = [
    ["a live object where a document belongs", registry],
    ["a duplicate key", "{\"spec\":\"noa.action-class-enrolment/0.1\",\"spec\":\"other\"}"],
    ["a __proto__ key", "{\"spec\":\"noa.action-class-enrolment/0.1\",\"__proto__\":{\"closed\":true}}"],
    ["a null entry in the list", null],
  ];
  for (const [why, doc] of cases) {
    const res = verifyEvidence(b(fx.bundle), {
      tenantRoot: b(fx.tenantRoot),
      checkpointKeyring: b(fx.checkpointKeyring),
      // Deliberately NOT run through `b()`: the point is what happens when the caller hands over
      // something that is not the bytes of a document.
      enrolmentRegistries: [doc as never],
      audience: fx.audience!,
      now: fx.now,
      maxAgeMs: fx.maxAgeHours * 3600 * 1000,
      schemas,
    });
    assert.equal(res.verdict, "UNVERIFIED", `${why}: verdict ${res.verdict}`);
    assert.equal(res.code, "E_ENROLMENT_UNVERIFIABLE", `${why}: code ${res.code}`);
  }
});

test("DECISION: an EMPTY registry list means the same as no list, and the CLI cannot produce one", () => {
  // Pinned because it is a DECISION, not an accident, and the two readings are both defensible.
  // `undefined` and `[]` both say "this reader holds no registries", so they behave identically. The
  // failure mode that would make this wrong — a caller whose file read failed silently yielding `[]`
  // and losing the check — is closed at the surface an operator actually uses: the CLI omits the
  // option entirely when it read no registry file, and a file it CANNOT read is a usage error (exit
  // 5), never an empty list. An in-process caller assembling the array owns its own emptiness.
  const fx = load(ENROLLED);
  const none = run(fx, { registries: undefined, audience: undefined });
  const empty = run(fx, { registries: [], audience: fx.audience });
  assert.equal(none.verdict, "VALID_FULL_CHAIN");
  assert.equal(empty.verdict, none.verdict, "an empty list and no list disagreed");
  assert.equal(empty.enrolment, "NOT_EVALUATED");
  assert.equal(exitOf(empty), 0);
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
