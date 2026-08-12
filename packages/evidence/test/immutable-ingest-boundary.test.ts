/**
 * The fifth review's evidence-side findings, pinned:
 *   C1 — a live `governance` getter that returns one verdict to the role check and another to a
 *        reread flips INVALID→VALID; and the verdict POLICY TABLE was a mutable Set.
 *   H1 — `rolesAsserted` recorded ATTEMPTED checks, not SUCCESSFUL ones, so step 19's coverage gate
 *        was hollow.
 *   H3 — `purpose` is an erased union with no runtime validation, and the AUDIT authorization
 *        dimension omitted the manifest window at `now`.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { verifyEvidence, loadSchemas } from "../src/verify-evidence.js";
import { assertReceiptRole, RECEIPT_ROLE_VERDICTS, MANDATORY_RECEIPT_ROLES, type ReceiptRole } from "../src/receipt-roles.js";
import { buildResolvedKeyring, buildReceiptKeyring } from "../src/trust.js";
import type { EvidenceBundle } from "../src/types.js";
import { b } from "./helpers/bytes.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const schemas = loadSchemas();

interface Fixture {
  expectVerdict: string;
  now: string;
  maxAgeHours: number;
  bundle: EvidenceBundle;
  tenantRoot: Record<string, unknown>;
  checkpointKeyring: Record<string, unknown>;
}
function loadValid(name: string): Fixture {
  return JSON.parse(readFileSync(join(HERE, "..", "..", "conformance", "valid", name), "utf8")) as Fixture;
}
function run(fx: Fixture, over: Partial<{ now: string; purpose: "audit" | "authorize" }> = {}) {
  return verifyEvidence(b(fx.bundle), {
    tenantRoot: b(fx.tenantRoot),
    checkpointKeyring: b(fx.checkpointKeyring),
    now: over.now ?? fx.now,
    maxAgeMs: fx.maxAgeHours * 60 * 60 * 1000,
    schemas,
    ...(over.purpose ? { purpose: over.purpose } : {}),
  });
}

// ── C1 — the flipping-getter + mutable-table class ────────────────────────────────────────────────

test("C1: the verdict policy table is deeply frozen — the runtime-widening exploit is dead", () => {
  assert.ok(Object.isFrozen(RECEIPT_ROLE_VERDICTS));
  assert.ok(Object.isFrozen(RECEIPT_ROLE_VERDICTS.deferredReceipt));
  // The review's `RECEIPT_ROLE_VERDICTS.deferredReceipt.add("ALLOWED")` widened an INVALID into
  // VALID_FULL_CHAIN. There is no `.add` on a frozen array, and every mutation throws.
  assert.equal(typeof (RECEIPT_ROLE_VERDICTS.deferredReceipt as unknown as { add?: unknown }).add, "undefined");
  assert.throws(() => (RECEIPT_ROLE_VERDICTS.deferredReceipt as unknown as string[]).push("ALLOWED"), TypeError);
  assert.ok(Object.isFrozen(MANDATORY_RECEIPT_ROLES));
});

/**
 * ── C1, RE-EXPRESSED AS BYTES ────────────────────────────────────────────────────────────────────
 *
 * The two tests below used to install a LIVE `governance` getter on the bundle and assert that the
 * ingest snapshot fired it exactly once, so a value that flipped between reads could not show one
 * verdict to the role check and another to a reread.
 *
 * That attack is not expressible against `verifyEvidence` any more, and the reason is the fix: the
 * bundle is a DOCUMENT and arrives as bytes, which have no getters to fire. Deleting the tests
 * would be deleting the coverage; keeping them in object form would be asserting a property of an
 * argument the function no longer accepts. So each is translated into the nearest thing a BYTE
 * document can express, and the boundary is required to reject it:
 *
 *   • "two reads can disagree" becomes "one document carries the same key twice" — the classic
 *     forgery channel where a producer and a verifier disagree about which value is "the" value.
 *     `safeParse` refuses duplicate keys outright, so the whole document is rejected rather than
 *     silently resolved last-wins (which is what `JSON.parse` would have done).
 *
 *   • "the FIRST read is authoritative" becomes "a forged verdict in the byte form is caught by the
 *     same role check", proving the role rule still bites on the parsed document and that the
 *     honest bytes still verify — the negative and the positive control together.
 */

test("C1 (bytes): a live getter is not expressible — the honest bundle verifies from its BYTES", () => {
  const fx = loadValid("executed.json");
  const res = verifyEvidence(b(fx.bundle), {
    tenantRoot: b(fx.tenantRoot),
    checkpointKeyring: b(fx.checkpointKeyring),
    now: fx.now,
    maxAgeMs: fx.maxAgeHours * 60 * 60 * 1000,
    schemas,
  });
  assert.equal(res.verdict, "VALID_FULL_CHAIN", `bundle should verify from bytes; got ${res.verdict} (${res.reason ?? ""})`);
});

test("C1 (bytes): a DUPLICATE governance key — the byte-form of 'two reads disagree' — is REJECTED, never resolved last-wins", () => {
  const fx = loadValid("executed.json");
  const honest = JSON.stringify(fx.bundle);
  const deferredGov = JSON.stringify((fx.bundle as unknown as Record<string, Record<string, unknown>>)["deferredReceipt"]!["governance"]);
  // Inject a SECOND `"governance"` member into the deferredReceipt object, carrying a verdict unfit
  // for the role. `JSON.parse` would keep the last one and hand the verifier a laundered bundle;
  // the strict parser refuses the document.
  const forgedGov = JSON.stringify({ ...(fx.bundle as unknown as Record<string, Record<string, Record<string, unknown>>>)["deferredReceipt"]!["governance"], verdict: "BLOCKED" });
  const duplicated = honest.replace(`"governance":${deferredGov}`, `"governance":${deferredGov},"governance":${forgedGov}`);
  assert.notEqual(duplicated, honest, "the fixture must actually have been rewritten — otherwise this test proves nothing");
  assert.equal(
    (JSON.parse(duplicated) as Record<string, Record<string, Record<string, unknown>>>)["deferredReceipt"]!["governance"]!["verdict"],
    "BLOCKED",
    "sanity: a NAIVE parser silently takes the forged value — that is the attack this boundary refuses",
  );

  const res = verifyEvidence(new TextEncoder().encode(duplicated), {
    tenantRoot: b(fx.tenantRoot),
    checkpointKeyring: b(fx.checkpointKeyring),
    now: fx.now,
    maxAgeMs: fx.maxAgeHours * 60 * 60 * 1000,
    schemas,
  });
  assert.equal(res.verdict, "INVALID", "a duplicate-key document must never verify");
  assert.match(res.reason ?? "", /byte boundary/, "and it must be rejected AT the boundary, not deeper in");
});

test("C1 (bytes): a forged deferred verdict in the byte form is still caught by the role check", () => {
  const fx = loadValid("executed.json");
  const forged = structuredClone(fx.bundle) as unknown as Record<string, Record<string, Record<string, unknown>>>;
  forged["deferredReceipt"]!["governance"]!["verdict"] = "BLOCKED"; // UNFIT for the deferredReceipt role
  const res = verifyEvidence(b(forged), {
    tenantRoot: b(fx.tenantRoot),
    checkpointKeyring: b(fx.checkpointKeyring),
    now: fx.now,
    maxAgeMs: fx.maxAgeHours * 60 * 60 * 1000,
    schemas,
  });
  assert.notEqual(res.verdict, "VALID_FULL_CHAIN", "a flipped deferred verdict must never verify");
  assert.equal(res.verdict, "INVALID");
});

// ── H1 — rolesAsserted records SUCCESS, not attempt ───────────────────────────────────────────────

test("H1: assertReceiptRole records a role as covered ONLY after the verdict check PASSES", () => {
  const asserted = new Set<ReceiptRole>();
  // A present receipt whose signer attested a verdict UNFIT for the role: a FAILED assertion.
  const badBundle = { allowedReceipt: { governance: { verdict: "BLOCKED" } } } as unknown as Record<string, unknown>;
  const bad = assertReceiptRole(badBundle, "allowedReceipt", asserted);
  assert.equal(bad.ok, false, "a wrong-verdict receipt must fail the assertion");
  assert.equal(asserted.has("allowedReceipt"), false, "a FAILED assertion must NOT be recorded as covered (was ATTEMPTED-not-SUCCEEDED before)");

  // A present receipt with a fit verdict: recorded on success.
  const goodBundle = { allowedReceipt: { governance: { verdict: "ALLOWED" } } } as unknown as Record<string, unknown>;
  const good = assertReceiptRole(goodBundle, "allowedReceipt", asserted);
  assert.equal(good.ok, true);
  assert.equal(asserted.has("allowedReceipt"), true, "a SUCCESSFUL assertion is recorded as covered");
});

test("H1: an absent OPTIONAL role is a checked fact (recorded); an absent MANDATORY role fails (not recorded)", () => {
  const a1 = new Set<ReceiptRole>();
  const optAbsent = assertReceiptRole({} as Record<string, unknown>, "allowedReceipt", a1);
  assert.deepEqual(optAbsent, { ok: true, present: false, receipt: null });
  assert.equal(a1.has("allowedReceipt"), true, "absent-optional is a checked fact and IS recorded");

  const a2 = new Set<ReceiptRole>();
  const mandAbsent = assertReceiptRole({} as Record<string, unknown>, "deferredReceipt", a2);
  assert.equal(mandAbsent.ok, false, "an absent mandatory role fails");
  assert.equal(a2.has("deferredReceipt"), false, "a FAILED mandatory assertion is NOT recorded as covered");
});

// ── H3 — purpose runtime validation + audit manifest-expiry dimension ─────────────────────────────

test("H3: an unrecognised purpose fails CLOSED (UNVERIFIED), never silently downgrades to audit", () => {
  const fx = loadValid("executed.json");
  for (const bogus of ["AUTHORIZE", "authorize ", "bogus", "", "Audit"]) {
    const res = verifyEvidence(b(fx.bundle), {
      tenantRoot: b(fx.tenantRoot),
      checkpointKeyring: b(fx.checkpointKeyring),
      now: fx.now,
      maxAgeMs: fx.maxAgeHours * 60 * 60 * 1000,
      schemas,
      purpose: bogus as never,
    });
    assert.equal(res.verdict, "UNVERIFIED", `purpose ${JSON.stringify(bogus)} must fail closed`);
    assert.match(res.reason ?? "", /unrecognised purpose/);
  }
  // sanity: the two legal values are accepted
  assert.equal(run(fx, { purpose: "audit" }).verdict, "VALID_FULL_CHAIN");
});

test("H3: AUDIT refuses an expired MANIFEST window at verifier-controlled now", () => {
  // DENIED skips the envelope-liveness gate (a terminal negative), so `now` can advance past the
  // manifest window without tripping an unrelated liveness check. denied.json: manifest expires
  // 2026-07-15T09:30Z; delegation expires 2026-07-20T10:00Z. A `now` AFTER the manifest window but
  // INSIDE the delegation window is the isolating case: the pre-fix audit verdict stayed valid,
  // trusting the dependent receivedAt as history. maxAgeMs is widened
  // so the checkpoint stays fresh at the advanced `now` (a negative outcome needs a fresh checkpoint).
  const fx = loadValid("denied.json");
  const now = "2026-07-16T00:00:00.000Z";
  const res = verifyEvidence(b(fx.bundle), {
    tenantRoot: b(fx.tenantRoot),
    checkpointKeyring: b(fx.checkpointKeyring),
    now,
    maxAgeMs: 240 * 60 * 60 * 1000, // 10 days — keeps the checkpoint fresh at the advanced `now`
    schemas,
  });
  assert.equal(res.verdict, "INVALID", "an expired signer-claimed manifest window still verified under audit");
  assert.equal(res.failedStep, "STEP_1_HOLD_ENVELOPE");
  assert.equal(res.code, "E_HOLD_ENVELOPE");
  assert.equal(res.dimensions.authorization, "EXPIRED_NOW", "the audit dimension must report the manifest is EXPIRED_NOW even though the delegation is still open at `now`");
});

// ── BYTES-IN RESIDUAL — the guards that replaced three `TODO(bytes-in)` comments ──────────────────
//
// Those comments described an ABSENT defense on PUBLISHED functions ("the snapshot that used to
// stand here is GONE and nothing replaces it"). A comment claiming a defense nobody can exercise is
// the same defect class as a gate nobody runs, so each site now carries the smallest guard that is
// real — and each guard is pinned here. Every arm is paired with a control, so none of them can
// pass on a function that simply refuses everything.

test("BYTES-IN: assertReceiptRole REFUSES an accessor-backed role — it never reads it", () => {
  let reads = 0;
  const hostile: Record<string, unknown> = {};
  Object.defineProperty(hostile, "allowedReceipt", {
    enumerable: true,
    configurable: true,
    // The C1 exploit shape: fit verdict on the read this module makes, unfit on every read after.
    get() { reads++; return { governance: { verdict: reads === 1 ? "ALLOWED" : "BLOCKED" } }; },
  });
  const asserted = new Set<ReceiptRole>();
  const r = assertReceiptRole(hostile, "allowedReceipt", asserted);
  assert.equal(r.ok, false, "an accessor-backed role must be refused, not read");
  assert.equal(reads, 0, "the getter must not fire at all — refusing after reading is still reading");
  assert.equal(asserted.has("allowedReceipt"), false, "a refused role is not recorded as covered");

  // CONTROL: the SAME content as a plain data property is accepted, so the refusal above is about
  // the accessor and this arm is not passing against a function that refuses everything.
  const honest = { allowedReceipt: { governance: { verdict: "ALLOWED" } } } as unknown as Record<string, unknown>;
  const ok = assertReceiptRole(honest, "allowedReceipt", new Set<ReceiptRole>());
  assert.equal(ok.ok, true);
});

test("BYTES-IN: assertReceiptRole REFUSES an accessor-backed governance / verdict", () => {
  const receiptWithGovGetter: Record<string, unknown> = {};
  let govReads = 0;
  Object.defineProperty(receiptWithGovGetter, "governance", {
    enumerable: true, configurable: true,
    get() { govReads++; return { verdict: govReads === 1 ? "ALLOWED" : "BLOCKED" }; },
  });
  const r1 = assertReceiptRole({ allowedReceipt: receiptWithGovGetter }, "allowedReceipt", new Set<ReceiptRole>());
  assert.equal(r1.ok, false, "an accessor-backed governance must be refused");
  assert.equal(govReads, 0, "…and never read");

  const governanceWithVerdictGetter: Record<string, unknown> = {};
  let vReads = 0;
  Object.defineProperty(governanceWithVerdictGetter, "verdict", {
    enumerable: true, configurable: true,
    get() { vReads++; return vReads === 1 ? "ALLOWED" : "BLOCKED"; },
  });
  const r2 = assertReceiptRole({ allowedReceipt: { governance: governanceWithVerdictGetter } }, "allowedReceipt", new Set<ReceiptRole>());
  assert.equal(r2.ok, false, "an accessor-backed verdict must be refused");
  assert.equal(vReads, 0, "…and never read");
});

test("BYTES-IN: a flipping getter cannot install a key different from the one checked", () => {
  // The check-then-use window: `typeof k.publicKey === "string"` validated read #1 and
  // `publicKey: k.publicKey` installed read #2. Every caller-owned field is now read ONCE, so the
  // value checked IS the value installed — whatever the getter answers afterwards.
  const CHECKED = "AAAA-the-key-that-was-checked";
  const SWAPPED = "BBBB-the-key-that-would-have-been-installed";
  const makeKey = () => {
    const k: Record<string, unknown> = { kid: "gate-1", type: "GATE", roles: ["hold-signer"], validFrom: null, revokedAt: null };
    let n = 0;
    Object.defineProperty(k, "publicKey", { enumerable: true, configurable: true, get() { n++; return n === 1 ? CHECKED : SWAPPED; } });
    return k;
  };

  const receipts = buildReceiptKeyring({ keys: [makeKey()] } as never);
  assert.equal(receipts.keys["gate-1"]?.publicKey, CHECKED, "the receipt keyring installed a key it never checked");

  const resolved = buildResolvedKeyring(
    {},
    { delegatedKid: "man-1", delegatedPublicKey: "MMMM", permissions: ["key-manifest-sign"], validFrom: null } as never,
    { keys: [makeKey()] } as never,
  );
  assert.equal(resolved["gate-1"]?.publicKey, CHECKED, "the resolved keyring installed a key it never checked");

  // The returned graph shares nothing with the caller's input: mutating the source afterwards
  // cannot change what downstream verification is performed against.
  const roles = ["hold-signer"];
  const src = { keys: [{ kid: "gate-2", type: "GATE", roles, publicKey: "CCCC", validFrom: null, revokedAt: null }] };
  const snap = buildResolvedKeyring({}, { delegatedKid: "man-1", delegatedPublicKey: "MMMM", permissions: [], validFrom: null } as never, src as never);
  roles.push("execution-signer");
  src.keys[0]!.publicKey = "DDDD";
  assert.deepEqual(snap["gate-2"]?.roles, ["hold-signer"], "the keyring aliased the caller's array");
  assert.equal(snap["gate-2"]?.publicKey, "CCCC", "the keyring re-read the caller's object after returning it");
});
