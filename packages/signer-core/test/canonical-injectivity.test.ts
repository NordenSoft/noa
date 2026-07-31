/**
 * #77-B — CANONICALIZATION MUST BE INJECTIVE OVER WHAT IT ACCEPTS.
 *
 * Two semantically different accepted inputs must never produce the same canonical bytes, the same
 * commitment, or the same signed meaning — unless the specification declares them equivalent, in
 * which case the equivalence is documented and tested as such (see the INTENTIONAL EQUIVALENCE
 * section at the bottom: JCS key ordering and -0/0 are both deliberate).
 *
 * ─── B-1: TWO DEFINITIONS OF "THE DOCUMENT'S PROPERTIES" IN ONE SIGNING PATH ────────────────────
 *
 * `jcs.ts` walks `Object.keys` — own AND ENUMERABLE.
 * `deep-copy.ts` walks `getOwnPropertyNames` — own, INCLUDING NON-ENUMERABLE — and defines every
 * key it writes as `enumerable: true`.
 *
 * So an own non-enumerable property is INVISIBLE to the hash and VISIBLE (indeed promoted) in the
 * returned receipt. `signReceipt` computes `receiptHashInput(core)` and returns `inertDeepCopy(core)`,
 * so the two disagree. MEASURED end to end through the real producer and the real ROOT verifier,
 * with an honest receipt verifying VALID in the same run as the control:
 *
 *     signed pre-image   "governance":{"mode":"approvals_on","sandboxed":false,"verdict":"ALLOWED"}
 *     returned receipt   "governance":{"approval":{"by":"HUMAN:cfo-victim",…},"mode":…}
 *     root verifier      TAMPERED (hash mismatch)
 *
 * HONEST SCOPE: it fails CLOSED at the verifier. The realised harm is a producer that signs one
 * document and returns another, and a consumer reading the returned object BEFORE verifying it sees
 * a human approval that no signature covers and no auditor re-reading the bytes can find.
 *
 * ─── B-2: `canonicalize` IS A PUBLIC EXPORT AND WAS NOT INJECTIVE ──────────────────────────────
 *
 * An array with a named property canonicalized identically to one without it — `[1]` either way.
 * Not reachable through the producer (deep-copy refuses named array properties since 7e5c579) nor
 * from the wire (JSON cannot express one), but `canonicalize` is exported and a caller reaches it
 * directly. Two distinct values, one commitment, in a function whose entire job is to be injective.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { canonicalize } from "../src/jcs.js";
import { inertDeepCopy } from "../src/deep-copy.js";
import { buildReceiptDraft } from "../src/builder.js";
import { signReceipt } from "../src/sign.js";
import { generateKeyPair } from "../src/keygen.js";
import { receiptHashInput } from "../src/receipt-hash.js";
import { verifyChain } from "noa-receipt";

const kp = generateKeyPair("kid-B", new Uint8Array(32).fill(5));
const wire = (v: unknown): Uint8Array => new TextEncoder().encode(JSON.stringify(v));
const keyring = wire({ [kp.kid]: kp.publicKey });

const input = () => ({
  id: "rcpt_0",
  ts: "2026-07-31T12:00:00.000Z",
  scope: { chain: "chain-B" },
  agent: { id: "agent-1", model: null, principal: "HUMAN" as const },
  action: {
    id: "act-1",
    canonical: "finance.wire.transfer",
    riskClass: "CRITICAL" as const,
    paramsHash: ("sha256:" + "a".repeat(64)) as `sha256:${string}`,
    reversible: false,
    rollbackRef: null,
  },
  governance: { mode: "approvals_on" as const, verdict: "ALLOWED" as const, sandboxed: false, approval: null },
});

// ────────────────────────────────────────────────────────────────────────────────────────────────
// B-1 — a non-enumerable own property must not be able to differ between hash and receipt.
// ────────────────────────────────────────────────────────────────────────────────────────────────

test("#77-B/1: an own NON-ENUMERABLE property cannot split the hash from the returned receipt", () => {
  // PROOF THE VEHICLE IS LIVE: the two walks really do disagree about this property.
  const probe: Record<string, unknown> = {};
  Object.defineProperty(probe, "visible", { value: 1, enumerable: true, writable: true, configurable: true });
  Object.defineProperty(probe, "hidden", { value: "SMUGGLED", enumerable: false, writable: true, configurable: true });
  assert.equal(canonicalize(probe), '{"visible":1}', "JCS no longer skips non-enumerable properties — this test's premise is gone");
  assert.ok(Object.getOwnPropertyNames(probe).includes("hidden"), "the fixture has no non-enumerable own property");

  const draft = buildReceiptDraft(input() as never, null, kp.kid);
  Object.defineProperty(draft.governance, "approval", {
    value: { by: "HUMAN:cfo-victim", at: "2026-07-31T00:00:00Z" },
    enumerable: false,
    writable: true,
    configurable: true,
  });

  // The producer must REFUSE. Signing a document whose hash cannot see a field it carries is the
  // defect; emitting it and relying on the verifier to reject later is not a fix.
  assert.throws(
    () => signReceipt(draft, { kid: kp.kid, privateKey: kp.privateKey }),
    /non-enumerable/,
    "signReceipt produced a receipt whose signed pre-image omits a field the returned object " +
    "carries — one signature, two documents",
  );
});

test("#77-B/1: inertDeepCopy refuses a non-enumerable own property rather than promoting it", () => {
  const hostile: Record<string, unknown> = {};
  Object.defineProperty(hostile, "visible", { value: 1, enumerable: true, writable: true, configurable: true });
  Object.defineProperty(hostile, "hidden", { value: "SMUGGLED", enumerable: false, writable: true, configurable: true });

  assert.throws(
    () => inertDeepCopy(hostile),
    /non-enumerable property "hidden"/,
    "a non-enumerable own property was copied — and promoted to enumerable, so it appears in the " +
    "returned document while being invisible to the hash that was signed",
  );
});

// ────────────────────────────────────────────────────────────────────────────────────────────────
// B-2 — `canonicalize` is a public export; it must be injective over what it accepts.
// ────────────────────────────────────────────────────────────────────────────────────────────────

test("#77-B/2: canonicalize refuses a named array property instead of silently dropping it", () => {
  const arr: unknown[] = [1];
  (arr as unknown as Record<string, unknown>)["foo"] = "x";
  // Before the fix both sides produced `[1]`: two distinct values, one commitment, in the function
  // whose whole job is to be injective.
  assert.throws(
    () => canonicalize(arr),
    /named property "foo"/,
    "an array with a named property canonicalized to the same bytes as one without it",
  );

  const nearMax: unknown[] = [1];
  (nearMax as unknown as Record<string, unknown>)["4294967295"] = "named-not-index";
  assert.throws(() => canonicalize(nearMax), /named property "4294967295"/,
    "the 2^32-1 boundary name was treated as an index rather than a named property");
});

// ────────────────────────────────────────────────────────────────────────────────────────────────
// ANTI-VACUITY — distinct honest inputs must still produce DISTINCT commitments, and equivalent
// ones must still produce equal commitments. Without these, "refuse everything" would pass above.
// ────────────────────────────────────────────────────────────────────────────────────────────────

test("#77-B ANTI-VACUITY: semantically different receipts get different commitments", () => {
  const mk = (canonical: string, paramsHash: string) => {
    const i = input();
    i.action.canonical = canonical;
    i.action.paramsHash = paramsHash as typeof i.action.paramsHash;
    return signReceipt(buildReceiptDraft(i as never, null, kp.kid), { kid: kp.kid, privateKey: kp.privateKey });
  };
  const a = mk("finance.wire.transfer", "sha256:" + "a".repeat(64));
  const b = mk("production.delete.all", "sha256:" + "a".repeat(64));
  const c = mk("finance.wire.transfer", "sha256:" + "b".repeat(64));

  assert.notEqual(a.chain.hash, b.chain.hash, "two different ACTIONS share a chain hash");
  assert.notEqual(a.chain.hash, c.chain.hash, "two different PARAMS share a chain hash");
  assert.notEqual(a.sig.value, b.sig.value, "two different actions share a signature");
  assert.notEqual(receiptHashInput(a), receiptHashInput(b), "two different actions share a pre-image");
});

test("#77-B ANTI-VACUITY: an ordinary receipt still builds, signs and verifies VALID at the ROOT", () => {
  const r = signReceipt(buildReceiptDraft(input() as never, null, kp.kid), { kid: kp.kid, privateKey: kp.privateKey });
  const v = verifyChain(wire([r]), { keyring });
  assert.equal(v.status, "VALID", `an honest receipt did not verify at the root: ${v.reason}`);
  // and ordinary shapes still canonicalize rather than being caught by the new refusals
  assert.equal(canonicalize({ b: 1, a: [1, 2, { c: null }] }), '{"a":[1,2,{"c":null}],"b":1}');
});

// ────────────────────────────────────────────────────────────────────────────────────────────────
// INTENTIONAL EQUIVALENCE — declared by RFC 8785 and pinned here so a future "fix" that made these
// distinct would be caught. The owner's rule: where equivalence is intentional, document AND test it.
// ────────────────────────────────────────────────────────────────────────────────────────────────

test("#77-B: the two INTENTIONAL equivalences are intentional, and pinned", () => {
  // Property order: JCS sorts by UTF-16 code unit, so source order carries no meaning. Two objects
  // differing only in key order ARE the same document.
  assert.equal(canonicalize({ b: 1, a: 2 }), canonicalize({ a: 2, b: 1 }));
  assert.equal(canonicalize({ b: 1, a: 2 }), '{"a":2,"b":1}');

  // -0 and 0: RFC 8785 serialises both as "0". JavaScript distinguishes them (`Object.is(-0, 0)` is
  // false), so this equivalence is a deliberate narrowing and must stay deliberate.
  assert.equal(canonicalize({ n: -0 }), canonicalize({ n: 0 }));
  assert.equal(canonicalize({ n: -0 }), '{"n":0}');
  assert.equal(Object.is(-0, 0), false, "the runtime no longer distinguishes -0 from 0 — this equivalence has become vacuous");
});
