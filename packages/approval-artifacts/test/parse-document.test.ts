/**
 * THE PARSE BOUNDARY OF THIS PACKAGE — permanent regression suite (ADR-0005, Slice 3).
 *
 * `src/parse-document.ts` claimed, from the day it was written, that it "does NOT introduce a second
 * parser". The claim was true of the GRAMMAR and false of the BOUNDARY: a parse boundary is a type
 * test, a ceiling, a decode AND a grammar, and that file had its own of the middle two. Two defects
 * were measured on the pre-fix tree and each is pinned below.
 *
 * RULES THIS FILE OBEYS (owner instruction, 2026-07-30):
 *   1. Assert the SECURITY OUTCOME, never the implementation's structure. "the code imports
 *      inert-core" would pass a refactor that reintroduced a local decoder.
 *   2. Every attack has an ANTI-VACUITY CONTROL in the same run. A boundary that refuses everything
 *      is indistinguishable from a broken import, and this project has twice read an unfailable run
 *      as a passing one.
 *   3. KNOCKOUT-OBSERVED. Each control below was seen RED with the pre-fix code restored, then GREEN
 *      again — the evidence is in the Slice 3 report. A control never observed to fail is not known
 *      to be a control.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { parseDocument } from "../src/parse-document.js";

const enc = new TextEncoder();

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// FORGERY CHANNEL — a BOM made two distinct byte strings into one document.
//
// Measured pre-fix: this file's own decoder was `new TextDecoder("utf-8", { fatal: true })`.
// `ignoreBOM` DEFAULTS TO FALSE, which — against the reading its name invites — means the decoder
// SILENTLY STRIPS a leading U+FEFF. So the 7 bytes `{"a":1}` and the 10 bytes `EF BB BF {"a":1}`
// both parsed to the same document, and ONE signature covered TWO different byte strings.
//
// The property asserted is not "reject a BOM". It is the general one: DISTINCT BYTES, DISTINCT
// DOCUMENT (or a refusal). A signature is over bytes; if two byte strings collapse to one value,
// the signature no longer says which bytes were signed.
// ─────────────────────────────────────────────────────────────────────────────────────────────────

test("BOM: two distinct byte strings must never parse to one document", () => {
  const plain = enc.encode('{"a":1}');
  const bomd = new Uint8Array([0xef, 0xbb, 0xbf, ...plain]);

  assert.notEqual(plain.length, bomd.length, "fixture precondition: the two inputs differ in bytes");

  const a = parseDocument(plain, "body");
  const withBom = parseDocument(bomd, "body");

  const collapsed =
    a.ok && withBom.ok && JSON.stringify(a.value) === JSON.stringify(withBom.value);

  assert.equal(collapsed, false,
    `${plain.length} bytes and ${bomd.length} bytes produced the SAME document. A leading byte was ` +
      "silently deleted by the decoder, so one signature covers two distinct byte strings — a " +
      "forgery channel. The decode must preserve the BOM (ignoreBOM: true) and let the strict " +
      "parser refuse it.");

  assert.equal(withBom.ok, false, "the BOM-prefixed form must be refused, not silently normalised");
  assert.match(String((withBom as { reason: string }).reason), /position 0/,
    "the refusal must name the offending position, so a 422 can carry the parser's own reason");
});

test("BOM anti-vacuity: the un-prefixed form still parses", () => {
  const r = parseDocument(enc.encode('{"a":1}'), "body");
  assert.equal(r.ok, true, "the honest byte string must still parse — otherwise the test above is vacuous");
  assert.deepEqual(JSON.parse(JSON.stringify((r as { value: unknown }).value)), { a: 1 });
});

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// DoS — the ceiling landed AFTER the decode.
//
// Measured pre-fix: the only bound was `safeParse`'s `maxLength`, which is a property of an
// ALREADY-MATERIALISED string. A 17 MB input was therefore decoded IN FULL into a 17 MB string and
// only then refused, at "position 17825792". The core boundary checks `byteLength` BEFORE the decode
// (ADR §3.4) and refuses having allocated nothing.
//
// The two failure modes are told apart by their REASON, which is deterministic — not by timing,
// which is not. A post-decode refusal cannot produce the byte-ceiling reason, because at that point
// nobody has looked at the bytes.
// ─────────────────────────────────────────────────────────────────────────────────────────────────

test("ceiling: an over-ceiling input is refused on BYTES, before any decode", () => {
  const over = new Uint8Array(17 * 1024 * 1024).fill(0x20);
  const r = parseDocument(over, "body");

  assert.equal(r.ok, false, "a 17 MB document must be refused");
  assert.match(String((r as { reason: string }).reason), /exceeds the \d+-byte ceiling/,
    "the refusal came from the STRING length, not the BYTE length — so the input was fully decoded " +
      "into memory before anything objected. The ceiling must be enforced on byteLength pre-decode.");
});

test("ceiling anti-vacuity: a large but in-bounds document still parses", () => {
  // 1 MiB of payload — comfortably inside the 16 MiB ceiling, far outside anything a unit fixture
  // would hit by accident. If this fails, the test above proves nothing about the ceiling.
  const big = enc.encode(JSON.stringify({ pad: "x".repeat(1024 * 1024) }));
  const r = parseDocument(big, "body");
  assert.equal(r.ok, true, "an in-bounds document must still parse");
});

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// NEVER THROWS, AND NEVER COERCES.
//
// The boundary's whole purpose is that a caller-owned object cannot enter. It must therefore refuse
// one WITH A REASON, rather than throwing (an exception object's `message` getter is
// attacker-reachable, ADR §3.5) and rather than coercing (`String(obj)` runs the attacker's
// `toString`, which is the silent serialization this boundary exists to forbid).
// ─────────────────────────────────────────────────────────────────────────────────────────────────

test("non-bytes: a hostile caller-owned object is refused with a reason and runs none of its code", () => {
  let hostileCodeRan = 0;
  const hostile = {
    get decision() { hostileCodeRan += 1; return "APPROVE"; },
    toJSON() { hostileCodeRan += 1; return { decision: "APPROVE" }; },
    toString() { hostileCodeRan += 1; return '{"decision":"APPROVE"}'; },
    get length() { hostileCodeRan += 1; return 7; },
    get byteLength() { hostileCodeRan += 1; return 7; },
    [Symbol.toStringTag]: "Uint8Array", // a forged tag, to defeat a naive type test
  };

  let threw: unknown = null;
  let r: ReturnType<typeof parseDocument> | undefined;
  try {
    r = parseDocument(hostile, "decisionArtifact");
  } catch (e) {
    threw = e;
  }

  assert.equal(threw, null,
    "the boundary THREW on a caller-owned object. A thrown value hands the caller an exception whose " +
      "own `message` getter the attacker controls; every failure must be a returned reason.");
  assert.equal(r?.ok, false, "a caller-owned object is not a document and must be refused");
  assert.match(String((r as { reason: string }).reason), /Uint8Array/,
    "the refusal must say what a document is, so the 422 is actionable");
  assert.equal(hostileCodeRan, 0,
    `the boundary invoked ${hostileCodeRan} of the object's own accessors. A forged Symbol.toStringTag ` +
      "must not be believed and no property of a rejected value may be read: the type test has to " +
      "consult an internal slot.");
});

test("non-bytes anti-vacuity: real bytes carrying the same document are accepted", () => {
  const r = parseDocument(enc.encode('{"decision":"APPROVE"}'), "decisionArtifact");
  assert.equal(r.ok, true, "the honest bytes-in path must work — otherwise the refusal above is vacuous");
  assert.equal((r as { value: Record<string, unknown> }).value["decision"], "APPROVE");
});

test("malformed bytes are refused with the parser's own reason, never a throw", () => {
  let threw: unknown = null;
  let r: ReturnType<typeof parseDocument> | undefined;
  try {
    r = parseDocument(enc.encode('{"a":1'), "body"); // truncated
  } catch (e) {
    threw = e;
  }
  assert.equal(threw, null, "a malformed document must return a reason, not throw");
  assert.equal(r?.ok, false);
  assert.ok(String((r as { reason: string }).reason).startsWith("body:"),
    "the reason must be scoped by the `what` label so a caller knows WHICH document was rejected");
});

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// THE ONE THING THIS FILE ADDS OVER THE CORE — the deep freeze.
//
// `safeParse` already returns null-prototype, accessor-free values, so the ATTACKER cannot reach the
// snapshot without this. The freeze exists because ADR-0005's clause is "DEEPLY IMMUTABLE snapshot"
// and it also protects against OUR OWN code mutating a snapshot between two reads — a defect class
// this project has shipped twice.
// ─────────────────────────────────────────────────────────────────────────────────────────────────

test("the snapshot is deeply frozen, so no later code can split two reads of it", () => {
  const r = parseDocument(enc.encode('{"a":{"b":[1,2]}}'), "body");
  assert.equal(r.ok, true, "fixture precondition: the document parses");
  const v = (r as { value: Record<string, unknown> }).value;

  assert.equal(Object.isFrozen(v), true, "the root of the snapshot must be frozen");
  const inner = v["a"] as Record<string, unknown>;
  assert.equal(Object.isFrozen(inner), true, "a nested object must be frozen — a shallow freeze is not the clause");
  assert.equal(Object.isFrozen(inner["b"]), true, "a nested array must be frozen too");

  // The observable consequence: a mutation attempt cannot change what a later read sees.
  try { (v as Record<string, unknown>)["a"] = 99; } catch { /* strict-mode TypeError is also fine */ }
  assert.notEqual(v["a"], 99, "the snapshot was mutated after parsing — two reads of it can now disagree");
});
