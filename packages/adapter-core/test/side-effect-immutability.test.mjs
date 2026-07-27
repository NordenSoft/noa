/**
 * The fifth review's H6, pinned: the side-effect spec was a mutable, prototype-bypassable table.
 *   • `next("NOT_DISPATCHED", "__proto__") === Object.prototype` — a prototype key masqueraded as a
 *     real transition.
 *   • `SIDE_EFFECT_UNCONFIRMED.safeToRetry` flipped false→true after mutation — only the TOP level of
 *     the tables was frozen, the inner rows/metadata were live.
 * Plus the DESIGN 3 throw-classification brand the gate now depends on.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  SIDE_EFFECT_STATES,
  EVIDENCE_OUTCOME_FOR,
  next,
  isSafeToRetry,
  isTerminal,
  IllegalSideEffectTransition,
} from "../src/side-effect-state.mjs";

test("H6: a prototype-chain key is an ILLEGAL transition, not a truthy Object.prototype", () => {
  // The review's exact exploit: next("NOT_DISPATCHED", "__proto__") used to return Object.prototype.
  for (const badEvent of ["__proto__", "constructor", "toString", "hasOwnProperty", "valueOf"]) {
    assert.throws(() => next("NOT_DISPATCHED", badEvent), IllegalSideEffectTransition, `event ${badEvent} must be illegal`);
  }
  for (const badState of ["__proto__", "constructor", "toString"]) {
    assert.throws(() => next(badState, "DISPATCH_STARTED"), IllegalSideEffectTransition, `state ${badState} must be illegal`);
  }
  // sanity: a real transition still resolves
  assert.equal(next("NOT_DISPATCHED", "DISPATCH_STARTED"), "DISPATCHED");
  assert.equal(next("DISPATCHED", "TOOL_THREW_AFTER_DISPATCH"), "SIDE_EFFECT_UNCONFIRMED");
});

test("H6: isSafeToRetry / isTerminal reject prototype-chain 'states' too", () => {
  for (const bad of ["__proto__", "constructor", "toString"]) {
    assert.throws(() => isSafeToRetry(bad), IllegalSideEffectTransition);
    assert.throws(() => isTerminal(bad), IllegalSideEffectTransition);
  }
  assert.equal(isSafeToRetry("SIDE_EFFECT_UNCONFIRMED"), false);
  assert.equal(isSafeToRetry("FAILED_NO_SIDE_EFFECT"), true);
});

test("H6: the spec tables are DEEPLY frozen — inner rows/metadata cannot be rewritten at runtime", () => {
  assert.ok(Object.isFrozen(SIDE_EFFECT_STATES));
  assert.ok(Object.isFrozen(SIDE_EFFECT_STATES.SIDE_EFFECT_UNCONFIRMED), "inner state metadata must be frozen");
  assert.ok(Object.isFrozen(EVIDENCE_OUTCOME_FOR));
  // The review's `SIDE_EFFECT_UNCONFIRMED.safeToRetry = true` must now throw (strict) or be a no-op.
  assert.throws(() => { SIDE_EFFECT_STATES.SIDE_EFFECT_UNCONFIRMED.safeToRetry = true; }, TypeError);
  assert.equal(SIDE_EFFECT_STATES.SIDE_EFFECT_UNCONFIRMED.safeToRetry, false, "the unconfirmed state is NEVER safe to retry");
  assert.throws(() => { EVIDENCE_OUTCOME_FOR.SIDE_EFFECT_UNCONFIRMED = "EXECUTED"; }, TypeError);
});

// C4 (review #6): the two tests that stood here asserted that `threwBeforeSideEffect` was a sound
// brand check. It was sound as a BRAND and worthless as PROOF: the brand lived in the global
// `Symbol.for` registry, so the party whose honesty it certified could write it. The API is deleted;
// `no-retry-safe-after-dispatch.test.mjs` now proves the property the brand was standing in for,
// over the transition graph, where forgery is not a parameter.
