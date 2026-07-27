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
  markThrewBeforeSideEffect,
  threwBeforeSideEffect,
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

test("DESIGN 3: threwBeforeSideEffect is a marked-only, never-throwing brand check", () => {
  assert.equal(threwBeforeSideEffect(new Error("bare")), false, "an unmarked throw is NOT proven pre-side-effect");
  assert.equal(threwBeforeSideEffect(markThrewBeforeSideEffect(new Error("refused"))), true);
  // primitives and null can't carry the brand → false, never a throw
  for (const v of [null, undefined, 0, "", false, NaN, 0n, "x", 42]) {
    assert.equal(threwBeforeSideEffect(v), false);
  }
  // a revoked proxy must answer false, never throw
  const { proxy, revoke } = Proxy.revocable({}, {});
  revoke();
  assert.doesNotThrow(() => threwBeforeSideEffect(proxy));
  assert.equal(threwBeforeSideEffect(proxy), false);
});

test("DESIGN 3: marking a frozen/hostile value does not throw (it is simply treated as UNCONFIRMED)", () => {
  const frozen = Object.freeze(new Error("frozen"));
  assert.doesNotThrow(() => markThrewBeforeSideEffect(frozen));
  assert.equal(threwBeforeSideEffect(frozen), false, "a value that could not carry the mark is unconfirmed");
  // marking a primitive is a no-op that returns it unchanged
  assert.equal(markThrewBeforeSideEffect(0), 0);
});
