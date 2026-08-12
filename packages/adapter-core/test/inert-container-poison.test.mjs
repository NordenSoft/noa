/**
 * THE [[Set]] CLASS, AS A REGRESSION TEST.
 *
 * Writing into an ordinary `[]` or `{}` performs `[[Set]]`, and `[[Set]]` WALKS THE RECEIVER'S
 * PROTOTYPE CHAIN. An ordinary container's chain ends at the mutable `Object.prototype`, so an
 * accessor installed at `Object.prototype["0"]` SWALLOWS the element write while `push` still bumps
 * `length` — and every later read comes back from the attacker's getter.
 *
 * NOT ONE BUILTIN IS REPLACED in any of this. The captured `arrayPush` applies the PRISTINE
 * `Array.prototype.push`; what the attacker owns is the RECEIVER's prototype chain, which capturing
 * the method does nothing about. That is why `scripts/lint-security-gates.mjs`'s L2/L8 — which model
 * dispatch as a call or a read and, in their own words, "have no grammar for a write" — contribute
 * ZERO findings about this file. The source-level gate for the class is
 * `scripts/lint-inert-containers.mjs`; these are the runtime halves that go red if a fix is reverted.
 *
 * MEASURED BEFORE THE FIX (`packages/adapter-core/src/pre-check.mjs`, ordinary `items`/`parts`):
 *
 *     writes swallowed = 2
 *     canonicalParamsHash({amountMinor: 10,     rate: 1.5}) = sha256:01d61d6c…
 *     canonicalParamsHash({amountMinor: 900000, rate: 1.5}) = sha256:01d61d6c…   <- THE SAME
 *
 * Two different tool calls, one paramsHash: an approval minted for the small transfer authorises
 * the large one. The poison is installed AFTER module load and withdrawn before anything is
 * asserted, which is the realistic gadget — poison, hole the container, withdraw, serve.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { canonicalParamsHash } from "../src/pre-check.mjs";
import { validateApprovalRules } from "../src/approval-rules.mjs";

/**
 * Run `fn` with an accessor at `Object.prototype["0"]`. The setter SWALLOWS (creates no own
 * property); the getter answers with `forged`.
 *
 * Deliberately synchronous end to end: while this accessor is installed, every ordinary `arr[0] = x`
 * in the process is holed, so nothing else may be allowed to run. Restoration is in a `finally` and
 * is asserted by the caller.
 */
function withPoisonedIndexZero(forged, fn) {
  let swallowed = 0;
  Object.defineProperty(Object.prototype, "0", {
    configurable: true,
    get() { return forged; },
    set() { swallowed += 1; },
  });
  try {
    return { value: fn(), swallowed };
  } finally {
    delete Object.prototype["0"];
  }
}

test("[[Set]] class: a poisoned Object.prototype[\"0\"] cannot collapse two tool calls onto one paramsHash", () => {
  const SMALL = { amountMinor: 10, rate: 1.5 };
  const LARGE = { amountMinor: 900000, rate: 1.5 };

  // CONTROL — the two calls are distinguishable with no poison present. Without this the assertion
  // under poison could pass for the wrong reason (e.g. both throwing, or both returning null).
  const cleanSmall = canonicalParamsHash(SMALL);
  const cleanLarge = canonicalParamsHash(LARGE);
  assert.notEqual(cleanSmall, cleanLarge, "control: distinct args must hash distinctly");
  assert.match(cleanSmall, /^sha256:[0-9a-f]{64}$/, "control: the fallback path must produce a real hash");

  // The float `rate` is what pushes both calls onto `stableStringifyFallback` — JCS refuses a
  // non-integer number, and a float rate is ordinary tool-call input. That is the reachable path.
  const { value, swallowed } = withPoisonedIndexZero('"amountMinor":10', () => ({
    small: canonicalParamsHash(SMALL),
    large: canonicalParamsHash(LARGE),
  }));

  assert.equal(swallowed, 0,
    "an inert container takes no swallowed write: [[Set]] on a null-rooted/inert-rooted receiver " +
    "never reaches the accessor on Object.prototype");
  assert.notEqual(value.small, value.large,
    "POISONED: two different tool calls collapsed onto one paramsHash — an approval bound to the " +
    "small transfer would authorise the large one");
  assert.equal(value.small, cleanSmall, "the poison must not move the hash at all");
  assert.equal(value.large, cleanLarge, "the poison must not move the hash at all");
});

test("[[Set]] class: a poisoned Object.prototype[\"0\"] cannot rewrite what the approval-rule validator reports", () => {
  // Two malformed rules, so the validator produces at least two messages and index 0 is populated.
  const RULES = [{ id: "", match: { type: "nope", action: "" } }, { id: "b", match: null }];

  const clean = validateApprovalRules(RULES);
  assert.equal(clean.ok, false, "control: the malformed rule set must be refused");
  assert.ok(clean.errors.length >= 2, `control: expected several messages, got ${clean.errors.length}`);

  const { value, swallowed } = withPoisonedIndexZero("approvalRules[0].id: non-empty string",
    () => validateApprovalRules(RULES));

  assert.equal(swallowed, 0, "the validator's error array must take no swallowed write");
  assert.equal(value.ok, false, "still refused");
  assert.deepEqual(
    Array.prototype.slice.call(value.errors), Array.prototype.slice.call(clean.errors),
    "the reported errors must be the ones the validator produced, not the attacker's getter value",
  );
});

test("the poison harness itself is real: an ordinary array DOES lose the write", () => {
  // ANTI-VACUITY. If `withPoisonedIndexZero` ever stopped installing anything, both tests above
  // would pass while measuring nothing. This one fails unless the poison genuinely bites.
  const { value, swallowed } = withPoisonedIndexZero("FORGED", () => {
    const ordinary = [];
    ordinary.push("real");
    return { length: ordinary.length, own0: Object.hasOwn(ordinary, "0"), read0: ordinary[0] };
  });
  assert.equal(swallowed, 1, "the harness must have swallowed exactly one write");
  assert.equal(value.length, 1, "`length` still moves — that is what makes the hole invisible");
  assert.equal(value.own0, false, "no own element was created");
  assert.equal(value.read0, "FORGED", "the read comes back from the attacker's getter");
});

test("the poison is fully withdrawn afterwards", () => {
  assert.equal(Object.getOwnPropertyDescriptor(Object.prototype, "0"), undefined,
    "a harness that leaves the accessor installed would silently poison every later test");
  const probe = [];
  probe.push("x");
  assert.equal(probe[0], "x");
});
