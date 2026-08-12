import { test } from "node:test";
import assert from "node:assert/strict";
import { validateApprovalRules, requireValidApprovalRules, compileApprovalRules, isCompiledApprovalRules, matchApprovalRule, tryIdentifyToolCallForTicketLookup } from "../src/approval-rules.mjs";
import { canonicalParamsHash } from "../src/pre-check.mjs";

test("validateApprovalRules: undefined/null/empty are valid; rejects non-array, missing id, bad match.type, duplicate id, bad threshold", () => {
  assert.equal(validateApprovalRules(undefined).ok, true);
  assert.equal(validateApprovalRules([]).ok, true);
  assert.equal(validateApprovalRules("nope").ok, false);
  assert.equal(validateApprovalRules([{ match: { type: "exact", action: "x" } }]).ok, false);
  assert.equal(validateApprovalRules([{ id: "r1", match: { type: "regex", action: "x" } }]).ok, false);
  assert.equal(
    validateApprovalRules([{ id: "dup", match: { type: "exact", action: "a" } }, { id: "dup", match: { type: "exact", action: "b" } }]).ok,
    false,
  );
  assert.equal(validateApprovalRules([{ id: "r", match: { type: "exact", action: "a" }, threshold: { path: "x", op: "eq", value: 1 } }]).ok, false);
  assert.equal(validateApprovalRules([{ id: "r", match: { type: "exact", action: "a" }, threshold: { path: "x", op: "ge", value: 1.5 } }]).ok, false);
});

// The LOAD-PATH gate. `validateApprovalRules` above has always been able to see every one of these
// shapes; nothing called it where a rule set is actually loaded, and each of the first four executed
// a real, over-threshold, unapproved transfer through the shipped proxy (measured 2026-08-12).
// `matchApprovalRule(nonArray, …) -> null` and `null` means "forward", so a malformed rule set is
// not a weaker gate — it is no gate.
test("requireValidApprovalRules: every non-array shape is REFUSED, including null (which validateApprovalRules calls valid)", () => {
  for (const bad of [{}, null, "nope", 5, true]) {
    assert.throws(
      () => requireValidApprovalRules(bad, "--approval-rules"),
      /must be a JSON ARRAY of rules/,
      `a ${JSON.stringify(bad)} rule set must be refused, not silently treated as "nothing needs approval"`,
    );
  }
  // undefined too: this function is only ever called where a rule set was supposed to have been
  // loaded, so "absent" is a misconfiguration here even though it is a legitimate library default.
  assert.throws(() => requireValidApprovalRules(undefined, "--approval-rules"), /must be a JSON ARRAY of rules/);
});

test("requireValidApprovalRules: a PARTIALLY-invalid array is refused in full, and the error names the offending index", () => {
  const partiallyValid = [
    { id: "r1", match: { type: "exact", action: "payment.refund" }, threshold: { path: "amountMinor", op: "ge", value: 4000 } },
    { id: "r2", match: { type: "regex", action: "transfer_funds" } },
  ];
  // Pre-fix this loaded happily and rule 2 simply never matched — an approval bypass that looks like
  // a working gate from the outside, which is why a partial accept is not on offer.
  assert.throws(() => requireValidApprovalRules(partiallyValid, "--approval-rules"), /approvalRules\[1\]\.match\.type/);
  assert.throws(() => requireValidApprovalRules(partiallyValid, "--approval-rules"), /structurally invalid/);
});

test("requireValidApprovalRules: an honest rule set is accepted and returned as a COMPILED SNAPSHOT, not as the caller's own object", () => {
  const honest = [{ id: "transfer-needs-human", match: { type: "exact", action: "transfer_funds" }, threshold: { path: "amountMinor", op: "ge", value: 5000 } }];
  const snapshot = requireValidApprovalRules(honest, "--approval-rules");

  // The CONTROL first: a compiler that refused everything would pass every rejection test in this
  // file while destroying the product. The honest rule still gates the action it names.
  assert.equal(matchApprovalRule(snapshot, "transfer_funds", { amountMinor: 7000 })?.id, "transfer-needs-human");
  assert.equal(matchApprovalRule(snapshot, "transfer_funds", { amountMinor: 10 }), null, "below the threshold is still a genuine no-match");
  assert.equal(requireValidApprovalRules([], "--approval-rules").length, 0, "an EMPTY array is a deliberate, valid rule set — it just gates nothing");

  // ROUND 2: the returned value must NOT be the caller's array. It used to be, and that identity WAS
  // the defect — validation and use were then two reads of one object anyone could change between.
  assert.notEqual(snapshot, honest, "returning the caller's array is what let a post-validation mutation re-open the gate");
  assert.ok(isCompiledApprovalRules(snapshot), "the snapshot must be branded as compiled by this package");
  assert.ok(!isCompiledApprovalRules(honest), "the caller's own array is not, and must never become, a snapshot");
  assert.ok(Object.isFrozen(snapshot) && Object.isFrozen(snapshot[0]) && Object.isFrozen(snapshot[0].match), "frozen at every level a decision reads");
  assert.equal(Object.getPrototypeOf(snapshot[0]), null, "each compiled rule is null-prototype, so no inherited field can answer for a missing one");

  // Idempotent: re-validating a snapshot yields THAT SAME snapshot. The CLI validates and so does
  // createProxyServer; the second call must not manufacture a second object.
  assert.equal(requireValidApprovalRules(snapshot, "createProxyServer: `approvalRules`"), snapshot);
});

test("requireValidApprovalRules: MUTATING the caller's rules after validation cannot change what the snapshot gates (reproduced bypass)", () => {
  const live = [{ id: "transfer-needs-human", match: { type: "exact", action: "transfer_funds" }, threshold: { path: "amountMinor", op: "ge", value: 5000 } }];
  const snapshot = requireValidApprovalRules(live, "--approval-rules");

  live[0].match.action = "something-else"; // the measured attack: validated honest, then rewritten
  live[0].threshold.value = 999_999_999;
  live.length = 0;

  assert.equal(
    matchApprovalRule(snapshot, "transfer_funds", { amountMinor: 7000 })?.id,
    "transfer-needs-human",
    "the snapshot still gates: pre-fix this exact mutation executed an unapproved 7000-unit transfer through a real proxy",
  );
});

test("compileApprovalRules: an INHERITED critical field is refused, never resolved (reproduced bypass)", () => {
  // The rule's OWN data says "gate every transfer_funds". Its prototype supplies a threshold aimed at
  // a path that is never in `inputs`, which turns "hold every match" into "hold nothing" while
  // validation reports the rule well-formed.
  const inherited = Object.create({ threshold: { path: "never-in-inputs", op: "ge", value: 0 } });
  inherited.id = "transfer-needs-human";
  inherited.match = { type: "exact", action: "transfer_funds" };
  assert.equal(Object.prototype.hasOwnProperty.call(inherited, "threshold"), false);
  assert.notEqual(inherited.threshold, undefined, "the inherited value IS what ordinary property access returns — that is the whole trick");

  const compiled = compileApprovalRules([inherited]);
  assert.equal(compiled.ok, false);
  assert.match(compiled.errors.join("; "), /threshold: must be an OWN DATA property/);
  assert.throws(() => requireValidApprovalRules([inherited], "--approval-rules"), /OWN DATA property/);

  // The same trick from Object.prototype itself, which is where a prototype-pollution gadget lands.
  const plain = { id: "transfer-needs-human", match: { type: "exact", action: "transfer_funds" } };
  Object.prototype.threshold = { path: "never-in-inputs", op: "ge", value: 0 };
  try {
    assert.equal(compileApprovalRules([plain]).ok, false, "a polluted Object.prototype must refuse the rule set, not quietly re-aim it");
    assert.equal(matchApprovalRule([plain], "transfer_funds", { amountMinor: 7000 })?.id, "approval-rules-unusable", "and the matcher must HOLD rather than report no-match");
  } finally {
    delete Object.prototype.threshold;
  }
});

test("compileApprovalRules: an ACCESSOR-backed critical field is refused WITHOUT the getter ever running (reproduced bypass)", () => {
  let getterReads = 0;
  const twoFaced = {
    id: "transfer-needs-human",
    get match() {
      getterReads += 1;
      return getterReads <= 1 ? { type: "exact", action: "transfer_funds" } : { type: "exact", action: "not-this-tool" };
    },
  };

  const compiled = compileApprovalRules([twoFaced]);
  assert.equal(compiled.ok, false);
  assert.match(compiled.errors.join("; "), /match: must be an OWN DATA property .*getter\/setter/);
  assert.equal(getterReads, 0, "refused by its DESCRIPTOR — a getter that is never invoked cannot answer twice");

  // An accessor ELEMENT of the array itself is the same trick one level out.
  const sneakyArray = [];
  Object.defineProperty(sneakyArray, 0, { enumerable: true, configurable: true, get() { return { id: "r", match: { type: "exact", action: "transfer_funds" } }; } });
  assert.equal(compileApprovalRules(sneakyArray).ok, false);
  assert.match(compileApprovalRules(sneakyArray).errors.join("; "), /OWN DATA element/);
});

// ── THE BRANDED HOLE (third review, 2026-08-12) ──────────────────────────────────────────────────
// `push` performs [[Set]], and [[Set]] walks the RECEIVER'S prototype chain. The compiler built its
// accumulators as ordinary arrays and re-rooted the finished one onto the inert prototype at the
// END, so an accessor at `Object.prototype["0"]` swallowed the element write while `push` still
// bumped `length`. The result was a snapshot that was branded, reported `length: 1`, and held
// nothing:
//
//     branded=true  length=1  own0=false   ->  preCheck(over-threshold transfer) = ALLOW
//
// The realistic gadget is TIMED — poison during the compile, withdraw, then serve — because with the
// poison left installed the policy engine DENYs earlier for unrelated reasons.
function withIndexZeroPoisoned(fn) {
  Object.defineProperty(Object.prototype, "0", { configurable: true, set() {}, get() { return undefined; } });
  try {
    return fn();
  } finally {
    delete Object.prototype[0];
  }
}

test("compileApprovalRules: an accessor on Object.prototype cannot hole the snapshot while it is being filled", () => {
  const honest = [{ id: "transfer-needs-human", match: { type: "exact", action: "transfer_funds" }, threshold: { path: "amountMinor", op: "ge", value: 5000 } }];

  const compiled = withIndexZeroPoisoned(() => compileApprovalRules(honest));
  assert.equal(compiled.ok, true, "an honest rule set still compiles under the poison");
  assert.equal(compiled.rules.length, 1);
  assert.equal(Object.prototype.hasOwnProperty.call(compiled.rules, 0), true, "the rule LANDED — pre-fix `length` said 1 and index 0 was absent");
  assert.equal(compiled.rules[0].id, "transfer-needs-human");

  // The TIMED gadget, end to end: hole it at load, clean up, then serve.
  const snapshot = withIndexZeroPoisoned(() => requireValidApprovalRules(honest, "--approval-rules"));
  assert.equal(
    matchApprovalRule(snapshot, "transfer_funds", { amountMinor: 7000 })?.id,
    "transfer-needs-human",
    "a snapshot compiled under the poison must still gate afterwards",
  );
});

test("compileApprovalRules: the ERRORS container cannot be holed either — a refusal keeps its reason", () => {
  const invalid = [{ id: "", match: { type: "regex", action: "x" } }];
  const compiled = withIndexZeroPoisoned(() => compileApprovalRules(invalid));
  assert.equal(compiled.ok, false);
  assert.ok(compiled.errors.length > 0);
  assert.notEqual(compiled.errors[0], undefined, "pre-fix the COUNT was right and the message itself had vanished");
  assert.match(compiled.errors.join("; "), /approvalRules\[0\]/);
});

test("matchApprovalRule: a THROW while evaluating a matched rule's threshold HOLDS, never skips", () => {
  const rules = [{ id: "big-transfer", match: { type: "exact", action: "transfer_funds" }, threshold: { path: "amountMinor", op: "ge", value: 5000 } }];
  const hostileInputs = {};
  Object.defineProperty(hostileInputs, "amountMinor", { enumerable: true, configurable: true, get() { throw new Error("boom"); } });

  const held = matchApprovalRule(rules, "transfer_funds", hostileInputs);
  assert.notEqual(held, null, "pre-fix the throw was caught and the rule SKIPPED — which a caller reads as 'no approval needed'");
  assert.equal(held?.id, "big-transfer", "the rule that matched the action is the rule that gates it");

  // CONTROL: an honest `inputs` still decides both ways.
  assert.equal(matchApprovalRule(rules, "transfer_funds", { amountMinor: 7000 })?.id, "big-transfer");
  assert.equal(matchApprovalRule(rules, "transfer_funds", { amountMinor: 10 }), null);
});

test("compileApprovalRules: a Proxy is refused wherever it appears, and own-data scalar extras survive compilation", () => {
  const rule = { id: "r", match: { type: "exact", action: "x" } };
  assert.equal(compileApprovalRules(new Proxy([rule], {})).ok, false, "a Proxy rule SET can answer differently on every read");
  assert.equal(compileApprovalRules([new Proxy(rule, {})]).ok, false, "and so can a Proxy rule");

  // DEFAULT_APPROVAL_RULES carries a `risk` field that consumers read off the MATCHED rule, so the
  // compiler must carry own-data scalars through rather than reduce every rule to id/match/threshold.
  const withExtras = compileApprovalRules([{ id: "r", risk: "MONEY", weight: 3, urgent: true, match: { type: "exact", action: "x" } }]);
  assert.equal(withExtras.ok, true);
  assert.equal(withExtras.rules[0].risk, "MONEY");
  assert.equal(withExtras.rules[0].weight, 3);
  assert.equal(withExtras.rules[0].urgent, true);
});

test("matchApprovalRule: exact match / prefix match (the feature dsl.ts cannot express) / no match", () => {
  assert.equal(matchApprovalRule([{ id: "r1", match: { type: "exact", action: "payment.refund" } }], "payment.refund", {})?.id, "r1");
  assert.equal(matchApprovalRule([{ id: "r1", match: { type: "exact", action: "payment.refund" } }], "payment.other", {}), null);
  const prefixRules = [{ id: "any-db-write", match: { type: "prefix", action: "db." } }];
  assert.equal(matchApprovalRule(prefixRules, "db.delete", {})?.id, "any-db-write");
  assert.equal(matchApprovalRule(prefixRules, "email.send", {}), null);
});

test("matchApprovalRule: threshold ge/gt first-match-wins; absent path -> no match; ambiguous-type path -> fail-closed match", () => {
  const rules = [
    { id: "over-limit", match: { type: "exact", action: "wire.transfer" }, threshold: { path: "amountMinor", op: "ge", value: 1_000_000 } },
    { id: "over-limit-strict", match: { type: "exact", action: "wire.transfer" }, threshold: { path: "amountMinor", op: "gt", value: 500_000 } },
  ];
  assert.equal(matchApprovalRule(rules, "wire.transfer", { amountMinor: 1_000_000 })?.id, "over-limit");
  // R4-FIX (recipe self-contradiction): approval-rules.mjs's matcher is FAIL-CLOSED-TOWARD-GATING
  // with continue-on-threshold-miss (its own docstring) — it OR's the rules, so a value that misses
  // the first rule's threshold still gates if a LATER rule matches. The recipe's original assertion
  // expected null here with the comment "999999 is not > 500000", which is arithmetically false
  // (999999 > 500000) and would mean silently auto-executing a held-worthy transfer — the exact
  // opposite of the matcher's stated fail-closed intent. Corrected to the matcher's real, safe
  // behavior; a value below BOTH thresholds is the genuine no-match case.
  assert.equal(matchApprovalRule(rules, "wire.transfer", { amountMinor: 999_999 })?.id, "over-limit-strict", "misses over-limit (ge 1000000) but fails closed to over-limit-strict (999999 > 500000)");
  assert.equal(matchApprovalRule(rules, "wire.transfer", { amountMinor: 400_000 }), null, "below BOTH thresholds -> genuine no-match");
  assert.equal(matchApprovalRule([{ id: "r", match: { type: "exact", action: "x" }, threshold: { path: "amountMinor", op: "ge", value: 1 } }], "x", {}), null);
  assert.equal(matchApprovalRule([{ id: "r", match: { type: "exact", action: "x" }, threshold: { path: "amount", op: "ge", value: 1 } }], "x", { amount: "0.5" })?.id, "r");
});

// ⚠ THIS TEST'S EXPECTATION WAS DELIBERATELY REVERSED ON 2026-08-12 (round 2), and the old one is
// written out here rather than deleted, because it looked exactly like safety.
//
// It used to assert that a hostile rule mid-array is SKIPPED and the scan continues — `?.id ===
// "good"`. That is a partial accept: the rule set as a whole was never trustworthy, and continuing
// past the part that could not be read is how "some of your rules are live" gets reported as a
// working gate. An adversarial review then used exactly this tolerance — a `match` GETTER answering
// one way while validated and another way while used — to execute an unapproved 7000-unit transfer
// through a real proxy. A rule set with an unreadable rule in it is now refused WHOLE, and the
// matcher's answer for it is a HOLD, not a no-match.
//
// What is unchanged, and still asserted: it never throws, and "no rules configured" still matches
// nothing.
test("matchApprovalRule: a malformed rule anywhere makes the WHOLE rule set unusable -> HOLD (never a silent skip); empty/undefined/null still never match", () => {
  const evil = {};
  Object.defineProperty(evil, "match", { enumerable: true, get() { throw new Error("boom"); } });
  const rules = [evil, { id: "good", match: { type: "exact", action: "x" } }];

  assert.doesNotThrow(() => matchApprovalRule(rules, "x", {}));
  const held = matchApprovalRule(rules, "x", {});
  assert.equal(held?.id, "approval-rules-unusable", "the hostile rule condemns the whole set; the action is held for a human");
  assert.notEqual(held?.id, "good", "the pre-2026-08-12 expectation — skip the bad rule, keep matching — is withdrawn as unsafe");

  // "No approval rules configured" is a different statement from "your rule set is broken", and only
  // the second one gates. Gating on the first would hold every call for every caller who never
  // enabled the feature.
  assert.equal(matchApprovalRule([], "x", {}), null);
  assert.equal(matchApprovalRule(undefined, "x", {}), null);
  assert.equal(matchApprovalRule(null, "x", {}), null);
});

test("matchApprovalRule: a non-array rule set HOLDS instead of forwarding — the five public decision APIs inherit this from one line", () => {
  for (const bad of [{}, "nope", 5, true, new Proxy([], {})]) {
    assert.equal(
      matchApprovalRule(bad, "transfer_funds", { amountMinor: 7000 })?.id,
      "approval-rules-unusable",
      `${JSON.stringify(bad) ?? String(bad)} must hold the action, not report "no rule matched" (which the caller reads as "forward it")`,
    );
  }
});

test("tryIdentifyToolCallForTicketLookup: resolves actionId+paramsHash identically to preCheck; null on non-string/empty/throwing name, never throws", () => {
  const id = tryIdentifyToolCallForTicketLookup({ name: "payment.refund", args: { amountMinor: 4200 } }, canonicalParamsHash);
  assert.equal(id.actionId, "payment.refund");
  assert.equal(id.paramsHash, canonicalParamsHash({ amountMinor: 4200 }));
  assert.equal(tryIdentifyToolCallForTicketLookup({ name: 123, args: {} }, canonicalParamsHash), null);
  assert.equal(tryIdentifyToolCallForTicketLookup({ name: "", args: {} }, canonicalParamsHash), null);
  const evil = { args: {} };
  Object.defineProperty(evil, "name", { enumerable: true, get() { throw new Error("boom"); } });
  assert.doesNotThrow(() => tryIdentifyToolCallForTicketLookup(evil, canonicalParamsHash));
  assert.equal(tryIdentifyToolCallForTicketLookup(evil, canonicalParamsHash), null);
});


// REDTEAM 2026-08-03, reproduced by the lead before the fix.
//
// Every failure mode in `matchApprovalRule` lands on "no rule matched", and the caller reads that as
// "no human approval required". Two poisoned type predicates reached it directly — not by
// mis-evaluating a rule, but by making the rule INVISIBLE, which is indistinguishable from an empty
// policy. Measured: a 900,000-cent refund against a rule with a 4,000 threshold went straight through.
test("matchApprovalRule: poisoned type predicates cannot make a matching approval rule invisible", () => {
  const rules = [{ id: "big-refund", match: { type: "exact", action: "payment.refund" }, threshold: { path: "amountMinor", op: "ge", value: 4000 } }];
  const call = () => matchApprovalRule(rules, "payment.refund", { amountMinor: 900000 });

  assert.equal(call()?.id, "big-refund", "control: the rule must match unpoisoned, or nothing below means anything");

  const realIsArray = Array.isArray;
  let viaIsArray;
  try {
    Array.isArray = () => false;
    viaIsArray = call();
  } finally {
    Array.isArray = realIsArray;
  }
  assert.equal(viaIsArray?.id, "big-refund",
    "a poisoned Array.isArray made the whole rule set vanish, so an action needing human approval " +
    "was treated as needing none");

  const realHasOwn = Object.prototype.hasOwnProperty;
  let viaHasOwn;
  try {
    // eslint-disable-next-line no-extend-native
    Object.prototype.hasOwnProperty = () => false;
    viaHasOwn = call();
  } finally {
    // eslint-disable-next-line no-extend-native
    Object.prototype.hasOwnProperty = realHasOwn;
  }
  assert.equal(viaHasOwn?.id, "big-refund",
    "a poisoned hasOwnProperty made the threshold value read as absent, so the rule was skipped");

  assert.equal(Array.isArray, realIsArray, "control: Array.isArray was not restored");
  assert.equal(Object.prototype.hasOwnProperty, realHasOwn, "control: hasOwnProperty was not restored");
});
