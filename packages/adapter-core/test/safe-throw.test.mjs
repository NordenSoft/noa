/**
 * BOUNDARY 2 — the boundary itself, against the SHARED adversarial corpus.
 *
 * The corpus lives at `scripts/thrown-value-corpus.mjs` (repo root, one copy) and is run against
 * every governed package. This file holds the boundary to the four properties everything else
 * depends on:
 *
 *   TOTAL      — every function returns for every input, including values that fight back.
 *   NEVER-THROWS — no input makes the conversion itself raise, because a handler that raises is a
 *                  handler that lost the failure it was reporting.
 *   HONEST     — falsy values are named, not collapsed into "no error"; hostile values are
 *                described as hostile rather than silently rendered as "".
 *   IDENTITY-PRESERVING — describing a value never replaces it; callers re-throw the original.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  describeThrown,
  describeThrownDetailed,
  isErrorLike,
  thrownName,
  thrownCode,
  truncateThrown,
  MAX_DESCRIPTION_LEN,
} from "../src/safe-throw.mjs";
import { ToolOutcomeNotRecorded } from "../src/tool-outcome-not-recorded.mjs";
import { THROWN_CORPUS, THROWN_CORPUS_ASYNC, FALSY_THROWN } from "../../../scripts/thrown-value-corpus.mjs";

test("the corpus is non-trivial and covers the falsy values", () => {
  assert.ok(THROWN_CORPUS.length >= 25, `corpus too small (${THROWN_CORPUS.length})`);
  assert.equal(FALSY_THROWN.length, 8, "the eight Node-reachable falsy values (document.all is browser-only)");
});

for (const entry of THROWN_CORPUS) {
  test(`describeThrown is total and never throws: ${entry.name}`, () => {
    const value = entry.make();
    const description = describeThrown(value);
    assert.equal(typeof description, "string");
    assert.ok(description.length > 0, "an empty description is indistinguishable from 'nothing was thrown'");
    assert.ok(description.length <= MAX_DESCRIPTION_LEN + 32, `unbounded description (${description.length} chars)`);
  });

  test(`every accessor is total and never throws: ${entry.name}`, () => {
    const value = entry.make();
    assert.equal(typeof isErrorLike(value), "boolean");
    const name = thrownName(value);
    assert.ok(name === null || typeof name === "string");
    const code = thrownCode(value);
    assert.ok(code === null || typeof code === "string");
  });

  test(`the structured descriptor is safe to serialize: ${entry.name}`, () => {
    const value = entry.make();
    const d = describeThrownDetailed(value);
    assert.equal(typeof d.message, "string");
    assert.equal(typeof d.isError, "boolean");
    assert.equal(typeof d.type, "string");
    // THE POINT: a logger reaching for the descriptor must not reach the untrusted value. `raw` is
    // non-enumerable, so JSON.stringify never walks into a revoked proxy or a throwing getter.
    assert.doesNotThrow(() => JSON.stringify(d), "serializing the descriptor must never touch `raw`");
    assert.equal(Object.keys(d).includes("raw"), false, "`raw` must not be enumerable");
    assert.equal(Object.prototype.hasOwnProperty.call(d, "raw"), true, "`raw` must still be reachable for re-throwing");
  });

  test(`ToolOutcomeNotRecorded survives it as a cause: ${entry.name}`, () => {
    const value = entry.make();
    let e;
    // The constructor USED to do `cause instanceof Error ? cause.message : String(cause)`. With any
    // of these values that threw from inside `new ToolOutcomeNotRecorded(...)`, so the throw
    // statement raised a plain TypeError and the caller lost `executionHappened === true` —
    // mistaking an operation that had already run for one that could be safely retried.
    assert.doesNotThrow(() => {
      e = new ToolOutcomeNotRecorded("payment.refund", { outcome: "EXECUTED", cause: value, component: "test" });
    }, "constructing the anti-retry discriminator must never depend on the cause behaving");
    assert.equal(e.executionHappened, true);
    assert.equal(ToolOutcomeNotRecorded.is(e), true, "the brand must identify it");
    assert.equal(typeof e.message, "string");
    assert.ok(e.causeDescription.length > 0);
  });
}

for (const entry of THROWN_CORPUS_ASYNC) {
  test(`async rejection path: ${entry.name}`, async () => {
    // The same payloads through the other door: `await` delivers them to a different catch block,
    // and only the synchronous door was ever exercised.
    let caught;
    let threw = false;
    try {
      await entry.make();
    } catch (e) {
      threw = true;
      caught = e;
    }
    assert.equal(threw, true, "a rejected promise must reach the catch block");
    assert.equal(typeof describeThrown(caught), "string");
    assert.doesNotThrow(() => JSON.stringify(describeThrownDetailed(caught)));
  });
}

test("falsy thrown values are NAMED, never collapsed into 'nothing was thrown'", () => {
  for (const entry of FALSY_THROWN) {
    const d = describeThrown(entry.make());
    assert.ok(d.length > 0 && !/^\s*$/.test(d), `${entry.name} produced an empty description`);
    assert.match(d, /thrown/, `${entry.name}: the description must say something was thrown (got ${JSON.stringify(d)})`);
  }
});

test("-0 and 0 are distinguishable, and NaN is named", () => {
  assert.match(describeThrown(-0), /^-0 /);
  assert.match(describeThrown(0), /^0 /);
  assert.match(describeThrown(NaN), /^NaN /);
});

test("isErrorLike sees a cross-realm Error that `instanceof` cannot", () => {
  const crossRealm = THROWN_CORPUS.find((e) => e.name.startsWith("cross-realm")).make();
  assert.equal(crossRealm instanceof Error, false, "precondition: same-realm instanceof is blind to it");
  assert.equal(isErrorLike(crossRealm), true, "the brand probe must see it");
});

test("isErrorLike does not throw on a revoked proxy (where bare `instanceof` does)", () => {
  const revocable = Proxy.revocable({}, {});
  revocable.revoke();
  assert.throws(() => revocable.proxy instanceof Error, TypeError, "precondition: bare instanceof throws here");
  assert.equal(isErrorLike(revocable.proxy), false);
});

test("descriptions are bounded even for a 2 MiB message", () => {
  const huge = new Error("x".repeat(2 * 1024 * 1024));
  const d = describeThrown(huge);
  assert.ok(d.length <= MAX_DESCRIPTION_LEN + 32, `unbounded: ${d.length}`);
  assert.match(d, /truncated/);
});

test("truncateThrown returns '' for non-strings rather than coercing them", () => {
  assert.equal(truncateThrown(undefined), "");
  assert.equal(truncateThrown({ toString() { throw new Error("no"); } }), "");
  assert.equal(truncateThrown("short"), "short");
});

test("ToolOutcomeNotRecorded.is() beats instanceof across duplicate copies of the class", async () => {
  // Two module instances = two distinct classes. A caller's `e instanceof ToolOutcomeNotRecorded`
  // silently answers false and takes the RETRY path — on an operation that already ran.
  const second = await import(`../src/tool-outcome-not-recorded.mjs?copy=${Date.now()}`);
  const e = new second.ToolOutcomeNotRecorded("t", { outcome: "EXECUTED", cause: new Error("x") });
  assert.equal(e instanceof ToolOutcomeNotRecorded, false, "precondition: instanceof is copy-sensitive");
  assert.equal(ToolOutcomeNotRecorded.is(e), true, "the brand crosses copies");
});

test("ToolOutcomeNotRecorded.is() never throws, for any corpus value", () => {
  for (const entry of THROWN_CORPUS) {
    assert.doesNotThrow(() => ToolOutcomeNotRecorded.is(entry.make()), entry.name);
  }
});
