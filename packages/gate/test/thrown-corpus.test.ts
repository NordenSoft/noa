/**
 * BOUNDARY 2 applied at THIS package's thrown-value sites, using the SHARED corpus.
 *
 * TWO THINGS THIS PINS:
 *
 *   1. `execute()` may throw ANYTHING. The wrapper must still reach `report(...)` so the attempt is
 *      not left dangling — but WHAT it reports is decided by the DESIGN 3 state machine, not guessed.
 *      An UNMARKED throw after dispatch is SIDE_EFFECT_UNCONFIRMED → reported UNKNOWN (never a
 *      determinate FAILED_BEFORE_DISPATCH, which would be a signed "it did not run" for a tool that
 *      may have run). A throw the tool MARKED as pre-side-effect is FAILED_BEFORE_DISPATCH. `throw
 *      null` cannot masquerade as success: only `{ ok: true }` is a dispatch.
 *
 *   2. `report(...)` may throw. It was awaited OUTSIDE any try, so a transport failure there
 *      propagated raw AND TOOK `ran: true` WITH IT — the caller saw an ordinary failure for a
 *      command that had already run, and the correct response to an ordinary failure is a retry.
 *      A non-200 report already preserved the discriminator (`{ outcome: "ERROR", ran: ok }`); a
 *      THROWN report did not. It now raises `ToolOutcomeNotRecorded`, the same type
 *      framework-adapters and mcp-proxy use, whose `executionHappened === true` is the signal.
 *
 * The corpus is loaded through a computed specifier so the repo-root file (deliberately outside any
 * package) stays out of this package's TypeScript program while still being the ONE copy.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { guard, type GateClient } from "../src/wrapper.js";
import type { EngineResult } from "../src/engine.js";
import { ToolOutcomeNotRecorded } from "noa-mcp-adapter-core/tool-outcome-not-recorded";
import { markThrewBeforeSideEffect } from "noa-mcp-adapter-core/side-effect-state";

interface CorpusEntry {
  name: string;
  make: () => unknown;
}
// This package compiles to `dist/test/*.js` and is ALWAYS run from there (`npm test` = build then
// `node --test dist/test/*.test.js`), so the depth is relative to dist/test, not to this source
// file. Resolved at run time through a computed specifier, which also keeps the repo-root corpus
// out of this package's TypeScript program (it is deliberately outside every package: one copy).
const corpusHref = new URL("../../../../scripts/thrown-value-corpus.mjs", import.meta.url).href;
const { THROWN_CORPUS } = (await import(corpusHref)) as { THROWN_CORPUS: CorpusEntry[] };

const PARAMS_HASH = "sha256:" + "c".repeat(64);

/** A client that approves immediately with a grant bound to whatever hash the wrapper derives. */
function clientThatApproves(opts: {
  paramsHash: string;
  report: () => Promise<EngineResult>;
  onReserve?: () => void;
}): GateClient {
  return {
    createHold: () => Promise.resolve({ status: 201, body: { holdId: "h1" } } as EngineResult),
    wait: () =>
      Promise.resolve({
        status: 200,
        body: { status: "APPROVED", executionGrant: { grantId: "g1", paramsHash: opts.paramsHash } },
      } as EngineResult),
    reserve: () => {
      opts.onReserve?.();
      return Promise.resolve({ status: 200, body: {} } as EngineResult);
    },
    report: opts.report,
  };
}

/** RAW mode keeps the hash under the test's control, so the corpus is the only variable. */
function guardWith(overrides: { execute: () => Promise<{ ok: boolean; detail?: string }>; report: () => Promise<EngineResult>; onReserve?: () => void }) {
  return guard({
    client: clientThatApproves({ paramsHash: PARAMS_HASH, report: overrides.report, ...(overrides.onReserve ? { onReserve: overrides.onReserve } : {}) }),
    action: { canonical: "noa.command.exec", riskClass: "HIGH", reversible: false },
    mode: "RAW",
    paramsHash: PARAMS_HASH,
    params: { cmd: "true" },
    idempotencyKey: "idem-corpus",
    waitMs: 100,
    execute: overrides.execute,
  });
}

for (const entry of THROWN_CORPUS) {
  test(`execute() throwing an UNMARKED value reports UNKNOWN, never a determinate FAILED_BEFORE_DISPATCH: ${entry.name}`, async () => {
    // C4: an UNMARKED throw after dispatch proves NOTHING about whether the side effect occurred. The
    // gate must NOT sign FAILED_BEFORE_DISPATCH ("it did not run") — a tool that incremented a
    // side-effect counter then threw would be signed as a clean failure, and the correct handling of a
    // clean failure is to retry it. The honest report is UNKNOWN → the gate's Execution Uncertainty
    // path. This test used to codify the unsafe FAILED_BEFORE_DISPATCH result; it now pins the fix.
    const thrown = entry.make();
    let reportedBody: unknown;
    const result = await guardWith({
      execute: async () => { throw thrown; },
      report: async (...args: unknown[]) => {
        reportedBody = (args as [string, unknown])[1];
        // The real engine answers an UNKNOWN report with 202 (a hint; it signs nothing synchronously).
        return { status: 202, body: { status: "UNCERTAINTY_PENDING_GATE_CORROBORATION" } } as EngineResult;
      },
    });
    assert.equal(result.outcome, "UNKNOWN_AFTER_DISPATCH", `got ${result.outcome}: ${result.detail ?? ""}`);
    assert.deepEqual(reportedBody, { result: "UNKNOWN" }, "a bare throw must be reported as UNKNOWN, never FAILED_BEFORE_DISPATCH");
    assert.equal(result.ran, true, "UNKNOWN_AFTER_DISPATCH is conservatively ran:true — a side effect MAY have occurred; do not retry");
    assert.equal(typeof result.detail, "string");
  });

  test(`report() throwing it after a SUCCESSFUL dispatch raises ToolOutcomeNotRecorded: ${entry.name}`, async () => {
    const thrown = entry.make();
    let executed = 0;
    let caught: unknown;
    try {
      await guardWith({
        execute: async () => { executed++; return { ok: true }; },
        report: async () => { throw thrown; },
      });
    } catch (e) {
      caught = e;
    }
    assert.equal(executed, 1, "the command really ran — that is what makes this dangerous");
    assert.equal(
      ToolOutcomeNotRecorded.is(caught),
      true,
      "a caller that sees an ordinary failure here retries a command that has already executed",
    );
    const e = caught as InstanceType<typeof ToolOutcomeNotRecorded>;
    assert.equal(e.executionHappened, true, "THE DISCRIMINATOR");
    assert.equal(e.outcome, "EXECUTED");
    assert.equal(typeof e.causeDescription, "string");
    assert.ok(e.causeDescription.length > 0);
  });

  test(`report() throwing it after a FAILED dispatch stays an ordinary ERROR: ${entry.name}`, async () => {
    const thrown = entry.make();
    // Nothing ran, so there is no side effect to protect: this must NOT be raised as
    // ToolOutcomeNotRecorded (that type means "it ran"), and must not throw either.
    const result = await guardWith({
      execute: async () => ({ ok: false, detail: "command exited 1" }),
      report: async () => { throw thrown; },
    });
    assert.equal(result.outcome, "ERROR");
    assert.equal(result.ran, false);
    assert.match(result.detail ?? "", /report threw:/);
  });
}

test("a benign dispatch still succeeds end to end (no over-correction)", async () => {
  const result = await guardWith({
    execute: async () => ({ ok: true }),
    report: async () => ({ status: 200, body: { consumption: { ok: true }, attemptReceipt: { governance: { verdict: "EXECUTED" } } } } as EngineResult),
  });
  assert.equal(result.outcome, "EXECUTED");
  assert.equal(result.ran, true);
});

test("C4 reproduction: a tool that causes a side effect and THEN throws is UNKNOWN, never a signed FAILED_BEFORE_DISPATCH", async () => {
  // The review's exact repro: execute() increments a side-effect counter (the remote committed) then
  // throws as if its response was lost. Pre-fix the gate signed FAILED_BEFORE_DISPATCH — a determinate
  // "it did not run" for a side effect that HAD happened. The gate cannot know, so it reports UNKNOWN.
  let sideEffects = 0;
  let reportedBody: unknown;
  const result = await guardWith({
    execute: async () => {
      sideEffects++; // the remote committed
      throw new Error("response lost after the remote committed");
    },
    report: async (...args: unknown[]) => {
      reportedBody = (args as [string, unknown])[1];
      return { status: 202, body: { status: "UNCERTAINTY_PENDING_GATE_CORROBORATION" } } as EngineResult;
    },
  });
  assert.equal(sideEffects, 1, "the side effect really happened — that is what makes the old signed FAILED a lie");
  assert.equal(result.outcome, "UNKNOWN_AFTER_DISPATCH");
  assert.deepEqual(reportedBody, { result: "UNKNOWN" }, "the gate must NOT sign FAILED_BEFORE_DISPATCH for a side effect that may have happened");
});

test("a throw MARKED as pre-side-effect IS a determinate failure — FAILED_BEFORE_DISPATCH (positive evidence)", async () => {
  // The only way back to a retryable determinate failure after a THROW: the tool proves the throw
  // preceded any side effect (a pre-dispatch refusal it explicitly marked). Then, and only then, the
  // gate may sign FAILED_BEFORE_DISPATCH.
  let reportedBody: unknown;
  const result = await guardWith({
    execute: async () => { throw markThrewBeforeSideEffect(new Error("connection refused before request was sent")); },
    report: async (...args: unknown[]) => {
      reportedBody = (args as [string, unknown])[1];
      return { status: 200, body: { consumption: {}, attemptReceipt: {} } } as EngineResult;
    },
  });
  assert.equal(result.outcome, "EXECUTION_FAILED");
  assert.equal(result.ran, false, "a proven pre-side-effect throw did not run");
  assert.deepEqual(reportedBody, { result: "FAILED_BEFORE_DISPATCH" });
});

test("a clean { ok: false } return is FAILED_BEFORE_DISPATCH — the tool ran and asserts no dispatch", async () => {
  let reportedBody: unknown;
  const result = await guardWith({
    execute: async () => ({ ok: false, detail: "exit 1" }),
    report: async (...args: unknown[]) => {
      reportedBody = (args as [string, unknown])[1];
      return { status: 200, body: { consumption: {}, attemptReceipt: {} } } as EngineResult;
    },
  });
  assert.equal(result.outcome, "EXECUTION_FAILED");
  assert.equal(result.ran, false);
  assert.deepEqual(reportedBody, { result: "FAILED_BEFORE_DISPATCH" });
});
