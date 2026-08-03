/**
 * The /wait long-poll must keep the event loop alive until its promise settles.
 *
 * ─── WHY THIS TEST SPAWNS A CHILD PROCESS ────────────────────────────────────────────────────────
 *
 * Because the defect is INVISIBLE from inside a normal suite, and that is not a detail — it is the
 * whole reason the bug survived.
 *
 * `engine.ts` unref'd the long-poll timer. An unref'd timer does not hold the event loop open, so
 * once the process has nothing else to do, Node concludes the loop has drained while the `wait()`
 * promise is still pending, and emits:
 *
 *     'Promise resolution is still pending but the event loop has already resolved'
 *
 * Inside a running test suite there is ALWAYS something else to do — other files, other timers, the
 * runner's own I/O — so the timer fires long before the loop could drain, and every local run is
 * green. On CI it drained. The measured cost: one hang in `cross-agent-authz.test.js` took SIX
 * siblings down with it as `cancelledByParent`, and those six are the tenant-isolation tests — a
 * foreign customer cannot ENUMERATE, cannot DECIDE, an unclaimed device can do nothing. They were
 * not failing. They were NOT RUNNING, and `cancelled` is not `failed`, so nothing shouted.
 *
 * So the only honest way to test the property is to reproduce the condition: an OTHERWISE-IDLE
 * process whose sole pending work is one `wait()`. That is what the child is. A test that ran in
 * this process would inherit exactly the blindness that hid the defect.
 *
 * ⚠ THIS IS NOT MERELY A TEST FIX. A long-poll whose timer does not hold the loop can be dropped
 * while a human's phone is waiting on an approval — the promise never settles and the request hangs.
 * The sibling unref at `server.ts` IS correct: a background sweeper must not keep the process alive.
 * A request-scoped timer with a caller awaiting its promise is the opposite case, and the two were
 * written the same way.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const HERE = dirname(fileURLToPath(import.meta.url));
const HELPERS = join(HERE, "helpers.js");

/** Runs ONE `wait()` in an otherwise-idle process and reports. If the loop is not held open, the
 *  child exits before the write and stdout is empty — the failure this test exists to catch.
 *
 *  `decideFirst` selects which of the two `wait()` branches is exercised:
 *    false → the hold stays PENDING, so the only thing that can settle the promise is the
 *            long-poll's own timer (`engine.ts` — the code under test).
 *    true  → the hold is already resolved, so `wait()` returns at its fast path and NEVER creates a
 *            timer. Same child, same imports, same harness, same build artifacts — different branch. */
function runInIdleChild(timeoutMs: number, decideFirst: boolean): { stdout: string; stderr: string; code: number | null } {
  const script = `
    import { makeHarness, makeAgent, makeDevice, signDecisionReceipt, bodyOf, PARAMS_HASH } from ${JSON.stringify(HELPERS)};
    const ACTION = { canonical: "wire.transfer", riskClass: "CRITICAL", paramsHash: PARAMS_HASH };
    const h = makeHarness();
    const v = makeAgent(h, "owner");
    const { holdId } = bodyOf(h.engine.createHold(v.agent, "idem-idle", { action: ACTION }));
    if (${decideFirst}) {
      const d = makeDevice(h, v.agent);
      const receipt = signDecisionReceipt({
        kid: d.kid, privateKey: d.privateKey,
        canonical: ACTION.canonical, paramsHash: ACTION.paramsHash, verdict: "ALLOWED",
      });
      h.engine.decide(d.device, holdId, { receipt });
    }
    const r = await h.engine.wait(v.agent, holdId, ${timeoutMs});
    process.stdout.write("SETTLED:" + r.status);
  `;
  const r = spawnSync(process.execPath, ["--input-type=module", "--eval", script], {
    encoding: "utf8",
    timeout: 30_000,
  });
  return { stdout: (r.stdout ?? "").trim(), stderr: (r.stderr ?? "").trim(), code: r.status };
}

/** CONTROL FIRST, deliberately — it is the one that decides whether the attack below means anything.
 *
 *  ⚠ MY FIRST VERSION OF THIS CONTROL WAS NOT A CONTROL. It re-ran the SAME timer branch with a
 *  longer budget, so when the defect was present BOTH went red and the pair could not tell "the
 *  long-poll is broken" from "the child script does not run at all". A control that fails for the
 *  same reason as the attack measures nothing — this repository's own standard, and I had to be shown
 *  it by the output.
 *
 *  This one takes the branch that never creates a timer: a hold that is already decided returns from
 *  `wait()`'s fast path. Same child, same imports, same build artifacts, same harness — so if THIS
 *  fails, the fixture is broken and the attack proves nothing; if only the ATTACK fails, the finding
 *  is real. */
test("CONTROL — an already-decided hold settles in the same idle child (no timer involved)", () => {
  const r = runInIdleChild(150, true);
  assert.equal(r.stdout, "SETTLED:200",
    "FIXTURE BROKEN, NOT A FINDING: the child could not complete a wait() that never touches a " +
      `timer, so the test below is measuring the harness, not the long-poll. stderr: ${r.stderr || "(empty)"}`);
});

test("the /wait long-poll holds the event loop open until its promise settles", () => {
  const r = runInIdleChild(150, false);
  assert.equal(
    r.stdout,
    "SETTLED:200",
    "the wait() promise never settled in an idle process — the long-poll timer does not hold the " +
      "event loop open. In a suite this is invisible (something else always keeps the loop busy) and " +
      "on CI it cancels the test AND every sibling after it. In production it can drop an in-flight " +
      `approval wait. stderr: ${r.stderr || "(empty)"}`,
  );
  assert.equal(r.code, 0, `the idle child exited ${r.code}, not 0`);
});
