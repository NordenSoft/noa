/**
 * The gate's /wait long-poll must keep the event loop alive until its promise settles.
 *
 * ─── THIS IS THE NEIGHBOUR, AND IT IS WHY THE SWEEP HAPPENED ─────────────────────────────────────
 *
 * The identical defect was found first in `packages/relay/src/engine.ts`: the long-poll timer was
 * `unref()`ed, copied from the background sweeper. An unref'd timer does not hold the event loop
 * open, so Node can decide the loop has drained while a caller is still awaiting, and emits
 * `'Promise resolution is still pending but the event loop has already resolved'`.
 *
 * In relay that cancelled the hanging test AND SIX SIBLINGS via `cancelledByParent` — the
 * tenant-isolation suite — for nine CI runs, silently, because `cancelled` is not `failed`.
 *
 * A repo-wide sweep for the class then found this one. **Fixing a site and not its neighbour produced
 * a CRITICAL in three consecutive releases of this project**, so the sweep is the fix and this file
 * is its evidence here.
 *
 * ⚠ THE STAKES ARE HIGHER ON THIS ROUTE THAN IN RELAY. `wait()` hands back the EXECUTION GRANT on
 * APPROVED. A long-poll that can be dropped is a human's phone waiting on an approval whose answer
 * can never arrive.
 *
 * The sweep's other two results, recorded so the classification is not re-litigated:
 *   • the `server.ts` sweepers (gate, relay, adapter-core session-store) are CORRECTLY unref'd — a
 *     periodic background task has no caller and must not keep the process alive.
 *   • `signer-sidecar/src/client.mjs` is unref'd and SAFE — measured, not reasoned: against a
 *     connected-but-silent server in an otherwise-idle process it rejected after 304ms, because a
 *     connected socket is itself a ref'd handle that keeps the loop alive.
 * The distinction is CALLER-AWAITED vs BACKGROUND, not "timer".
 *
 * ─── WHY A CHILD PROCESS ─────────────────────────────────────────────────────────────────────────
 *
 * Inside a suite there is always something else keeping the loop busy, so this defect is invisible
 * and every local run is green. The only honest test reproduces the condition: an otherwise-idle
 * process whose sole pending work is one `wait()`.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const HERE = dirname(fileURLToPath(import.meta.url));
const HELPERS = join(HERE, "helpers.js");

/** Runs ONE `wait()` in an otherwise-idle process and reports.
 *
 *  `decideFirst` selects the branch:
 *    false → the hold stays PENDING, so only the long-poll's own timer can settle the promise.
 *    true  → already resolved, so `wait()` returns at its fast path and never creates a timer. Same
 *            child, same imports, same build artifacts — the discriminating control. */
function runInIdleChild(timeoutMs: number, decideFirst: boolean): { stdout: string; stderr: string; code: number | null } {
  const script = `
    import { setupGate, signPhoneDecision, sampleCommandParams, body } from ${JSON.stringify(HELPERS)};
    const fx = setupGate({ approverRole: "approve-high" });
    const created = fx.engine.createHold(fx.agent, "idem-idle", body({
      mode: "ENFORCED",
      action: { canonical: "noa.command.exec", riskClass: "HIGH", reversible: false },
      params: sampleCommandParams(),
      chain: "chain-idle",
    }));
    if (created.status !== 201 && created.status !== 200) {
      process.stdout.write("FIXTURE:createHold " + created.status + " " + JSON.stringify(created.body));
    } else {
      const holdId = created.body.holdId;
      if (${decideFirst}) {
        const pending = fx.store.listHolds({ status: "PENDING" }).find((h) => h.id === holdId);
        const { receipt, decisionArtifact } = signPhoneDecision({
          trust: fx.trust, deferredReceipt: pending.deferredReceipt,
          holdEnvelope: pending.holdEnvelope, decision: "APPROVE",
        });
        fx.engine.decide(holdId, body({ receipt, decisionArtifact }));
      }
      // Nobody else will decide this hold, so on the PENDING branch the long-poll's own timer is the
      // only thing that can settle the promise. Nothing else is scheduled in this process.
      const r = await fx.engine.wait(holdId, ${timeoutMs}, fx.agent);
      process.stdout.write("SETTLED:" + r.status);
    }
  `;
  const r = spawnSync(process.execPath, ["--input-type=module", "--eval", script], {
    encoding: "utf8",
    timeout: 30_000,
  });
  return { stdout: (r.stdout ?? "").trim(), stderr: (r.stderr ?? "").trim(), code: r.status };
}

/** CONTROL FIRST — it is what decides whether the test below means anything. If the child cannot
 *  complete a `wait()` that never touches a timer, the fixture is broken and the finding is not one. */
test("CONTROL — an already-decided hold settles in the same idle child (no timer involved)", () => {
  const r = runInIdleChild(150, true);
  assert.equal(r.stdout, "SETTLED:200",
    "FIXTURE BROKEN, NOT A FINDING: the child could not complete a wait() that never touches a " +
      `timer, so the test below would be measuring the harness. stdout: ${r.stdout || "(empty)"} · stderr: ${r.stderr || "(empty)"}`);
});

test("the /wait long-poll holds the event loop open until its promise settles", () => {
  const r = runInIdleChild(150, false);
  assert.equal(
    r.stdout,
    "SETTLED:200",
    "the wait() promise never settled in an idle process — the long-poll timer does not hold the " +
      "event loop open. Invisible inside a suite, and on CI it cancels this test AND every sibling " +
      "after it. On THIS route it means a human's phone waiting on an approval whose answer can " +
      `never arrive. stderr: ${r.stderr || "(empty)"}`,
  );
  assert.equal(r.code, 0, `the idle child exited ${r.code}, not 0`);
});
