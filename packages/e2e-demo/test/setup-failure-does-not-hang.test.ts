/**
 * PERMANENT REGRESSION — a failing setup must FAIL, not HANG.
 *
 * MEASURED 2026-07-31. `setupHarness()` starts the gate and relay listening, then runs the relay
 * onboarding. Every caller is shaped
 *
 *     const ctx = await setupHarness();  try { … } finally { await teardownHarness(ctx); }
 *
 * so the `finally` only exists AFTER setup returns. When the R8-07 enrolment change made
 * `registerRelayDevice` answer 503, setup threw with two sockets already listening and nobody
 * holding a reference to close them — and Node cannot exit while a server is listening.
 *
 * The demo did not fail. It HUNG. Eight such processes accumulated at 0.0% CPU holding 42 listening
 * sockets, up to 2h20m each, and I reported them to the owner as "running", because from outside a
 * hang and slow work look identical. A failure that presents as a hang is worse than a crash: a
 * crash names itself.
 *
 * This test pins the property that makes that impossible: setup either returns a usable context, or
 * throws AND leaves nothing listening.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { setupHarness, teardownHarness } from '../src/harness.js';

/**
 * Count listening handles this process still owns. `_getActiveHandles` is internal, which is exactly
 * why it is right here: the property under test is "Node would not be able to exit", and the active
 * handle set IS that property. Asserting on ports or on a timeout would measure something adjacent.
 */
function listeningHandles(): number {
  const handles = (process as unknown as { _getActiveHandles(): Array<{ listening?: boolean }> })._getActiveHandles();
  let n = 0;
  for (const h of handles) if (h && h.listening === true) n += 1;
  return n;
}

test('a setup that throws leaves NOTHING listening — the demo fails instead of hanging', async () => {
  const before = listeningHandles();

  // Force the exact failure that produced the hang: the relay refuses enrolment, so
  // `registerRelayDevice` throws AFTER both servers are already listening.
  //
  // `setupHarness` takes no config hook, so the failure is injected where the real one occurred —
  // at the network boundary. `fetch` is replaced for the duration and restored in `finally`, so a
  // failure inside the assertion cannot leave the process patched for other tests.
  const realFetch = globalThis.fetch;
  let threw = false;
  try {
    globalThis.fetch = (async (input: unknown, init?: unknown) => {
      const url = String(input);
      if (url.includes('/v1/devices')) {
        return new Response(JSON.stringify({ error: 'ENROLMENT_NOT_CONFIGURED' }), {
          status: 503,
          headers: { 'content-type': 'application/json' },
        });
      }
      return realFetch(input as Parameters<typeof fetch>[0], init as Parameters<typeof fetch>[1]);
    }) as typeof fetch;

    await assert.rejects(
      () => setupHarness({ echo: false }),
      'setup must PROPAGATE the failure — swallowing it is how a broken demo reports success',
    );
    threw = true;
  } finally {
    globalThis.fetch = realFetch;
  }

  assert.equal(threw, true, 'precondition: the injected 503 really did make setup fail');

  // THE PROPERTY. Before the fix this was `before + 2` — the gate and the relay, still listening,
  // unreferenced, keeping the process alive forever.
  assert.equal(
    listeningHandles(),
    before,
    'setupHarness threw and left a listening socket behind — the process can no longer exit, which ' +
      'is the hang that was reported as "running" for two hours',
  );
});

test('ANTI-VACUITY: a SUCCESSFUL setup does listen, and teardown closes it', async () => {
  // Without this, the test above would pass on a harness that never starts a server at all — it
  // would be asserting that nothing leaked from something that never ran.
  const before = listeningHandles();

  const ctx = await setupHarness({ echo: false });
  const during = listeningHandles();
  assert.ok(
    during > before,
    `a successful setup must actually be listening (before=${before} during=${during}) — otherwise ` +
      'the leak assertion above is measuring nothing',
  );

  await teardownHarness(ctx);
  assert.equal(listeningHandles(), before, 'teardown must close everything setup opened');
});
