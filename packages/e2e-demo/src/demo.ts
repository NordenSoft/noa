/**
 * `npm run demo` — the Instant-Tether GOLDEN DEMO entry point (spec §2).
 *
 * One command, one proven end-to-end flow: a fake agent proposes a HIGH-risk infra action → the gate
 * freezes it → the relay carries it → a headless phone (real §3 pairing + device-key Decision) approves
 * → the gate grants + the exact-execution wrapper runs a harmless command → the §13 Approval Evidence
 * Bundle verifies offline = VALID, and the receipt chain verifies = VALID. Prints the flow, the
 * verdicts (pasted, not summarized), and the measured flow duration.
 */
import { verifyChain } from 'noa-receipt';
import { setupHarness, teardownHarness, runApprovedFlow } from './harness.js';

const FLOW = String.raw`
  ┌─────────┐  1.propose(HIGH infra)   ┌──────────┐  2.freeze+sign HoldEnvelope   ┌──────────┐
  │  AGENT  │ ───────────────────────► │   GATE   │ ────────────────────────────► │  RELAY   │
  │ (guard) │                          │ (signer) │       (untrusted transport)   │ (carries)│
  └─────────┘                          └──────────┘                               └────┬─────┘
       ▲   ▲                                 ▲                                          │ 3.push notify
       │   │ 8.grant→reserve→EXECUTE         │ 7.re-verify(D18)+GRANT+CONSUME+EXECUTED  │    (opaque id)
       │   │    (harmless command)           │                                          ▼
       │   └─────────────────────────────────┤                                    ┌──────────┐
       │           6.forward decision         │◄────── 5.device-signed decision ───│  PHONE   │
       └── verdict ───────────────────────────┘         (relay→gate via bridge)    │ (D2+sign)│
                                                                                    └──────────┘
                                              4.pair (SAS, §3) · D2 verify · sign ALLOWED + Decision
   ═══► Approval Evidence Bundle (§13)  →  noa verify-evidence = VALID  +  verifyChain = VALID
`;

async function main(): Promise<void> {
  process.stdout.write(FLOW + '\n');
  process.stdout.write('── running the golden flow (JSON-line audit log below) ──────────────────────────\n');

  const ctx = await setupHarness({ echo: true });
  try {
    const result = await runApprovedFlow(ctx, 'APPROVE');

    const chain = [result.artifacts.deferredReceipt, result.artifacts.allowedReceipt, result.artifacts.executedReceipt];
    const vc = verifyChain(chain as never[], { keyring: ctx.trust.receiptKeyring, requireTenantConsistency: true });

    process.stdout.write('\n── VERDICTS (pasted from the real verifiers) ────────────────────────────────────\n');
    process.stdout.write('verify-evidence: ' + JSON.stringify({ verdict: result.verdict.verdict, outcome: result.verdict.outcome, steps: result.verdict.steps.length, warnings: result.verdict.warnings.length }) + '\n');
    process.stdout.write('verifyChain:     ' + JSON.stringify({ status: vc.status, count: vc.count }) + '\n');
    process.stdout.write('side-effect ran: ' + JSON.stringify({ ran: result.executeSpy.ran, outputPath: result.executeSpy.outputPath }) + '\n');
    process.stdout.write('flow duration:   ' + result.elapsedMs + ' ms\n');

    const ok = result.verdict.verdict === 'VALID_FULL_CHAIN' && vc.status === 'VALID' && result.guardResult.outcome === 'EXECUTED' && result.executeSpy.ran;
    if (!ok) {
      process.stderr.write('\nDEMO FAILED — verdict not fully VALID.\n');
      process.exitCode = 1;
      return;
    }
    process.stdout.write('\n✔ GOLDEN DEMO: VALID end-to-end (evidence VALID_FULL_CHAIN + chain VALID + side-effect gated by the human).\n');
  } finally {
    await teardownHarness(ctx);
  }
}

main().catch((e) => {
  process.stderr.write('\nDEMO ERROR: ' + (e instanceof Error ? e.stack ?? e.message : String(e)) + '\n');
  process.exitCode = 1;
});
