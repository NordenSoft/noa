/**
 * The fake customer AI agent. It proposes a HIGH-risk infra action (the §2 pilot shape:
 * `noa.command.exec`, ENFORCED) through the gate's REAL exact-execution wrapper (`guard`, D3/D14/D18)
 * over loopback HTTP, and — only if a fresh grant is reserved and the exact-execution check passes —
 * runs a HARMLESS side effect (writes a temp file). The wrapper's D14 guarantee is the load-bearing
 * property: approve action A, run action B is impossible; the file is only written for an EXECUTED
 * outcome, proving the human's approval actually gated the side effect.
 */
import { guard, HttpGateClient, type GuardResult, type GateClient } from 'noa-gate';
import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { Logger } from './log.js';

/** The one ENFORCED command the alpha `noa.command.exec/1` adapter binds (D14). Real deploy shape. */
export function deployCommandParams(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    executable: '/usr/local/bin/deploy',
    argv: ['--service', 'api', '--env', 'production'],
    cwd: '/srv/app',
    targetEnv: 'production',
    allowedEnvHash: 'sha256:' + 'a'.repeat(64),
    stdinHash: null,
    ...overrides,
  };
}

/** Records whether the harmless side effect actually ran (proof the gate gated it). */
export interface ExecuteSpy {
  ran: boolean;
  calls: number;
  outputPath: string | null;
}

/** A harmless, idempotent-ish side effect: write a temp file. `ran` flips true iff it executed. */
export function makeHarmlessExecute(log: Logger): { execute: () => Promise<{ ok: boolean; detail?: string }>; spy: ExecuteSpy } {
  const spy: ExecuteSpy = { ran: false, calls: 0, outputPath: null };
  const execute = async (): Promise<{ ok: boolean; detail?: string }> => {
    spy.calls += 1;
    const privateDir = await mkdtemp(join(tmpdir(), 'noa-demo-exec-'));
    const p = join(privateDir, 'result.txt');
    await writeFile(p, `harmless demo side effect at ${new Date().toISOString()}\n`, {
      encoding: 'utf8',
      mode: 0o600,
      flag: 'wx',
    });
    spy.ran = true;
    spy.outputPath = p;
    log.event('agent.harmless_command_ran', { outputPath: p });
    return { ok: true, detail: `wrote ${p}` };
  };
  return { execute, spy };
}

export interface FakeAgentInput {
  gateBaseUrl: string;
  apiKey: string;
  canonical: string;
  riskClass: string;
  params: unknown;
  chain: string;
  idempotencyKey: string;
  waitMs: number;
  execute: () => Promise<{ ok: boolean; detail?: string }>;
  /** Override the transport (scenario e injects a stub grant to exercise the D14 refusal). */
  client?: GateClient;
  log: Logger;
}

/** Run the agent: freeze the action via the gate wrapper and (if approved) execute exactly it. */
export async function runFakeAgent(input: FakeAgentInput): Promise<GuardResult> {
  const client = input.client ?? new HttpGateClient(input.gateBaseUrl, input.apiKey);
  input.log.event('agent.action_proposed', { canonical: input.canonical, riskClass: input.riskClass, chain: input.chain });
  const result = await guard({
    client,
    action: { canonical: input.canonical, riskClass: input.riskClass },
    params: input.params,
    mode: 'ENFORCED',
    chain: input.chain,
    idempotencyKey: input.idempotencyKey,
    waitMs: input.waitMs,
    execute: input.execute,
  });
  input.log.event('agent.guard_result', { outcome: result.outcome, ran: result.ran, holdId: result.holdId, grantId: result.grantId });
  return result;
}
