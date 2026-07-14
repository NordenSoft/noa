/**
 * Named error taxonomy (enterprise bar): every failure carries a stable code + the protocol LAYER
 * that owns it, so a failed run names exactly where + why it broke. No silent fallback — a driver
 * that cannot positively satisfy a step throws a `DemoError`, it never degrades quietly.
 */

export type DemoLayer =
  | 'PAIRING' // §3 D10-v2 device-pairing ceremony
  | 'PHONE_D2' // §10 D2 pre-render verification on the phone
  | 'PHONE_SIGN' // device-key Decision / receipt signing
  | 'RELAY' // §9 untrusted transport
  | 'GATE' // §8 trusted signer / grant / wrapper
  | 'BRIDGE' // gate↔relay transport connector (this demo's glue; never signs)
  | 'EVIDENCE' // §13 bundle assembly + verify-evidence
  | 'ORCHESTRATION'; // harness wiring / timing / lifecycle

export type DemoErrorCode =
  | 'PAIRING_CHALLENGE_INVALID'
  | 'PAIRING_SAS_MISMATCH'
  | 'PAIRING_CONFIRMATION_REJECTED'
  | 'PAIRING_TRUST_REJECTED'
  | 'D2_DEFERRED_SIG_INVALID'
  | 'D2_ENVELOPE_SIG_INVALID'
  | 'D2_ENVELOPE_BINDING_MISMATCH'
  | 'D2_DISPLAY_BINDING_MISMATCH'
  | 'D2_MANIFEST_ROLLBACK'
  | 'D2_EXPIRED'
  | 'RELAY_DEVICE_REGISTER_FAILED'
  | 'RELAY_AGENT_REGISTER_FAILED'
  | 'RELAY_PUSH_FAILED'
  | 'RELAY_DECISION_REJECTED'
  | 'GATE_HOLD_FAILED'
  | 'GATE_DECISION_REJECTED'
  | 'GATE_UNEXPECTED_STATUS'
  | 'BRIDGE_NO_GATE_HOLD'
  | 'BRIDGE_NO_DECISION'
  | 'EVIDENCE_ASSEMBLY_INCOMPLETE'
  | 'EVIDENCE_VERDICT_UNEXPECTED'
  | 'TIMED_OUT'
  | 'INVARIANT_VIOLATION';

export class DemoError extends Error {
  readonly code: DemoErrorCode;
  readonly layer: DemoLayer;
  readonly detail: Record<string, unknown>;
  constructor(layer: DemoLayer, code: DemoErrorCode, message: string, detail: Record<string, unknown> = {}) {
    super(`[${layer}/${code}] ${message}`);
    this.name = 'DemoError';
    this.layer = layer;
    this.code = code;
    this.detail = detail;
  }
}

/** Bounded poll-until (event/deadline, never a fixed sleep-race): resolve as soon as `probe`
 *  returns a non-undefined value; throw TIMED_OUT at the deadline. `intervalMs` is a poll cadence,
 *  not a latency assumption — the loop returns the instant the condition holds. */
export async function pollUntil<T>(
  probe: () => T | undefined | Promise<T | undefined>,
  opts: { timeoutMs: number; intervalMs?: number; what: string; layer: DemoLayer; code: DemoErrorCode },
): Promise<T> {
  const interval = opts.intervalMs ?? 5;
  const deadline = Date.now() + opts.timeoutMs;
  for (;;) {
    const v = await probe();
    if (v !== undefined) return v;
    if (Date.now() >= deadline) {
      throw new DemoError(opts.layer, opts.code, `poll-until timed out waiting for ${opts.what}`, { timeoutMs: opts.timeoutMs });
    }
    await new Promise((r) => setTimeout(r, interval));
  }
}
