/**
 * The clients that talk to the untrusted §9 relay over REAL loopback HTTP.
 *
 *  - `registerRelayAgent` / `registerRelayDevice` — onboarding (the relay mints an opaque agent
 *    API key + an opaque device secret; only sha256 hashes are stored relay-side).
 *  - `PhoneRelayClient` — the approver device's transport: poll the inbox (opaque summaries only,
 *    Red Line 11), fetch the encrypted-display ciphertext, POST the device-signed decision.
 *  - `GateRelayBridge` — the transport CONNECTOR that in production is the gate's built-in relay
 *    client (not yet a shipped package): it pushes the gate-signed hold onto the relay and reads the
 *    phone's decision back. It holds NO key and produces NO signature — it only moves already-signed
 *    bytes (Red Line 3). Every artifact it carries was signed by the gate or the phone.
 *
 * NOTE (honest alpha residual): the relay's DEVICE-facing API serves the inbox summary + the
 * encrypted display, but not yet a "GET full signed hold context" endpoint — so the phone reads the
 * gate-signed Hold Envelope + DEFERRED receipt from what the relay CARRIED (its stored record) and
 * independently verifies every gate signature (transport is untrusted by design). See README.
 */
import { DemoError } from './errors.js';
import type { Logger } from './log.js';

type J = Record<string, unknown>;

async function postJson(url: string, body: unknown, headers: Record<string, string> = {}): Promise<{ status: number; body: J | null }> {
  const res = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body: JSON.stringify(body) });
  const parsed = (await res.json().catch(() => null)) as J | null;
  return { status: res.status, body: parsed };
}
async function getJson(url: string, headers: Record<string, string> = {}): Promise<{ status: number; body: J | null }> {
  const res = await fetch(url, { headers });
  const parsed = (await res.json().catch(() => null)) as J | null;
  return { status: res.status, body: parsed };
}

/** Onboard a transport agent (bridge) with the relay: pairing token → redeem → opaque API key. */
export async function registerRelayAgent(relayUrl: string, name: string): Promise<{ agentId: string; apiKey: string }> {
  const pair = await postJson(`${relayUrl}/v1/pairings`, {});
  const token = pair.body?.['token'];
  if (pair.status !== 201 || typeof token !== 'string') {
    throw new DemoError('RELAY', 'RELAY_AGENT_REGISTER_FAILED', 'could not create a relay pairing token', { status: pair.status });
  }
  const redeem = await postJson(`${relayUrl}/v1/pair`, { token, name });
  const apiKey = redeem.body?.['apiKey'];
  const agentId = redeem.body?.['agentId'];
  if (redeem.status !== 200 || typeof apiKey !== 'string' || typeof agentId !== 'string') {
    throw new DemoError('RELAY', 'RELAY_AGENT_REGISTER_FAILED', 'could not redeem the relay pairing token', { status: redeem.status });
  }
  return { agentId, apiKey };
}

/** Register the approver device's PUBLIC key (raw hex) with the relay. */
export async function registerRelayDevice(relayUrl: string, kid: string, publicKeyHex: string): Promise<{ deviceId: string; deviceSecret: string }> {
  const res = await postJson(`${relayUrl}/v1/devices`, { kid, publicKeyHex, custodyTier: 'software-native' });
  const deviceId = res.body?.['deviceId'];
  const deviceSecret = res.body?.['deviceSecret'];
  if (res.status !== 201 || typeof deviceId !== 'string' || typeof deviceSecret !== 'string') {
    throw new DemoError('RELAY', 'RELAY_DEVICE_REGISTER_FAILED', 'could not register the device with the relay', { status: res.status });
  }
  return { deviceId, deviceSecret };
}

export interface InboxHold {
  holdId: string;
  canonical: string;
  riskClass: string;
  paramsHash: string;
  expiresAt: string;
}

/** The approver device's transport client (device-authenticated). */
export class PhoneRelayClient {
  constructor(private readonly relayUrl: string, private readonly deviceSecret: string, private readonly log: Logger) {}

  private auth(): Record<string, string> {
    return { authorization: `Bearer ${this.deviceSecret}` };
  }

  /** Poll the inbox; returns the pending holds (opaque summaries only). */
  async pollInbox(): Promise<InboxHold[]> {
    const res = await getJson(`${this.relayUrl}/v1/holds?status=pending`, this.auth());
    if (res.status !== 200) throw new DemoError('RELAY', 'RELAY_DECISION_REJECTED', 'inbox poll failed', { status: res.status });
    const holds = (res.body?.['holds'] ?? []) as InboxHold[];
    return holds;
  }

  /** Fetch the encrypted-display ciphertext the relay carried (never plaintext). */
  async getDisplay(holdId: string): Promise<J> {
    const res = await getJson(`${this.relayUrl}/v1/holds/${encodeURIComponent(holdId)}/display`, this.auth());
    if (res.status !== 200 || !res.body) throw new DemoError('RELAY', 'RELAY_DECISION_REJECTED', 'display fetch failed', { status: res.status });
    return res.body;
  }

  /** POST the device-signed decision. The relay verifies the receipt signature against the
   *  registered device PUBLIC key (transport filter) and stores it; it NEVER creates a receipt. */
  async postDecision(holdId: string, decision: { receipt: unknown; decisionArtifact: unknown }): Promise<{ status: number; body: J | null }> {
    const res = await postJson(`${this.relayUrl}/v1/holds/${encodeURIComponent(holdId)}/decision`, decision, this.auth());
    this.log.event('relay.decision_posted', { relayHoldId: holdId, status: res.status });
    return res;
  }
}

/** The gate↔relay transport connector. Holds no key; signs nothing; moves signed bytes only. */
export class GateRelayBridge {
  constructor(private readonly relayUrl: string, private readonly apiKey: string, private readonly log: Logger) {}

  private auth(idempotencyKey?: string): Record<string, string> {
    return { authorization: `Bearer ${this.apiKey}`, ...(idempotencyKey ? { 'idempotency-key': idempotencyKey } : {}) };
  }

  /** Carry a gate-signed hold onto the relay (envelope + deferred + encrypted display). The relay
   *  integrity-checks the encrypted display against the envelope's `displayCiphertextHash` (F2). */
  async pushHold(
    idempotencyKey: string,
    payload: { action: { canonical: string; riskClass: string; paramsHash: string }; holdEnvelope: unknown; deferredReceipt: unknown; encryptedDisplay: unknown },
  ): Promise<string> {
    const res = await postJson(`${this.relayUrl}/v1/holds`, payload, this.auth(idempotencyKey));
    const holdId = res.body?.['holdId'];
    if ((res.status !== 201 && res.status !== 200) || typeof holdId !== 'string') {
      throw new DemoError('BRIDGE', 'RELAY_PUSH_FAILED', 'could not push the gate hold onto the relay', { status: res.status, body: res.body });
    }
    this.log.event('bridge.hold_carried_to_relay', { relayHoldId: holdId, canonical: payload.action.canonical });
    return holdId;
  }

  /** Read the phone's decision from the relay (routing view). Returns undefined until decided. */
  async readDecision(relayHoldId: string): Promise<{ decisionReceipt: unknown; decisionArtifact: unknown } | undefined> {
    const res = await getJson(`${this.relayUrl}/v1/holds/${encodeURIComponent(relayHoldId)}`, this.auth());
    if (res.status !== 200 || !res.body) return undefined;
    const status = res.body['status'];
    const decisionReceipt = res.body['decisionReceipt'];
    if ((status === 'APPROVED' || status === 'DENIED') && decisionReceipt) {
      return { decisionReceipt, decisionArtifact: res.body['decisionArtifact'] ?? null };
    }
    return undefined;
  }
}
