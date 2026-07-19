/**
 * NOA Relay — storage abstraction.
 *
 * `Store` is an interface so the localhost alpha runs on a hermetic in-memory store (no infra,
 * deterministic tests) while a Railway Postgres driver (FAZ-APP §4.1 schema) drops in behind the
 * SAME interface as the next slice — exactly mirroring the push-provider abstraction. No locked
 * decision (D1–D23) constrains the storage engine; the invariants it must uphold are behavioral
 * (never store a private key, fail-closed on expiry), not engine-specific.
 *
 * NOTE: no method accepts or returns a private key. Only public keys + secret HASHES are stored.
 */

import type {
  AgentRecord,
  DeviceRecord,
  HoldRecord,
  HoldStatus,
  KeyManifestRecord,
  PairingRecord,
  PushSubscriptionRecord,
} from "./types.js";

export interface Store {
  // agents
  putAgent(a: AgentRecord): void;
  getAgentById(id: string): AgentRecord | undefined;
  findAgentByApiKeyHash(hash: string): AgentRecord | undefined;

  // devices
  putDevice(d: DeviceRecord): void;
  getDeviceById(id: string): DeviceRecord | undefined;
  getDeviceByKid(kid: string): DeviceRecord | undefined;
  findDeviceBySecretHash(hash: string): DeviceRecord | undefined;

  // push
  putPush(rec: PushSubscriptionRecord): void;
  listPushForDevice(deviceId: string): PushSubscriptionRecord[];
  listAllDevices(): DeviceRecord[];

  // pairings
  putPairing(p: PairingRecord): void;
  getPairing(token: string): PairingRecord | undefined;

  // holds
  putHold(h: HoldRecord): void;
  getHold(id: string): HoldRecord | undefined;
  getHoldByIdem(agentId: string, idempotencyKey: string): HoldRecord | undefined;
  listHolds(filter: { status?: HoldStatus; agentId?: string }): HoldRecord[];
  countPending(agentId: string): number;

  // manifest (public key material only)
  putManifest(rec: KeyManifestRecord): void;
  getLatestManifest(tenant: string): KeyManifestRecord | undefined;

  /**
   * Optional cleanup hook for a `Store` holding external resources (#63-S3 / D6 — `FileStore`'s
   * exclusive single-process lock file). Purely additive: `InMemoryStore` does not implement it,
   * and `server.ts`'s `close()` calls it defensively via optional chaining (`store.close?.()`), so
   * every existing `InMemoryStore`-backed caller/test is unaffected.
   */
  close?(): void;
}

export class InMemoryStore implements Store {
  private readonly agents = new Map<string, AgentRecord>();
  private readonly devices = new Map<string, DeviceRecord>();
  private readonly devicesByKid = new Map<string, string>();
  private readonly push = new Map<string, PushSubscriptionRecord>();
  private readonly pairings = new Map<string, PairingRecord>();
  private readonly holds = new Map<string, HoldRecord>();
  private readonly holdsByIdem = new Map<string, string>();
  private readonly manifests = new Map<string, KeyManifestRecord>();

  putAgent(a: AgentRecord): void {
    this.agents.set(a.id, a);
  }
  getAgentById(id: string): AgentRecord | undefined {
    return this.agents.get(id);
  }
  findAgentByApiKeyHash(hash: string): AgentRecord | undefined {
    for (const a of this.agents.values()) if (a.apiKeyHash === hash) return a;
    return undefined;
  }

  putDevice(d: DeviceRecord): void {
    this.devices.set(d.id, d);
    this.devicesByKid.set(d.kid, d.id);
  }
  getDeviceById(id: string): DeviceRecord | undefined {
    return this.devices.get(id);
  }
  getDeviceByKid(kid: string): DeviceRecord | undefined {
    const id = this.devicesByKid.get(kid);
    return id ? this.devices.get(id) : undefined;
  }
  findDeviceBySecretHash(hash: string): DeviceRecord | undefined {
    for (const d of this.devices.values()) if (d.deviceSecretHash === hash) return d;
    return undefined;
  }

  putPush(rec: PushSubscriptionRecord): void {
    this.push.set(rec.deviceId, rec);
  }
  listPushForDevice(deviceId: string): PushSubscriptionRecord[] {
    const r = this.push.get(deviceId);
    return r ? [r] : [];
  }
  listAllDevices(): DeviceRecord[] {
    return [...this.devices.values()];
  }

  putPairing(p: PairingRecord): void {
    this.pairings.set(p.token, p);
  }
  getPairing(token: string): PairingRecord | undefined {
    return this.pairings.get(token);
  }

  private idemKey(agentId: string, idempotencyKey: string): string {
    return `${agentId.length}:${agentId}:${idempotencyKey}`;
  }
  putHold(h: HoldRecord): void {
    this.holds.set(h.id, h);
    this.holdsByIdem.set(this.idemKey(h.agentId, h.idempotencyKey), h.id);
  }
  getHold(id: string): HoldRecord | undefined {
    return this.holds.get(id);
  }
  getHoldByIdem(agentId: string, idempotencyKey: string): HoldRecord | undefined {
    const id = this.holdsByIdem.get(this.idemKey(agentId, idempotencyKey));
    return id ? this.holds.get(id) : undefined;
  }
  listHolds(filter: { status?: HoldStatus; agentId?: string }): HoldRecord[] {
    const out: HoldRecord[] = [];
    for (const h of this.holds.values()) {
      if (filter.status && h.status !== filter.status) continue;
      if (filter.agentId && h.agentId !== filter.agentId) continue;
      out.push(h);
    }
    return out;
  }
  countPending(agentId: string): number {
    let n = 0;
    for (const h of this.holds.values()) if (h.agentId === agentId && h.status === "PENDING") n++;
    return n;
  }

  putManifest(rec: KeyManifestRecord): void {
    const cur = this.manifests.get(rec.tenant);
    if (!cur || rec.version >= cur.version) this.manifests.set(rec.tenant, rec);
  }
  getLatestManifest(tenant: string): KeyManifestRecord | undefined {
    return this.manifests.get(tenant);
  }

  /**
   * Test/introspection helper: a plain-object dump of EVERYTHING the relay persists. Used by
   * test/engine-nosign.test.ts to prove no private-key material is ever at rest. Only public keys
   * + secret HASHES may appear here.
   */
  dump(): Record<string, unknown> {
    return {
      agents: [...this.agents.values()],
      devices: [...this.devices.values()],
      push: [...this.push.values()],
      pairings: [...this.pairings.values()],
      holds: [...this.holds.values()],
      manifests: [...this.manifests.values()],
    };
  }
}
