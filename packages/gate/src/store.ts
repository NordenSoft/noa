/**
 * NOA Gate — storage abstraction (the AUTHORITATIVE state; the wrapper-local record is only a
 * fast-path hint, F8a).
 *
 * `Store` is an interface so the localhost alpha runs on a hermetic in-memory store while a durable
 * driver drops in behind the SAME interface later. The gate's grant record here is the atomic
 * single-use ENFORCER — the CAS UNUSED→RESERVED and the one-shot terminal-report lock both live on
 * this record, never on a client flag.
 */

import type { AgentRecord, GrantRecord, HoldRecord, HoldStatus } from "./types.js";

export interface Store {
  // agents (per-agent API key, F29)
  putAgent(a: AgentRecord): void;
  findAgentByApiKeyHash(hash: string): AgentRecord | undefined;

  // holds
  putHold(h: HoldRecord): void;
  getHold(id: string): HoldRecord | undefined;
  getHoldByIdem(agentId: string, idempotencyKey: string): HoldRecord | undefined;
  listHolds(filter: { status?: HoldStatus; agentId?: string }): HoldRecord[];
  countPending(agentId: string): number;
  /** True iff the agent already has an unresolved (PENDING) hold on this chain (D17). */
  hasPendingOnChain(agentId: string, chain: string): boolean;

  // grants (the atomic single-use record — F8a)
  putGrant(g: GrantRecord): void;
  getGrant(grantId: string): GrantRecord | undefined;
  listGrants(): GrantRecord[];
}

export class InMemoryStore implements Store {
  private readonly agents = new Map<string, AgentRecord>();
  private readonly holds = new Map<string, HoldRecord>();
  private readonly holdsByIdem = new Map<string, string>();
  private readonly grants = new Map<string, GrantRecord>();

  putAgent(a: AgentRecord): void {
    this.agents.set(a.id, a);
  }
  findAgentByApiKeyHash(hash: string): AgentRecord | undefined {
    for (const a of this.agents.values()) if (a.apiKeyHash === hash) return a;
    return undefined;
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
  hasPendingOnChain(agentId: string, chain: string): boolean {
    for (const h of this.holds.values()) {
      if (h.agentId === agentId && h.chain === chain && h.status === "PENDING") return true;
    }
    return false;
  }

  putGrant(g: GrantRecord): void {
    this.grants.set(g.grant.grantId, g);
  }
  getGrant(grantId: string): GrantRecord | undefined {
    return this.grants.get(grantId);
  }
  listGrants(): GrantRecord[] {
    return [...this.grants.values()];
  }
}
