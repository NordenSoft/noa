/**
 * S2 — a store that behaves like a DURABLE driver, so the single-use claim can be tested at all.
 *
 * WHY THIS EXISTS. `InMemoryStore.getGrant` returns the LIVE object out of its map, so
 * `rec.status = "RESERVED"` mutates the store before `putGrant` is even called. Under that driver a
 * read-compare-write and a compare-and-swap are INDISTINGUISHABLE — every single-use test passes
 * either way. That is precisely how "atomic single-use" stayed a property of one driver while
 * reading, in `engine.ts` and in the docs, like a property of the gate. `store.ts`'s own header had
 * said so since 2026-07-31 and nothing could demonstrate it.
 *
 * `DetachedStore` changes exactly ONE thing: reads return a DETACHED COPY. Nothing else is
 * adversarial — no delays, no reordering, no injected failures. Every durable driver behaves this
 * way, because a row fetched from a database is not the row. That single change is enough to make
 * the old code visibly wrong and the new code visibly right, which is the point: the defect was
 * never exotic, it was invisible.
 *
 * The compare-and-swap methods are implemented the way a real driver implements them — as ONE
 * indivisible step against the authoritative state, the shape of
 * `UPDATE ... WHERE id = $1 AND status = $2 RETURNING *`. A driver that implemented them as
 * read-then-write would have reintroduced exactly the defect they replaced, so this file must not
 * be "simplified" into doing that.
 */

import { InMemoryStore } from "../src/store.js";
import type { Store } from "../src/store.js";
import type { AgentRecord, GrantRecord, GrantStatus, HoldRecord, HoldStatus } from "../src/types.js";

/** A structural copy deep enough that no caller can reach the stored object through the result. */
function detach<T>(value: T): T {
  return structuredClone(value);
}

export class DetachedStore implements Store {
  private readonly inner = new InMemoryStore();
  /** Every CAS attempt, won or lost — so a test can assert the engine went through the primitive. */
  readonly casAttempts: Array<{ kind: "status" | "reported"; grantId: string; won: boolean }> = [];

  /**
   * CONCURRENCY, modelled honestly. `reserve()` is synchronous, so calling it twice in a row is not
   * a race — the first call finishes writing before the second starts reading, and a
   * read-compare-write survives that. My first version of the racing test made exactly that mistake
   * and passed against the defective engine; it claimed more than its body proved.
   *
   * What two PROCESSES actually do is read before either has written. `pinReads()` reproduces that
   * and nothing else: while pinned, every `getGrant` answers from the snapshot taken at the pin,
   * however many writes have landed since. Writes still go through to the authoritative state — so a
   * CAS, which asks the authoritative state, still sees the truth, while a read-compare-write, which
   * trusts what it was handed, does not. That asymmetry IS the defect, and it is the only thing this
   * mode introduces.
   */
  private pinnedGrants: Map<string, GrantRecord> | null = null;
  pinReads(): void {
    this.pinnedGrants = new Map(this.inner.listGrants().map((g) => [g.grant.grantId, detach(g)]));
  }
  unpinReads(): void {
    this.pinnedGrants = null;
  }

  putAgent(a: AgentRecord): void { this.inner.putAgent(detach(a)); }
  findAgentByApiKeyHash(hash: string): AgentRecord | undefined {
    const found = this.inner.findAgentByApiKeyHash(hash);
    return found ? detach(found) : undefined;
  }

  putHold(h: HoldRecord): void { this.inner.putHold(detach(h)); }
  getHold(id: string): HoldRecord | undefined {
    const found = this.inner.getHold(id);
    return found ? detach(found) : undefined;
  }
  getHoldByIdem(agentId: string, idempotencyKey: string): HoldRecord | undefined {
    const found = this.inner.getHoldByIdem(agentId, idempotencyKey);
    return found ? detach(found) : undefined;
  }
  listHolds(filter: { status?: HoldStatus; agentId?: string }): HoldRecord[] {
    return this.inner.listHolds(filter).map(detach);
  }
  countPending(agentId: string): number { return this.inner.countPending(agentId); }
  hasPendingOnChain(agentId: string, chain: string): boolean { return this.inner.hasPendingOnChain(agentId, chain); }

  putGrant(g: GrantRecord): void { this.inner.putGrant(detach(g)); }
  getGrant(grantId: string): GrantRecord | undefined {
    // While pinned, a reader sees what it would have seen had it read at the same moment as the
    // other caller — the whole point being that a WRITE by the other caller does not retroactively
    // change what this one was handed. The CAS methods below deliberately DO NOT consult the pin:
    // an `UPDATE ... WHERE status = $expected` is evaluated by the database against the row as it
    // is now, never against whatever the client last read.
    if (this.pinnedGrants) {
      const pinned = this.pinnedGrants.get(grantId);
      return pinned ? detach(pinned) : undefined;
    }
    const found = this.inner.getGrant(grantId);
    return found ? detach(found) : undefined;
  }
  listGrants(): GrantRecord[] { return this.inner.listGrants().map(detach); }

  claimGrantStatus(grantId: string, expected: GrantStatus, next: GrantStatus, at: number): GrantRecord | null {
    // ONE indivisible step against the authoritative state — the shape of a single UPDATE ... WHERE.
    const won = this.inner.claimGrantStatus(grantId, expected, next, at);
    this.casAttempts.push({ kind: "status", grantId, won: won !== null });
    return won ? detach(won) : null;
  }

  claimGrantReported(grantId: string, at: number): GrantRecord | null {
    const won = this.inner.claimGrantReported(grantId, at);
    this.casAttempts.push({ kind: "reported", grantId, won: won !== null });
    return won ? detach(won) : null;
  }
}
