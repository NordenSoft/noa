/**
 * Test helpers — build REAL keypairs + REAL signed receipts with `noa-signer`, so the relay's
 * transport-level verify is exercised against genuine Ed25519 signatures (not stubs). This is
 * also the proof that the relay's preimage matches what the phone/noa-receipt sign.
 */

import {
  generateKeyPair,
  buildReceipt,
  spkiEd25519ToRawPublicKey,
  bytesToHex,
  type Receipt,
} from "noa-signer";
import { InMemoryStore, type Store } from "../src/store.js";
import { NoopLogPushProvider } from "../src/push.js";
import { resolveConfig, type RelayConfig } from "../src/config.js";
import { RelayEngine } from "../src/engine.js";
import type { AgentRecord, DeviceRecord } from "../src/types.js";

export const PARAMS_HASH = "sha256:" + "a".repeat(64);

export interface Clock {
  t: number;
}

export interface Harness {
  clock: Clock;
  config: RelayConfig;
  /** Typed against the `Store` interface (not the `InMemoryStore` class) so #63-S3 store-contract
   * tests can parametrize the SAME harness helpers (makeAgent/makeDevice/...) over any `Store`
   * implementation (e.g. `FileStore`). Default construction still uses `InMemoryStore` (see below),
   * so every existing test is unaffected; only `test/engine-nosign.test.ts`'s introspection-only
   * `dump()` calls need an explicit `InMemoryStore` cast, since `dump()` is not part of `Store`. */
  store: Store;
  push: NoopLogPushProvider;
  engine: RelayEngine;
  /**
   * Every structured log event the engine emitted, in order.
   *
   * ADDED 2026-07-30, because the log surface had NO assertions anywhere in the suite. Blind
   * transport narrowed four published surfaces and each one is pinned by a test; the two `this.log`
   * lines carrying the same information were pinned by nothing, so the rule held on the routes
   * somebody remembered to check. `makeHarness` previously passed no `log` at all, which made the
   * sink a no-op and the omission invisible.
   *
   * Purely additive: the engine treats `log` as optional and every existing caller ignores this
   * field. Collecting is not asserting — what it buys is that a test CAN now assert, and
   * `blind-transport-log.test.ts` does.
   */
  logs: Array<{ event: string; fields: Record<string, unknown> }>;
}

export function makeHarness(overrides: Partial<RelayConfig> = {}, storeOverride?: Store): Harness {
  const clock: Clock = { t: 1_700_000_000_000 };
  // R8-07: enrolment is CLOSED by default in production, so a test harness that mints credentials
  // has to say so. Declared here once, visibly, rather than inherited from a bind address —
  // `overrides` can still turn it off to exercise the refusal itself.
  const config = resolveConfig({ now: () => clock.t, allowAnonymousEnrolment: true, ...overrides });
  const store = storeOverride ?? new InMemoryStore();
  const push = new NoopLogPushProvider();
  const logs: Array<{ event: string; fields: Record<string, unknown> }> = [];
  const engine = new RelayEngine({
    store,
    push,
    config,
    log: (event, fields) => {
      logs[logs.length] = { event, fields };
    },
  });
  return { clock, config, store, push, engine, logs };
}

/** Register an agent through the real pairing flow; return the AgentRecord + its api key. */
/**
 * Register an agent through the real pairing flow.
 *
 * `tenant` (R8-11) is carried on the OPERATOR-ISSUED pairing token and is the scope the redeemed
 * agent may publish a key manifest for. It defaults to `null`, which FAILS CLOSED — an agent whose
 * tenant nobody declared cannot publish at all. That default is deliberate: it means a test must
 * say out loud which tenant it is acting for, so a new manifest test cannot accidentally inherit a
 * permissive scope the way `?? "default"` used to hand one out.
 */
export function makeAgent(
  h: Harness,
  name = "test-agent",
  tenant: string | null = null,
): { agent: AgentRecord; apiKey: string } {
  const pair = bodyOf<{ token: string }>(h.engine.createPairing({ tenant }));
  const red = bodyOf<{ agentId: string; apiKey: string }>(
    h.engine.redeemPairing({ token: pair.token, name }),
  );
  const agent = h.store.getAgentById(red.agentId);
  if (!agent) throw new Error("agent not stored");
  return { agent, apiKey: red.apiKey };
}

/** Shorthand for the common manifest-test shape: an agent scoped to exactly the tenant under test. */
export function agentForTenant(h: Harness, tenant: string): AgentRecord {
  return makeAgent(h, `agent-${tenant}`, tenant).agent;
}

export interface TestDevice {
  device: DeviceRecord;
  deviceSecret: string;
  kid: string;
  publicKeyHex: string;
  privateKey: string;
}

/**
 * Register a device with a real Ed25519 keypair AND bind it to an agent; return record + private key.
 *
 * `agent` IS REQUIRED, and that is the point. Enrolment proves possession of a keypair; it proves
 * nothing about whose approvals the device may see. An unclaimed device can read and decide nothing,
 * so a test that forgets to bind one is testing an inert object. Making the parameter required means
 * the COMPILER finds every call site rather than leaving 20 suites silently exercising a device that
 * happens to work by accident.
 *
 * Pass `claim: false` to get a genuinely unclaimed device — that is what the cross-customer tests use.
 */
export function makeDevice(
  h: Harness,
  agent: AgentRecord,
  kid = "approver-1",
  seedByte = 7,
  opts: { claim?: boolean } = {},
): TestDevice {
  const kp = generateKeyPair(kid, new Uint8Array(32).fill(seedByte));
  const publicKeyHex = bytesToHex(spkiEd25519ToRawPublicKey(kp.publicKey));
  const reg = bodyOf<{ deviceId: string; deviceSecret: string }>(
    h.engine.registerDevice({ kid, publicKeyHex }),
  );
  if (opts.claim !== false) {
    const claimed = h.engine.claimDevice(agent, reg.deviceId);
    if (claimed.status !== 200) throw new Error(`claimDevice failed: ${JSON.stringify(claimed.body)}`);
  }
  const device = h.store.getDeviceById(reg.deviceId);
  if (!device) throw new Error("device not stored");
  return { device, deviceSecret: reg.deviceSecret, kid, publicKeyHex, privateKey: kp.privateKey };
}

/** Build a REAL signed ALLOWED/BLOCKED decision receipt for a given action, by a device key. */
/**
 * ⚠ `prev` IS THE HOLD'S DEFERRED RECEIPT, AND OMITTING IT IS NOW A REFUSED DECISION (P1-4/R8-14).
 *
 * This helper used to build every decision with `prev = null` — a genesis receipt chained onto
 * nothing. **That is not what the shipping phone sends:** `noa-mobile/src/transport/decision.ts:82-83`
 * passes the hold's deferred receipt, so a real decision always carries `chain.prevHash`.
 *
 * The drift mattered. Binding a decision to `(canonical, paramsHash)` alone let an approval of hold A
 * be accepted on hold B — and this fixture could not see it, because it never produced the field the
 * binding needed. **A fixture that is weaker than its client tests a system nobody runs.**
 */
export function signDecisionReceipt(opts: {
  kid: string;
  privateKey: string;
  canonical: string;
  paramsHash: string;
  verdict: "ALLOWED" | "BLOCKED";
  chain?: string;
  ts?: string;
  /** The hold's deferred receipt. Omit ONLY to exercise the unchained-decision refusal. */
  prev?: Receipt | null;
}): Receipt {
  const ts = opts.ts ?? "2026-07-14T12:00:00.000Z";
  return buildReceipt(
    {
      id: "rcpt-" + opts.verdict.toLowerCase(),
      ts,
      scope: { chain: opts.chain ?? "chain-test-1" },
      agent: { id: "approver-device", model: null, principal: "HUMAN" },
      action: {
        id: "act-1",
        canonical: opts.canonical,
        riskClass: "HIGH",
        paramsHash: opts.paramsHash,
        reversible: false,
        rollbackRef: null,
      },
      governance: {
        mode: "approvals_on",
        verdict: opts.verdict,
        sandboxed: false,
        approval: { by: opts.kid, at: ts },
      },
    },
    opts.prev ?? null,
    { kid: opts.kid, privateKey: opts.privateKey },
  );
}

export function bodyOf<T>(r: { status: number; body: unknown }): T {
  return r.body as T;
}
