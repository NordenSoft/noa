/**
 * Test harness for the gate: a controllable clock, an alpha trust root, a registered agent, a
 * TEST-ONLY display sealer, and a "phone" that signs the ALLOWED/BLOCKED verdict receipt + the
 * noa.decision/0.1 Decision Artifact exactly as the real approver device would.
 */

import { buildReceipt, type Receipt } from "noa-receipt";
import { signArtifact, refHash, canonicalize, sha256Prefixed } from "noa-approval-artifacts";
import { GateEngine, type DisplaySealer } from "../src/engine.js";
import { resolveGateConfig, type GateConfig } from "../src/config.js";
import { createAlphaTrust, type GateTrust } from "../src/trust.js";
import { InMemoryStore, type Store } from "../src/store.js";
import { hashSecret } from "../src/auth.js";
import { loadSchemas } from "../src/schemas.js";
import type { AgentRecord, HoldEnvelope } from "../src/types.js";
import { b } from "./helpers/bytes.js";

/**
 * A REQUEST BODY, as bytes (ADR-0005 Slice 1 — `createHold`/`decide`/`report` take `Uint8Array`).
 *
 * KURAL 5: this is the SAME encoder as `b()`, re-exported under the name a request body reads as. A
 * second `TextEncoder` here would be a second answer to "what are these bytes", which is the whole
 * class of defect this slice closes — so `body` and `b` are one function, not two.
 */
export { b, b as body } from "./helpers/bytes.js";

/** A mutable clock so timeout + uncertainty-sweep windows are deterministically testable. */
export interface Clock {
  t: number;
  advance(ms: number): void;
}
export function makeClock(start = Date.parse("2026-07-14T12:00:00Z")): Clock {
  const c: Clock = { t: start, advance: (ms: number) => { c.t += ms; } };
  return c;
}

/**
 * TEST-ONLY sealer. It produces a STRUCTURALLY-valid noa.encrypted-display/0.1 object so the gate
 * can bind it via `displayCiphertextHash` (F2). It does NOT perform real HPKE — the real sealer is
 * @noa/signer, injected in production (KURAL 5: the gate never reimplements HPKE and never fakes it
 * in `src/`). This lives in TEST code only, exercising the BINDING, not encryption.
 */
export const testSealer: DisplaySealer = ({ tenant, holdId, deferredReceiptHash, expiresAt, display, recipients }) => ({
  spec: "noa.encrypted-display/0.1",
  tenant,
  holdId,
  deferredReceiptHash,
  expiresAt,
  suite: { kem: 32, kdf: 1, aead: 3 },
  payload: { nonce: "AAAAAAAAAAAAAAAA", ciphertext: Buffer.from(JSON.stringify(display), "utf8").toString("base64") },
  recipients: recipients.map((r) => ({ kid: r.kid, enc: "ZW5jYXBzdWxhdGVk", wrappedCek: "d3JhcHBlZC1jZWs" })),
  aadHash: sha256Prefixed(canonicalize({ tenant, holdId, deferredReceiptHash, expiresAt })),
});

/**
 * The alpha/test configuration is the ONLY one in which the gate process holds the approver's
 * private half — `createAlphaTrust` refuses to generate it once the grant signer is external. This
 * accessor is where that assumption is stated once and checked, so a fixture built the other way
 * fails loudly here instead of type-erroring in nine test files.
 */
export function alphaPhoneSigner(trust: GateTrust): { kid: string; privateKey: string } {
  const privateKey = trust.approver.privateKey;
  if (!privateKey) {
    throw new Error("alphaPhoneSigner: this trust root holds no approver private key — it was built with an ENROLLED approver public key, which is the production posture. Simulate the phone with the key you enrolled.");
  }
  return { kid: trust.approver.kid, privateKey };
}

export interface GateFixture {
  clock: Clock;
  trust: GateTrust;
  store: Store;
  engine: GateEngine;
  agent: AgentRecord;
  apiKey: string;
}

export function setupGate(opts: {
  approverRole?: "approve-high" | "approve-critical";
  config?: Partial<GateConfig>;
  /** ADR-0005 M5 / G5. The sealer is INJECTED in production, so a test must be able to inject a
   *  wrong one — that is the whole threat: the gate asks for a display bound to THIS hold and signs
   *  whatever comes back. Defaults to `testSealer`, so every existing call site is unchanged. */
  sealer?: DisplaySealer;
  /**
   * S2. The store is INJECTED in production too, so a test must be able to supply one that behaves
   * like a DURABLE driver rather than like an in-process map — above all one that does NOT hand out
   * live objects. Without this the single-use compare-and-swap cannot be tested at all: against
   * `InMemoryStore` a read-compare-write and a CAS are indistinguishable, which is exactly how
   * "atomic single-use" stayed a property of one driver while reading like a property of the gate.
   * Defaults to `InMemoryStore`, so every existing call site is unchanged.
   */
  store?: Store;
} = {}): GateFixture {
  const clock = makeClock();
  const now = () => clock.t;
  let seq = 0;
  const ids = () => `id-${(seq++).toString(16).padStart(8, "0")}`;
  const trust = createAlphaTrust({ tenant: "alpha-tenant", now, ...(opts.approverRole ? { approverRole: opts.approverRole } : {}), ids });
  const store = opts.store ?? new InMemoryStore();
  const apiKey = "noa_gateagent_test-secret-abc123";
  const agent: AgentRecord = { id: "agent-1", name: "test-agent", apiKeyHash: hashSecret(apiKey), createdAt: now() };
  store.putAgent(agent);
  const config = resolveGateConfig({ now, ...(opts.config ?? {}) });
  // The fixture is the DEVELOPMENT posture and now has to say so: the engine refuses to hold a
  // grant key without an explicit acknowledgement (adversarial review 2026-08-12, finding 9).
  const engine = new GateEngine({ store, config, trust, schemas: loadSchemas(), sealDisplay: opts.sealer ?? testSealer, unsafeInProcessGrantKey: true });
  return { clock, trust, store, engine, agent, apiKey };
}

/**
 * The phone: builds the ALLOWED/BLOCKED verdict receipt (chaining onto the DEFERRED) + the signed
 * Decision Artifact, both under the approver device key. Mirrors what the real PWA produces (D18: no
 * ticket, no grant — only a Decision Artifact + a verdict receipt).
 */
export function signPhoneDecision(args: {
  trust: GateTrust;
  deferredReceipt: Receipt;
  holdEnvelope: HoldEnvelope;
  decision: "APPROVE" | "DENY";
  reasonCode?: "vendor-verified" | "suspicious" | "other" | null;
  at?: string;
  /** The phone's key. Defaults to the alpha in-process pair; a test running the PRODUCTION posture
   *  (approver enrolled by public key only) passes the key it kept for itself. */
  signer?: { kid: string; privateKey: string };
}): { receipt: Receipt; decisionArtifact: Record<string, unknown> } {
  const { trust, deferredReceipt, holdEnvelope } = args;
  const phone = args.signer ?? alphaPhoneSigner(trust);
  const at = args.at ?? new Date(trust.now()).toISOString();
  const verdict = args.decision === "APPROVE" ? "ALLOWED" : "BLOCKED";
  const ruleId = args.decision === "APPROVE" ? "human-approved" : "human-denied";

  const receipt = buildReceipt(
    {
      id: `verdict-${deferredReceipt.id}`,
      ts: at,
      scope: { tenant: deferredReceipt.scope.tenant, chain: deferredReceipt.scope.chain },
      agent: { id: "approver-human-1", model: null, principal: "HUMAN" },
      action: { ...deferredReceipt.action },
      governance: {
        mode: "approvals_on",
        verdict,
        ruleId,
        approval: { by: phone.kid, at }, // opaque approver id (D8), never raw PII
        sandboxed: false,
      },
    },
    deferredReceipt,
    phone,
  );

  const decisionArtifact = signArtifact(
    b({
      spec: "noa.decision/0.1",
      holdEnvelopeHash: refHash(holdEnvelope),
      decision: args.decision,
      reasonCode: args.reasonCode ?? "vendor-verified",
      reasonEncryption: null,
      decidedAt: at,
      approverKid: phone.kid,
    }),
    "NOA-Decision-v0.1-sig",
    phone,
  ) as unknown as Record<string, unknown>;

  return { receipt, decisionArtifact };
}

/** The one ENFORCED command the alpha adapter accepts (noa.command.exec/1, D14 bind). */
export function sampleCommandParams(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    executable: "/usr/local/bin/deploy",
    argv: ["--service", "api", "--env", "production"],
    cwd: "/srv/app",
    targetEnv: "production",
    allowedEnvHash: "sha256:" + "a".repeat(64),
    stdinHash: null,
    ...overrides,
  };
}
