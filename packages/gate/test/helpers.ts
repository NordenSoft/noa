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
import { InMemoryStore } from "../src/store.js";
import { hashSecret } from "../src/auth.js";
import { loadSchemas } from "../src/schemas.js";
import type { AgentRecord, HoldEnvelope } from "../src/types.js";

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

export interface GateFixture {
  clock: Clock;
  trust: GateTrust;
  store: InMemoryStore;
  engine: GateEngine;
  agent: AgentRecord;
  apiKey: string;
}

export function setupGate(opts: { approverRole?: "approve-high" | "approve-critical"; config?: Partial<GateConfig> } = {}): GateFixture {
  const clock = makeClock();
  const now = () => clock.t;
  let seq = 0;
  const ids = () => `id-${(seq++).toString(16).padStart(8, "0")}`;
  const trust = createAlphaTrust({ tenant: "alpha-tenant", now, ...(opts.approverRole ? { approverRole: opts.approverRole } : {}), ids });
  const store = new InMemoryStore();
  const apiKey = "noa_gateagent_test-secret-abc123";
  const agent: AgentRecord = { id: "agent-1", name: "test-agent", apiKeyHash: hashSecret(apiKey), createdAt: now() };
  store.putAgent(agent);
  const config = resolveGateConfig({ now, ...(opts.config ?? {}) });
  const engine = new GateEngine({ store, config, trust, schemas: loadSchemas(), sealDisplay: testSealer });
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
}): { receipt: Receipt; decisionArtifact: Record<string, unknown> } {
  const { trust, deferredReceipt, holdEnvelope } = args;
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
        approval: { by: trust.approver.kid, at }, // opaque approver id (D8), never raw PII
        sandboxed: false,
      },
    },
    deferredReceipt,
    { kid: trust.approver.kid, privateKey: trust.approver.privateKey },
  );

  const decisionArtifact = signArtifact(
    {
      spec: "noa.decision/0.1",
      holdEnvelopeHash: refHash(holdEnvelope),
      decision: args.decision,
      reasonCode: args.reasonCode ?? "vendor-verified",
      reasonEncryption: null,
      decidedAt: at,
      approverKid: trust.approver.kid,
    },
    "NOA-Decision-v0.1-sig",
    { kid: trust.approver.kid, privateKey: trust.approver.privateKey },
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
