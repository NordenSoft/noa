/**
 * THE AUTHORITY ROOT, UNDER A FULLY COMPROMISED GATE PROCESS.
 *
 * `NON-CLAIMS.md` carried this defect verbatim: the grant-signing key was a base64 string in the
 * gate's own Node process, so *"the same ambient attacker who motivates this entire architecture can
 * read that key from process memory and mint grants that are cryptographically indistinguishable
 * from genuine ones."* This file is the measurement that the split closes it, and the measurement of
 * exactly where it stops closing it.
 *
 * ── THE ATTACKER MODELLED HERE ──────────────────────────────────────────────────────────────────
 * Everything the gate process has: every private key on its heap (the gate's `hold-signer` /
 * receipt key), the store, the trust root, the socket path and the client shim — plus arbitrary
 * code. It may call the signer directly, off the engine's path, with any bytes it likes. What it
 * does NOT have is the APPROVER's device key: that is on the phone, and a gate that holds it has no
 * approval boundary to defend in the first place. The final test measures that boundary rather than
 * assuming it — an attacker who also holds the approver key DOES get a grant, and that is stated as
 * a precondition, not hidden as an assumption.
 *
 * A test that only proved "the key is not in this variable" would prove nothing. Every refusal below
 * is a real request to a real sidecar process over a real socket, and the anti-vacuity control — an
 * honest approval getting a real, manifest-verifiable grant through the same socket in the same run
 * — is asserted alongside them.
 */

import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync, chmodSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { buildReceipt } from "noa-receipt";
import {
  generateKeyPair,
  refHash,
  receiptRefHash,
  signArtifact,
  verifyArtifact,
} from "noa-approval-artifacts";
import { GateEngine } from "../src/engine.js";
import { remoteExecutionSigner, type ExecutionSigner } from "../src/exec-signer.js";
import { createAlphaTrust, type GateTrust } from "../src/trust.js";
import { InMemoryStore } from "../src/store.js";
import { resolveGateConfig } from "../src/config.js";
import { hashSecret } from "../src/auth.js";
import { loadSchemas } from "../src/schemas.js";
import type { AgentRecord, HoldEnvelope, Receipt } from "../src/types.js";
import { testSealer, signPhoneDecision, sampleCommandParams, body } from "./helpers.js";
import { b } from "./helpers/bytes.js";

const schemas = loadSchemas();
const HERE = path.dirname(fileURLToPath(import.meta.url));
const SIDECAR = path.join(HERE, "..", "src", "grant-sidecar.js");
const CALL_SHIM = path.join(HERE, "..", "src", "grant-signer-call.js");

interface Harness {
  dir: string;
  socket: string;
  child: ChildProcess;
  trust: GateTrust;
  store: InMemoryStore;
  engine: GateEngine;
  agent: AgentRecord;
  signer: ExecutionSigner;
}
let H: Harness;

/** The attacker's own channel to the signer: the socket path and the shim, nothing else. This is
 *  literally what a compromised gate process holds, used exactly as it would use it. */
function rawCall(request: unknown): Record<string, unknown> {
  const res = spawnSync(process.execPath, [CALL_SHIM, "--socket", H.socket], {
    input: JSON.stringify(request) + "\n",
    encoding: "utf8",
  });
  if (res.status !== 0) return { error: `client exited ${String(res.status)}: ${(res.stderr ?? "").trim()}` };
  return JSON.parse(res.stdout) as Record<string, unknown>;
}

/** An UNSIGNED `noa.execution-grant/0.1` document, exactly as the engine builds one. */
function grantDoc(o: {
  grantId: string;
  holdId: string;
  paramsHash: string;
  holdEnvelope: unknown;
  approvalReceipt: Receipt;
  issuedAt?: string;
  expiresAt?: string;
  nonce?: string;
}): Record<string, unknown> {
  const now = Date.now();
  return {
    spec: "noa.execution-grant/0.1",
    grantId: o.grantId,
    holdId: o.holdId,
    paramsHash: o.paramsHash,
    holdEnvelopeHash: refHash(o.holdEnvelope),
    approvalReceiptHash: receiptRefHash(o.approvalReceipt as unknown as Record<string, unknown>),
    issuedAt: o.issuedAt ?? new Date(now).toISOString(),
    expiresAt: o.expiresAt ?? new Date(now + 5 * 60_000).toISOString(),
    maxUses: 1,
    nonce: o.nonce ?? `nonce-${Math.random().toString(16).slice(2)}`,
  };
}

function freshHold(chain: string): { holdId: string; holdEnvelope: HoldEnvelope; deferred: Receipt; paramsHash: string } {
  const created = H.engine.createHold(H.agent, `idem-${chain}`, body({
    mode: "ENFORCED",
    action: { canonical: "noa.command.exec", riskClass: "HIGH", reversible: false },
    params: sampleCommandParams(),
    chain,
  }));
  assert.equal(created.status, 201, JSON.stringify(created.body));
  const holdId = (created.body as { holdId: string }).holdId;
  const holdEnvelope = (created.body as { holdEnvelope: HoldEnvelope }).holdEnvelope;
  const hold = H.store.getHold(holdId)!;
  return { holdId, holdEnvelope, deferred: hold.deferredReceipt, paramsHash: hold.action.paramsHash };
}

before(async () => {
  const dir = mkdtempSync(path.join(tmpdir(), "noa-grant-signer-"));
  chmodSync(dir, 0o700);
  const socket = path.join(dir, "grant.sock");
  const keyFile = path.join(dir, "grant-signer.key.json");
  const trustFile = path.join(dir, "grant-signer-trust.json");

  // 1. PROVISION the execution-signer key OUTSIDE the gate — the operator step. The gate never sees
  //    the private half; the test writes it straight to the sidecar's key file and keeps only the
  //    public half, which is what goes into the key manifest.
  const grantKey = generateKeyPair("grant-signer-1");
  writeFileSync(keyFile, JSON.stringify({ kid: grantKey.kid, privateKey: grantKey.privateKey, publicKey: grantKey.publicKey }), { mode: 0o600 });
  chmodSync(keyFile, 0o600);

  // 2. The trust root names THAT kid as the tenant's only `execution-signer`; the gate key drops to
  //    `hold-signer`. Real clock, because the sidecar's approval-freshness window is measured
  //    against its own clock and a frozen 2026-07-14 fixture would be refused as stale — correctly.
  const trust = createAlphaTrust({
    tenant: "alpha-tenant",
    approverRole: "approve-high",
    executionSigner: { kid: grantKey.kid, publicKey: grantKey.publicKey },
  });

  // 3. The sidecar's OWN trust material, provisioned to it — never taken from a request.
  writeFileSync(trustFile, JSON.stringify({
    spec: "noa.grant-signer-trust/1",
    tenant: trust.tenant,
    keyring: trust.keyring,
    receiptKeyring: trust.receiptKeyring,
  }), { mode: 0o600 });

  const child = spawn(process.execPath, [SIDECAR, "--key-file", keyFile, "--trust-file", trustFile, "--socket", socket], {
    stdio: ["ignore", "pipe", "pipe"],
  });
  await new Promise<void>((resolve, reject) => {
    const t = setTimeout(() => reject(new Error("grant sidecar did not report listening within 10s")), 10_000);
    child.stderr!.setEncoding("utf8");
    child.stderr!.on("data", (chunk: string) => {
      if (chunk.includes("listening on")) {
        clearTimeout(t);
        resolve();
      }
    });
    child.once("exit", (code) => {
      clearTimeout(t);
      reject(new Error(`grant sidecar exited early with code ${String(code)}`));
    });
  });

  const signer = remoteExecutionSigner({ socketPath: socket });
  assert.equal(signer.kid, grantKey.kid, "the running sidecar is the key the manifest authorizes");

  const store = new InMemoryStore();
  const apiKey = "noa_gateagent_test-secret-abc123";
  const agent: AgentRecord = { id: "agent-1", name: "test-agent", apiKeyHash: hashSecret(apiKey), createdAt: Date.now() };
  store.putAgent(agent);
  const engine = new GateEngine({
    store,
    config: resolveGateConfig({}),
    trust,
    schemas,
    sealDisplay: testSealer,
    executionSigner: signer,
  });

  H = { dir, socket, child, trust, store, engine, agent, signer };
});

after(() => {
  H?.child?.kill("SIGTERM");
  if (H?.dir) rmSync(H.dir, { recursive: true, force: true });
});

// ════════════════════════════════════════════════════════════════════════════════════════════════
// THE PROPERTY
// ════════════════════════════════════════════════════════════════════════════════════════════════

test("the gate process holds NO key the manifest lets sign an Execution Grant", () => {
  // The custody claim, stated as the manifest states it. `gate-prod-1` is still a GATE key and still
  // signs hold envelopes and receipts; what it has lost is the role that makes a grant valid.
  const gateEntry = H.trust.keyring[H.trust.gate.kid]!;
  assert.deepEqual(gateEntry.roles, ["hold-signer"]);
  const execEntry = H.trust.keyring[H.trust.executionSigner!.kid]!;
  assert.deepEqual(execEntry.roles, ["execution-signer"]);
  assert.equal(execEntry.type, "GATE");
  // And nothing on the gate's heap carries that key's private half.
  assert.equal(Object.prototype.hasOwnProperty.call(H.trust.executionSigner!, "privateKey"), false);

  // ── THE OTHER HALF OF THE SAME PROPERTY, AND IT IS EASY TO LOSE BY ACCIDENT ────────────────────
  // Stripping the role from the gate key buys nothing if the gate can re-sign the KEY MANIFEST and
  // hand the role back to itself. It cannot: `createAlphaTrust` mints the root and the delegated
  // manifest signer as locals and returns neither, so the only private keys reachable from a
  // GateTrust are the gate's own and — in the alpha only — the simulated phone's. Asserted by
  // enumeration rather than by reading the constructor, so a future field that quietly starts
  // carrying a third private key fails here.
  const privateKeyPaths = (o: unknown, prefix = ""): string[] => {
    const out: string[] = [];
    for (const [k, v] of Object.entries((o ?? {}) as Record<string, unknown>)) {
      if (typeof v === "string" && k.toLowerCase().includes("private")) out.push(prefix + k);
      else if (v && typeof v === "object" && !Array.isArray(v)) out.push(...privateKeyPaths(v, `${prefix}${k}.`));
    }
    return out;
  };
  assert.deepEqual(privateKeyPaths(H.trust).sort(), ["approver.privateKey", "gate.privateKey"]);
});

test("EVIDENCE GATE: a fully compromised gate cannot obtain a grant for unapproved params", async () => {
  const A = freshHold("chain-attack");
  // The genuine human approval — for the params the human actually saw.
  const approval = signPhoneDecision({
    trust: H.trust,
    deferredReceipt: A.deferred,
    holdEnvelope: A.holdEnvelope,
    decision: "APPROVE",
  });
  const attackerParamsHash = "sha256:" + "b".repeat(64);
  assert.notEqual(attackerParamsHash, A.paramsHash);

  // ── ATTACK 1 — sign it yourself. The attacker has the gate's private key and uses it. ─────────
  const forged = signArtifact(
    b(grantDoc({ grantId: "forged-1", holdId: A.holdId, paramsHash: attackerParamsHash, holdEnvelope: A.holdEnvelope, approvalReceipt: approval.receipt })),
    "NOA-ExecGrant-v0.1-sig",
    { kid: H.trust.gate.kid, privateKey: H.trust.gate.privateKey },
  );
  const forgedCheck = verifyArtifact(b(forged), b({ schemas, keyring: H.trust.keyring, now: new Date().toISOString() }));
  assert.equal(forgedCheck.ok, false, "a grant signed with the gate's own key must not verify");
  assert.match(String(forgedCheck.reason), /lack required execution-signer/);

  // ── ATTACK 2 — ask the real signer, with the real approval, for the attacker's params. ────────
  const poisoned = rawCall({
    op: "sign-grant",
    artifact: grantDoc({ grantId: "attack-2", holdId: A.holdId, paramsHash: attackerParamsHash, holdEnvelope: A.holdEnvelope, approvalReceipt: approval.receipt }),
    proof: { holdEnvelope: A.holdEnvelope, decisionArtifact: approval.decisionArtifact, deferredReceipt: A.deferred, approvalReceipt: approval.receipt },
  });
  assert.equal(poisoned["artifact"], undefined);
  assert.match(String(poisoned["error"]), /is not the paramsHash a human approved/);

  // ── ATTACK 3 — manufacture the approval out of the keys you DO have. ──────────────────────────
  // The gate's key signs a `noa.decision/0.1` claiming APPROVE. It is a real Ed25519 signature over
  // a real document; it is simply not an approver's.
  const fakeDecision = signArtifact(
    b({
      spec: "noa.decision/0.1",
      holdEnvelopeHash: refHash(A.holdEnvelope),
      decision: "APPROVE",
      reasonCode: "vendor-verified",
      reasonEncryption: null,
      decidedAt: new Date().toISOString(),
      approverKid: H.trust.gate.kid,
    }),
    "NOA-Decision-v0.1-sig",
    { kid: H.trust.gate.kid, privateKey: H.trust.gate.privateKey },
  );
  const manufactured = rawCall({
    op: "sign-grant",
    artifact: grantDoc({ grantId: "attack-3", holdId: A.holdId, paramsHash: attackerParamsHash, holdEnvelope: A.holdEnvelope, approvalReceipt: approval.receipt }),
    proof: { holdEnvelope: A.holdEnvelope, decisionArtifact: fakeDecision, deferredReceipt: A.deferred, approvalReceipt: approval.receipt },
  });
  assert.equal(manufactured["artifact"], undefined);
  assert.match(String(manufactured["error"]), /^REFUSED: decision artifact invalid/);

  // ── ATTACK 3b — forge the APPROVAL RECEIPT itself, with the key you have, carrying YOUR params.
  // The most direct route to the goal: a real Ed25519 signature over a real receipt chaining onto
  // the real DEFERRED, declaring `ALLOWED` for the attacker's parameters. It is refused because the
  // signer is a GATE key and an approval is an APPROVER's to make.
  const forgedApproval = buildReceipt(
    {
      id: `verdict-forged-${A.holdId}`,
      ts: new Date().toISOString(),
      scope: { tenant: A.deferred.scope.tenant, chain: A.deferred.scope.chain },
      agent: { id: "approver-human-1", model: null, principal: "HUMAN" },
      action: { ...A.deferred.action, paramsHash: attackerParamsHash },
      governance: {
        mode: "approvals_on",
        verdict: "ALLOWED",
        ruleId: "human-approved",
        approval: { by: H.trust.gate.kid, at: new Date().toISOString() },
        sandboxed: false,
      },
    },
    A.deferred,
    { kid: H.trust.gate.kid, privateKey: H.trust.gate.privateKey },
  );
  const selfApproved = rawCall({
    op: "sign-grant",
    artifact: grantDoc({ grantId: "attack-3b", holdId: A.holdId, paramsHash: attackerParamsHash, holdEnvelope: A.holdEnvelope, approvalReceipt: forgedApproval }),
    proof: { holdEnvelope: A.holdEnvelope, decisionArtifact: approval.decisionArtifact, deferredReceipt: A.deferred, approvalReceipt: forgedApproval },
  });
  assert.equal(selfApproved["artifact"], undefined);
  assert.match(String(selfApproved["error"]), /is not an APPROVER key in this signer's own trust material/);

  // ── ATTACK 4 — route the grant through the ungated attestation op. ────────────────────────────
  const smuggled = rawCall({
    op: "sign-attestation",
    artifact: grantDoc({ grantId: "attack-4", holdId: A.holdId, paramsHash: attackerParamsHash, holdEnvelope: A.holdEnvelope, approvalReceipt: approval.receipt }),
  });
  assert.equal(smuggled["artifact"], undefined);
  assert.match(String(smuggled["error"]), /authority, not an attestation/);

  // ── ATTACK 5 — mix and match: another hold's genuine approval, this hold's envelope. ──────────
  const Bh = freshHold("chain-other");
  const bApproval = signPhoneDecision({ trust: H.trust, deferredReceipt: Bh.deferred, holdEnvelope: Bh.holdEnvelope, decision: "APPROVE" });
  const mixed = rawCall({
    op: "sign-grant",
    artifact: grantDoc({ grantId: "attack-5", holdId: A.holdId, paramsHash: A.paramsHash, holdEnvelope: A.holdEnvelope, approvalReceipt: bApproval.receipt }),
    proof: { holdEnvelope: A.holdEnvelope, decisionArtifact: approval.decisionArtifact, deferredReceipt: A.deferred, approvalReceipt: bApproval.receipt },
  });
  assert.equal(mixed["artifact"], undefined);
  assert.ok(String(mixed["error"]).startsWith("REFUSED"), mixed["error"] as string);

  // ── ATTACK 6 — a genuine but STALE approval, resurrected by the compromised gate. ─────────────
  const stale = signPhoneDecision({
    trust: H.trust,
    deferredReceipt: A.deferred,
    holdEnvelope: A.holdEnvelope,
    decision: "APPROVE",
    at: new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString(),
  });
  const resurrected = rawCall({
    op: "sign-grant",
    artifact: grantDoc({ grantId: "attack-6", holdId: A.holdId, paramsHash: A.paramsHash, holdEnvelope: A.holdEnvelope, approvalReceipt: stale.receipt }),
    proof: { holdEnvelope: A.holdEnvelope, decisionArtifact: stale.decisionArtifact, deferredReceipt: A.deferred, approvalReceipt: stale.receipt },
  });
  assert.equal(resurrected["artifact"], undefined);
  assert.match(String(resurrected["error"]), /freshness window/);

  // ── ATTACK 8 — the approved parameters, but a capability that never expires. ──────────────────
  // Found by attacking this design rather than by writing it: every other check binds WHAT is
  // authorized and none of them bounded FOR HOW LONG. Single-use is burned in the store the attacker
  // controls, so an unbounded lifetime is a standing capability for the approved action.
  const eternal = rawCall({
    op: "sign-grant",
    artifact: grantDoc({
      grantId: "attack-8",
      holdId: A.holdId,
      paramsHash: A.paramsHash,
      holdEnvelope: A.holdEnvelope,
      approvalReceipt: approval.receipt,
      expiresAt: new Date(Date.now() + 10 * 365 * 24 * 60 * 60 * 1000).toISOString(),
    }),
    proof: { holdEnvelope: A.holdEnvelope, decisionArtifact: approval.decisionArtifact, deferredReceipt: A.deferred, approvalReceipt: approval.receipt },
  });
  assert.equal(eternal["artifact"], undefined);
  assert.match(String(eternal["error"]), /exceeds the \d+s this signer will authorize/);

  // ── ANTI-VACUITY — the honest path, same socket, same run, same approval. ─────────────────────
  const t0 = process.hrtime.bigint();
  const decided = H.engine.decide(A.holdId, body({ receipt: approval.receipt, decisionArtifact: approval.decisionArtifact }));
  const decideMs = Number(process.hrtime.bigint() - t0) / 1e6;
  assert.equal(decided.status, 200, JSON.stringify(decided.body));
  const dv = decided.body as { status: string; grantId: string; executionGrant: Record<string, unknown> };
  assert.equal(dv.status, "APPROVED");
  assert.ok(dv.executionGrant, "the honest approval DID produce a grant");
  assert.equal(dv.executionGrant["paramsHash"], A.paramsHash);
  assert.equal((dv.executionGrant["sig"] as { kid: string }).kid, H.trust.executionSigner!.kid);

  const grantCheck = verifyArtifact(b(dv.executionGrant), b({
    schemas,
    keyring: H.trust.keyring,
    now: new Date().toISOString(),
    refHashChecks: [
      { path: "holdEnvelopeHash", rule: "side", artifact: A.holdEnvelope },
      { path: "approvalReceiptHash", rule: "receipt", artifact: approval.receipt },
    ],
  }));
  assert.ok(grantCheck.ok, `the sidecar-signed grant must verify against the manifest: ${grantCheck.reason}`);

  // ── ATTACK 7 — one human decision authorizes ONE grant, even off the engine's path. ───────────
  const replayed = rawCall({
    op: "sign-grant",
    artifact: grantDoc({ grantId: "attack-7", holdId: A.holdId, paramsHash: A.paramsHash, holdEnvelope: A.holdEnvelope, approvalReceipt: approval.receipt }),
    proof: { holdEnvelope: A.holdEnvelope, decisionArtifact: approval.decisionArtifact, deferredReceipt: A.deferred, approvalReceipt: approval.receipt },
  });
  assert.equal(replayed["artifact"], undefined);
  assert.match(String(replayed["error"]), /already been granted once/);

  // eslint-disable-next-line no-console
  console.log(`  [measured] decide() with the remote grant signer: ${decideMs.toFixed(1)}ms (grant TTL budget: ${resolveGateConfig({}).grantTtlMs}ms)`);
});

test("MEASURED: the signer round trip, against the TTL floor it must fit inside", () => {
  const samples: number[] = [];
  for (let i = 0; i < 7; i++) {
    const t0 = process.hrtime.bigint();
    const r = rawCall({ op: "pubkey" });
    samples.push(Number(process.hrtime.bigint() - t0) / 1e6);
    assert.equal(r["kid"], H.trust.executionSigner!.kid);
  }
  samples.sort((x, y) => x - y);
  const median = samples[3]!;
  const cfg = resolveGateConfig({});
  // eslint-disable-next-line no-console
  console.log(`  [measured] blocking signer round trip: min ${samples[0]!.toFixed(1)}ms · median ${median.toFixed(1)}ms · max ${samples[samples.length - 1]!.toFixed(1)}ms`);
  // The KILL CRITERION, mechanised: a grant must be obtainable well inside the window in which it is
  // valid. Two orders of magnitude of headroom, so the assertion cannot pass by luck on a slow box.
  assert.ok(median * 100 < cfg.grantTtlMs, `round trip ${median}ms is not comfortably inside the ${cfg.grantTtlMs}ms grant TTL`);
  assert.ok(median * 100 < cfg.minTtlMs, `round trip ${median}ms is not comfortably inside the ${cfg.minTtlMs}ms minimum hold TTL`);
});

test("the ATTESTATION op still works, and cannot be turned into authority", () => {
  // The three attestations moved out of process with the grant (one F15 role covers all four), so
  // this proves the gate can still resolve a hold — otherwise the split would be a liveness break
  // wearing a security costume.
  const C = freshHold("chain-deny");
  const denial = signPhoneDecision({ trust: H.trust, deferredReceipt: C.deferred, holdEnvelope: C.holdEnvelope, decision: "DENY" });
  const decided = H.engine.decide(C.holdId, body({ receipt: denial.receipt, decisionArtifact: denial.decisionArtifact }));
  assert.equal(decided.status, 200, JSON.stringify(decided.body));
  const dv = decided.body as { status: string; holdResolution: Record<string, unknown> };
  assert.equal(dv.status, "DENIED");
  const resCheck = verifyArtifact(b(dv.holdResolution), b({
    schemas,
    keyring: H.trust.keyring,
    now: new Date().toISOString(),
    refHashChecks: [{ path: "holdEnvelopeHash", rule: "side", artifact: C.holdEnvelope }],
  }));
  assert.ok(resCheck.ok, `hold resolution must verify under the remote signer: ${resCheck.reason}`);
});

test("HONEST LIMIT (measured, not assumed): an attacker holding the APPROVER key does get a grant", () => {
  // The property above is conditional on the approver's device key not being co-resident with the
  // gate. `createAlphaTrust` mints that key in-process for the alpha demo, so this run CAN play the
  // stronger attacker — and it succeeds. Recorded here rather than in prose so the precondition is a
  // measurement someone can re-run, and so a future change that quietly weakens it has a test to
  // break. `NON-CLAIMS.md` states the same limit in words.
  const D = freshHold("chain-honest-limit");
  const attackerApproval = signPhoneDecision({
    trust: H.trust, // includes trust.approver.privateKey — the phone key, present only in the alpha
    deferredReceipt: D.deferred,
    holdEnvelope: D.holdEnvelope,
    decision: "APPROVE",
  });
  const got = rawCall({
    op: "sign-grant",
    artifact: grantDoc({ grantId: "limit-1", holdId: D.holdId, paramsHash: D.paramsHash, holdEnvelope: D.holdEnvelope, approvalReceipt: attackerApproval.receipt }),
    proof: { holdEnvelope: D.holdEnvelope, decisionArtifact: attackerApproval.decisionArtifact, deferredReceipt: D.deferred, approvalReceipt: attackerApproval.receipt },
  });
  assert.ok(got["artifact"], `expected the approver-key-holding attacker to SUCCEED, got ${String(got["error"])}`);
});
