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
import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync, chmodSync, symlinkSync, readFileSync } from "node:fs";
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
import { createGate } from "../src/server.js";
import { remoteExecutionSigner, type ExecutionSigner } from "../src/exec-signer.js";
import {
  ApprovalReplayStore,
  assertSocketDirIsNotWorldAccessible,
  loadGrantSignerTrust,
  validateGrantRequest,
} from "../src/grant-sidecar.js";
import { createAlphaTrust, type GateTrust } from "../src/trust.js";
import { InMemoryStore } from "../src/store.js";
import { resolveGateConfig } from "../src/config.js";
import { hashSecret } from "../src/auth.js";
import { loadSchemas } from "../src/schemas.js";
import type { AgentRecord, HoldEnvelope, Receipt } from "../src/types.js";
import { testSealer, signPhoneDecision, sampleCommandParams, body } from "./helpers.js";
import { b } from "./helpers/bytes.js";

const schemas = loadSchemas();

/** An X25519 public half for the enrolled approver record. Real key material; the §8 protocol does
 *  not exercise it here, but the manifest entry must carry a well-formed one. */
function generateX25519PublicForTest(): string {
  const { publicKey } = generateKeyPairSync("x25519");
  return (publicKey.export({ type: "spki", format: "der" }) as Buffer).toString("base64");
}

/**
 * A stand-in listener speaking the sidecar's wire protocol, so a test can play a HOSTILE signer.
 *
 * IT MUST BE ITS OWN PROCESS, and finding that out is worth recording: the client shim is driven by
 * `spawnSync`, so while the gate waits for a reply its event loop is BLOCKED. A rogue listener
 * living in this test process could never accept the connection, and the first version of these two
 * tests deadlocked for the full 10-second client timeout instead of measuring anything. The
 * synchronous transport that keeps `decide()` atomic has this as its cost, and a test harness that
 * hides it would be lying about the shape of the system.
 *
 * `reply` is stringified into the child, so it must be self-contained.
 */
async function rogueSigner(socketPath: string, replySource: string): Promise<ChildProcess> {
  const script = path.join(H.dir, `rogue-${path.basename(socketPath)}.mjs`);
  writeFileSync(script, `
import { createServer } from "node:net";
const reply = ${replySource};
const server = createServer((sock) => {
  let buf = "";
  sock.setEncoding("utf8");
  sock.on("data", (chunk) => {
    buf += chunk;
    const nl = buf.indexOf("\\n");
    if (nl === -1) return;
    let req = {};
    try { req = JSON.parse(buf.slice(0, nl)); } catch { /* a hostile peer need not be well-formed */ }
    sock.end(JSON.stringify(reply(req)) + "\\n");
  });
  sock.on("error", () => sock.destroy());
});
server.listen(${JSON.stringify(socketPath)}, () => console.error("rogue: listening"));
`);
  const child = spawn(process.execPath, [script], { stdio: ["ignore", "pipe", "pipe"] });
  await new Promise<void>((resolve, reject) => {
    const t = setTimeout(() => reject(new Error("rogue signer did not start")), 10_000);
    child.stderr!.setEncoding("utf8");
    child.stderr!.on("data", (c: string) => {
      if (c.includes("rogue: listening")) {
        clearTimeout(t);
        resolve();
      }
    });
    child.once("exit", (code) => {
      clearTimeout(t);
      reject(new Error(`rogue signer exited early (${String(code)})`));
    });
  });
  return child;
}
const HERE = path.dirname(fileURLToPath(import.meta.url));
const SIDECAR = path.join(HERE, "..", "src", "grant-sidecar.js");
const CALL_SHIM = path.join(HERE, "..", "src", "grant-signer-call.js");

interface Harness {
  dir: string;
  socket: string;
  trustFile: string;
  child: ChildProcess;
  trust: GateTrust;
  store: InMemoryStore;
  engine: GateEngine;
  agent: AgentRecord;
  signer: ExecutionSigner;
  /** THE PHONE. Held by the test, never by `trust` — that is the point of the production posture. */
  phone: { kid: string; privateKey: string; publicKey: string };
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

  // 1b. THE PHONE. Minted here and kept HERE — `createAlphaTrust` gets the public half only, so the
  //     gate's trust root has no approver private key to steal. The first cut of this file called
  //     `createAlphaTrust()` with no approver argument, which GENERATED the phone key inside the
  //     gate, and then described the resulting attack as an "honest limit" while shipping it as the
  //     only wiring (adversarial review 2026-08-12, CRITICAL 2). The posture is now the tested one.
  const phoneKey = generateKeyPair("approver-1-device-1");
  const phoneHpke = generateX25519PublicForTest();

  // 2. The trust root names THAT kid as the tenant's only `execution-signer`; the gate key drops to
  //    `hold-signer`. Real clock, because the sidecar's approval-freshness window is measured
  //    against its own clock and a frozen 2026-07-14 fixture would be refused as stale — correctly.
  const trust = createAlphaTrust({
    tenant: "alpha-tenant",
    approverRole: "approve-high",
    executionSigner: { kid: grantKey.kid, publicKey: grantKey.publicKey },
    approverPublicKey: { kid: phoneKey.kid, publicKey: phoneKey.publicKey, hpkePublicKey: phoneHpke },
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

  // The signer's identity is OPERATOR-supplied (from the key we provisioned above), never learned
  // from the socket — CRITICAL 3.
  const signer = remoteExecutionSigner({ socketPath: socket, expect: { kid: grantKey.kid, publicKey: grantKey.publicKey } });
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

  H = { dir, socket, trustFile, child, trust, store, engine, agent, signer, phone: phoneKey };
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
  // ── STRONGER THAN IT WAS, AND THE REVIEW IS WHY ─────────────────────────────────────────────
  // This used to accept `["approver.privateKey", "gate.privateKey"]` — i.e. the "fully compromised
  // gate" the headline test names was handed the phone's key by the fixture, and the principal
  // attack then excluded it by stipulation. In the production posture the gate's trust root holds
  // exactly one private key: its own.
  assert.deepEqual(privateKeyPaths(H.trust).sort(), ["gate.privateKey"]);
});

test("EVIDENCE GATE: a fully compromised gate cannot obtain a grant for unapproved params", async () => {
  const A = freshHold("chain-attack");
  // The genuine human approval — for the params the human actually saw.
  const approval = signPhoneDecision({
    trust: H.trust,
    signer: H.phone,
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
  const bApproval = signPhoneDecision({ trust: H.trust, signer: H.phone, deferredReceipt: Bh.deferred, holdEnvelope: Bh.holdEnvelope, decision: "APPROVE" });
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
    signer: H.phone,
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
  const denial = signPhoneDecision({ trust: H.trust, signer: H.phone, deferredReceipt: C.deferred, holdEnvelope: C.holdEnvelope, decision: "DENY" });
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

test("the phone key is what the boundary rests on, and the gate no longer holds it", () => {
  // THE PRECONDITION, MEASURED FROM BOTH SIDES.
  //
  // Positive: whoever holds the phone key can produce an approval this signer accepts — that is not
  // a weakness, it is what an approver IS, and it keeps this suite from proving its refusals by
  // being unable to approve at all.
  const D = freshHold("chain-phone-key");
  const approval = signPhoneDecision({
    trust: H.trust,
    signer: H.phone, // the PHONE's key — held by this test, absent from H.trust
    deferredReceipt: D.deferred,
    holdEnvelope: D.holdEnvelope,
    decision: "APPROVE",
  });
  const got = rawCall({
    op: "sign-grant",
    artifact: grantDoc({ grantId: "phone-1", holdId: D.holdId, paramsHash: D.paramsHash, holdEnvelope: D.holdEnvelope, approvalReceipt: approval.receipt }),
    proof: { holdEnvelope: D.holdEnvelope, decisionArtifact: approval.decisionArtifact, deferredReceipt: D.deferred, approvalReceipt: approval.receipt },
  });
  assert.ok(got["artifact"], `the enrolled approver must be able to approve, got ${String(got["error"])}`);

  // Negative: and the compromised gate cannot reach that key, because the trust root it was built
  // with never received it. The earlier version of this file asserted the OPPOSITE and called it an
  // honest limit while shipping the co-resident wiring as the only path.
  assert.equal(H.trust.approver.privateKey, undefined);
  assert.equal(H.trust.approver.kid, H.phone.kid);
  assert.equal(H.trust.approver.publicKey, H.phone.publicKey);
});

// ════════════════════════════════════════════════════════════════════════════════════════════════
// REGRESSION SUITE — ONE TEST PER FINDING FROM THE 2026-08-12 ADVERSARIAL REVIEW.
//
// Every one of these was reproducible against commit 44ab9dc while the gate's own 251-test suite
// passed. That is the lesson worth keeping: the earlier tests modelled what the author intended,
// not what the attacker could reach. Each test below names its finding and fails without its fix.
// ════════════════════════════════════════════════════════════════════════════════════════════════

test("F1 (CRITICAL): a trust file whose two keyrings disagree about a kid is refused at startup", () => {
  // THE ATTACK: `keyring[kid]` = the phone's real public key, `receiptKeyring.keys[kid]` = the
  // COMPROMISED GATE's public key, same kid. A genuine phone Decision then authenticates against one
  // map while a gate-forged ALLOWED receipt carrying attacker parameters authenticates against the
  // other, and a kid-string comparison sees one approver. Reproduced end to end: the sidecar signed,
  // and the shipped verifier returned ok:true on the result.
  const genuine = JSON.parse(readFileSync(H.trustFile, "utf8")) as {
    keyring: Record<string, { publicKey: string }>;
    receiptKeyring: { keys: Record<string, { publicKey: string }> };
  };
  const confused = JSON.parse(JSON.stringify(genuine)) as typeof genuine;
  confused.receiptKeyring.keys[H.phone.kid]!.publicKey = H.trust.gate.publicKey;
  const file = path.join(H.dir, "confused-trust.json");
  writeFileSync(file, JSON.stringify(confused), { mode: 0o600 });

  assert.throws(
    () => loadGrantSignerTrust(file),
    /DIFFERENT public keys in keyring and receiptKeyring/,
    "a kid that denotes two different keys is two trust roots, and this process must have exactly one",
  );

  // The same confusion refused at the POINT OF USE, so a trust object that never went through the
  // loader cannot reintroduce it. These two controls fail independently on purpose.
  const perRequest = validateGrantRequest({
    grant: { spec: "noa.execution-grant/0.1" },
    proof: {},
    trust: {
      spec: "noa.grant-signer-trust/1",
      tenant: H.trust.tenant,
      keyring: { [H.phone.kid]: { publicKey: H.phone.publicKey, type: "APPROVER", roles: ["approve-high"] } },
      receiptKeyring: { spec: "noa.signing-key-lifecycle/0.1", keys: { [H.phone.kid]: { publicKey: H.trust.gate.publicKey, retiredAt: null } } },
    } as never,
    schemas,
    nowMs: Date.now(),
    maxApprovalAgeMs: 900_000,
    maxGrantTtlMs: 300_000,
  });
  assert.equal(perRequest.ok, false);
});

test("F2 (CRITICAL): an external grant signer with an in-process approver key is refused outright", () => {
  // The gate's out-of-process authority root authorizes on exactly one thing an attacker inside the
  // gate cannot forge: the approver's signature. Generating that key in the gate makes the boundary
  // decorative — and it was the ONLY shipped wiring, while this file called it an honest limit.
  assert.throws(
    () => createAlphaTrust({ tenant: "t", executionSigner: { kid: "grant-signer-1", publicKey: H.trust.executionSigner!.publicKey } }),
    /requires `approverPublicKey`/,
    "coupling the two is the fix; documenting the danger is not",
  );
  // ANTI-VACUITY: the correct combination is accepted, so the refusal above is a discrimination and
  // not a blanket failure.
  const ok = createAlphaTrust({
    tenant: "t",
    executionSigner: { kid: "grant-signer-1", publicKey: H.trust.executionSigner!.publicKey },
    approverPublicKey: { kid: H.phone.kid, publicKey: H.phone.publicKey, hpkePublicKey: generateX25519PublicForTest() },
  });
  assert.equal(ok.approver.privateKey, undefined);
});

test("F3 (CRITICAL): the signer's identity comes from the operator, not from the socket", async () => {
  // The gate MINTS A KEY MANIFEST naming its execution-signer. Learning that identity from the
  // socket meant anyone who could replace the listener before startup could publish themselves as
  // the tenant's authority root and sign without any policy checks at all.
  const attacker = generateKeyPair("attacker-signer-1");
  const rogueSocket = path.join(H.dir, "rogue.sock");
  const server = await rogueSigner(rogueSocket, `() => (${JSON.stringify({ kid: attacker.kid, pub: attacker.publicKey, alg: "ed25519" })})`);
  try {
    assert.throws(
      () => remoteExecutionSigner({
        socketPath: rogueSocket,
        expect: { kid: H.trust.executionSigner!.kid, publicKey: H.trust.executionSigner!.publicKey },
      }),
      /do not match the operator-pinned identity/,
      "a signer that can name itself is not an authority root",
    );
  } finally {
    server.kill("SIGTERM");
  }
});

test("F4 (HIGH): a returned signature that does not verify is refused, not shipped", async () => {
  // `assertSignedDocMatches` checked fields, shape and kid and never ran Ed25519. Reproduced: a
  // response echoing the exact document with value:"not-a-signature" made decide() return 200 and
  // persist an APPROVED hold with an UNUSED grant — the gate believing in authority it never got.
  const real = H.trust.executionSigner!;
  const rogueSocket = path.join(H.dir, "liar.sock");
  const server = await rogueSigner(
    rogueSocket,
    `(req) => req.op === "pubkey"
      ? ${JSON.stringify({ kid: real.kid, pub: real.publicKey, alg: "ed25519" })}
      : { artifact: { ...req.artifact, sig: { alg: "ed25519", kid: ${JSON.stringify(real.kid)}, value: "not-a-signature" } } }`,
  );
  try {
    // The liar passes the identity check — it presents the pinned kid and public key — so only the
    // cryptographic check can catch it. That is exactly the gap this closes.
    const signer = remoteExecutionSigner({ socketPath: rogueSocket, expect: { kid: real.kid, publicKey: real.publicKey } });
    assert.throws(
      () => signer.signAttestation({
        spec: "noa.execution-consumption/0.1",
        grantHash: "sha256:" + "c".repeat(64),
        consumedAt: new Date().toISOString(),
        attemptReceiptHash: "sha256:" + "d".repeat(64),
        result: "DISPATCHED",
      }),
      /does not verify under the pinned public key/,
    );
  } finally {
    server.kill("SIGTERM");
  }
});

test("F5 (HIGH): a hold that has already expired can never carry a grant", () => {
  const E = freshHold("chain-expiry");
  const approval = signPhoneDecision({ trust: H.trust, signer: H.phone, deferredReceipt: E.deferred, holdEnvelope: E.holdEnvelope, decision: "APPROVE" });
  const envelopeExpiryMs = Date.parse(E.holdEnvelope.expiresAt);
  // Driven through the pure validator so the clock is an argument rather than a sleep. The approval
  // itself is still inside its freshness window — only the HOLD has run out, which is precisely the
  // case the freshness check could not see.
  const afterExpiry = envelopeExpiryMs + 120_000;
  const verdict = validateGrantRequest({
    grant: grantDoc({
      grantId: "expired-1", holdId: E.holdId, paramsHash: E.paramsHash, holdEnvelope: E.holdEnvelope,
      approvalReceipt: approval.receipt,
      issuedAt: new Date(afterExpiry).toISOString(),
      expiresAt: new Date(afterExpiry + 60_000).toISOString(),
    }),
    proof: { holdEnvelope: E.holdEnvelope, decisionArtifact: approval.decisionArtifact, deferredReceipt: E.deferred, approvalReceipt: approval.receipt },
    trust: loadGrantSignerTrust(H.trustFile),
    schemas,
    nowMs: afterExpiry,
    maxApprovalAgeMs: 24 * 60 * 60 * 1000, // deliberately generous: isolate the HOLD deadline
    maxGrantTtlMs: 300_000,
  });
  assert.equal(verdict.ok, false);
  assert.match(verdict.ok ? "" : verdict.reason, /hold expired/);
});

test("F5a (HIGH): the deadline has NO skew allowance — one second past expiry is already refused", () => {
  // WHY THIS EXISTS. F5 above probes 120s past the deadline, and the check it was written against
  // read `nowMs > expiry + CLOCK_SKEW_MS` — so it passed while the whole first MINUTE after expiry
  // was still accepted. An independent review measured it live: a genuine approval granted 30s past
  // the deadline returned ok:true. A test that only samples far outside the hole cannot see the hole.
  // This one samples one second in.
  const E = freshHold("chain-expiry-1s");
  const approval = signPhoneDecision({ trust: H.trust, signer: H.phone, deferredReceipt: E.deferred, holdEnvelope: E.holdEnvelope, decision: "APPROVE" });
  const expiry = Date.parse(E.holdEnvelope.expiresAt);
  const justAfter = expiry + 1_000;
  const verdict = validateGrantRequest({
    grant: grantDoc({
      grantId: "expired-1s", holdId: E.holdId, paramsHash: E.paramsHash, holdEnvelope: E.holdEnvelope,
      approvalReceipt: approval.receipt,
      issuedAt: new Date(justAfter).toISOString(),
      expiresAt: new Date(justAfter + 30_000).toISOString(),
    }),
    proof: { holdEnvelope: E.holdEnvelope, decisionArtifact: approval.decisionArtifact, deferredReceipt: E.deferred, approvalReceipt: approval.receipt },
    trust: loadGrantSignerTrust(H.trustFile),
    schemas,
    nowMs: justAfter,
    maxApprovalAgeMs: 24 * 60 * 60 * 1000,
    maxGrantTtlMs: 300_000,
  });
  assert.equal(verdict.ok, false);
  assert.match(verdict.ok ? "" : verdict.reason, /hold expired/);
});

test("F5b (HIGH): a grant may not OUTLIVE its hold — bounding duration is not bounding the end", () => {
  // The deadline check's own comment claimed "no grant may outlive it" while nothing enforced it:
  // only `expiresAt - issuedAt <= maxGrantTtlMs` was checked, so with a five-minute TTL a grant taken
  // against a hold expiring in 30s stayed valid 270s past that hold. A property asserted in prose and
  // enforced nowhere is the worse kind of gap — every later reader believes it.
  const E = freshHold("chain-outlive");
  const approval = signPhoneDecision({ trust: H.trust, signer: H.phone, deferredReceipt: E.deferred, holdEnvelope: E.holdEnvelope, decision: "APPROVE" });
  const expiry = Date.parse(E.holdEnvelope.expiresAt);
  const now = expiry - 30_000;                             // comfortably INSIDE the hold: only the END is wrong
  const verdict = validateGrantRequest({
    grant: grantDoc({
      grantId: "outlive-1", holdId: E.holdId, paramsHash: E.paramsHash, holdEnvelope: E.holdEnvelope,
      approvalReceipt: approval.receipt,
      issuedAt: new Date(now).toISOString(),
      expiresAt: new Date(expiry + 60_000).toISOString(),   // past the hold, still inside maxGrantTtlMs
    }),
    proof: { holdEnvelope: E.holdEnvelope, decisionArtifact: approval.decisionArtifact, deferredReceipt: E.deferred, approvalReceipt: approval.receipt },
    trust: loadGrantSignerTrust(H.trustFile),
    schemas,
    nowMs: now,
    maxApprovalAgeMs: 24 * 60 * 60 * 1000,
    maxGrantTtlMs: 300_000,                                // generous ON PURPOSE: isolate the hold bound
  });
  assert.equal(verdict.ok, false);
  assert.match(verdict.ok ? "" : verdict.reason, /may not outlive its hold/);
});

test("F5c CONTROL: a grant ending exactly WITH its hold is still accepted", () => {
  // Without this, F5a/F5b would also pass against a validator that refused everything — the failure
  // mode this repository has already caught once inside its own security tests.
  const E = freshHold("chain-outlive-ok");
  const approval = signPhoneDecision({ trust: H.trust, signer: H.phone, deferredReceipt: E.deferred, holdEnvelope: E.holdEnvelope, decision: "APPROVE" });
  const expiry = Date.parse(E.holdEnvelope.expiresAt);
  const now = expiry - 30_000;
  const verdict = validateGrantRequest({
    grant: grantDoc({
      grantId: "outlive-ok", holdId: E.holdId, paramsHash: E.paramsHash, holdEnvelope: E.holdEnvelope,
      approvalReceipt: approval.receipt,
      issuedAt: new Date(now).toISOString(),
      expiresAt: new Date(expiry).toISOString(),            // ends exactly with the hold
    }),
    proof: { holdEnvelope: E.holdEnvelope, decisionArtifact: approval.decisionArtifact, deferredReceipt: E.deferred, approvalReceipt: approval.receipt },
    trust: loadGrantSignerTrust(H.trustFile),
    schemas,
    nowMs: now,
    maxApprovalAgeMs: 24 * 60 * 60 * 1000,
    maxGrantTtlMs: 300_000,
  });
  assert.equal(verdict.ok, true, verdict.ok ? "" : verdict.reason);
});

test("F6 (HIGH): a spent approval stays spent across a restart", () => {
  // An in-memory-only anti-replay set records this process's uptime, not what has been authorized.
  const journal = path.join(H.dir, "f6-replay.jsonl");
  const t0 = Date.now();
  const first = new ApprovalReplayStore(900_000, journal);
  assert.equal(first.claim("sha256:approval-f6", t0, t0), true);
  // A NEW instance over the same journal is what a restart looks like.
  const afterRestart = new ApprovalReplayStore(900_000, journal);
  assert.equal(afterRestart.claim("sha256:approval-f6", t0, t0 + 1000), false, "the restart must not forget a spent approval");
});

test("F7 (HIGH): retention is anchored to the approval, not to when it was first used", () => {
  // Reproduced: an approval stamped t0+60s (accepted, inside the skew allowance) first granted at
  // t0 was evicted at t0+900001ms — while still inside its own freshness window — and granted again.
  const t0 = Date.now();
  const store = new ApprovalReplayStore(900_000, null);
  assert.equal(store.claim("sha256:approval-f7", t0 + 60_000, t0), true);
  assert.equal(
    store.claim("sha256:approval-f7", t0 + 60_000, t0 + 900_001),
    false,
    "the entry must outlive the freshness window of the approval it records, not of the moment it was used",
  );
});

test("F8 (HIGH): a request that fails after validation does not burn the human's approval", () => {
  // The slot was claimed BEFORE signing and BEFORE the schema self-check, so one schema-forbidden
  // extra property on the submitted document permanently wedged a genuine approval.
  const G = freshHold("chain-wedge");
  const approval = signPhoneDecision({ trust: H.trust, signer: H.phone, deferredReceipt: G.deferred, holdEnvelope: G.holdEnvelope, decision: "APPROVE" });
  const proof = { holdEnvelope: G.holdEnvelope, decisionArtifact: approval.decisionArtifact, deferredReceipt: G.deferred, approvalReceipt: approval.receipt };
  const base = grantDoc({ grantId: "wedge-1", holdId: G.holdId, paramsHash: G.paramsHash, holdEnvelope: G.holdEnvelope, approvalReceipt: approval.receipt });

  const rejected = rawCall({ op: "sign-grant", artifact: { ...base, smuggled: "extra" }, proof });
  assert.equal(rejected["artifact"], undefined);
  assert.match(String(rejected["error"]), /fails its own schema/);

  // THE POINT: the same approval must still be usable. A refusal that costs a human another tap is
  // a denial-of-service delivered by the security control.
  const accepted = rawCall({ op: "sign-grant", artifact: base, proof });
  assert.ok(accepted["artifact"], `the approval was burnt by a refused request: ${String(accepted["error"])}`);
});

test("F9 (HIGH): a gate refuses to hold a grant key unless the unsafe posture is stated", () => {
  // Protection was the opt-in and the defect was the default. For an authority root that is
  // backwards: the UNSAFE configuration is the one that must be typed out.
  const trust = createAlphaTrust({ tenant: "t" });
  assert.throws(
    () => new GateEngine({ store: new InMemoryStore(), config: resolveGateConfig({}), trust, schemas }),
    /unsafeInProcessGrantKey/,
  );
  // ANTI-VACUITY: stating it explicitly still works, or every existing test would be measuring the
  // throw rather than the gate.
  assert.ok(new GateEngine({ store: new InMemoryStore(), config: resolveGateConfig({}), trust, schemas, unsafeInProcessGrantKey: true }));
});

test("F11 (HIGH): the trust file and the socket directory are held to their own permissions", () => {
  // This file decides WHICH KEYS MAY APPROVE. It was read with a plain readFileSync on a path: a
  // symlink was followed, the mode was never looked at.
  const groupWritable = path.join(H.dir, "f11-trust.json");
  writeFileSync(groupWritable, readFileSync(H.trustFile, "utf8"), { mode: 0o660 });
  chmodSync(groupWritable, 0o660);
  assert.throws(() => loadGrantSignerTrust(groupWritable), /writable by group or others/);

  const link = path.join(H.dir, "f11-link.json");
  symlinkSync(H.trustFile, link);
  assert.throws(() => loadGrantSignerTrust(link), /is a symlink/);

  // A group-writable socket directory lets anyone in that group unlink the socket and bind their
  // own listener in its place — a full impersonation of the authority root.
  const openDir = path.join(H.dir, "f11-dir");
  mkdirSync(openDir, { mode: 0o770 });
  chmodSync(openDir, 0o770);
  assert.throws(() => assertSocketDirIsNotWorldAccessible(path.join(openDir, "s.sock")), /world-accessible or group-writable/);
  // ANTI-VACUITY: the deployment posture this rule exists to permit — group READ + traverse, for a
  // sidecar running as a different OS user — is still allowed.
  const sharedDir = path.join(H.dir, "f11-shared");
  mkdirSync(sharedDir, { mode: 0o750 });
  chmodSync(sharedDir, 0o750);
  assert.doesNotThrow(() => assertSocketDirIsNotWorldAccessible(path.join(sharedDir, "s.sock")));
});

test("F12 (MEDIUM): a signing failure inside the background sweep does not kill the gate", async () => {
  // Before the execution signer moved out of process these sweepers could not fail: they signed
  // with a local key. Now a socket hiccup inside `sweepExpired` reaches a `setInterval` callback,
  // and an uncaught throw there takes the whole process down — a custody improvement shipping an
  // availability regression alongside it.
  const clock = { t: Date.parse("2026-07-14T12:00:00Z") };
  const trust = createAlphaTrust({ tenant: "sweep-tenant", now: () => clock.t });
  const events: string[] = [];
  const exploding: ExecutionSigner = {
    kid: trust.gate.kid,
    publicKey: trust.gate.publicKey,
    signGrant: () => { throw new Error("signer unreachable"); },
    signAttestation: () => { throw new Error("signer unreachable"); },
  };
  const store = new InMemoryStore();
  const apiKey = "noa_gateagent_sweep-secret-000000";
  store.putAgent({ id: "agent-sweep", name: "sweep", apiKeyHash: hashSecret(apiKey), createdAt: clock.t });
  const gate = createGate({
    trust,
    store,
    schemas,
    sealDisplay: testSealer,
    executionSigner: exploding,
    config: { bindAddress: "127.0.0.1", port: 0, now: () => clock.t, expirySweepMs: 10 },
    log: (event) => events.push(event),
  });
  await gate.listen();
  try {
    const created = gate.engine.createHold(store.findAgentByApiKeyHash(hashSecret(apiKey))!, "idem-sweep", body({
      mode: "ENFORCED",
      action: { canonical: "noa.command.exec", riskClass: "HIGH", reversible: false },
      params: sampleCommandParams(),
      chain: "chain-sweep",
    }));
    assert.equal(created.status, 201, JSON.stringify(created.body));
    // Push the hold past its TTL so the sweeper tries to mint a Hold Resolution — and fails.
    clock.t += 60 * 60 * 1000;
    await new Promise((r) => setTimeout(r, 120));
    // If the throw had escaped the interval, this process would be gone and there would be no
    // assertion to run. Reaching this line at all is half the measurement; the log is the other.
    assert.ok(events.includes("sweep.failed"), `expected the failure to be recorded, saw ${JSON.stringify(events)}`);
    // FAIL-CLOSED, not fail-quiet: the hold is still PENDING, so nothing was resolved without its
    // attestation and the next tick will try again.
    assert.equal(store.getHold((created.body as { holdId: string }).holdId)!.status, "PENDING");
  } finally {
    await gate.close();
  }
});
