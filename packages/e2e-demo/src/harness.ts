/**
 * The orchestrator: it stands up the real §8 gate + §9 relay on loopback, runs the §3 pairing
 * ceremony so the gate trusts the phone's device key, and drives ONE end-to-end approval flow with
 * the fake agent, the headless phone, and the untrusted-transport bridge running concurrently. It
 * signs NOTHING itself — every signature originates at the gate (gate/policy key) or the phone
 * (device key). It plays the human operator for the out-of-band SAS comparison (the §3 trust anchor)
 * and cleans up every process + port at the end.
 */
import { createGate, hashSecret, guard, type Gate, type AgentRecord, type DisplaySealer, type EncryptedDisplay, type GateClient, type EngineResult } from 'noa-gate';
import { createRelay, type Relay } from 'noa-relay';
import { sealEncryptedDisplay } from 'noa-signer';
import { mobileRefHash } from './mobile.js';
import type { Receipt } from 'noa-receipt';
import type { EvidenceOutcome } from 'noa-approval-evidence';
import { makeClock, makeIds, type Clock } from './support.js';
import { createLogger, type Logger } from './log.js';
import { DemoError, pollUntil } from './errors.js';
import { createDemoAuthority, issueChallenge, gateDeriveSas, acceptPairing, assembleGateTrust, type DemoAuthority } from './pairing.js';
import { HeadlessPhone, type PhoneHold } from './phone.js';
import { sasEquals } from './mobile.js';
import { GateRelayBridge, PhoneRelayClient, registerRelayAgent, registerRelayDevice } from './relay-transport.js';
import { runFakeAgent, makeHarmlessExecute, deployCommandParams, type ExecuteSpy } from './agent.js';
import { assembleBundle, verifyBundle, type FlowArtifacts } from './evidence.js';
import type { KeyEntry } from 'noa-approval-artifacts';
import type { GateTrust } from 'noa-gate';
import type { GuardResult } from 'noa-gate';
import type { VerifyEvidenceResult } from 'noa-approval-evidence';

const TENANT = 'acme-tenant';
const PILOT_CANONICAL = 'noa.command.exec';
const PILOT_RISK = 'HIGH';
const GATE_AGENT_KEY = 'noa_gateagent_demo-secret-0001';

type J = Record<string, unknown>;

/**
 * REAL HPKE display sealer (D15-v2) — the gate's injected `@noa/signer` job (KURAL 5: the gate never
 * reimplements HPKE, it only BINDS the sealed object via `displayCiphertextHash`, F2). It produces a
 * genuine `noa.encrypted-display/0.1`: the whole human-readable display is ChaCha20Poly1305-encrypted
 * under a random CEK, and that CEK is HPKE-wrapped (RFC 9180 base mode, X25519-HKDF-SHA256) to each
 * recipient device's X25519 public key. Only a device holding the matching secret can read it — the
 * gate holds no secret. This replaces the earlier structural stub end-to-end.
 */
function realDisplaySealer(): DisplaySealer {
  return ({ tenant, holdId, deferredReceiptHash, expiresAt, display, recipients }) =>
    sealEncryptedDisplay({ tenant, holdId, deferredReceiptHash, expiresAt, display, recipients }) as EncryptedDisplay;
}

export interface HarnessContext {
  clock: Clock;
  ids: () => string;
  logger: Logger;
  authority: DemoAuthority;
  phone: HeadlessPhone;
  trust: GateTrust;
  tenantRoot: Record<string, KeyEntry>;
  gate: Gate;
  relay: Relay;
  gateBaseUrl: string;
  relayBaseUrl: string;
  bridge: GateRelayBridge;
  phoneClient: PhoneRelayClient;
  gateHoldQueue: string[];
}

/** Stand up a fully-wired, freshly-paired demo (own gate + relay + phone). Caller teardown()s it. */
export async function setupHarness(opts: { echo?: boolean; sink?: string[] } = {}): Promise<HarnessContext> {
  const clock = makeClock();
  const ids = makeIds('demo');
  const logger = createLogger({ scope: 'demo', echo: opts.echo ?? false, ...(opts.sink ? { sink: opts.sink } : {}) });

  // 1. Gate + tenant-authority key world + the phone (device key generated on-device).
  const authority = createDemoAuthority(TENANT, clock);
  const phone = await HeadlessPhone.create(logger.child('phone'));

  // 2. The §3 pairing ceremony — the operator (this harness) compares the two independently-derived
  //    SAS strings; manifest issuance proceeds ONLY on a match (the trust anchor, never transmitted).
  const pairingId = 'pair-' + ids();
  const challenge = issueChallenge(authority, pairingId, clock);
  const { confirmation, transcript, sas: phoneSas } = await phone.pairBegin(challenge, TENANT, clock.iso());
  const { sas: gateSas } = gateDeriveSas(authority, confirmation);
  if (!sasEquals(phoneSas, gateSas)) {
    throw new DemoError('PAIRING', 'PAIRING_SAS_MISMATCH', 'operator SAS comparison failed', { phoneSas, gateSas });
  }
  logger.event('pairing.sas_matched', { sas: phoneSas });
  const phoneKeys = { approverKid: phone.approverKid, approverPublicKey: phone.approverPublicKey, approverHpkePublicKey: phone.hpkePublicKeyHex };
  const accept = acceptPairing(authority, confirmation, transcript, phoneKeys, clock);
  phone.pairFinish({ accepted: accept.accepted, localConfirmation: accept.localConfirmation, delegation: accept.delegation, manifest: accept.manifest, transcript, challenge, nowIso: clock.iso() });
  const { trust, tenantRoot } = assembleGateTrust(authority, accept.manifest, accept.manifestHash, phoneKeys, clock, ids);

  // 3. Real loopback gate + relay (ephemeral ports, no collision). The gate log hook feeds the
  //    hold-created event to the bridge; both share the injected clock.
  const gateHoldQueue: string[] = [];
  const gate = createGate({
    trust,
    config: { port: 0, now: () => clock.now() },
    sealDisplay: realDisplaySealer(),
    log: (event, fields) => {
      logger.child('gate').event(event, fields);
      if (event === 'hold.created' && typeof fields['holdId'] === 'string') gateHoldQueue.push(fields['holdId']);
    },
  });
  const relay = createRelay({ config: { port: 0, now: () => clock.now() }, log: (event, fields) => logger.child('relay').event(event, fields) });

  // register the gate-side agent credential (the gate has no pairing endpoint; agents are provisioned).
  const gateAgent: AgentRecord = { id: 'gate-agent-1', name: 'demo-agent', apiKeyHash: hashSecret(GATE_AGENT_KEY), createdAt: clock.now() };
  gate.store.putAgent(gateAgent);

  const g = await gate.listen();
  const r = await relay.listen();
  const gateBaseUrl = `http://127.0.0.1:${g.port}`;
  const relayBaseUrl = `http://127.0.0.1:${r.port}`;

  // 4. Onboard the transport bridge (relay agent) + the phone (relay device).
  const { apiKey: relayAgentKey } = await registerRelayAgent(relayBaseUrl, 'demo-bridge');
  const bridge = new GateRelayBridge(relayBaseUrl, relayAgentKey, logger.child('bridge'));
  const { deviceSecret } = await registerRelayDevice(relayBaseUrl, phone.approverKid, phone.approverPublicKeyRawHex);
  const phoneClient = new PhoneRelayClient(relayBaseUrl, deviceSecret, logger.child('phone'));

  logger.event('harness.ready', { gate: g.port, relay: r.port, tenant: TENANT, approverKid: phone.approverKid });
  return { clock, ids, logger, authority, phone, trust, tenantRoot, gate, relay, gateBaseUrl, relayBaseUrl, bridge, phoneClient, gateHoldQueue };
}

export async function teardownHarness(ctx: HarnessContext): Promise<void> {
  await ctx.gate.close();
  await ctx.relay.close();
  ctx.logger.event('harness.torn_down', {});
}

/** Forward the phone's decision from the relay to the gate over HTTP (D18 re-verification path). */
async function forwardDecisionToGate(ctx: HarnessContext, gateHoldId: string, decisionReceipt: unknown, decisionArtifact: unknown): Promise<{ status: number; body: J | null }> {
  const res = await fetch(`${ctx.gateBaseUrl}/v1/holds/${encodeURIComponent(gateHoldId)}/decision`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${GATE_AGENT_KEY}` },
    body: JSON.stringify({ receipt: decisionReceipt, decisionArtifact }),
  });
  const body = (await res.json().catch(() => null)) as J | null;
  return { status: res.status, body };
}

export interface ApprovedFlowResult {
  outcome: EvidenceOutcome;
  guardResult: GuardResult;
  executeSpy: ExecuteSpy;
  artifacts: FlowArtifacts;
  bundle: ReturnType<typeof assembleBundle>;
  verdict: VerifyEvidenceResult;
  gateHoldId: string;
  elapsedMs: number;
}

/**
 * The gate→relay→phone→relay→gate happy/deny flow. The agent's `guard` blocks on the gate long-poll;
 * concurrently the bridge carries the hold to the relay and the phone verifies (D2) + signs the
 * decision + posts it back; the bridge forwards it to the gate, waking `guard`. Deterministic:
 * every wait is an event/poll-until with a deadline, never a fixed sleep.
 */
export async function runApprovedFlow(ctx: HarnessContext, decision: 'APPROVE' | 'DENY'): Promise<ApprovedFlowResult> {
  const chain = 'chain-' + ctx.ids();
  const idem = 'idem-' + ctx.ids();
  const { execute, spy } = makeHarmlessExecute(ctx.logger.child('agent'));
  const started = Date.now();

  // Background: carry the hold to the relay, run the phone, forward the decision to the gate.
  const carryTask = (async (): Promise<void> => {
    const gateHoldId = await pollUntil(() => ctx.gateHoldQueue.shift(), { timeoutMs: 10_000, what: 'gate hold.created', layer: 'BRIDGE', code: 'BRIDGE_NO_GATE_HOLD' });
    const gh = ctx.gate.store.getHold(gateHoldId);
    if (!gh || !gh.holdEnvelope || !gh.deferredReceipt || !gh.encryptedDisplay) {
      throw new DemoError('BRIDGE', 'BRIDGE_NO_GATE_HOLD', 'gate hold missing envelope/deferred/display', { gateHoldId });
    }
    const relayHoldId = await ctx.bridge.pushHold('bridge-' + ctx.ids(), {
      action: { canonical: gh.action.canonical, riskClass: gh.action.riskClass, paramsHash: gh.action.paramsHash },
      holdEnvelope: gh.holdEnvelope,
      deferredReceipt: gh.deferredReceipt,
      encryptedDisplay: gh.encryptedDisplay,
    });

    // Phone: inbox (HTTP) → display (HTTP) → D2 verify (gate-signed envelope+deferred the relay carried) → sign → post (HTTP).
    await pollUntil(async () => {
      const inbox = await ctx.phoneClient.pollInbox();
      return inbox.some((h) => h.holdId === relayHoldId) ? true : undefined;
    }, { timeoutMs: 10_000, what: 'relay inbox notification', layer: 'RELAY', code: 'RELAY_DECISION_REJECTED' });
    const displayHttp = await ctx.phoneClient.getDisplay(relayHoldId);
    const carried = ctx.relay.store.getHold(relayHoldId);
    if (!carried || !carried.holdEnvelope || !carried.deferredReceipt) {
      throw new DemoError('RELAY', 'RELAY_DECISION_REJECTED', 'relay did not carry the gate-signed hold context', { relayHoldId });
    }
    const phoneHold: PhoneHold = { holdEnvelope: carried.holdEnvelope as J, deferredReceipt: carried.deferredReceipt as never, encryptedDisplay: displayHttp };
    ctx.phone.verifyHoldForRender(phoneHold, ctx.clock.iso());
    const signed = await ctx.phone.signDecision(decision, phoneHold, ctx.clock.iso());
    const posted = await ctx.phoneClient.postDecision(relayHoldId, signed);
    if (posted.status !== 200) throw new DemoError('RELAY', 'RELAY_DECISION_REJECTED', 'relay rejected the device-signed decision', { status: posted.status, body: posted.body });

    // Bridge: read the decision from the relay, forward it to the gate (D18 re-verify).
    const dec = await pollUntil(() => ctx.bridge.readDecision(relayHoldId), { timeoutMs: 10_000, what: 'phone decision at relay', layer: 'BRIDGE', code: 'BRIDGE_NO_DECISION' });
    const fwd = await forwardDecisionToGate(ctx, gateHoldId, dec.decisionReceipt, dec.decisionArtifact);
    if (fwd.status !== 200) throw new DemoError('GATE', 'GATE_DECISION_REJECTED', 'gate rejected the forwarded decision', { status: fwd.status, body: fwd.body });
  })();

  const guardResult = await runFakeAgent({
    gateBaseUrl: ctx.gateBaseUrl,
    apiKey: GATE_AGENT_KEY,
    canonical: PILOT_CANONICAL,
    riskClass: PILOT_RISK,
    params: deployCommandParams(),
    chain,
    idempotencyKey: idem,
    waitMs: 15_000,
    execute,
    log: ctx.logger.child('agent'),
  });
  await carryTask;

  const elapsedMs = Date.now() - started;
  const outcome: EvidenceOutcome = decision === 'APPROVE' ? 'EXECUTED' : 'DENIED';
  const gateHoldId = guardResult.holdId ?? '';
  const hold = ctx.gate.store.getHold(gateHoldId);
  if (!hold) throw new DemoError('ORCHESTRATION', 'INVARIANT_VIOLATION', 'gate hold vanished after the flow', { gateHoldId });

  const artifacts: FlowArtifacts = {
    holdEnvelope: hold.holdEnvelope,
    deferredReceipt: hold.deferredReceipt as unknown as Receipt,
    holdResolution: hold.holdResolution,
    keyManifest: ctx.trust.keyManifest,
    keyDelegation: ctx.trust.keyDelegation,
    decisionArtifact: hold.decisionArtifact,
    ...(decision === 'APPROVE'
      ? {
          allowedReceipt: hold.verdictReceipt as unknown as Receipt,
          executionGrant: guardResult.grantId ? ctx.gate.store.getGrant(guardResult.grantId)?.grant : undefined,
          executionConsumption: guardResult.consumption,
          executedReceipt: guardResult.attemptReceipt as Receipt,
        }
      : { blockedReceipt: hold.verdictReceipt as unknown as Receipt }),
  };

  const bundle = assembleBundle(outcome, artifacts, ctx.trust, ctx.clock);
  const verdict = verifyBundle(bundle, ctx.trust, ctx.tenantRoot, ctx.clock);
  return { outcome, guardResult, executeSpy: spy, artifacts, bundle, verdict, gateHoldId, elapsedMs };
}

// ── scenario (c): timeout → POLICY-signed BLOCKED receipt ──────────────────────────────────────

export interface TimeoutFlowResult {
  outcome: EvidenceOutcome; // EXPIRED
  gateHoldId: string;
  timeoutReceipt: Receipt;
  deferredReceipt: Receipt;
  bundle: ReturnType<typeof assembleBundle>;
  verdict: VerifyEvidenceResult;
}

/**
 * The agent freezes an action; the phone never decides. The gate's TTL elapses (deterministically —
 * the clock is advanced, no wall-clock sleep) and the gate mints the D19 timeout receipt: verdict
 * BLOCKED, ruleId `approval-timeout`, POLICY signer — never ALLOWED, never a human denial.
 */
export async function runTimeoutFlow(ctx: HarnessContext): Promise<TimeoutFlowResult> {
  const chain = 'chain-' + ctx.ids();
  const idem = 'idem-' + ctx.ids();
  const ttlMs = ctx.gate.config.minTtlMs;
  const res = await fetch(`${ctx.gateBaseUrl}/v1/holds`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${GATE_AGENT_KEY}`, 'idempotency-key': idem },
    body: JSON.stringify({ mode: 'ENFORCED', action: { canonical: PILOT_CANONICAL, riskClass: PILOT_RISK }, params: deployCommandParams(), chain, ttlMs }),
  });
  const body = (await res.json().catch(() => null)) as J | null;
  const gateHoldId = body && typeof body['holdId'] === 'string' ? (body['holdId'] as string) : '';
  if (res.status !== 201 || !gateHoldId) throw new DemoError('GATE', 'GATE_HOLD_FAILED', 'could not freeze the hold', { status: res.status, body });

  // Advance past the TTL and run the gate's own expiry sweep — deterministic, no sleep-race.
  ctx.clock.advance(ttlMs + 1000);
  ctx.gate.engine.sweepExpired();

  const hold = ctx.gate.store.getHold(gateHoldId);
  if (!hold || hold.status !== 'EXPIRED' || !hold.verdictReceipt || !hold.holdResolution) {
    throw new DemoError('GATE', 'GATE_UNEXPECTED_STATUS', 'hold did not expire to a POLICY timeout receipt', { status: hold?.status });
  }
  const timeoutReceipt = hold.verdictReceipt as unknown as Receipt;
  const artifacts: FlowArtifacts = {
    holdEnvelope: hold.holdEnvelope,
    deferredReceipt: hold.deferredReceipt as unknown as Receipt,
    holdResolution: hold.holdResolution,
    keyManifest: ctx.trust.keyManifest,
    keyDelegation: ctx.trust.keyDelegation,
    timeoutReceipt,
  };
  const bundle = assembleBundle('EXPIRED', artifacts, ctx.trust, ctx.clock);
  const verdict = verifyBundle(bundle, ctx.trust, ctx.tenantRoot, ctx.clock);
  return { outcome: 'EXPIRED', gateHoldId, timeoutReceipt, deferredReceipt: hold.deferredReceipt as unknown as Receipt, bundle, verdict };
}

// ── scenario (d): a tampered decision is rejected by the gate ───────────────────────────────────

export interface TamperFlowResult {
  gateStatus: number;
  gateBody: J | null;
  holdStatusAfter: string;
  grantIdAfter: string | null;
}

/**
 * The phone signs a valid APPROVE decision; the transport tampers the verdict receipt's signature.
 * The gate's D18 re-verification MUST reject it (the chain signature no longer verifies) — the hold
 * stays PENDING and no Execution Grant is ever issued, so the action cannot run.
 */
export async function runTamperFlow(ctx: HarnessContext): Promise<TamperFlowResult> {
  const chain = 'chain-' + ctx.ids();
  const idem = 'idem-' + ctx.ids();
  const res = await fetch(`${ctx.gateBaseUrl}/v1/holds`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${GATE_AGENT_KEY}`, 'idempotency-key': idem },
    body: JSON.stringify({ mode: 'ENFORCED', action: { canonical: PILOT_CANONICAL, riskClass: PILOT_RISK }, params: deployCommandParams(), chain }),
  });
  const created = (await res.json().catch(() => null)) as J | null;
  const gateHoldId = created && typeof created['holdId'] === 'string' ? (created['holdId'] as string) : '';
  if (res.status !== 201 || !gateHoldId) throw new DemoError('GATE', 'GATE_HOLD_FAILED', 'could not freeze the hold', { status: res.status });

  const hold = ctx.gate.store.getHold(gateHoldId);
  if (!hold || !hold.holdEnvelope || !hold.deferredReceipt || !hold.encryptedDisplay) {
    throw new DemoError('ORCHESTRATION', 'INVARIANT_VIOLATION', 'gate hold missing context', { gateHoldId });
  }
  const phoneHold: PhoneHold = { holdEnvelope: hold.holdEnvelope as unknown as J, deferredReceipt: hold.deferredReceipt as never, encryptedDisplay: hold.encryptedDisplay as unknown as J };
  ctx.phone.verifyHoldForRender(phoneHold, ctx.clock.iso());
  const signed = await ctx.phone.signDecision('APPROVE', phoneHold, ctx.clock.iso());

  // TAMPER: replace the verdict-receipt signature with a same-length but invalid value.
  const tamperedReceipt = JSON.parse(JSON.stringify(signed.receipt)) as { sig: { value: string } };
  tamperedReceipt.sig.value = 'A'.repeat(signed.receipt.sig.value.length);

  const fwd = await forwardDecisionToGate(ctx, gateHoldId, tamperedReceipt, signed.decisionArtifact);
  const after = ctx.gate.store.getHold(gateHoldId);
  return { gateStatus: fwd.status, gateBody: fwd.body, holdStatusAfter: after?.status ?? 'UNKNOWN', grantIdAfter: after?.grantId ?? null };
}

// ── scenario (e): the exact-execution wrapper refuses a params mismatch (approve A, run B) ───────

/** A stub gate transport that returns an APPROVED grant bound to a DIFFERENT paramsHash than the
 *  wrapper's action derives. Exercises the D14 refusal in isolation (approve A / run B). It records
 *  whether reserve/report were reached — they must NOT be. */
class MismatchStubClient implements GateClient {
  reserveCalled = false;
  reportCalled = false;
  createHold(): Promise<EngineResult> {
    return Promise.resolve({ status: 201, body: { holdId: 'stub-hold', status: 'PENDING' } });
  }
  wait(): Promise<EngineResult> {
    return Promise.resolve({ status: 200, body: { status: 'APPROVED', grantId: 'stub-grant', executionGrant: { grantId: 'stub-grant', paramsHash: 'sha256:' + '0'.repeat(64) } } });
  }
  reserve(): Promise<EngineResult> {
    this.reserveCalled = true;
    return Promise.resolve({ status: 200, body: { status: 'RESERVED' } });
  }
  report(): Promise<EngineResult> {
    this.reportCalled = true;
    return Promise.resolve({ status: 200, body: {} });
  }
}

export interface MismatchProbeResult {
  guardResult: GuardResult;
  executeSpy: ExecuteSpy;
  reserveCalled: boolean;
}

/** The D14 exact-execution refusal: the grant authorizes params A, the wrapper would run params B →
 *  the wrapper refuses BEFORE reserving, and the side effect never runs. */
export async function runParamsMismatchProbe(logger: Logger): Promise<MismatchProbeResult> {
  const client = new MismatchStubClient();
  const { execute, spy } = makeHarmlessExecute(logger.child('agent'));
  const guardResult = await guard({
    client,
    action: { canonical: PILOT_CANONICAL, riskClass: PILOT_RISK },
    params: deployCommandParams(),
    mode: 'ENFORCED',
    idempotencyKey: 'mismatch-1',
    waitMs: 5_000,
    execute,
  });
  return { guardResult, executeSpy: spy, reserveCalled: client.reserveCalled };
}

// ── scenario (f): the gate HPKE-seals the display; the phone decrypts it locally to the exact plaintext ─

export interface EncryptedDisplayProbe {
  /** The display the gate sealed (RAW mode: caller-supplied, so we have the exact expected plaintext). */
  knownDisplay: J;
  /** What the phone recovered by HPKE-decrypting with its device X25519 secret. */
  openedDisplay: J;
  /** true iff the payload is real AEAD ciphertext (the old structural stub was base64(JSON)). */
  isRealHpke: boolean;
  /** F2: refHash of the WHOLE encrypted-display object, and the value the gate signed into the envelope. */
  actualDisplayHash: string;
  envelopeDisplayHash: string;
  /** true iff the phone REFUSED a tampered encrypted display (never rendered it). */
  tamperRejected: boolean;
  tamperErrorCode: string | null;
}

/**
 * Freeze a RAW hold with a KNOWN human-readable display, let the gate seal it with real HPKE, and
 * have the headless phone decrypt it locally (its X25519 device secret never leaves it). Proves the
 * "gate encrypts the screen → phone opens it → shows the exact plaintext" claim end-to-end, plus the
 * F2 whole-object binding and the fail-closed refusal of a tampered display.
 */
export async function runEncryptedDisplayRoundTrip(ctx: HarnessContext): Promise<EncryptedDisplayProbe> {
  const chain = 'chain-' + ctx.ids();
  const idem = 'idem-' + ctx.ids();
  const knownDisplay: J = {
    title: 'Wire transfer approval',
    amountMinor: 420000, // integer minor units (€4,200.00)
    currency: 'EUR',
    to: 'ACME GmbH',
    memo: 'invoice 2026-0715',
  };
  const paramsHash = 'sha256:' + 'a'.repeat(64);
  const res = await fetch(`${ctx.gateBaseUrl}/v1/holds`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${GATE_AGENT_KEY}`, 'idempotency-key': idem },
    body: JSON.stringify({ mode: 'RAW', action: { canonical: 'noa.custom.wire', riskClass: 'HIGH', paramsHash }, display: knownDisplay, chain }),
  });
  const body = (await res.json().catch(() => null)) as J | null;
  const gateHoldId = body && typeof body['holdId'] === 'string' ? (body['holdId'] as string) : '';
  if (res.status !== 201 || !gateHoldId) throw new DemoError('GATE', 'GATE_HOLD_FAILED', 'RAW hold for the encrypted-display probe failed', { status: res.status, body });

  const hold = ctx.gate.store.getHold(gateHoldId);
  if (!hold || !hold.holdEnvelope || !hold.deferredReceipt || !hold.encryptedDisplay) {
    throw new DemoError('ORCHESTRATION', 'INVARIANT_VIOLATION', 'gate hold missing context for the display probe', { gateHoldId });
  }
  const encryptedDisplay = hold.encryptedDisplay as unknown as J;

  // The phone decrypts locally as part of its D2 pre-render verification (real AEAD open inside).
  const phoneHold: PhoneHold = { holdEnvelope: hold.holdEnvelope as unknown as J, deferredReceipt: hold.deferredReceipt as never, encryptedDisplay };
  const view = ctx.phone.verifyHoldForRender(phoneHold, ctx.clock.iso());

  // Real HPKE, not the old stub: the stub's ciphertext was base64(JSON) and would parse straight back.
  const payload = (encryptedDisplay['payload'] ?? {}) as { ciphertext?: string };
  let isRealHpke = true;
  try {
    JSON.parse(Buffer.from(String(payload.ciphertext), 'base64').toString('utf8'));
    isRealHpke = false;
  } catch {
    isRealHpke = true;
  }

  const envelopeDisplayHash = String((hold.holdEnvelope as unknown as J)['displayCiphertextHash']);
  const actualDisplayHash = mobileRefHash(encryptedDisplay);

  // Negative: a tampered display must be refused by the phone (the F2 whole-object binding breaks).
  let tamperRejected = false;
  let tamperErrorCode: string | null = null;
  const tampered = JSON.parse(JSON.stringify(encryptedDisplay)) as J;
  (tampered['payload'] as { ciphertext: string }).ciphertext = Buffer.from('tampered', 'utf8').toString('base64');
  try {
    ctx.phone.verifyHoldForRender({ holdEnvelope: hold.holdEnvelope as unknown as J, deferredReceipt: hold.deferredReceipt as never, encryptedDisplay: tampered }, ctx.clock.iso());
  } catch (e) {
    tamperRejected = true;
    tamperErrorCode = e instanceof DemoError ? e.code : 'UNKNOWN';
  }

  return { knownDisplay, openedDisplay: view.display, isRealHpke, actualDisplayHash, envelopeDisplayHash, tamperRejected, tamperErrorCode };
}
