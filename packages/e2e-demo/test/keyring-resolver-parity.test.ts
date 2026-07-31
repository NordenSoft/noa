/**
 * P0-8 — KEYRING RESOLVER PARITY, proven at the REAL verifier (2026-07-31).
 *
 * ─── THE DEFECT THIS PINS ───────────────────────────────────────────────────────────────────────
 *
 * `assembleGateTrust` (`src/pairing.ts`) built the LIVE keyring — the exact map the gate engine
 * hands to `verifyArtifact` for Decision verification (`gate/src/engine.ts:711`) — with
 * `revokedAt: null` and NO `validFrom` on all four entries, while the v2 Key Manifest signed in
 * the SAME FILE declares `validFrom` on every key. `KeyEntry.validFrom` is optional and
 * `verify.ts` enforces activation only when the field is non-null, so the declared activation
 * window was silently open at one end on the golden live path. The `tenantRoot` map returned by
 * the same function had the same omission. This was the SEVENTH resolver of this class (after
 * P0-1's ROOT map and P0-5's gate live keyring), found after the inventory had twice been
 * declared complete — which is why these tests exist per-resolver and the resolver census is now
 * reconciled mechanically (`scripts/lint-resolver-parity.mjs`).
 *
 * ─── THE NORMATIVE RULE (all resolvers, one sentence) ───────────────────────────────────────────
 *
 * A DECLARED `validFrom`/`revokedAt` is CARRIED into every produced KeyEntry and ENFORCED by the
 * consuming verifier; an UNDECLARED value stays ABSENT (documented legacy always-active — no
 * default is invented); a MALFORMED declared value is CARRIED so the verifier fails CLOSED
 * ("cannot evaluate activation time"), never dropped (dropping would skip the check and fail
 * OPEN).
 *
 * Proof IDs referenced by scripts/resolver-inventory.json — do not rename without updating it:
 *   [PROOF:RES-PAR-E2E-KEYRING]    the pairing live keyring carries + the verifier enforces
 *   [PROOF:RES-PAR-E2E-TENANTROOT] the external tenant root map carries
 *   [PROOF:RES-PAR-XRES-EQUIV]     evidence/gate/e2e resolvers agree at the verifier
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createAlphaTrust, loadSchemas } from 'noa-gate';
import {
  ARTIFACTS,
  generateKeyPair,
  signArtifact,
  verifyArtifact,
  type KeyEntry,
} from 'noa-approval-artifacts';
import {
  asRootKeyEntryMap,
  buildResolvedKeyring,
  type DelegationDoc,
  type ManifestDoc,
} from 'noa-approval-evidence';
import {
  createDemoAuthority,
  issueChallenge,
  gateDeriveSas,
  acceptPairing,
  assembleGateTrust,
  type DemoAuthority,
} from '../src/pairing.js';
import { HeadlessPhone } from '../src/phone.js';
import { sasEquals } from '../src/mobile.js';
import { makeClock, makeIds, type Clock } from '../src/support.js';
import { createLogger } from '../src/log.js';
import { encodeDocument } from '../src/bytes.js';
import type { GateTrust } from 'noa-gate';

const TENANT = 'acme-tenant';
const schemas = loadSchemas();

type J = Record<string, unknown>;
const enc = (o: unknown): Uint8Array => encodeDocument(o as J);

/** ARTIFACTS lookup under noUncheckedIndexedAccess: a missing domain is a fixture bug. */
function domainOf(spec: string): string {
  const d = ARTIFACTS[spec]?.domain;
  assert.ok(typeof d === 'string', `fixture: no signing domain registered for ${spec}`);
  return d;
}

/** Index access under noUncheckedIndexedAccess: a missing entry is a fixture bug, not a result. */
function entryOf(map: Record<string, KeyEntry>, kid: string, what: string): KeyEntry {
  const e = map[kid];
  assert.ok(e !== undefined, `fixture: ${what} has no entry for kid "${kid}"`);
  return e;
}

/** The REAL §3 pairing ceremony, exactly as the harness runs it (SAS compare included). */
async function pairedTrust(): Promise<{
  auth: DemoAuthority;
  clock: Clock;
  trust: GateTrust;
  tenantRoot: Record<string, KeyEntry>;
}> {
  const clock = makeClock();
  const ids = makeIds('parity');
  const logger = createLogger({ scope: 'parity', echo: false });
  const auth = createDemoAuthority(TENANT, clock);
  const phone = await HeadlessPhone.create(logger.child('phone'));
  const challenge = issueChallenge(auth, 'pair-' + ids(), clock);
  const { confirmation, transcript, sas: phoneSas } = await phone.pairBegin(challenge, TENANT, clock.iso());
  const { sas: gateSas } = gateDeriveSas(auth, confirmation);
  assert.ok(sasEquals(phoneSas, gateSas), 'ceremony: SAS mismatch');
  const phoneKeys = {
    approverKid: phone.approverKid,
    approverPublicKey: phone.approverPublicKey,
    approverHpkePublicKey: phone.hpkePublicKeyHex,
  };
  const accept = acceptPairing(auth, confirmation, transcript, phoneKeys, clock);
  phone.pairFinish({
    accepted: accept.accepted,
    localConfirmation: accept.localConfirmation,
    delegation: accept.delegation,
    manifest: accept.manifest,
    transcript,
    challenge,
    nowIso: clock.iso(),
  });
  const { trust, tenantRoot } = assembleGateTrust(auth, accept.manifest, accept.manifestHash, phoneKeys, clock, ids);
  return { auth, clock, trust, tenantRoot };
}

/** Re-sign the REAL v2 manifest with a chosen issuedAt, using the REAL delegated authority key.
 *  `verifyArtifact` resolves a key-manifest's artifact time from `doc.issuedAt`, so this is the
 *  activation probe for the DELEGATED entry of whatever keyring is passed in. */
function manifestIssuedAt(auth: DemoAuthority, manifest: unknown, issuedAt: string): J {
  const { sig: _sig, ...unsigned } = manifest as J;
  return signArtifact(enc({ ...unsigned, issuedAt }), 'NOA-KeyManifest-v0.1-sig', {
    kid: auth.authority.kid,
    privateKey: auth.authority.privateKey,
  });
}

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// THE DEFECT — declared activation must SURVIVE the resolver, or the verifier cannot enforce it.
// ─────────────────────────────────────────────────────────────────────────────────────────────────

test('[PROOF:RES-PAR-E2E-KEYRING] the live keyring CARRIES the declared activation on every entry', async () => {
  const { auth, trust } = await pairedTrust();
  for (const [kid, what] of [
    [trust.gate.kid, 'GATE'],
    [trust.approver.kid, 'APPROVER'],
    [auth.authority.kid, 'DELEGATED'],
    [auth.root.kid, 'ROOT'],
  ] as const) {
    const e = entryOf(trust.keyring, kid, `live keyring (${what})`);
    assert.equal(
      e.validFrom,
      auth.validFrom,
      `${what} keyring entry dropped its declared validFrom — the v2 manifest in the same file ` +
        `declares it, so the activation window is open at one end on the LIVE decision path ` +
        `(gate/src/engine.ts:711 verifies with exactly this map)`,
    );
    // ANTI-VACUITY sibling: revokedAt IS carried on the same branch, so a dropped validFrom is a
    // SPECIFIC omission, not a broken resolver.
    assert.equal(e.revokedAt, null, `${what} keyring entry lost its revokedAt — resolver broken`);
  }
});

test('[PROOF:RES-PAR-E2E-TENANTROOT] the external tenant root map CARRIES the declared activation', async () => {
  const { auth, tenantRoot } = await pairedTrust();
  const e = entryOf(tenantRoot, auth.root.kid, 'tenantRoot');
  assert.equal(
    e.validFrom,
    auth.validFrom,
    'the §13 external trust anchor dropped the ROOT activation — same class as P0-1, one map over',
  );
  assert.equal(e.revokedAt, null, 'tenantRoot lost revokedAt — resolver broken, not the field');
});

test('[PROOF:RES-PAR-E2E-KEYRING] ENFORCED at the real verifier: a manifest issued before the delegated signer’s activation is REFUSED through the assembled keyring', async () => {
  const { auth, clock, trust } = await pairedTrust();
  const preIso = new Date(Date.parse(auth.validFrom) - 60 * 60 * 1000).toISOString();

  const probe = manifestIssuedAt(auth, trust.keyManifest, preIso);
  const r = verifyArtifact(enc(probe), enc({ schemas, keyring: trust.keyring, now: clock.iso() }));
  assert.equal(
    r.ok,
    false,
    'a manifest stamped BEFORE the delegated signer’s own activation verified clean through the ' +
      'live keyring — the resolver dropped validFrom, so verifyArtifact skipped the check',
  );
  assert.match(r.reason ?? '', /before its validFrom/, `refused, but for the wrong reason: ${r.reason}`);

  // ANTI-VACUITY control, same run: the UNMODIFIED real manifest verifies clean through the same
  // keyring — so the refusal above is the activation check, not broken wiring.
  const ctl = verifyArtifact(enc(trust.keyManifest), enc({ schemas, keyring: trust.keyring, now: clock.iso() }));
  assert.equal(ctl.ok, true, `control failed — harness/verifier wiring broken: ${ctl.reason}`);
});

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// CROSS-RESOLVER EQUIVALENCE — every resolver, same normative semantics, at the real verifier.
// ─────────────────────────────────────────────────────────────────────────────────────────────────

const F = '2026-07-14T10:00:00.000Z'; // declared activation
const PRE = '2026-07-14T08:00:00.000Z'; // before it
const POST = '2026-07-14T12:00:00.000Z'; // after it
const REV = '2026-07-14T11:00:00.000Z'; // a declared revocation
const EXP = '2027-01-01T00:00:00.000Z';
const ENVELOPE_HASH = 'sha256:' + '1'.repeat(64);

function decisionBy(kid: string, privateKey: string, decidedAt: string): J {
  return signArtifact(
    enc({
      spec: 'noa.decision/0.1',
      holdEnvelopeHash: ENVELOPE_HASH,
      decision: 'APPROVE',
      reasonCode: 'vendor-verified',
      reasonEncryption: null,
      decidedAt,
      approverKid: kid,
    }),
    domainOf('noa.decision/0.1'),
    { kid, privateKey },
  );
}

function verdict(decision: J, keyring: Record<string, KeyEntry>): { ok: boolean; reason?: string } {
  return verifyArtifact(enc(decision), enc({ schemas, keyring, now: POST, riskClass: 'HIGH' }));
}

test('[PROOF:RES-PAR-XRES-EQUIV] evidence, gate and e2e resolvers yield the SAME activation semantics at the real verifier', async () => {
  const outcomes: Record<string, { preRefused: boolean; postAccepted: boolean }> = {};

  // ── resolver 1: evidence buildResolvedKeyring (delegation + manifest → KeyEntry map) ─────────
  {
    const root = generateKeyPair('xr-root-1');
    const authority = generateKeyPair('xr-authority-1');
    const approver = generateKeyPair('xr-approver-1');
    const revoked = generateKeyPair('xr-approver-revoked');
    const legacy = generateKeyPair('xr-approver-legacy');
    const malformed = generateKeyPair('xr-approver-malformed');
    const delegation = signArtifact(
      enc({
        spec: 'noa.key-delegation/0.1',
        tenant: TENANT,
        delegatedKid: authority.kid,
        delegatedPublicKey: authority.publicKey,
        permissions: ['key-manifest-sign'],
        validFrom: F,
        expiresAt: EXP,
      }),
      domainOf('noa.key-delegation/0.1'),
      { kid: root.kid, privateKey: root.privateKey },
    ) as unknown as DelegationDoc;
    const manifest = signArtifact(
      enc({
        spec: 'noa.key-manifest/0.1',
        tenant: TENANT,
        version: 1,
        issuedAt: POST,
        expiresAt: EXP,
        previousManifestHash: null,
        keys: [
          { kid: approver.kid, type: 'APPROVER', roles: ['approve-high'], publicKey: approver.publicKey, validFrom: F, revokedAt: null },
          { kid: revoked.kid, type: 'APPROVER', roles: ['approve-high'], publicKey: revoked.publicKey, validFrom: F, revokedAt: REV },
          // UNDECLARED activation — the documented legacy: absent stays absent, always-active.
          { kid: legacy.kid, type: 'APPROVER', roles: ['approve-high'], publicKey: legacy.publicKey, validFrom: null, revokedAt: null },
          // MALFORMED declared activation — must be CARRIED so the verifier fails CLOSED.
          { kid: malformed.kid, type: 'APPROVER', roles: ['approve-high'], publicKey: malformed.publicKey, validFrom: 'not-a-timestamp', revokedAt: null },
        ],
      }),
      domainOf('noa.key-manifest/0.1'),
      { kid: authority.kid, privateKey: authority.privateKey },
    ) as unknown as ManifestDoc;
    const keyring = buildResolvedKeyring({}, delegation, manifest);

    const pre = verdict(decisionBy(approver.kid, approver.privateKey, PRE), keyring);
    const post = verdict(decisionBy(approver.kid, approver.privateKey, POST), keyring);
    assert.match(pre.reason ?? '', /before its validFrom/, `evidence resolver: pre-activation reason: ${pre.reason}`);
    outcomes['evidence.buildResolvedKeyring'] = { preRefused: !pre.ok, postAccepted: post.ok };

    // declared revocation is carried AND enforced through the same resolver
    const rev = verdict(decisionBy(revoked.kid, revoked.privateKey, POST), keyring);
    assert.equal(rev.ok, false, 'a decision signed AFTER the declared revocation verified clean');
    assert.match(rev.reason ?? '', /was revoked at/, `revocation reason: ${rev.reason}`);

    // undeclared activation keeps the documented legacy always-active behaviour (no invented default)
    const leg = verdict(decisionBy(legacy.kid, legacy.privateKey, PRE), keyring);
    assert.equal(leg.ok, true, `legacy (no declared validFrom) must stay always-active: ${leg.reason}`);

    // malformed declared activation fails CLOSED at the verifier — carried, never dropped
    const mal = verdict(decisionBy(malformed.kid, malformed.privateKey, POST), keyring);
    assert.equal(mal.ok, false, 'a MALFORMED declared validFrom was dropped — the check was skipped (fail OPEN)');
    assert.match(mal.reason ?? '', /cannot evaluate activation time/, `malformed reason: ${mal.reason}`);
  }

  // ── resolver 2: evidence asRootKeyEntryMap (bytes → ROOT KeyEntry map) — field semantics ─────
  {
    const declared = asRootKeyEntryMap(
      enc({ 'root-x': { type: 'ROOT', publicKey: 'aa'.repeat(32), roles: [], validFrom: F, revokedAt: null } }),
    );
    assert.equal(entryOf(declared, 'root-x', 'asRootKeyEntryMap(declared)').validFrom, F, 'declared ⇒ carried');
    const terse = asRootKeyEntryMap(enc({ 'root-y': 'aa'.repeat(32) }));
    assert.equal(entryOf(terse, 'root-y', 'asRootKeyEntryMap(terse)').validFrom, undefined, 'undeclared ⇒ absent (legacy), never invented');
  }

  // ── resolver 3: gate createAlphaTrust (generated declaration → live keyring) ─────────────────
  {
    const T0 = Date.parse(POST);
    const alpha = createAlphaTrust({ tenant: TENANT, now: () => T0 });
    const alphaFrom = entryOf(alpha.keyring, alpha.approver.kid, 'alpha keyring').validFrom;
    assert.ok(typeof alphaFrom === 'string', 'alpha resolver dropped validFrom — P0-5 regressed');
    const pre = verdict(decisionBy(alpha.approver.kid, alpha.approver.privateKey, new Date(Date.parse(alphaFrom) - 3_600_000).toISOString()), alpha.keyring);
    const post = verdict(decisionBy(alpha.approver.kid, alpha.approver.privateKey, new Date(T0 + 1_000).toISOString()), alpha.keyring);
    assert.match(pre.reason ?? '', /before its validFrom/, `gate resolver: pre-activation reason: ${pre.reason}`);
    outcomes['gate.createAlphaTrust'] = { preRefused: !pre.ok, postAccepted: post.ok };
  }

  // ── resolver 4: e2e assembleGateTrust (real ceremony → live keyring), DELEGATED probe ────────
  {
    const { auth, clock, trust } = await pairedTrust();
    const preIso = new Date(Date.parse(auth.validFrom) - 3_600_000).toISOString();
    const pre = verifyArtifact(enc(manifestIssuedAt(auth, trust.keyManifest, preIso)), enc({ schemas, keyring: trust.keyring, now: clock.iso() }));
    const post = verifyArtifact(enc(trust.keyManifest), enc({ schemas, keyring: trust.keyring, now: clock.iso() }));
    outcomes['e2e.assembleGateTrust'] = { preRefused: !pre.ok, postAccepted: post.ok };
  }

  // ── the equivalence claim itself ─────────────────────────────────────────────────────────────
  for (const [resolver, o] of Object.entries(outcomes)) {
    assert.deepEqual(
      o,
      { preRefused: true, postAccepted: true },
      `resolver "${resolver}" diverges from the normative semantics (declared activation enforced, ` +
        `in-window signature accepted): ${JSON.stringify(o)}`,
    );
  }
  assert.equal(Object.keys(outcomes).length, 3, 'equivalence table lost a resolver — the claim narrowed silently');
});
