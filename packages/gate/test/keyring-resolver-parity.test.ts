/**
 * KEYRING RESOLVER PARITY — the test P0-7 claimed existed, now actually written (2026-07-31).
 *
 * ─── WHY THIS FILE EXISTS ───────────────────────────────────────────────────────────────────────
 *
 * A comment in `src/trust.ts` asserted that "the parity test added with this change is what makes
 * a fourth [resolver] fail loudly instead of silently". No such test existed —
 * `grep -rn "parity" packages/gate/test/` returned nothing, and deleting all four keyring
 * `validFrom` properties left every then-existing test GREEN. That claim is withdrawn in place
 * (see src/trust.ts); THIS file is the real control, and it is registered in
 * `scripts/resolver-inventory.json` so `scripts/lint-resolver-parity.mjs` fails if it is removed,
 * skipped or stops resolving.
 *
 * ─── WHAT IT PROVES ─────────────────────────────────────────────────────────────────────────────
 *
 * 1. CARRIAGE — every activation/revocation value DECLARED in the alpha Key Manifest (and the
 *    root delegation) survives into the LIVE keyring `engine.ts` verifies Decisions against.
 *    Deleting `validFrom` from any keyring entry in `createAlphaTrust` turns this RED.
 * 2. OFFLINE-CONSUMER ENFORCEMENT — through the resolver's own output, a decision dated before
 *    the approver's activation is REFUSED by `verifyArtifact` (the §13/offline shape, artifact
 *    time from `decidedAt`). Also RED if the resolver drops `validFrom`.
 * 3. LIVE-ENGINE ENFORCEMENT — a future-activated approver (the injected-`GateTrust` exposure
 *    P0-5 recorded: `createGate` accepts an injected trust) cannot mint a grant: the engine's
 *    authorization-time check refuses with "before its validFrom".
 *
 * Proof ID referenced by scripts/resolver-inventory.json — do not rename without updating it:
 *   [PROOF:RES-PAR-GATE-KEYRING]
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { signArtifact, verifyArtifact, type KeyEntry } from "noa-approval-artifacts";
import { createAlphaTrust } from "../src/trust.js";
import { loadSchemas } from "../src/schemas.js";
import { setupGate, signPhoneDecision, sampleCommandParams, body } from "./helpers.js";
import { b } from "./helpers/bytes.js";

const schemas = loadSchemas();

type ManifestKey = {
  kid: string;
  type: string;
  roles: string[];
  publicKey?: string;
  validFrom?: string | null;
  revokedAt?: string | null;
};

function entryOf(map: Record<string, KeyEntry>, kid: string, what: string): KeyEntry {
  const e = map[kid];
  assert.ok(e !== undefined, `fixture: ${what} has no keyring entry for kid "${kid}"`);
  return e;
}

test("[PROOF:RES-PAR-GATE-KEYRING] resolver parity: every DECLARED activation/revocation survives into the live keyring", () => {
  const T0 = Date.parse("2026-07-14T12:00:00.000Z");
  const trust = createAlphaTrust({ tenant: "acme-tenant", now: () => T0 });

  // The manifest is the DECLARATION; the keyring is what the engine actually verifies against
  // (`engine.ts:711`). Parity means: declared ⇒ carried, per key, no exceptions.
  const declaredKeys = (trust.keyManifest as { keys?: ManifestKey[] }).keys;
  assert.ok(Array.isArray(declaredKeys) && declaredKeys.length >= 3, "fixture: manifest lost its keys[]");
  let signersChecked = 0;
  for (const k of declaredKeys) {
    if (typeof k.publicKey !== "string") {
      // AUDIT is hpke-only, never a signer — it must NOT resolve in the signer keyring.
      assert.equal(trust.keyring[k.kid], undefined, `non-signer manifest key "${k.kid}" leaked into the signer keyring`);
      continue;
    }
    const e = entryOf(trust.keyring, k.kid, `live keyring (${k.type})`);
    assert.equal(
      e.validFrom,
      k.validFrom,
      `${k.type} keyring entry does not carry the manifest-declared validFrom — the activation ` +
        `window is open at one end on the LIVE decision path (this is the P0-5 defect class)`,
    );
    assert.equal(e.revokedAt, k.revokedAt, `${k.type} keyring entry does not carry the declared revokedAt`);
    signersChecked++;
  }
  assert.equal(signersChecked, 2, "fixture: expected exactly GATE + APPROVER signer keys in the alpha manifest");

  // The DELEGATED manifest signer's activation is declared by the root-signed delegation.
  const delegationFrom = (trust.keyDelegation as { validFrom?: unknown }).validFrom;
  assert.ok(typeof delegationFrom === "string", "fixture: delegation lost its validFrom");
  const authorityKid = (trust.keyDelegation as { delegatedKid?: unknown }).delegatedKid;
  assert.ok(typeof authorityKid === "string", "fixture: delegation lost its delegatedKid");
  assert.equal(
    entryOf(trust.keyring, authorityKid, "live keyring (DELEGATED)").validFrom,
    delegationFrom,
    "DELEGATED keyring entry does not carry the delegation-declared validFrom",
  );

  // The ROOT anchor shares the same declared bootstrap window (src/trust.ts binds one `validFrom`
  // for the whole self-contained alpha world; the delegation is its signed declaration).
  const rootKid = ((trust.keyDelegation as { sig?: { kid?: unknown } }).sig ?? {}).kid;
  assert.ok(typeof rootKid === "string", "fixture: delegation lost its signing root kid");
  assert.equal(
    entryOf(trust.keyring, rootKid, "live keyring (ROOT)").validFrom,
    delegationFrom,
    "ROOT keyring entry does not carry the declared bootstrap activation",
  );
});

test("[PROOF:RES-PAR-GATE-KEYRING] offline consumer: a pre-activation trusted time is REFUSED through the resolver's own keyring", () => {
  const T0 = Date.parse("2026-07-14T12:00:00.000Z");
  const trust = createAlphaTrust({ tenant: "acme-tenant", now: () => T0 });
  const preIso = new Date(T0 - 2 * 60 * 60 * 1000).toISOString(); // long before validFrom (T0-60s)

  // The phone helper needs a full hold; the offline shape only needs the artifact + the
  // resolver's keyring, so sign the minimal schema-valid Decision directly.
  const signed = (decidedAt: string) =>
    b({
      spec: "noa.decision/0.1",
      holdEnvelopeHash: "sha256:" + "1".repeat(64),
      decision: "APPROVE",
      reasonCode: "vendor-verified",
      reasonEncryption: null,
      decidedAt,
      approverKid: trust.approver.kid,
    });

  // The caller supplies the independent time at which it accepted the decision. The phone-written
  // decidedAt is deliberately not an activation witness.
  const probe = signArtifact(signed(preIso), "NOA-Decision-v0.1-sig", {
    kid: trust.approver.kid,
    privateKey: trust.approver.privateKey,
  });
  const r = verifyArtifact(b(probe), b({ schemas, keyring: trust.keyring, now: new Date(T0).toISOString(), authorizationTime: preIso, riskClass: "HIGH" }));
  assert.equal(
    r.ok,
    false,
    "a decision accepted at a trusted time BEFORE the approver's activation verified through the " +
      "resolver's keyring — validFrom was dropped or unenforced",
  );
  assert.match(r.reason ?? "", /before its validFrom/, `refused for the wrong reason: ${r.reason}`);

  // ANTI-VACUITY control, same run: an in-window decision verifies clean through the same keyring.
  const ctl = signArtifact(signed(new Date(T0).toISOString()), "NOA-Decision-v0.1-sig", {
    kid: trust.approver.kid,
    privateKey: trust.approver.privateKey,
  });
  const c = verifyArtifact(b(ctl), b({ schemas, keyring: trust.keyring, now: new Date(T0).toISOString(), authorizationTime: new Date(T0).toISOString(), riskClass: "HIGH" }));
  assert.equal(c.ok, true, `control failed — probe wiring broken, not the activation check: ${c.reason}`);
});

test("[PROOF:RES-PAR-GATE-KEYRING] live engine: a future-activated approver cannot mint a grant (injected-GateTrust exposure)", () => {
  const fx = setupGate({ approverRole: "approve-high" });
  const created = fx.engine.createHold(fx.agent, "idem-parity-future-activation", body({
    mode: "ENFORCED",
    action: { canonical: "noa.command.exec", riskClass: "HIGH", reversible: false },
    params: sampleCommandParams(),
    chain: "chain-parity-activation",
  }));
  assert.equal(created.status, 201);
  const holdId = (created.body as { holdId: string }).holdId;
  const hold = fx.store.getHold(holdId)!;

  const gateNow = fx.clock.t;
  const e = fx.trust.keyring[fx.trust.approver.kid]!;
  // CARRIAGE precondition: the resolver put an activation here at all (P0-5). If this fails, fix
  // the resolver, not this test.
  assert.ok(typeof e.validFrom === "string", "resolver carried no validFrom — P0-5 regressed");
  // The injected-trust shape P0-5 recorded: a keyring whose approver activates in the FUTURE.
  e.validFrom = new Date(gateNow + 60_000).toISOString();

  const signed = signPhoneDecision({
    trust: fx.trust,
    deferredReceipt: hold.deferredReceipt,
    holdEnvelope: hold.holdEnvelope,
    decision: "APPROVE",
    at: new Date(gateNow).toISOString(),
  });
  const result = fx.engine.decide(holdId, body(signed));

  assert.equal(result.status, 422, JSON.stringify(result.body));
  assert.equal((result.body as { error?: string }).error, "DECISION_ARTIFACT_INVALID");
  assert.match(String((result.body as { detail?: string }).detail), /before its validFrom/);
  assert.equal(fx.store.getHold(holdId)!.status, "PENDING", "the hold advanced on a pre-activation approval");
  assert.equal(fx.store.listGrants().length, 0, "a grant was minted from a pre-activation approval");

  // ANTI-VACUITY control, same run: with the resolver's own (past) activation restored, the same
  // flow authorizes — the refusal above was the activation window, not broken wiring.
  e.validFrom = new Date(gateNow - 60_000).toISOString();
  const created2 = fx.engine.createHold(fx.agent, "idem-parity-activation-control", body({
    mode: "ENFORCED",
    action: { canonical: "noa.command.exec", riskClass: "HIGH", reversible: false },
    params: sampleCommandParams(),
    chain: "chain-parity-activation-2",
  }));
  assert.equal(created2.status, 201);
  const holdId2 = (created2.body as { holdId: string }).holdId;
  const hold2 = fx.store.getHold(holdId2)!;
  const ok = fx.engine.decide(holdId2, body(signPhoneDecision({
    trust: fx.trust,
    deferredReceipt: hold2.deferredReceipt,
    holdEnvelope: hold2.holdEnvelope,
    decision: "APPROVE",
    at: new Date(fx.clock.t).toISOString(),
  })));
  assert.equal(ok.status, 200, JSON.stringify(ok.body));
  assert.equal(fx.store.getHold(holdId2)!.status, "APPROVED");
});
