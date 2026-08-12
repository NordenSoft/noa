/**
 * R8-01 + R8-16 — PERMANENT REGRESSION. An approval must name the party that signed it.
 *
 * MEASURED BEFORE THE FIX, with the LEGITIMATE authorized approver device doing the signing — no
 * forgery, no stolen key, nothing tampered after signature:
 *
 *     signer kid    approver-1-device-1
 *     approval.by   HUMAN:cfo-victim           <- a different human entirely
 *     approval.at   2099-01-01T00:00:00.000Z   <- a time that has not happened
 *     agent.principal  SERVICE                 <- not a human at all
 *     decide 200, execution grant ISSUED
 *
 * The signature proved a KEY approved. The evidence bundle presents a NAMED HUMAN as the approver.
 * Nothing connected the two — `governance.approval.by`, `agent.principal` and `approval.at` were
 * compared to NOTHING, here or in the evidence verifier. For a product whose sole claim is
 * cryptographic evidence that THIS human approved THIS action, that is the claim failing.
 *
 * R8-16 is the same defect one field group over: the action binding checked `canonical` and
 * `paramsHash` only, so an enrolled approver could restate `action.id`, downgrade `riskClass`
 * HIGH -> LOW, or flip `reversible` false -> true and still mint a grant. Fixing one and not the
 * other leaves the forgery, which is why they are one test file.
 *
 * ── WHAT THIS DOES *NOT* PROVE, stated so no reader over-reads it ────────────────────────────────
 * This binds the approval to the SIGNING KEY the manifest authorized. It does NOT prove the named
 * human is a real person — `agent.id` remains a signer-asserted label (THREAT-MODEL.md:92-94), and
 * resolving it to a person needs a tenant identity registry, which is ADR-0006. The honest reading
 * is "a manifest-authorized approver key approved this", not "this named person did".
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { setupGate, sampleCommandParams, body, b, alphaPhoneSigner } from "./helpers.js";
import { buildReceipt } from "noa-receipt";
import { signArtifact, refHash } from "noa-approval-artifacts";

type Mutate = (r: Record<string, unknown>) => void;

/** Drive one decide() with a receipt the AUTHORIZED approver signs after `mutate` shapes it. */
function decideWith(mutate: Mutate): { status: number; error: string; grant: boolean } {
  const fx = setupGate({ approverRole: "approve-critical" });
  const created = fx.engine.createHold(
    fx.agent,
    "idem-1",
    body({
      action: { canonical: "noa.command.exec", riskClass: "HIGH", reversible: false },
      params: sampleCommandParams(),
    }),
  );
  const holdId = String((created.body as Record<string, unknown>)["holdId"]);
  const hold = fx.store.getHold(holdId)!;
  const at = new Date(fx.trust.now()).toISOString();

  const core: Record<string, unknown> = {
    id: `verdict-${hold.deferredReceipt!.id}`,
    ts: at,
    scope: { tenant: hold.deferredReceipt!.scope.tenant, chain: hold.deferredReceipt!.scope.chain },
    agent: { id: "approver-human-1", model: null, principal: "HUMAN" },
    action: { ...hold.deferredReceipt!.action },
    governance: {
      mode: "approvals_on",
      verdict: "ALLOWED",
      ruleId: "human-approved",
      approval: { by: fx.trust.approver.kid, at },
      sandboxed: false,
    },
  };
  mutate(core);

  const receipt = buildReceipt(core as never, hold.deferredReceipt!, alphaPhoneSigner(fx.trust));
  const decisionArtifact = signArtifact(
    b({
      spec: "noa.decision/0.1",
      holdEnvelopeHash: refHash(hold.holdEnvelope as object),
      decision: "APPROVE",
      reasonCode: "vendor-verified",
      reasonEncryption: null,
      decidedAt: at,
      approverKid: fx.trust.approver.kid,
    }),
    "NOA-Decision-v0.1-sig",
    alphaPhoneSigner(fx.trust),
  ) as unknown as Record<string, unknown>;

  const d = fx.engine.decide(holdId, body({ receipt, decisionArtifact }));
  const bd = d.body as Record<string, unknown>;
  return { status: d.status, error: String(bd["error"] ?? ""), grant: bd["executionGrant"] !== undefined };
}

/** Mutations that must each be refused, with the error they must produce. */
const REFUSALS: Array<[string, Mutate, string]> = [
  [
    "R8-01: approval.by names a DIFFERENT human than the signer",
    (r) => {
      (r["governance"] as Record<string, unknown>)["approval"] = { by: "HUMAN:cfo-victim", at: (r["ts"] as string) };
    },
    "APPROVAL_IDENTITY_MISMATCH",
  ],
  [
    "R8-01: the principal is not HUMAN",
    (r) => {
      (r["agent"] as Record<string, unknown>)["principal"] = "SERVICE";
    },
    "APPROVAL_IDENTITY_MISMATCH",
  ],
  [
    "R8-01: approval.at is in the future",
    (r) => {
      const g = r["governance"] as Record<string, unknown>;
      g["approval"] = { ...(g["approval"] as Record<string, unknown>), at: "2099-01-01T00:00:00.000Z" };
    },
    "APPROVAL_TIME_OUT_OF_WINDOW",
  ],
  [
    "R8-01: approval.at predates the hold",
    (r) => {
      const g = r["governance"] as Record<string, unknown>;
      g["approval"] = { ...(g["approval"] as Record<string, unknown>), at: "2000-01-01T00:00:00.000Z" };
    },
    "APPROVAL_TIME_OUT_OF_WINDOW",
  ],
  [
    "R8-16: the receipt restates a different action.id",
    (r) => {
      (r["action"] as Record<string, unknown>)["id"] = "some-other-action";
    },
    "ACTION_BINDING_MISMATCH",
  ],
  [
    "R8-16: the receipt downgrades riskClass HIGH -> LOW",
    (r) => {
      (r["action"] as Record<string, unknown>)["riskClass"] = "LOW";
    },
    "ACTION_BINDING_MISMATCH",
  ],
  [
    "R8-16: the receipt flips reversible false -> true",
    (r) => {
      (r["action"] as Record<string, unknown>)["reversible"] = true;
    },
    "ACTION_BINDING_MISMATCH",
  ],
];

for (const [name, mutate, expected] of REFUSALS) {
  test(name, () => {
    const r = decideWith(mutate);
    assert.equal(r.status, 422, `accepted a mutated approval (got ${r.status})`);
    assert.equal(r.error, expected);
    assert.equal(r.grant, false, "a refused decision must not mint an execution grant");
  });
}

test("ANTI-VACUITY: the HONEST approval is still accepted and still mints a grant", () => {
  // Without this every assertion above would pass on a gate that refuses everything — which would
  // be a broken product rather than a fixed one, and indistinguishable from the outside.
  const r = decideWith(() => {});
  assert.equal(r.status, 200, `the honest path was refused: ${r.error}`);
  assert.equal(r.grant, true, "an accepted approval must still issue the execution grant");
});
