/**
 * M5 — CROSS-HOLD DISPLAY REPLAY. The gate must VERIFY the sealed display it is about to sign.
 *
 * ─── THE DEFECT, AND WHY IT SURVIVED A DESIGN DOCUMENT THAT NAMED IT ─────────────────────────────
 *
 * `engine.ts` asks the sealer for a display bound to THIS hold — `{tenant, holdId,
 * deferredReceiptHash, expiresAt, recipients}` — and then signs whatever comes back. **It never
 * checks that the returned envelope carries the fields it asked for.** The sealer is INJECTED
 * (`deps.sealDisplay`), so "whatever comes back" is not a hypothetical: it is a component the gate
 * does not control, and the gate's own Hold Envelope then binds it via `displayCiphertextHash` and
 * signs the result.
 *
 * A sealer that returns another hold's blob therefore produces a gate-signed envelope in which the
 * human's approval is bound to a display belonging to a DIFFERENT hold. Everything downstream is
 * consistent: genuine signature, correct chain, honest projection identity. Nothing can tell.
 *
 * ADR-0005 §5 named this control ("verified on egress") and §7 named its knockout `G5
 * display-aad-egress-check`. **Neither was ever built.** The knockout registry refused to register
 * G5 and said why (`scripts/lint-control-knockout.mjs:96-108`): *"A knockout deletes a control; there
 * is nothing here to delete, so writing a G5 entry would have manufactured the appearance of coverage
 * over a control that was never built."* That refusal is the reason this defect was findable at all —
 * the registry declined to fake coverage, and the gap stayed visible for five days until someone read
 * it.
 *
 * ─── WHY THE CONTROL COMES FIRST IN THIS FILE ────────────────────────────────────────────────────
 *
 * Every assertion below is "the gate REFUSES". A gate that refuses everything — a broken fixture, a
 * malformed request, an unrelated 422 — satisfies all of them. The control is what makes the refusals
 * mean something, so it is written first and read first.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { canonicalize, sha256Prefixed } from "noa-approval-artifacts";
import { setupGate, testSealer, sampleCommandParams, body } from "./helpers.js";
import type { DisplaySealer } from "../src/engine.js";

const ACTION = { canonical: "noa.command.exec", riskClass: "HIGH", reversible: false };

function createHoldWith(sealer: DisplaySealer, chain: string) {
  const fx = setupGate({ approverRole: "approve-high", sealer });
  return fx.engine.createHold(fx.agent, `idem-${chain}`, body({
    mode: "ENFORCED",
    action: ACTION,
    params: sampleCommandParams(),
    chain,
  }));
}

/** ANTI-VACUITY. Read this before any refusal below. */
test("CONTROL — an honest sealer completes the hold, so a refusal below is about the SEALER", () => {
  const created = createHoldWith(testSealer, "chain-honest");
  assert.equal(created.status, 201,
    `the honest path must succeed or every assertion in this file is vacuous: ${JSON.stringify(created.body)}`);
});

/** Each entry rewrites ONE field of what the sealer returns. The gate asked for this hold; the sealer
 *  answers with a blob describing a different one. Nothing else about the envelope is malformed. */
const CROSS_HOLD_VECTORS: Array<{ name: string; corrupt: (v: Record<string, unknown>) => void }> = [
  { name: "holdId — the blob belongs to ANOTHER hold", corrupt: (v) => { v["holdId"] = "hold-belonging-to-someone-else"; } },
  { name: "tenant — the blob belongs to another TENANT", corrupt: (v) => { v["tenant"] = "a-different-tenant"; } },
  { name: "deferredReceiptHash — bound to a different question", corrupt: (v) => { v["deferredReceiptHash"] = `sha256:${"b".repeat(64)}`; } },
  { name: "expiresAt — a different validity window", corrupt: (v) => { v["expiresAt"] = "2099-01-01T00:00:00.000Z"; } },
  { name: "aadHash — does not commit to the fields it carries", corrupt: (v) => { v["aadHash"] = `sha256:${"c".repeat(64)}`; } },
];

for (const vec of CROSS_HOLD_VECTORS) {
  test(`M5: a sealer returning a blob bound to a DIFFERENT hold is REFUSED — ${vec.name}`, () => {
    const hostile: DisplaySealer = (req) => {
      const sealed = testSealer(req) as unknown as Record<string, unknown>;
      vec.corrupt(sealed);
      return sealed as never;
    };
    const created = createHoldWith(hostile, `chain-${vec.name.slice(0, 12).replace(/\W+/g, "-")}`);
    assert.notEqual(created.status, 201,
      "the gate SIGNED a display it had not verified. The human's approval is now bound to a display " +
        "belonging to a different hold, and every downstream check passes: genuine signature, correct " +
        "chain, honest projection identity. This is M5.");
    assert.equal((created.body as { error?: string }).error, "DISPLAY_EGRESS_AAD_MISMATCH",
      `the refusal must name the reason (got ${JSON.stringify(created.body)}) — a generic 422 would ` +
        "mean this test passes for reasons unrelated to the egress check");
  });
}

test("M5: the AUDIT recipient cannot be dropped by the sealer", () => {
  // ADR-0005 Slice 4 made the audit key a non-optional recipient because a display only the approver
  // can open is a binding no third party can ever verify. The engine puts it in the REQUEST; nothing
  // checked that it survived into the RESPONSE, so the sealer could quietly drop it and the gate would
  // sign an envelope whose display no auditor can ever open.
  const dropsAudit: DisplaySealer = (req) => {
    const sealed = testSealer(req) as unknown as Record<string, unknown>;
    sealed["recipients"] = (sealed["recipients"] as unknown[]).slice(0, 1);
    return sealed as never;
  };
  const created = createHoldWith(dropsAudit, "chain-noaudit");
  assert.notEqual(created.status, 201, "the sealer dropped the audit recipient and the gate signed it anyway");
  assert.equal((created.body as { error?: string }).error, "DISPLAY_EGRESS_AAD_MISMATCH");
});

test("CONTROL — a sealer that changes only the CIPHERTEXT still succeeds", () => {
  // The egress check verifies the AAD BINDING, not the payload: the gate cannot decrypt, and pretending
  // to check the ciphertext would be exactly the kind of decorative control this project deletes. This
  // control keeps the refusals above honest — they must fire on the binding fields and nothing else.
  const differentCiphertext: DisplaySealer = (req) => {
    const sealed = testSealer(req) as unknown as Record<string, unknown>;
    const p = sealed["payload"] as Record<string, unknown>;
    sealed["payload"] = { ...p, ciphertext: Buffer.from("a completely different plaintext", "utf8").toString("base64") };
    return sealed as never;
  };
  const created = createHoldWith(differentCiphertext, "chain-ct");
  assert.equal(created.status, 201,
    "the egress check refused a payload difference. It verifies the AAD BINDING; the gate has no key " +
      "and cannot judge the ciphertext, so refusing here would be a control that measures nothing.");
});

test("the aadHash the gate accepts is the one it can RE-DERIVE from the fields it asked for", () => {
  // The strongest form of the check: not "is aadHash present" but "does it equal our own derivation".
  // Otherwise a sealer could return self-consistent nonsense — an aadHash committing to ITS fields
  // rather than to the hold's — and satisfy a presence check.
  const fx = setupGate({ approverRole: "approve-high" });
  const created = fx.engine.createHold(fx.agent, "idem-aad-derive", body({
    mode: "ENFORCED", action: ACTION, params: sampleCommandParams(), chain: "chain-aad-derive",
  }));
  assert.equal(created.status, 201, JSON.stringify(created.body));
  const hold = fx.store.listHolds({}).find((h) => h.chain === "chain-aad-derive")!;
  const enc = hold.encryptedDisplay as unknown as Record<string, unknown>;
  assert.equal(
    enc["aadHash"],
    sha256Prefixed(canonicalize({
      tenant: enc["tenant"], holdId: enc["holdId"],
      deferredReceiptHash: enc["deferredReceiptHash"], expiresAt: enc["expiresAt"],
    })),
    "the stored aadHash is not reproducible from the stored AAD fields",
  );
});
