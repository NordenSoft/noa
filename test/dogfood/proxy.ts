/**
 * test/dogfood/proxy.ts — PRIVATE internal dogfood harness. NOT part of the published
 * noa-receipt surface: it lives under `test/`, which package.json `files` does not ship.
 *
 * Purpose: wrap a SAMPLE agent action — a deterministic policy DECISION over integer-minor-unit
 * inputs — and emit a HASH-ONLY receipt for it via the existing public lib. It REUSES the public
 * primitives only (buildReceipt + complianceCommit + evaluate): it authors NO new replay
 * wire-spec, integer-commitment, or redaction construction (those are crown-jewel, out of scope).
 *
 * Hash-only contract: raw decision inputs never touch the receipt. They appear only as
 *   - action.paramsHash                       (sha256 over the JCS-canonical inputs), and
 *   - governance.compliance.{policyHash,      (the L2 commitment produced by complianceCommit:
 *       readSetHash, inputsHash, verdict}      binds the exact signed policy + exact recorded
 *                                              inputs by hash, and records the re-run verdict).
 * The raw inputs travel OUT-OF-BAND to a later replay (see ./replay.ts).
 */

import { canonicalize } from "../../src/jcs.js";
import { sha256Prefixed } from "../../src/hash.js";
import { generateKeyPair, type KeyPair } from "../../src/keys.js";
import { buildReceipt, type BuildInput, type Signer } from "../../src/builder.js";
import { evaluate, type EvalResult } from "../../src/policy/eval.js";
import { complianceCommit } from "../../src/policy/compliance.js";
import type { Policy, InputSnapshot } from "../../src/policy/dsl.js";
import type { Receipt, RiskClass, Verdict } from "../../src/types.js";

/** A long-lived Ed25519 identity for the harness: the signer plus its matching keyring (trust root). */
export interface DogfoodSigner {
  readonly kid: string;
  readonly signer: Signer;
  /** kid -> base64 SPKI; supply this as `keyring` to verifyChain / verifyReceiptCompliance. */
  readonly keyring: Record<string, string>;
}

/** Mint a fresh harness identity. The returned keyring IS the offline trust root. */
export function newDogfoodSigner(kid: string): DogfoodSigner {
  const kp: KeyPair = generateKeyPair(kid);
  return {
    kid: kp.kid,
    signer: { kid: kp.kid, privateKey: kp.privateKey },
    keyring: { [kp.kid]: kp.publicKey },
  };
}

/** Refunds at/above this many minor units are blocked by the sample policy. $10,000.00 in cents. */
export const REFUND_CEILING_MINOR = 1_000_000;

/**
 * The SAMPLE policy: a refund-approval GUARD over integer minor units. Deterministic by
 * construction (integer-only; no floats / clock / RNG / locale) — exactly what the reference
 * evaluator re-runs byte-for-byte on any machine.
 *   - amountMinor >= REFUND_CEILING_MINOR  ⇒ DENY "too-large"
 *   - action      != "payment.refund"      ⇒ DENY "wrong-action"
 *   - otherwise                            ⇒ ALLOW "allow-refund"
 */
export function refundGuardPolicy(): Policy {
  return {
    spec: "noa.policy/0.2",
    id: "dogfood.refund-guard/v1",
    requiredPaths: ["action", "amountMinor"],
    rules: [
      { id: "too-large", when: { op: "ge", path: "amountMinor", value: REFUND_CEILING_MINOR }, then: "DENY" },
      { id: "wrong-action", when: { op: "ne", path: "action", value: "payment.refund" }, then: "DENY" },
      {
        id: "allow-refund",
        when: {
          op: "and",
          clauses: [
            { op: "eq", path: "action", value: "payment.refund" },
            { op: "lt", path: "amountMinor", value: REFUND_CEILING_MINOR },
          ],
        },
        then: "ALLOW",
      },
    ],
  };
}

/** The SAMPLE agent action: an agent asking to refund `amountMinor` integer minor units. */
export interface AgentActionRequest {
  id: string;
  ts: string; // RFC 3339 UTC
  scope: { tenant?: string; chain: string };
  agent: { id: string; model?: string | null };
  action: { canonical: string; riskClass: RiskClass; reversible: boolean };
  /** Decision inputs (integer minors). Carried HASH-ONLY on the receipt; raw values stay here. */
  inputs: InputSnapshot;
}

/** Build the sample refund request for `amountMinor` minor units (defaults keep tests deterministic). */
export function refundRequest(
  amountMinor: number,
  opts: { id?: string; ts?: string; chain?: string; tenant?: string; agentId?: string } = {},
): AgentActionRequest {
  return {
    id: opts.id ?? "dogfood_rc_0",
    ts: opts.ts ?? "2026-06-22T00:00:00.000Z",
    scope: { tenant: opts.tenant ?? "dogfood", chain: opts.chain ?? "dogfood-chain-1" },
    agent: { id: opts.agentId ?? "dogfood-agent", model: "vendor/dogfood-model-v1" },
    action: { canonical: "payment.refund", riskClass: "HIGH", reversible: true },
    inputs: { action: "payment.refund", amountMinor },
  };
}

/** Everything an emit produces — the receipt plus the out-of-band material a replay needs. */
export interface EmittedReceipt {
  receipt: Receipt;
  policy: Policy;
  /** The recorded decision inputs (out-of-band; never serialized onto the receipt). */
  inputs: InputSnapshot;
  /** The verdict the evaluator produced at emit time (recorded verbatim in the commitment). */
  evalResult: EvalResult;
}

/** Map a policy verdict (ALLOW/DENY) onto the receipt's governance verdict enum. */
function governanceVerdictFor(decision: "ALLOW" | "DENY"): Verdict {
  return decision === "ALLOW" ? "EXECUTED" : "BLOCKED";
}

/**
 * Emit a HASH-ONLY receipt for `req` under `policy`, signed by `signer`, chained onto `prev`.
 *
 * Runs the deterministic evaluator, commits the L2 (policyHash + readSetHash + inputsHash + the
 * re-run verdict) via complianceCommit, and hashes the inputs into action.paramsHash. Raw inputs
 * are NEVER placed on the receipt — only their hashes (see the hash-only contract above).
 */
export function emitReceipt(
  req: AgentActionRequest,
  policy: Policy,
  signer: DogfoodSigner,
  prev: Receipt | null,
): EmittedReceipt {
  const evalResult = evaluate(policy, req.inputs);
  const inputsHash = sha256Prefixed(canonicalize(req.inputs));

  const buildInput: BuildInput = {
    id: req.id,
    ts: req.ts,
    scope: req.scope,
    agent: { id: req.agent.id, model: req.agent.model ?? null, principal: "SERVICE" },
    action: {
      id: req.action.canonical,
      canonical: req.action.canonical,
      riskClass: req.action.riskClass,
      paramsHash: inputsHash, // hash-only: raw inputs never on the receipt
      reversible: req.action.reversible,
      rollbackRef: null,
    },
    governance: {
      mode: "on",
      verdict: governanceVerdictFor(evalResult.verdict),
      ruleId: evalResult.ruleFired,
      approval: null,
      sandboxed: false,
      compliance: complianceCommit(policy, req.inputs),
    },
  };

  const receipt = buildReceipt(buildInput, prev, signer.signer);
  return { receipt, policy, inputs: req.inputs, evalResult };
}
