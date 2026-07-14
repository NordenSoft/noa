/**
 * NOA Gate — the gate-signed RECEIPTS (spec §5/§8).
 *
 * These are `noa.receipt/0.1` receipts (the FROZEN core), built with `noa-receipt`'s own
 * `buildReceipt` — never re-implemented, never a new field (Red Line 5, KURAL 5). The gate signs
 * the DEFERRED (freeze), the EXECUTED/FAILED (attempt), and — D19 — the timeout BLOCKED receipt.
 * The ALLOWED/BLOCKED verdict receipt from a human decision is built by the PHONE, not here (D18).
 *
 * D19 — `buildTimeoutReceipt` did not exist in `noa-receipt` and the spec (§5) says ADD it. We add
 * it HERE, in the gate, as a pure wrapper over `buildReceipt` (no core-package change, no schema
 * change): `agent:{id:"approval-timeout-policy", principal:"POLICY"}`,
 * `governance:{verdict:"BLOCKED", ruleId:"approval-timeout", approval:null}`, signed by the
 * GATE/POLICY signer — never a human key. A timed-out approval is a DISTINCT outcome, never dressed
 * up as ALLOWED and never mislabeled as a human denial (Red Line 6).
 */

import { buildReceipt, type Receipt } from "noa-receipt";
import type { GateKeyPair } from "./trust.js";
import type { HoldAction } from "./types.js";

const MODE = "approvals_on" as const;

export interface ReceiptActionInput {
  id: string;
  canonical: string;
  riskClass: HoldAction["riskClass"];
  paramsHash: string;
  reversible: boolean;
}

function signer(gate: GateKeyPair): { kid: string; privateKey: string } {
  return { kid: gate.kid, privateKey: gate.privateKey };
}

/** The genesis DEFERRED receipt — the frozen action, signed by the gate at freeze time. */
export function buildDeferredReceipt(args: {
  id: string;
  ts: string;
  tenant: string;
  chain: string;
  agentId: string;
  action: ReceiptActionInput;
  gate: GateKeyPair;
}): Receipt {
  return buildReceipt(
    {
      id: args.id,
      ts: args.ts,
      scope: { tenant: args.tenant, chain: args.chain },
      agent: { id: args.agentId, model: null, principal: "SERVICE" },
      action: { ...args.action, rollbackRef: null },
      governance: { mode: MODE, verdict: "DEFERRED", ruleId: null, approval: null, sandboxed: false },
    },
    null,
    signer(args.gate),
  );
}

/**
 * D19 — the timeout receipt: verdict BLOCKED, ruleId "approval-timeout", POLICY principal, gate
 * signer. Chains onto the DEFERRED (the human never decided). NEVER a human key, NEVER ALLOWED.
 */
export function buildTimeoutReceipt(args: {
  id: string;
  expiredAt: string;
  tenant: string;
  chain: string;
  action: ReceiptActionInput;
  deferredReceipt: Receipt;
  gate: GateKeyPair;
}): Receipt {
  return buildReceipt(
    {
      id: args.id,
      ts: args.expiredAt,
      scope: { tenant: args.tenant, chain: args.chain },
      agent: { id: "approval-timeout-policy", model: null, principal: "POLICY" },
      action: { ...args.action, rollbackRef: null },
      governance: { mode: MODE, verdict: "BLOCKED", ruleId: "approval-timeout", approval: null, sandboxed: false },
    },
    args.deferredReceipt,
    signer(args.gate),
  );
}

/** The post-execution attempt receipt (EXECUTED, or FAILED per the schema-legal `FAILED` verdict). */
export function buildAttemptReceipt(args: {
  id: string;
  ts: string;
  tenant: string;
  chain: string;
  agentId: string;
  action: ReceiptActionInput;
  outcome: "EXECUTED" | "FAILED";
  prev: Receipt;
  gate: GateKeyPair;
}): Receipt {
  return buildReceipt(
    {
      id: args.id,
      ts: args.ts,
      scope: { tenant: args.tenant, chain: args.chain },
      agent: { id: args.agentId, model: null, principal: "SERVICE" },
      action: { ...args.action, rollbackRef: null },
      governance: { mode: MODE, verdict: args.outcome, ruleId: null, approval: null, sandboxed: false },
    },
    args.prev,
    signer(args.gate),
  );
}
