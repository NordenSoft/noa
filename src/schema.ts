/**
 * Strict structural validator for NOA Receipt v0.1.
 *
 * Hand-rolled (zero dependencies) and STRICT: unknown fields are rejected everywhere
 * (additionalProperties:false). Rejecting unknown fields is a security control, not a nicety
 * — it closes the "smuggle PII / extra data in an unrecognized field" channel and keeps the
 * hashed surface exactly the documented surface. A machine-readable JSON Schema is shipped
 * separately at schema/noa-receipt-0.1.schema.json for external tooling.
 */

import { RECEIPT_SPEC } from "./types.js";

const RISK_CLASSES = new Set(["LOW", "MEDIUM", "HIGH", "CRITICAL", "IRREVERSIBLE"]);
const PRINCIPALS = new Set(["HUMAN", "SERVICE", "POLICY", "SANDBOX_SIM"]);
const MODES = new Set(["off", "shadow", "approvals_on", "on"]);
const VERDICTS = new Set([
  "ALLOWED",
  "BLOCKED",
  "DEFERRED",
  "EXECUTED",
  "FAILED",
  "ROLLED_BACK",
  "SIMULATED",
]);

const HASH_RE = /^sha256:[0-9a-f]{64}$/;
const PARAMS_HASH_RE = /^(sha256|hmac-sha256):[0-9a-f]{64}$/;
// RFC 3339 §5.6 permits lowercase 't' and 'z' — accept both so a conforming producer using any
// RFC-3339 library is not falsely flagged MALFORMED (must match schema/noa-receipt-0.1.schema.json).
const RFC3339_RE =
  /^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(\.\d{1,9})?([Zz]|[+-]\d{2}:\d{2})$/;

export interface SchemaResult {
  ok: boolean;
  errors: string[];
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function checkExactKeys(
  obj: Record<string, unknown>,
  required: string[],
  optional: string[],
  path: string,
  errors: string[],
): void {
  const allowed = new Set([...required, ...optional]);
  for (const k of Object.keys(obj)) {
    if (!allowed.has(k)) errors.push(`${path}: unknown field "${k}"`);
  }
  for (const k of required) {
    if (!(k in obj)) errors.push(`${path}: missing required field "${k}"`);
  }
}

function str(v: unknown): v is string {
  return typeof v === "string";
}

export function validateReceiptShape(value: unknown): SchemaResult {
  const errors: string[] = [];
  if (!isPlainObject(value)) {
    return { ok: false, errors: ["receipt: not an object"] };
  }
  const r = value;

  checkExactKeys(
    r,
    ["spec", "id", "ts", "scope", "agent", "action", "governance", "chain", "sig"],
    [],
    "receipt",
    errors,
  );

  if (r.spec !== RECEIPT_SPEC) errors.push(`receipt.spec: must be "${RECEIPT_SPEC}"`);
  if (!str(r.id) || r.id.length === 0 || r.id.length > 128) errors.push("receipt.id: non-empty string ≤128 chars");
  if (!str(r.ts) || !RFC3339_RE.test(r.ts)) errors.push("receipt.ts: must be RFC 3339 UTC timestamp");

  // scope
  if (isPlainObject(r.scope)) {
    checkExactKeys(r.scope, ["chain"], ["tenant"], "receipt.scope", errors);
    if (!str(r.scope.chain) || r.scope.chain.length === 0) errors.push("receipt.scope.chain: non-empty string");
    if ("tenant" in r.scope && !str(r.scope.tenant)) errors.push("receipt.scope.tenant: string");
  } else errors.push("receipt.scope: object required");

  // agent
  if (isPlainObject(r.agent)) {
    checkExactKeys(r.agent, ["id", "principal"], ["model"], "receipt.agent", errors);
    if (!str(r.agent.id) || r.agent.id.length === 0) errors.push("receipt.agent.id: non-empty string");
    if (!PRINCIPALS.has(r.agent.principal as string)) errors.push("receipt.agent.principal: invalid enum");
    if ("model" in r.agent && r.agent.model !== null && !str(r.agent.model))
      errors.push("receipt.agent.model: string or null");
  } else errors.push("receipt.agent: object required");

  // action
  if (isPlainObject(r.action)) {
    checkExactKeys(
      r.action,
      ["id", "canonical", "riskClass", "paramsHash", "reversible"],
      ["rollbackRef"],
      "receipt.action",
      errors,
    );
    if (!str(r.action.id) || r.action.id.length === 0) errors.push("receipt.action.id: non-empty string");
    if (!str(r.action.canonical) || r.action.canonical.length === 0)
      errors.push("receipt.action.canonical: non-empty string");
    if (!RISK_CLASSES.has(r.action.riskClass as string)) errors.push("receipt.action.riskClass: invalid enum");
    if (!str(r.action.paramsHash) || !PARAMS_HASH_RE.test(r.action.paramsHash))
      errors.push("receipt.action.paramsHash: must match (sha256|hmac-sha256):<64 hex>");
    if (typeof r.action.reversible !== "boolean") errors.push("receipt.action.reversible: boolean");
    if ("rollbackRef" in r.action && r.action.rollbackRef !== null && !str(r.action.rollbackRef))
      errors.push("receipt.action.rollbackRef: string or null");
  } else errors.push("receipt.action: object required");

  // governance
  if (isPlainObject(r.governance)) {
    checkExactKeys(
      r.governance,
      ["mode", "verdict", "sandboxed"],
      ["ruleId", "approval"],
      "receipt.governance",
      errors,
    );
    if (!MODES.has(r.governance.mode as string)) errors.push("receipt.governance.mode: invalid enum");
    if (!VERDICTS.has(r.governance.verdict as string)) errors.push("receipt.governance.verdict: invalid enum");
    if (typeof r.governance.sandboxed !== "boolean") errors.push("receipt.governance.sandboxed: boolean");
    if ("ruleId" in r.governance && r.governance.ruleId !== null && !str(r.governance.ruleId))
      errors.push("receipt.governance.ruleId: string or null");
    if ("approval" in r.governance && r.governance.approval !== null) {
      if (isPlainObject(r.governance.approval)) {
        checkExactKeys(r.governance.approval, ["by", "at"], [], "receipt.governance.approval", errors);
        if (!str(r.governance.approval.by)) errors.push("receipt.governance.approval.by: string");
        if (!str(r.governance.approval.at) || !RFC3339_RE.test(r.governance.approval.at as string))
          errors.push("receipt.governance.approval.at: RFC 3339 UTC");
      } else errors.push("receipt.governance.approval: object or null");
    }
  } else errors.push("receipt.governance: object required");

  // chain
  if (isPlainObject(r.chain)) {
    checkExactKeys(r.chain, ["seq", "prevHash", "hash"], [], "receipt.chain", errors);
    if (typeof r.chain.seq !== "number" || !Number.isSafeInteger(r.chain.seq) || r.chain.seq < 0)
      errors.push("receipt.chain.seq: non-negative safe integer");
    if (r.chain.prevHash !== null && (!str(r.chain.prevHash) || !HASH_RE.test(r.chain.prevHash)))
      errors.push("receipt.chain.prevHash: sha256:<64 hex> or null");
    if (!str(r.chain.hash) || !HASH_RE.test(r.chain.hash)) errors.push("receipt.chain.hash: sha256:<64 hex>");
  } else errors.push("receipt.chain: object required");

  // sig (mandatory)
  if (isPlainObject(r.sig)) {
    checkExactKeys(r.sig, ["alg", "kid", "value"], [], "receipt.sig", errors);
    if (r.sig.alg !== "ed25519") errors.push('receipt.sig.alg: must be "ed25519"');
    if (!str(r.sig.kid) || r.sig.kid.length === 0) errors.push("receipt.sig.kid: non-empty string");
    if (!str(r.sig.value) || r.sig.value.length === 0) errors.push("receipt.sig.value: non-empty string");
  } else errors.push("receipt.sig: object required (signatures are mandatory in v0.1)");

  return { ok: errors.length === 0, errors };
}
