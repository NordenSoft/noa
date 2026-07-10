/**
 * preCheck — the MCP pre-flight Policy Decision Point, extracted from
 * examples/mcp-preflight/preflight.mjs into a shared, unit-testable module.
 *
 * Sits between an MCP host and its tool servers. For EVERY tool call it runs the
 * DETERMINISTIC policy evaluator `evaluate(policy, inputs)` (noa-receipt's offline-replayable
 * policy engine, imported from the built library) and returns a SIGNED receipt of the
 * ALLOW/DENY decision. FAIL-CLOSED: any policy/input error resolves to DENY, never a throw,
 * never a silent allow.
 *
 * Coupling note (recorded per the task's own instruction to document the choice): this module
 * imports noa-receipt via a RELATIVE path into the repo root's built output
 * (`../../../dist/src/index.js`), not a `file:` package dependency. This package is not meant to
 * be published or used outside this repo checkout; a relative import keeps the coupling
 * explicit and avoids an extra npm-link/symlink step for what is a proof-of-architecture
 * skeleton. Root `npm run build` must have produced `dist/` before this module is imported.
 */
import {
  buildReceipt,
  evaluate,
  policyHash,
  complianceCommit,
  verifyReceiptCompliance,
  canonicalize,
} from "../../../dist/src/index.js";
import { sha256Prefixed } from "../../../dist/src/hash.js";

/** Cap on how deep `flattenArgsToPolicyInputs` will descend into nested args, and on how many
 *  scalar paths it will emit — a defensive bound against a maliciously deep/huge tool-call
 *  payload turning "project every arg into the policy input snapshot" into unbounded recursion
 *  or an unbounded key count. Well past anything a real tool call's arguments look like. */
const MAX_ARGS_FLATTEN_DEPTH = 32;
const MAX_ARGS_FLATTEN_ENTRIES = 2_000;

/**
 * Projects `toolCall.args` into the FLAT `path -> scalar` shape the policy DSL's `InputSnapshot`
 * requires (see src/policy/dsl.ts — v0.2 is a closed-world flat map, no nested traversal), so a
 * policy rule can read `args.recipient` / `args.items.0.id` etc, not just the two hand-picked
 * fields (`action`, `amountMinor`) preCheck used to expose. Every emitted key is namespaced under
 * `args.` so raw tool args can never collide with (or spoof) the trusted `action` field preCheck
 * itself sets from `toolCall.name` — see also agentId in preCheck() below, which is likewise never
 * sourced from `toolCall.args`.
 *
 * Only WELL-FORMED policy scalars (string, boolean, safe-integer) are ever added. A leaf that
 * ISN'T a valid policy scalar — a float, `null`, a value outside the safe-integer range — is
 * simply OMITTED (the path reads as "absent" to the policy), not smuggled in raw. This matters
 * because `evaluate()` asserts EVERY key in the input snapshot is a valid scalar and fail-closed
 * DENYs the entire call if even one isn't (src/policy/eval.ts) — so blindly projecting an
 * unrelated float somewhere in a tool's args (e.g. a `temperature: 0.7` parameter that no policy
 * rule even reads) would otherwise turn "full args visibility" into "any float anywhere in args
 * denies every call", a correctness regression far worse than the field being merely absent to
 * the policy engine.
 *
 * Honest limit: a raw arg key that itself contains a literal "." (e.g. `{"a.b": 1}`) is
 * indistinguishable in the flattened path from a nested `{a: {b: 1}}` — same as any dot-path
 * flattening convention. Not solved here; a policy author relying on such a key should know this.
 */
function flattenArgsToPolicyInputs(args, prefix = "args", depth = 0, out = {}) {
  if (Object.keys(out).length >= MAX_ARGS_FLATTEN_ENTRIES || depth > MAX_ARGS_FLATTEN_DEPTH) return out;
  if (args === null || args === undefined) return out; // absent, not a scalar — omitted, not coerced
  const t = typeof args;
  if (t === "string" || t === "boolean") {
    out[prefix] = args;
    return out;
  }
  if (t === "number") {
    if (Number.isSafeInteger(args)) out[prefix] = args;
    // else: a float / unsafe-range number — not a valid policy scalar; deliberately omitted
    // (see the function docstring). The dedicated top-level `amountMinor` slot below is
    // unaffected and keeps its own strict fail-closed-DENY-on-float behavior exactly as before.
    return out;
  }
  if (Array.isArray(args)) {
    for (let i = 0; i < args.length; i++) {
      if (Object.keys(out).length >= MAX_ARGS_FLATTEN_ENTRIES) break;
      flattenArgsToPolicyInputs(args[i], `${prefix}.${i}`, depth + 1, out);
    }
    return out;
  }
  if (t === "object") {
    for (const k of Object.keys(args)) {
      if (Object.keys(out).length >= MAX_ARGS_FLATTEN_ENTRIES) break;
      flattenArgsToPolicyInputs(args[k], `${prefix}.${k}`, depth + 1, out);
    }
    return out;
  }
  return out; // functions / symbols / bigint: not JSON-representable, skipped
}

/**
 * The receipt's `action.paramsHash` binding for `args`. Prefers the same JCS canonicalization the
 * rest of the receipt is hashed with (deterministic, key-order-independent — see src/jcs.ts), so
 * two logically-identical arg objects with differently-ordered keys hash identically. JCS is
 * deliberately integer-only/finite/depth-bounded (receipts carry no floats); a downstream MCP
 * tool's args are THAT TOOL's business, not policy inputs, and may legitimately contain a shape
 * JCS refuses (a float parameter, a very deeply nested structure). Falling back to
 * `JSON.stringify` in that case keeps preCheck's "malformed input never throws" contract — it is
 * simply NOT key-order-independent for that narrower, documented case.
 */
function canonicalParamsHash(args) {
  const value = args ?? {};
  try {
    return sha256Prefixed(canonicalize(value));
  } catch {
    return sha256Prefixed(JSON.stringify(value));
  }
}

/**
 * The Policy Decision Point. Pure + deterministic (beyond the caller-supplied `ts`, which is a
 * real wall-clock read — the underlying `evaluate()` itself remains pure/deterministic).
 * Returns `{ decision, receipt, evidence }`. `evidence` (policyHash + inputs) is what a third
 * party re-runs to reproduce the verdict offline.
 *
 * @param {{ name: string, args?: Record<string, unknown>, agentId?: string }} toolCall
 * @param {{
 *   signer: import("../../../dist/src/builder.js").Signer,
 *   policy: import("../../../dist/src/policy/dsl.js").Policy,
 *   prev?: import("../../../dist/src/types.js").Receipt | null,
 *   seq?: number,
 *   tenant?: string,
 *   chain?: string,
 *   ts?: string,
 * }} options
 */
export function preCheck(
  toolCall,
  { signer, policy, prev = null, seq = 0, tenant = "default-tenant", chain, ts } = {},
) {
  if (!signer) throw new Error("preCheck: `signer` is required");
  if (!policy) throw new Error("preCheck: `policy` is required (no implicit default policy)");

  // The CLOSED-WORLD decision inputs. `action`/`amountMinor` are the original, hand-picked fields
  // (kept unchanged for backward compatibility — an existing policy reading top-level
  // `amountMinor` keeps working exactly as before, float-and-all fail-closed). `args.*` is the
  // FULL tool-call argument surface, flattened to scalar-only dotted paths (see
  // flattenArgsToPolicyInputs above) so a policy can additionally read e.g. `args.recipient`.
  // `amountMinor` is optional: tools that don't carry a monetary amount simply omit it, and any
  // policy rule reading it treats "absent" as a non-match rather than a required field (unless
  // the policy itself lists it in requiredPaths).
  const inputs = { action: toolCall.name, amountMinor: toolCall.args?.amountMinor };
  if (inputs.amountMinor === undefined) delete inputs.amountMinor;
  Object.assign(inputs, flattenArgsToPolicyInputs(toolCall.args));

  const ev = evaluate(policy, inputs); // ALLOW | DENY, fail-closed, re-runnable
  const decision = ev.verdict === "ALLOW" ? "ALLOW" : "DENY";

  // Commit the policy+inputs ONLY when the inputs are canonicalizable. Malformed inputs (e.g. a
  // float amount) → fail-closed DENY with NO compliance block (there is nothing valid to
  // commit/replay).
  let compliance = null;
  try {
    compliance = complianceCommit(policy, inputs);
  } catch {
    compliance = null;
  }

  const receipt = buildReceipt(
    {
      id: `rcpt_${seq}`,
      ts: ts ?? new Date().toISOString(),
      scope: { tenant, chain: chain ?? `${tenant}:mcp` },
      // `toolCall.agentId` is the ONLY source for this field — never `toolCall.args` (a caller
      // that reads a request's own arguments into `agentId` would let the CALLER spoof its own
      // attribution; see packages/mcp-proxy's create-proxy-server.mjs, which sources this from a
      // static proxy-config value / the session id, never from the forwarded tool arguments).
      agent: { id: toolCall.agentId ?? "mcp-agent", model: null, principal: "POLICY" },
      action: {
        id: toolCall.name,
        canonical: toolCall.name,
        riskClass: decision === "DENY" ? "HIGH" : "LOW",
        paramsHash: canonicalParamsHash(toolCall.args),
        reversible: false,
        rollbackRef: null,
      },
      // verdict records the OUTCOME; ruleId records WHICH policy rule fired; compliance COMMITS
      // the policy + inputs by hash so the decision is re-checkable ON the receipt, not just
      // out-of-band.
      governance: {
        mode: "on",
        verdict: decision === "ALLOW" ? "EXECUTED" : "BLOCKED",
        ruleId: ev.ruleFired ?? "default-deny",
        approval: null,
        sandboxed: false,
        compliance,
      },
    },
    prev,
    signer,
  );

  return {
    decision,
    receipt,
    evidence: { policyHash: policyHash(policy), engine: ev.engine, ruleFired: ev.ruleFired, inputs },
  };
}

export { verifyReceiptCompliance };
