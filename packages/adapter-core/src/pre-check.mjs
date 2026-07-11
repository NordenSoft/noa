/**
 * preCheck — the MCP pre-flight Policy Decision Point, extracted from
 * examples/mcp-preflight/preflight.mjs into a shared, unit-testable module.
 *
 * Sits between an MCP host and its tool servers. For EVERY tool call it runs the
 * DETERMINISTIC policy evaluator `evaluate(policy, inputs)` (noa-receipt's offline-replayable
 * policy engine, imported from the noa-receipt package) and returns a SIGNED receipt of the
 * ALLOW/DENY decision. FAIL-CLOSED: any policy/input error resolves to DENY, never a throw,
 * never a silent allow.
 *
 * Dependency note: this module consumes noa-receipt as a published registry dependency
 * (`^0.4.0`, see package.json), imported by its package name. The receipt builder, policy
 * evaluator, and hash helpers below all resolve from that package's public entry point.
 */
import {
  buildReceipt,
  buildReceiptAsync,
  evaluate,
  policyHash,
  complianceCommit,
  verifyReceiptCompliance,
  canonicalize,
  sha256Prefixed,
} from "noa-receipt";
import { matchApprovalRule } from "./approval-rules.mjs";

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
 * Only WELL-FORMED policy scalars (string, boolean, safe-integer) are ever added AS-IS. A finite
 * number outside the safe-integer range (a float, or an integer past 2^53) is NOT a valid policy
 * scalar for `evaluate()`'s strict integer-only assertion — but it is also NEVER silently dropped
 * (that would be an omission-bypass: a "DENY if args.amount > X" rule reading an absent path
 * silently falls through to a later, more permissive rule — see the fix history below). It is
 * instead projected as a canonical DECIMAL STRING via `canonicalDecimalNumberString()`, so the path
 * is always VISIBLE to the policy (`exists`/`eq`/`in`-testable, and a numeric-typed `ge`/`gt`/...
 * rule against it now fails closed to DENY on the resulting string/number type mismatch — see
 * src/policy/eval.ts's `cmp()` — rather than silently reading "absent"). The dedicated top-level
 * `amountMinor` slot is unaffected and keeps its own strict, purely-numeric fail-closed-DENY-on-float
 * behavior exactly as before; this projection is only about the FULL `args.*` visibility surface.
 *
 * FLATTEN-AMBIGUITY GUARD: a raw arg object key that itself contains a literal "." (e.g.
 * `{"a.b": 1}`) is structurally indistinguishable, once flattened, from a nested `{a: {b: 1}}` —
 * both produce the exact path `args.a.b`. A caller can exploit this as a DECOY: present a genuine
 * over-limit nested value (`{transfer: {amount: 999999999}}`, which is what actually gets forwarded
 * to — and executed by — the downstream tool, UNMODIFIED) alongside a literal dotted key at the same
 * flattened path (`"transfer.amount": 1`) whose small, innocuous value happens to win the
 * insertion-order collision in the policy's view. `flattenArgsToPolicyInputs` itself no longer
 * silently resolves this collision one way or the other: `findAmbiguousDottedArgKey()` (below) scans
 * for ANY raw key containing "." anywhere in `args` FIRST, and `preCheck()` fails the ENTIRE call
 * closed (DENY, no compliance commit — the same "nothing valid to commit" posture as a malformed
 * float `amountMinor`) the moment one is found, rather than guessing which of two colliding values
 * the caller "really meant".
 */
function flattenArgsToPolicyInputs(args, prefix, depth, out, state) {
  if (state.count >= MAX_ARGS_FLATTEN_ENTRIES || depth > MAX_ARGS_FLATTEN_DEPTH) return out;
  if (args === null || args === undefined) return out; // absent, not a scalar — omitted, not coerced
  const t = typeof args;
  if (t === "string" || t === "boolean") {
    out[prefix] = args;
    state.count++;
    return out;
  }
  if (t === "number") {
    if (Number.isSafeInteger(args)) {
      out[prefix] = args;
    } else if (Number.isFinite(args)) {
      out[prefix] = canonicalDecimalNumberString(args);
    }
    // else: NaN / +-Infinity — no meaningful decimal-string projection exists; omitted, same as
    // before (this is not the omission-bypass case: no policy rule can compare against
    // "not-a-number"/infinity meaningfully via string equality/existence either).
    if (out[prefix] !== undefined) state.count++;
    return out;
  }
  if (Array.isArray(args)) {
    for (let i = 0; i < args.length; i++) {
      if (state.count >= MAX_ARGS_FLATTEN_ENTRIES) break;
      flattenArgsToPolicyInputs(args[i], `${prefix}.${i}`, depth + 1, out, state);
    }
    return out;
  }
  if (t === "object") {
    for (const k of Object.keys(args)) {
      if (state.count >= MAX_ARGS_FLATTEN_ENTRIES) break;
      // Dotted raw keys are rejected up-front by findAmbiguousDottedArgKey() before this function
      // is ever called (see preCheck()) — reaching here with one would mean a caller bypassed that
      // guard; defensively skip it rather than silently flattening an ambiguous path.
      if (k.includes(".")) continue;
      flattenArgsToPolicyInputs(args[k], `${prefix}.${k}`, depth + 1, out, state);
    }
    return out;
  }
  return out; // functions / symbols / bigint: not JSON-representable, skipped
}

/**
 * Recursively scans `args` (same depth bound as `flattenArgsToPolicyInputs`) for the first raw
 * object key that itself contains a literal "." — see `flattenArgsToPolicyInputs`'s docstring for
 * the flatten-collision this closes. Returns the offending dotted-path-so-far (for diagnostics), or
 * `null` if none exists. Deliberately does NOT attempt to detect whether a collision would
 * ACTUALLY occur (i.e., whether some other key/nesting produces the same flattened path) — that
 * detection is iteration-order-fragile and a policy rule reading the colliding path might not even
 * exist YET (a future policy update could start reading it) — so ANY dotted key anywhere is treated
 * as unresolvable ambiguity, unconditionally.
 */
function findAmbiguousDottedArgKey(args, prefix = "args", depth = 0) {
  if (depth > MAX_ARGS_FLATTEN_DEPTH) return null;
  if (args === null || typeof args !== "object") return null;
  if (Array.isArray(args)) {
    for (let i = 0; i < args.length; i++) {
      const found = findAmbiguousDottedArgKey(args[i], `${prefix}.${i}`, depth + 1);
      if (found !== null) return found;
    }
    return null;
  }
  for (const k of Object.keys(args)) {
    if (k.includes(".")) return `${prefix}.${k}`;
    const found = findAmbiguousDottedArgKey(args[k], `${prefix}.${k}`, depth + 1);
    if (found !== null) return found;
  }
  return null;
}

/**
 * Canonical decimal-string projection for a finite float / unsafe-integer-range number leaf — see
 * `flattenArgsToPolicyInputs`'s docstring. Uses the ECMA-262-specified `Number::toString` algorithm
 * (the shortest decimal string that round-trips to the exact same float64 bit pattern), which is
 * deterministic across engines by spec — two independent implementations of this projection always
 * agree byte-for-byte. Honest limit: outside roughly [1e-6, 1e21) this is scientific notation (e.g.
 * `"1e+21"`) rather than expanded decimal digits, and the DSL's `ge`/`gt`/... comparisons against it
 * are lexicographic (UTF-16 code-unit order, see src/policy/eval.ts's `cmp()`), not numeric — exactly
 * like any other string value. A policy author needing true numeric float comparison is exactly why
 * the DSL states "no floats" up front (src/policy/dsl.ts); this projection exists purely so the
 * value is VISIBLE (`exists`/`eq`/`in`-testable, and a numeric-typed rule against it now fails
 * closed instead of silently reading "absent"), never silently omitted.
 */
function canonicalDecimalNumberString(n) {
  return Object.is(n, -0) ? "0" : String(n);
}

/**
 * A deterministic, key-order-independent decimal-ish serialization used ONLY as
 * `canonicalParamsHash`'s fallback for `args` shapes JCS itself refuses (a float, a value outside
 * JCS's depth bound, `NaN`/`Infinity`, a `bigint`). Unlike a raw `JSON.stringify(value)` fallback —
 * which hashes each object's OWN key insertion order — this recursively SORTS every object's keys,
 * so two logically-identical arg objects built with differently-ordered keys still hash identically
 * even on this fallback path (closing the same "key-order-independent" gap JCS itself would give,
 * just without JCS's stricter integer/finite/depth-bound refusal). Returns `undefined` for a value
 * `JSON.stringify` would itself drop (a bare `undefined`/function/symbol at a spot the caller can't
 * otherwise represent) — the same convention `JSON.stringify` uses. Throws (caught by
 * `canonicalParamsHash`) on a value it fundamentally cannot represent at all: a circular reference.
 */
function stableStringifyFallback(value, seen) {
  if (value === null) return "null";
  const t = typeof value;
  if (t === "string") return JSON.stringify(value);
  if (t === "boolean") return value ? "true" : "false";
  if (t === "number") return Number.isFinite(value) ? canonicalDecimalNumberString(value) : "null";
  if (t === "bigint") return JSON.stringify(value.toString());
  if (t === "undefined" || t === "function" || t === "symbol") return undefined;
  if (Array.isArray(value)) {
    if (seen.has(value)) throw new Error("noa-mcp-adapter-core: circular structure in tool-call args");
    seen.add(value);
    const items = value.map((v) => stableStringifyFallback(v, seen) ?? "null");
    seen.delete(value);
    return `[${items.join(",")}]`;
  }
  if (t === "object") {
    if (seen.has(value)) throw new Error("noa-mcp-adapter-core: circular structure in tool-call args");
    seen.add(value);
    const parts = [];
    for (const k of Object.keys(value).sort()) {
      const encoded = stableStringifyFallback(value[k], seen);
      if (encoded === undefined) continue; // JSON.stringify semantics: undefined-valued keys are omitted
      parts.push(`${JSON.stringify(k)}:${encoded}`);
    }
    seen.delete(value);
    return `{${parts.join(",")}}`;
  }
  return undefined; // function/symbol nested value: not JSON-representable, dropped
}

/** Fixed, greppable sentinel `action.paramsHash` for the (extremely rare) case where `args`
 *  cannot be represented at all by EITHER canonicalization strategy `canonicalParamsHash` tries —
 *  concretely, a circular reference (a `bigint` leaf is handled by both strategies without ever
 *  reaching this sentinel). `preCheck()` treats this sentinel as "uncanonicalizable" and forces the
 *  ENTIRE call's decision to fail-closed DENY (see preCheck() below) — not merely "the hash
 *  computation itself didn't throw" but "there is nothing trustworthy to evaluate a policy against
 *  at all", the same posture already taken for a malformed float `amountMinor`. */
const UNCANONICALIZABLE_ARGS_SENTINEL_HASH = sha256Prefixed("noa-mcp-adapter-core:paramsHash-uncanonicalizable-args");

/**
 * The receipt's `action.paramsHash` binding for `args`. Prefers the same JCS canonicalization the
 * rest of the receipt is hashed with (deterministic, key-order-independent — see src/jcs.ts), so
 * two logically-identical arg objects with differently-ordered keys hash identically. JCS is
 * deliberately integer-only/finite/depth-bounded (receipts carry no floats); a downstream MCP
 * tool's args are THAT TOOL's business, not policy inputs, and may legitimately contain a shape
 * JCS refuses (a float parameter, a very deeply nested structure). Falls back to
 * `stableStringifyFallback` in that case — deliberately NOT a raw `JSON.stringify(value)` fallback
 * (that would hash by the ORIGINAL object's own key insertion order, breaking the
 * key-order-independence property for exactly the args shapes that need the fallback in the first
 * place). If even the fallback can't represent `value` (a circular reference), the fixed
 * `UNCANONICALIZABLE_ARGS_SENTINEL_HASH` is returned instead — `preCheck`'s "malformed input never
 * throws" contract holds even for circular content that would make BOTH `canonicalize()` and a
 * naive `JSON.stringify()` throw uncaught, and `preCheck()` additionally forces this case to a
 * fail-closed DENY decision (see below), not just a non-throwing hash.
 */
function canonicalParamsHash(args) {
  const value = args ?? {};
  try {
    return sha256Prefixed(canonicalize(value));
  } catch {
    try {
      return sha256Prefixed(stableStringifyFallback(value, new WeakSet()) ?? "null");
    } catch {
      // Neither JCS nor the stable-stringify fallback could represent this content at all (e.g. a
      // circular reference) — fall back to the fixed sentinel rather than letting the exception
      // escape `preCheck`'s "never throws" public contract.
      return UNCANONICALIZABLE_ARGS_SENTINEL_HASH;
    }
  }
}

/** Fixed, greppable sentinel for `evidence.policyHash` when `policyHash(policy)` itself throws —
 *  see `safePolicyHash` below for exactly when that can happen and why it is an operator/config
 *  error, not a normal outcome. */
const UNCANONICALIZABLE_POLICY_SENTINEL_HASH = sha256Prefixed("noa-mcp-adapter-core:policyHash-uncanonicalizable-policy");

/**
 * Fail-closed wrapper around `policyHash(policy)` for `preCheck()`'s `evidence` block.
 *
 * `evaluate(policy, inputs)` (used for the actual decision, earlier in `preCheck`) NEVER throws —
 * it runs `validatePolicy(policy)` first and returns a DENY `"policy-invalid"` verdict for anything
 * that validator rejects. For a policy `validatePolicy` ACCEPTS, that same validator's own final
 * check already asserts `canonicalize(policy)` succeeds (see src/policy/validate.ts), so
 * `policyHash()` — which canonicalizes the identical object — does not throw in that
 * case either. The residual gap is a policy `validatePolicy` REJECTS for a reason UNRELATED to
 * canonicalizability (e.g. an unknown top-level key, or a duplicate rule id) that trips one of the
 * validator's EARLIER structural checks and short-circuits before its own canonicalize-recheck ever
 * runs (`if (errors.length === 0) { try canonicalize(p) ... } }`) — `evaluate()` still correctly
 * DENYs `"policy-invalid"` for that policy (the decision is safe), but if that SAME object also
 * happens to be genuinely non-canonicalizable in its own right (e.g. a value nested past JCS's
 * MAX_DEPTH, or a `NaN`/`Infinity` tucked into an unrelated/unknown field), an UNGUARDED
 * `policyHash(policy)` call independently throws a `JcsError` on it — this used to escape
 * `preCheck()` uncaught, a crash on what is fundamentally an operator/policy-config mistake, not a
 * caller-input attack, but `preCheck()`'s own "never throws" contract must hold for it too. Falls
 * back to the fixed `UNCANONICALIZABLE_POLICY_SENTINEL_HASH` sentinel rather than raising — the
 * decision itself is already DENY by the time this runs (via `evaluate()`'s own policy-invalid
 * fail-close), so this wrapper only needs to keep `preCheck()` from crashing while computing
 * diagnostic evidence for that already-safe decision.
 */
function safePolicyHash(policy) {
  try {
    return policyHash(policy);
  } catch {
    return UNCANONICALIZABLE_POLICY_SENTINEL_HASH;
  }
}

/**
 * The DECISION half of the Policy Decision Point, shared by `preCheck` (sync signing) and
 * `preCheckAsync` (async/remote signing) -- everything up to but NOT including the actual
 * `buildReceipt`/`buildReceiptAsync` call. `signer` never appears in this function: the ONLY
 * signer-dependent step in the ORIGINAL preCheck() was its final `buildReceipt(..., signer)`
 * call, so this extraction is purely mechanical -- moves code, changes nothing about WHAT gets
 * decided, only WHERE the receipt gets built and signed.
 *
 * Returns `{ buildInput, decision, evidence }` -- `buildInput` is the exact object literal the
 * original preCheck() passed as `buildReceipt`'s first argument.
 *
 * @param {{ name: string, args?: Record<string, unknown>, agentId?: string }} toolCall
 * @param {{
 *   policy: import("noa-receipt").Policy,
 *   prev?: import("noa-receipt").Receipt | null,
 *   seq?: number,
 *   tenant?: string,
 *   chain?: string,
 *   ts?: string,
 * }} options
 */
function computeReceiptPlan(toolCall, { policy, prev = null, seq = 0, tenant = "default-tenant", chain, ts, approvalRules, suppressApprovalHold = false }) {
  if (!policy) throw new Error("preCheck: `policy` is required (no implicit default policy)");

  // FAIL-CLOSED READ GUARD (checked BEFORE anything else): `toolCall.name`/`toolCall.args`/
  // `toolCall.agentId` used to be read directly, UNGUARDED — `name`/`args`/`amountMinor` at this
  // exact spot (before ANY of the enumeration guards below ever run) and `agentId` even later,
  // inside the receipt-construction call at the bottom of this function. A caller embedding this
  // package in-process (documented as usable by "any MCP integration: proxy, gateway, in-process
  // guard") can legitimately hand it a `toolCall`/`args` shape carrying a throwing getter or Proxy
  // trap (never producible by `JSON.parse`, but a live JS object built by that caller's own code
  // can contain one) on ANY of these fields — e.g. an `args` object whose `amountMinor` property is
  // `{ get amountMinor() { throw ... } }`, or a `toolCall` whose `agentId` getter throws. Reading
  // any of them unguarded would throw straight out of `preCheck()`, before reaching ANY fail-closed
  // guard — violating this module's own "never throws, only DENY" contract. `safeName`/`safeArgs`/
  // `safeAmountMinor`/`safeAgentId` are captured ONCE, inside this ONE try/catch, and reused
  // EVERYWHERE below (the receipt's `action.id`/`canonical`/`agent.id` included, and every later
  // `toolCall.args` read) instead of re-reading `toolCall.name`/`toolCall.args`/`toolCall.agentId` a
  // second time — a second unguarded read would reopen the exact same gap for a throwing getter
  // (getters re-invoke on every access, they are not cached), and would also let a live getter hand
  // different call-sites inconsistent views of the "same" call for a single decision.
  let safeName;
  let safeArgs;
  let safeAmountMinor;
  let safeAgentId;
  let toolCallReadThrew = false;
  try {
    safeName = toolCall.name;
    safeArgs = toolCall.args;
    safeAmountMinor = safeArgs?.amountMinor;
    safeAgentId = toolCall.agentId;
  } catch {
    toolCallReadThrew = true;
  }

  const nameInvalid = !toolCallReadThrew && (typeof safeName !== "string" || safeName.length === 0);
  const safeActionId = toolCallReadThrew || nameInvalid ? "unknown-action" : safeName;
  const safeAgentIdForReceipt = typeof safeAgentId === "string" && safeAgentId.length > 0 ? safeAgentId : "mcp-agent";

  const inputs = toolCallReadThrew ? {} : { action: safeName, amountMinor: safeAmountMinor };
  if (inputs.amountMinor === undefined) delete inputs.amountMinor;

  const paramsHash = canonicalParamsHash(safeArgs);
  const argsUncanonicalizable = paramsHash === UNCANONICALIZABLE_ARGS_SENTINEL_HASH;

  let ambiguousArgKey = null;
  let argsEnumerationThrew = false;
  try {
    ambiguousArgKey = findAmbiguousDottedArgKey(safeArgs);
  } catch {
    argsEnumerationThrew = true;
  }

  let ev;
  if (toolCallReadThrew) {
    ev = { verdict: "DENY", ruleFired: "toolcall-read-threw", engine: "toolcall-read-guard" };
  } else if (nameInvalid) {
    ev = { verdict: "DENY", ruleFired: "invalid-action-name", engine: "toolcall-read-guard" };
  } else if (argsEnumerationThrew) {
    ev = { verdict: "DENY", ruleFired: "args-enumeration-threw", engine: "args-flatten-ambiguity-guard" };
  } else if (ambiguousArgKey !== null) {
    ev = { verdict: "DENY", ruleFired: "args-flatten-ambiguous-dotted-key", engine: "args-flatten-ambiguity-guard" };
  } else if (argsUncanonicalizable) {
    ev = { verdict: "DENY", ruleFired: "args-uncanonicalizable", engine: "args-canonicalization-guard" };
  } else {
    try {
      Object.assign(inputs, flattenArgsToPolicyInputs(safeArgs, "args", 0, {}, { count: 0 }));
      ev = evaluate(policy, inputs); // ALLOW | DENY, fail-closed, re-runnable
    } catch {
      argsEnumerationThrew = true;
      ev = { verdict: "DENY", ruleFired: "args-enumeration-threw", engine: "args-flatten-ambiguity-guard" };
    }
  }
  const decision = ev.verdict === "ALLOW" ? "ALLOW" : "DENY";

  // R4 — post-preCheck human-approval gate. Runs only when decision===ALLOW (a DENY is already
  // refused; nothing to hold). `inputs` is the SAME already-flattened snapshot evaluate() used.
  // approvalRules omitted/empty -> byte-identical prior behavior.
  //
  // `suppressApprovalHold` skips ONLY this hold-match, never the policy decision above — the
  // caller (an MCP proxy) sets it for exactly ONE call, immediately after a single-use approval
  // ticket for that same call was verified AND consumed. Without it, the consumed-ticket retry
  // would re-match the same rule and re-DEFER forever, making EXECUTED unreachable.
  const heldRule = decision === "ALLOW" && !suppressApprovalHold ? matchApprovalRule(approvalRules, safeActionId, inputs) : null;
  const finalDecision = heldRule ? "DEFERRED" : decision;

  let compliance = null;
  if (!toolCallReadThrew && !nameInvalid && !argsEnumerationThrew && ambiguousArgKey === null && !argsUncanonicalizable) {
    try {
      compliance = complianceCommit(policy, inputs);
    } catch {
      compliance = null;
    }
  }

  const buildInput = {
    id: `rcpt_${seq}`,
    ts: ts ?? new Date().toISOString(),
    scope: { tenant, chain: chain ?? `${tenant}:mcp` },
    agent: { id: safeAgentIdForReceipt, model: null, principal: "POLICY" },
    action: {
      id: safeActionId,
      canonical: safeActionId,
      riskClass: finalDecision === "ALLOW" ? "LOW" : "HIGH", // R4: a held call is elevated risk, same class as DENY
      paramsHash,
      reversible: false,
      rollbackRef: null,
    },
    governance: {
      mode: "on",
      verdict: finalDecision === "ALLOW" ? "EXECUTED" : finalDecision === "DEFERRED" ? "DEFERRED" : "BLOCKED",
      ruleId: heldRule ? `approval:${heldRule.id}` : (ev.ruleFired ?? "default-deny"),
      approval: null,
      sandboxed: false,
      compliance,
    },
  };

  return {
    buildInput,
    decision: finalDecision,
    evidence: { policyHash: safePolicyHash(policy), engine: ev.engine, ruleFired: ev.ruleFired, inputs, approvalRuleFired: heldRule ? heldRule.id : null },
  };
}

/**
 * The Policy Decision Point (sync signing). Pure + deterministic (beyond the caller-supplied `ts`,
 * which is a real wall-clock read — the underlying decision logic itself remains pure/deterministic).
 * Returns `{ decision, receipt, evidence }`. `evidence` (policyHash + inputs) is what a third
 * party re-runs to reproduce the verdict offline.
 *
 * @param {{ name: string, args?: Record<string, unknown>, agentId?: string }} toolCall
 * @param {{
 *   signer: import("noa-receipt").Signer,
 *   policy: import("noa-receipt").Policy,
 *   prev?: import("noa-receipt").Receipt | null,
 *   seq?: number,
 *   tenant?: string,
 *   chain?: string,
 *   ts?: string,
 * }} options
 */
export function preCheck(toolCall, { signer, policy, prev = null, seq = 0, tenant = "default-tenant", chain, ts, approvalRules, suppressApprovalHold = false } = {}) {
  if (!signer) throw new Error("preCheck: `signer` is required");
  const plan = computeReceiptPlan(toolCall, { policy, prev, seq, tenant, chain, ts, approvalRules, suppressApprovalHold });
  const receipt = buildReceipt(plan.buildInput, prev, signer);
  return { decision: plan.decision, receipt, evidence: plan.evidence };
}

/**
 * Async twin of `preCheck` for a `RemoteSigner` (`{ kid, sign }` — e.g. `packages/signer-sidecar`'s
 * client) or a local `Signer` used asynchronously. Identical decision logic (`computeReceiptPlan`,
 * shared with `preCheck` — never duplicated), only the final signing step is awaited.
 *
 * @param {{ name: string, args?: Record<string, unknown>, agentId?: string }} toolCall
 * @param {{
 *   signer: import("noa-receipt").Signer | import("noa-receipt").RemoteSigner,
 *   policy: import("noa-receipt").Policy,
 *   prev?: import("noa-receipt").Receipt | null,
 *   seq?: number,
 *   tenant?: string,
 *   chain?: string,
 *   ts?: string,
 * }} options
 */
export async function preCheckAsync(toolCall, { signer, policy, prev = null, seq = 0, tenant = "default-tenant", chain, ts, approvalRules, suppressApprovalHold = false } = {}) {
  if (!signer) throw new Error("preCheckAsync: `signer` is required");
  const plan = computeReceiptPlan(toolCall, { policy, prev, seq, tenant, chain, ts, approvalRules, suppressApprovalHold });
  const receipt = await buildReceiptAsync(plan.buildInput, prev, signer);
  return { decision: plan.decision, receipt, evidence: plan.evidence };
}

export { verifyReceiptCompliance };
export { canonicalParamsHash };
