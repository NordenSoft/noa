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
  evaluate,
  policyHash,
  complianceCommit,
  verifyReceiptCompliance,
  canonicalize,
  sha256Prefixed,
} from "noa-receipt";

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
 * The Policy Decision Point. Pure + deterministic (beyond the caller-supplied `ts`, which is a
 * real wall-clock read — the underlying `evaluate()` itself remains pure/deterministic).
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
export function preCheck(
  toolCall,
  { signer, policy, prev = null, seq = 0, tenant = "default-tenant", chain, ts } = {},
) {
  if (!signer) throw new Error("preCheck: `signer` is required");
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

  // ACTION-NAME SHAPE GUARD: a raw read that itself SUCCEEDED can still hand back a `name` that is
  // not a valid, non-empty string (a number, a plain object, `""`, ...). `evaluate()`'s own
  // integer/string-only scalar assertion already fails a NON-SCALAR `name` (e.g. an object) closed
  // to DENY internally, but a scalar-but-wrong-shape `name` (a number, or an empty string) sails
  // through evaluation untouched and then reaches `buildReceipt` below as `action.id`/
  // `action.canonical` — both of which `buildReceipt`'s own structural re-validation REQUIRES to be
  // non-empty strings (see src/schema.ts). Before this guard, that mismatch threw a `BuilderError`
  // straight out of `preCheck()` — a crash on a merely mis-shaped (not evil/throwing) `name`, not
  // even an adversarial one. Fixed the same way as a throwing read: force the WHOLE call fail-closed
  // DENY, and always feed `buildReceipt` the same safe sentinel (`"unknown-action"`) a raw read
  // failure already uses — a `name` that can't be trusted enough to evaluate a policy against can
  // also never be trusted enough to build a receipt with.
  const nameInvalid = !toolCallReadThrew && (typeof safeName !== "string" || safeName.length === 0);
  // The receipt's `action.id`/`action.canonical` value, resolved ONCE: the safe sentinel whenever
  // the raw read itself threw OR the read succeeded but `name` isn't a usable non-empty string;
  // `safeName` (already a valid non-empty string here) otherwise.
  const safeActionId = toolCallReadThrew || nameInvalid ? "unknown-action" : safeName;
  // `toolCall.agentId` is ATTRIBUTION metadata only — never read by `evaluate()`/policy matching
  // (see the receipt-construction comment below), so an invalid shape here does not need to force
  // the DECISION closed the way an invalid `name` does; it only needs to never reach `buildReceipt`
  // as a non-string/empty value (the same structural requirement `action.id` has). Falls back to
  // the SAME sentinel an absent `agentId` already used (`"mcp-agent"`) rather than inventing a
  // second, differently-worded sentinel for what is semantically the same "no trustworthy agent id
  // given" case.
  const safeAgentIdForReceipt = typeof safeAgentId === "string" && safeAgentId.length > 0 ? safeAgentId : "mcp-agent";

  // The CLOSED-WORLD decision inputs. `action`/`amountMinor` are the original, hand-picked fields
  // (kept unchanged for backward compatibility — an existing policy reading top-level
  // `amountMinor` keeps working exactly as before, float-and-all fail-closed). `args.*` is the
  // FULL tool-call argument surface, flattened to scalar-only dotted paths (see
  // flattenArgsToPolicyInputs above) so a policy can additionally read e.g. `args.recipient`.
  // `amountMinor` is optional: tools that don't carry a monetary amount simply omit it, and any
  // policy rule reading it treats "absent" as a non-match rather than a required field (unless
  // the policy itself lists it in requiredPaths). When the raw read above itself threw, there is
  // nothing valid to project at all — `inputs` stays empty and the branch below fails closed.
  const inputs = toolCallReadThrew ? {} : { action: safeName, amountMinor: safeAmountMinor };
  if (inputs.amountMinor === undefined) delete inputs.amountMinor;

  // Computed EARLY (not just when building the receipt below) so a truly uncanonicalizable `args`
  // (a circular reference — see canonicalParamsHash's docstring) can force the WHOLE call's
  // decision fail-closed, not merely avoid throwing during hash computation. Safe even when
  // `toolCallReadThrew` — `safeArgs` is simply `undefined` in that case, and canonicalParamsHash
  // treats an absent `args` as `{}`.
  const paramsHash = canonicalParamsHash(safeArgs);
  const argsUncanonicalizable = paramsHash === UNCANONICALIZABLE_ARGS_SENTINEL_HASH;

  // FLATTEN-AMBIGUITY GUARD (checked BEFORE any args are projected): a raw arg key containing a
  // literal "." is indistinguishable, once flattened, from a nested path — see
  // findAmbiguousDottedArgKey's docstring for the decoy-collision this closes. Fail the ENTIRE call
  // closed, unconditionally, rather than let a policy see one of two colliding values by accident
  // of iteration/insertion order.
  //
  // Both this scan AND the flatten step below descend into every enumerable value in `args` —
  // ordinarily just plain data, but a caller embedding this package in-process (documented as
  // usable by "any MCP integration: proxy, gateway, in-process guard") can legitimately hand it an
  // `args` object carrying a throwing getter or Proxy trap (never producible by `JSON.parse`, but
  // a live JS object built by that caller's own code can contain one). Reading such a property
  // throws the MOMENT either traversal reaches it — `preCheck`'s "never throws" contract (already
  // honored for a genuinely uncanonicalizable/circular `args` shape via `canonicalParamsHash`
  // above) must hold here too: a throw during either traversal fails the WHOLE call closed (DENY,
  // no compliance commit — the same "nothing valid to evaluate/replay" posture as the other
  // fail-closed paths), never escapes as an uncaught exception to the caller.
  let ambiguousArgKey = null;
  let argsEnumerationThrew = false;
  try {
    ambiguousArgKey = findAmbiguousDottedArgKey(safeArgs);
  } catch {
    argsEnumerationThrew = true;
  }

  let ev;
  if (toolCallReadThrew) {
    // Highest-priority fail-closed check: the raw `toolCall.name`/`toolCall.args` read itself
    // threw, BEFORE anything below could even run against real data — see the guard above.
    ev = { verdict: "DENY", ruleFired: "toolcall-read-threw", engine: "toolcall-read-guard" };
  } else if (nameInvalid) {
    // Second-priority fail-closed check: the raw read succeeded, but `name` itself is not a valid
    // non-empty string — see the ACTION-NAME SHAPE GUARD above. Forced closed before args are ever
    // considered, same posture as a read that threw outright.
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

  // Commit the policy+inputs ONLY when the raw toolCall read succeeded, `name` itself is a usable
  // non-empty string, AND the inputs are canonicalizable, unambiguous, AND args could be enumerated
  // at all. Malformed inputs (e.g. a float amount), an invalid action name, a dotted-key ambiguity,
  // a fully-uncanonicalizable args (a circular reference), a toolCall read that itself threw, or an
  // args enumeration that itself threw → fail-closed DENY with NO compliance block (there is
  // nothing valid to commit/replay).
  let compliance = null;
  if (!toolCallReadThrew && !nameInvalid && !argsEnumerationThrew && ambiguousArgKey === null && !argsUncanonicalizable) {
    try {
      compliance = complianceCommit(policy, inputs);
    } catch {
      compliance = null;
    }
  }

  const receipt = buildReceipt(
    {
      id: `rcpt_${seq}`,
      ts: ts ?? new Date().toISOString(),
      scope: { tenant, chain: chain ?? `${tenant}:mcp` },
      // `safeAgentIdForReceipt` (not a fresh `toolCall.agentId` re-read — see the guard above) so a
      // throwing `agentId` getter can never surface here, and an invalid-shaped-but-non-throwing
      // `agentId` can never reach `buildReceipt`'s own non-empty-string requirement either.
      // `toolCall.agentId` is the ONLY source for this field — never `toolCall.args` (a caller
      // that reads a request's own arguments into `agentId` would let the CALLER spoof its own
      // attribution; see packages/mcp-proxy's create-proxy-server.mjs, which sources this from a
      // static proxy-config value / the session id, never from the forwarded tool arguments).
      agent: { id: safeAgentIdForReceipt, model: null, principal: "POLICY" },
      action: {
        // `safeActionId` (not a fresh `toolCall.name` re-read — see the guard above) so a throwing
        // OR invalid-shaped `name` can never surface here either; it is already a
        // non-empty string (either `safeName` itself, or the `"unknown-action"` sentinel).
        id: safeActionId,
        canonical: safeActionId,
        riskClass: decision === "DENY" ? "HIGH" : "LOW",
        paramsHash,
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
    evidence: { policyHash: safePolicyHash(policy), engine: ev.engine, ruleFired: ev.ruleFired, inputs },
  };
}

export { verifyReceiptCompliance };
