/**
 * approval-rules.mjs — deterministic match layer for the human-approval gate (adapter-core-only,
 * NOT part of noa-receipt's core L2 policy DSL — src/policy/dsl.ts). This is a deliberately SEPARATE
 * small matcher rather than an extension of dsl.ts: it runs AFTER preCheck's own signed ALLOW/DENY
 * decision, so changing an approval threshold can never alter the signed L2 policy's semantics.
 *
 * Runs AFTER preCheck()'s own ALLOW/DENY decision, never before/instead of it.
 */
/*
 * ⚠ ROUND 4 / R4-11 — the phrase "never throws" appears below and is MEASURED FALSE in one case: a
 * revoked Proxy passed as caller input throws out of `preCheck`. Every input shape reached in
 * practice returns a DENY rather than throwing, which is what the contract is FOR; the absolute is
 * what was wrong. It is corrected in place rather than deleted, because "never" in a fail-closed
 * contract is precisely the kind of word a reader stops testing.
 */

const MATCH_TYPES = new Set(["exact", "prefix", "suffix"]);
const THRESHOLD_OPS = new Set(["ge", "gt"]);

/** Validated ONCE, at compile time, into a snapshot the matcher then reads — see the second-review note
 *  below for the three measured bypasses that made "validate the caller's object, then read the
 *  caller's object again" an unusable shape. */
import { intrinsics } from "noa-receipt";

// REDTEAM 2026-08-03. `matchApprovalRule` decides whether an action NEEDS a human approval, and
// every failure mode in it lands on "no rule matched" — which the caller reads as "no approval
// required". Two live-global reads reached that outcome directly, MEASURED against a rule with a
// 4,000 threshold and a 900,000-cent refund:
//
//     Array.isArray  -> false  =>  returns null immediately                     APPROVAL BYPASSED
//     hasOwnProperty -> false  =>  the threshold value reads as undefined and
//                                  the rule is skipped                          APPROVAL BYPASSED
//
// The DIRECTION of the failure is what makes this severe. Every deliberate branch in this file fails
// CLOSED — an ambiguous value returns the rule, a throw continues to the next one. But a poisoned
// type predicate does not mis-evaluate a rule, it makes the rule INVISIBLE, and an empty rule set is
// indistinguishable from "nothing needs approval here".

// ROUND 3 — THE THIRD FIX IN THIS FUNCTION, AND THE FIRST ONE AIMED AT THE CLASS.
// Round 2 hardened the named builtins; round 3 reproduced three MORE bypasses in the same code by
// poisoning the ones that had not been named: `Object.keys`, `Array.prototype.map`, and the array
// ITERATOR itself. Naming poisons one at a time is a race against whoever writes the next line.
//
// Iteration over caller-owned arrays on a decision path is now an INDEX LOOP. An index loop
// dispatches through no method at all — there is no `next`, no `map`, no `forEach` to replace — so
// the class is closed rather than its current members. This is the same move the kernel made when
// its key walk and code-point walk became index loops.
const {
  isArray, hasOwn, strStartsWith, strEndsWith, isSafeInteger, arrayPush, arrayJoin, arrayLength,
  getOwnPropertyDescriptor, ownKeys, objectCreateNull, objectFreeze, objectSetPrototypeOf,
  INERT_ARRAY_PROTOTYPE, newWeakSet, weakSetAdd, weakSetHas, newSet, setHas, setAdd, isProxy, numToString,
} = intrinsics;

// ── THE SECOND CRITICAL IN THIS FILE, AND WHY THE ANSWER IS A SNAPSHOT (2026-08-12, round 2) ──────
// The first fix made every load path CALL the validator. An adversarial review then walked straight
// past the validated gate three times, on the patched code, each ending in an executed 7000-unit
// transfer with no human:
//
//   1. A rule whose own data says "gate every transfer_funds", with `threshold` INHERITED from its
//      prototype ({path:"missing", op:"ge", value:0}). Validation read the inherited value and
//      called it well-formed; the matcher then looked for `inputs["missing"]`, did not find it,
//      skipped the rule, and forwarded. Same trick from `Object.prototype` — measured ALLOW.
//   2. An honest rule set MUTATED after `createProxyServer` validated it. Validation saw the honest
//      rules; the matcher read the mutated ones.
//   3. A `match` GETTER returning valid data on its first read and a non-matching action on its
//      second (`getterReads: 2`).
//
// All three are ONE defect: `requireValidApprovalRules` returned the CALLER'S OWN ARRAY, and both
// the validator and the matcher read it with ordinary property access. Nothing bound the object that
// was checked to the object that was used — which is precisely the check-then-use gap
// `config-artifact.mjs` closed on the filesystem, relocated into the object graph. A check that does
// not bind to the value it checked is not a check.
//
// So this module no longer holds a caller's object at all. `compileApprovalRules` walks the input
// ONCE and builds an inert snapshot: every field read through `getOwnPropertyDescriptor` (an OWN
// DATA property or it is not read), inherited or accessor-backed critical fields REFUSED rather than
// resolved, each rule a frozen null-prototype record, the array frozen and re-rooted onto the
// kernel's `INERT_ARRAY_PROTOTYPE`, and the result branded in a module-private WeakSet so the
// matcher can tell a snapshot from a live object. A getter is read exactly once, by the compiler,
// and its answer is refused rather than kept — there is no second read for it to answer differently.
// This is the same move `src/verify.ts` made when it stopped accepting live objects rather than
// cloning them: the house answer to "a live caller object" is "do not hold one".
const COMPILED_RULE_SETS = newWeakSet();

const FIELD_ABSENT = "absent";
const FIELD_DATA = "own-data";
const FIELD_INHERITED = "inherited from the prototype chain";
const FIELD_ACCESSOR = "defined by a getter/setter";

/**
 * Reads ONE field the only way a decision may read a caller's object: as an own DATA property.
 * An inherited value and an accessor are reported as what they are, never silently resolved — the
 * whole point is that `obj.key` would have answered for both.
 */
function readOwnField(obj, key) {
  const d = getOwnPropertyDescriptor(obj, key);
  if (d === undefined) return { kind: key in obj ? FIELD_INHERITED : FIELD_ABSENT, value: undefined };
  if (!hasOwn(d, "value")) return { kind: FIELD_ACCESSOR, value: undefined };
  return { kind: FIELD_DATA, value: d.value };
}

/** A record this module is willing to read fields off: not null, not an array, not a Proxy (whose
 *  traps can answer differently on every read, which is finding 3 with a different spelling). */
function isPlainRecord(v) {
  return v !== null && typeof v === "object" && !isArray(v) && !isProxy(v);
}

/** Reads a REQUIRED own-data field, recording a precise error when it is anything else. */
function requiredOwnField(obj, key, where, errors) {
  const f = readOwnField(obj, key);
  if (f.kind !== FIELD_DATA) {
    arrayPush(errors, `${where}.${key}: must be an OWN DATA property of the rule (this one is ${f.kind}) — a rule set is plain data, and a field that is computed or inherited can answer one way while it is checked and another way while it is used`);
    return null;
  }
  return f;
}

/** Compiles ONE rule into a frozen, null-prototype record, or returns null having recorded why. */
function compileRule(raw, idx, errors) {
  const where = `approvalRules[${idx}]`;
  if (!isPlainRecord(raw)) {
    arrayPush(errors, `${where}: must be an object`);
    return null;
  }
  const before = arrayLength(errors);

  const idField = requiredOwnField(raw, "id", where, errors);
  if (idField !== null && (typeof idField.value !== "string" || idField.value.length === 0)) {
    arrayPush(errors, `${where}.id: non-empty string`);
  }

  let match = null;
  const matchField = requiredOwnField(raw, "match", where, errors);
  if (matchField !== null) {
    const m = matchField.value;
    if (!isPlainRecord(m)) {
      arrayPush(errors, `${where}.match.type: must be "exact", "prefix", or "suffix"`);
    } else {
      const typeField = requiredOwnField(m, "type", `${where}.match`, errors);
      const actionField = requiredOwnField(m, "action", `${where}.match`, errors);
      if (typeField !== null && !setHas(MATCH_TYPES, typeField.value)) {
        arrayPush(errors, `${where}.match.type: must be "exact", "prefix", or "suffix"`);
      } else if (actionField !== null && (typeof actionField.value !== "string" || actionField.value.length === 0)) {
        arrayPush(errors, `${where}.match.action: non-empty string`);
      } else if (typeField !== null && actionField !== null) {
        match = objectCreateNull();
        match.type = typeField.value;
        match.action = actionField.value;
        objectFreeze(match);
      }
    }
  }

  // ABSENT means "gate every action this rule matches" — the fail-closed reading, and the one an
  // INHERITED threshold silently replaced with "gate nothing". Inherited/accessor is an error, not
  // an absence, so the two can never be confused again.
  let threshold;
  const tField = readOwnField(raw, "threshold");
  if (tField.kind === FIELD_INHERITED || tField.kind === FIELD_ACCESSOR) {
    arrayPush(errors, `${where}.threshold: must be an OWN DATA property of the rule (this one is ${tField.kind}) — an inherited threshold turns "hold every match" into "hold nothing" without changing a byte of the rule itself`);
  } else if (tField.kind === FIELD_DATA && tField.value !== undefined) {
    const t = tField.value;
    if (!isPlainRecord(t)) {
      arrayPush(errors, `${where}.threshold: must be an object`);
    } else {
      const pathField = requiredOwnField(t, "path", `${where}.threshold`, errors);
      const opField = requiredOwnField(t, "op", `${where}.threshold`, errors);
      const valueField = requiredOwnField(t, "value", `${where}.threshold`, errors);
      if (pathField !== null && (typeof pathField.value !== "string" || pathField.value.length === 0)) arrayPush(errors, `${where}.threshold.path: non-empty string`);
      if (opField !== null && !setHas(THRESHOLD_OPS, opField.value)) arrayPush(errors, `${where}.threshold.op: must be "ge" or "gt"`);
      if (valueField !== null && (typeof valueField.value !== "number" || !isSafeInteger(valueField.value))) arrayPush(errors, `${where}.threshold.value: safe integer`);
      if (arrayLength(errors) === before && pathField !== null && opField !== null && valueField !== null) {
        threshold = objectCreateNull();
        threshold.path = pathField.value;
        threshold.op = opField.value;
        threshold.value = valueField.value;
        objectFreeze(threshold);
      }
    }
  }

  if (arrayLength(errors) !== before) return null;

  const compiled = objectCreateNull();
  // Own-data SCALAR extras are carried through, because a matched rule is handed back to the caller
  // and consumers read their own metadata off it (`DEFAULT_APPROVAL_RULES` carries `risk`). Object-
  // valued extras are dropped rather than deep-copied: an unbounded walk of caller data on a
  // decision path buys nothing the gate uses, and a cyclic one would not terminate.
  const keys = ownKeys(raw);
  for (let k = 0; k < arrayLength(keys); k += 1) {
    const key = keys[k];
    if (typeof key !== "string") continue;
    if (key === "id" || key === "match" || key === "threshold") continue;
    const extra = readOwnField(raw, key);
    if (extra.kind !== FIELD_DATA) continue;
    const t = typeof extra.value;
    if (extra.value === null || t === "string" || t === "number" || t === "boolean") compiled[key] = extra.value;
  }
  compiled.id = idField.value;
  compiled.match = match;
  if (threshold !== undefined) compiled.threshold = threshold;
  return objectFreeze(compiled);
}

/**
 * Compiles a rule set into an INERT, DEEPLY IMMUTABLE snapshot built exclusively from own data
 * properties. Never throws; returns `{ ok, errors, rules }`. The snapshot — not the caller's object
 * — is what every decision below reads.
 */
export function compileApprovalRules(approvalRules) {
  const errors = [];
  if (!isArray(approvalRules) || isProxy(approvalRules)) {
    return { ok: false, errors: ["approvalRules: must be an array"], rules: null };
  }
  const compiledRules = [];
  const seenIds = newSet();
  const n = arrayLength(approvalRules);
  for (let i = 0; i < n; i += 1) {
    // Even the ELEMENTS are read as own data properties: `Object.defineProperty(rules, 0, {get(){…}})`
    // is a live array with an accessor element, and `rules[0]` would run it.
    const element = readOwnField(approvalRules, i);
    if (element.kind !== FIELD_DATA) {
      arrayPush(errors, `approvalRules[${numToString(i, 10)}]: must be an OWN DATA element of the array (this one is ${element.kind})`);
      continue;
    }
    const rule = compileRule(element.value, i, errors);
    if (rule === null) continue;
    if (setHas(seenIds, rule.id)) {
      arrayPush(errors, `approvalRules[${numToString(i, 10)}].id: duplicate rule id "${rule.id}"`);
      continue;
    }
    setAdd(seenIds, rule.id);
    arrayPush(compiledRules, rule);
  }
  if (arrayLength(errors) !== 0) return { ok: false, errors, rules: null };
  // Re-rooted onto the kernel's inert array prototype and frozen: nothing the caller (or a poisoned
  // `Array.prototype`) does afterwards can change what this snapshot says.
  objectSetPrototypeOf(compiledRules, INERT_ARRAY_PROTOTYPE);
  objectFreeze(compiledRules);
  weakSetAdd(COMPILED_RULE_SETS, compiledRules);
  return { ok: true, errors: [], rules: compiledRules };
}

/** True only for a snapshot THIS module compiled. The brand is a module-private WeakSet, so it
 *  cannot be forged by a caller and cannot be copied onto a look-alike object. */
export function isCompiledApprovalRules(value) {
  return value !== null && typeof value === "object" && weakSetHas(COMPILED_RULE_SETS, value);
}

/**
 * Reports on a rule set WITHOUT throwing — the compiler's verdict, discarding the snapshot. One
 * implementation: a reporting validator that accepted shapes the compiler refuses would be two
 * rules of what a rule set is, and the drift between them is where the next bypass lives.
 */
export function validateApprovalRules(approvalRules) {
  if (approvalRules === undefined || approvalRules === null) return { ok: true, errors: [] };
  const compiled = compileApprovalRules(approvalRules);
  return { ok: compiled.ok, errors: compiled.errors };
}

/**
 * THE FAIL-CLOSED ANSWER for a rule set this module cannot compile: a real, frozen rule that matches
 * whatever it is asked about, so the caller DEFERS the action to a human instead of forwarding it.
 * `id` travels into the receipt as `governance.ruleId` (`approval:approval-rules-unusable`) — an
 * ordinary string in an existing field, so no schema moves and an operator reading the receipt sees
 * exactly why the call was held.
 */
const UNUSABLE_RULE_SET = (() => {
  const match = objectCreateNull();
  match.type = "exact";
  match.action = "";
  objectFreeze(match);
  const rule = objectCreateNull();
  rule.id = "approval-rules-unusable";
  rule.match = match;
  return objectFreeze(rule);
})();

/** Names the SHAPE of a rejected rule set for the refusal message, without ever calling a method on
 *  the caller's value (a `toString` on an attacker-supplied object is not a safe thing to invoke
 *  while refusing that object). */
function shapeOfRuleSet(value) {
  if (value === undefined) return "absent (undefined)";
  if (value === null) return "null";
  const t = typeof value;
  if (t === "object") return "a JSON object";
  if (t === "string") return "a string";
  return `a ${t}`;
}

/**
 * THE LOAD-TIME GATE. `validateApprovalRules` above only REPORTS; nothing was calling it on the
 * paths that actually load a rule set, and that gap was a full approval bypass — MEASURED 2026-08-12
 * against the shipped CLI with a perfectly ordinary rule file (regular, mode 0600, owned by this
 * process) whose content was `{}`:
 *
 *     transfer_funds(amountMinor=7000, to="attacker-account")
 *     -> downstream answered "transferred 7000 (minor units) to attacker-account", no human involved
 *
 * The mechanism is `matchApprovalRule`'s own first line: a non-array returns `null`, `null` means
 * "no rule matched", and "no rule matched" means FORWARD. So EVERY malformed shape — `{}`, `null`,
 * a bare string, a number — reads to the caller exactly like "nothing here needs a human", which is
 * the one answer a fail-closed component must never give by accident. Six of the seven shapes below
 * were reproduced as live, executed, unapproved transfers.
 *
 * WHY THIS SITS ABOVE THE SYMLINK GUARD IT COMPLEMENTS. `config-artifact.mjs` closed the REDIRECT
 * class (which bytes the path resolves to) and honestly names same-uid CONTENT rewriting as an
 * accepted residual (NON-CLAIMS.md NC-6.9). That residual was judged acceptable on the assumption
 * that rewriting content still required writing PLAUSIBLE rules. It did not: two bytes, `{}`, turned
 * the gate off. This function is what makes that assumption true — any content-write primitive at
 * all now has to produce a rule set that survives structural validation.
 *
 * Throws (never returns a verdict object): every caller of this is a startup path whose only correct
 * response to a malformed rule set is to refuse to run.
 *
 * ⚠ USE THE RETURN VALUE. It is the compiled SNAPSHOT, not the object you passed in, and the caller
 * that keeps its own object instead has kept the bug: an honest rule set mutated after this call
 * returned was measured executing an unapproved 7000-unit transfer. The snapshot is frozen, so
 * nothing can move under the gate once this has returned.
 *
 * `undefined`/`null` are NOT accepted here, unlike in `validateApprovalRules` — a caller that wants
 * no approval rules omits the option entirely; a `null` that arrived from a config file is a
 * malformed rule set, and the two must not share an answer.
 */
export function requireValidApprovalRules(approvalRules, label) {
  // Idempotent: re-validating a snapshot returns that same snapshot. The proxy validates at the CLI
  // and again inside createProxyServer, and the second call must not manufacture a second object.
  if (isCompiledApprovalRules(approvalRules)) return approvalRules;
  if (!isArray(approvalRules)) {
    throw new Error(
      `${label}: a human-approval rule set must be a JSON ARRAY of rules — this one is ${shapeOfRuleSet(approvalRules)}. ` +
        `A non-array matches no rule, "no rule matched" means the call is FORWARDED, and a gate that forwards everything is a gate that is switched off. Refusing to start (fail-closed).`,
    );
  }
  const compiled = compileApprovalRules(approvalRules);
  if (!compiled.ok) {
    throw new Error(
      `${label}: the human-approval rule set is structurally invalid, so at least one rule cannot gate the action it names — refusing to start (fail-closed). ` +
        `Rejected in full, never partially: a rule set where rule 1 is honoured and rule 2 is silently skipped is the same bypass wearing a disguise. Errors: ${arrayJoin(compiled.errors, "; ")}`,
    );
  }
  return compiled.rules;
}

/**
 * Deterministic, pure, FAIL-CLOSED-TOWARD-GATING, first-match-wins matcher. `actionId` is
 * preCheck's own already-sanitized action id; `inputs` is preCheck's own already-flattened
 * policy-input snapshot (never re-reads toolCall.args).
 *
 * A threshold path ABSENT from `inputs` -> no match (mirrors evaluate()'s own "missing optional
 * path -> condition false"). A threshold path PRESENT but not a clean safe-integer (e.g. a
 * float-projected decimal string) -> fail-closed MATCH (gate it) — the safe direction is "hold
 * for a human", never "silently auto-execute".
 *
 * ── WHAT THIS FUNCTION IS ALLOWED TO READ (round 2, 2026-08-12) ──────────────────────────────────
 * A COMPILED SNAPSHOT, and nothing else. Handed anything unbranded it compiles it HERE, in one
 * pass, and matches against the snapshot — so a getter is read once by the compiler and never again
 * by the decision, and an inherited field is refused rather than resolved.
 *
 * Handed a rule set it cannot compile, it returns `UNUSABLE_RULE_SET` — a real rule object, so the
 * caller HOLDS the action for a human. This is the reversal that closes the second half of the
 * CRITICAL: `{}` used to reach `return null`, and `null` means forward. Every public decision entry
 * point in this package (`preCheck`, `preCheckAsync`, `prepareSessionReceipt`,
 * `prepareSessionReceiptAsync`, `preCheckSession`) funnels here, so all five fail closed from this
 * one line rather than from five guards that have to be kept in step.
 *
 * `undefined`/`null` still mean "no approval rules configured" and still match nothing — that is the
 * pre-R4 default, not a malformed rule set, and gating every action for a caller who configured no
 * gate at all would be a denial of service dressed as safety.
 *
 * Never throws: a compile failure and an unexpected throw both land on "hold it for a human".
 */
export function matchApprovalRule(approvalRules, actionId, inputs) {
  if (approvalRules === undefined || approvalRules === null) return null;
  let rules;
  if (isCompiledApprovalRules(approvalRules)) {
    rules = approvalRules;
  } else {
    let compiled;
    try {
      compiled = compileApprovalRules(approvalRules);
    } catch {
      return UNUSABLE_RULE_SET;
    }
    if (!compiled.ok) return UNUSABLE_RULE_SET;
    rules = compiled.rules;
  }
  try {
    return matchCompiled(rules, actionId, inputs);
  } catch {
    return UNUSABLE_RULE_SET;
  }
}

/** The match itself, over a frozen null-prototype snapshot. Every read below is an own data
 *  property of an object this module built. */
function matchCompiled(approvalRules, actionId, inputs) {
  for (let ri = 0; ri < arrayLength(approvalRules); ri += 1) {
    const rule = approvalRules[ri];
    try {
      if (!rule || typeof rule !== "object") continue;
      const m = rule.match;
      if (!m || typeof m !== "object") continue;
      let actionMatches = false;
      if (m.type === "exact") actionMatches = actionId === m.action;
      else if (m.type === "prefix") actionMatches = typeof actionId === "string" && strStartsWith(actionId, m.action);
      // "suffix" gates by the trailing segment of an action id (e.g. ".delete" catches "db.delete",
      // "s3.deleteObject" would NOT — endsWith is literal). Added for §19.1 risk-ladder defaults, which
      // must gate destructive verbs that are named as suffixes across integrations. Backward-compatible:
      // no pre-existing rule uses this type, so exact/prefix behavior is byte-identical.
      else if (m.type === "suffix") actionMatches = typeof actionId === "string" && strEndsWith(actionId, m.action);
      if (!actionMatches) continue;

      if (rule.threshold === undefined) return rule;

      const t = rule.threshold;
      const v = hasOwn(inputs, t.path) ? inputs[t.path] : undefined;
      if (v === undefined) continue;

      if (typeof v === "number" && isSafeInteger(v)) {
        const hit = t.op === "ge" ? v >= t.value : v > t.value;
        if (hit) return rule;
        continue;
      }
      return rule; // present but ambiguous type -> fail-closed match
    } catch {
      continue;
    }
  }
  return null;
}

/**
 * Best-effort, CONSERVATIVE (never-throws) action-id + paramsHash resolver for a toolCall, used
 * ONLY to look up a possible outstanding approval ticket BEFORE preCheck runs. On ANY ambiguity
 * returns `null` — the call then falls through to preCheck's own fully-guarded handling, never a
 * guess. `canonicalParamsHash` is a PARAMETER (not imported) to avoid an import cycle with
 * pre-check.mjs, which imports THIS module — the caller (create-proxy-server.mjs) passes
 * pre-check.mjs's own exported `canonicalParamsHash` so the value here is byte-identical to what
 * preCheck will independently compute for the same toolCall.
 */
export function tryIdentifyToolCallForTicketLookup(toolCall, canonicalParamsHash) {
  try {
    const name = toolCall?.name;
    if (typeof name !== "string" || name.length === 0) return null;
    return { actionId: name, paramsHash: canonicalParamsHash(toolCall?.args) };
  } catch {
    return null;
  }
}
