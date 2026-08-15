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
import { parseDocument } from "./bytes.js";
import { arrayPush, arrayIncludes, arrayConcat, hasOwn, objectKeys, isArray, arrayLength, strIsWellFormed, strCodePointCount, isSafeInteger } from "./intrinsics.js";
import { membership } from "./inert.js";
import { isSha256Hash, isParamsHash, isRfc3339Instant } from "./scan.js";

/**
 * ── EVERY ENUM HERE WAS A `Set`, AND A `Set` IS A DECISION THAT DISPATCHES THROUGH A MUTABLE SLOT ──
 *
 * `VERDICTS.has(r.governance.verdict)` looks like a lookup in a module-private constant. It is a
 * call to `Set.prototype.has`, which is a writable property of a mutable global. Review round 7
 * reproduced exactly that: `c02_sethas_verdict.mjs` assigned one function to `Set.prototype.has` and
 * a receipt carrying `governance.verdict: "ROOT_OVERRIDE"` — an out-of-enum verdict, re-signed so the
 * signature was genuine — verified `VALID`. Freezing the Set would not have helped; `Object.freeze`
 * does not touch `Set.prototype`.
 *
 * `membership` (src/inert.ts) replaces each one with ADR §5.5's primitive: a frozen, null-prototype
 * table probed by a `hasOwnProperty` captured at module load. No method is called on the table, so
 * there is no slot to rewrite; the table is null-rooted, so `Object.prototype` pollution cannot forge
 * a member; and it is frozen with no `add`, so it cannot be widened at runtime the way a `Set` can
 * (`Object.freeze` does not disable `Set.prototype.add` — reviews #5 and #6 both lost to that).
 */
const isRiskClass = membership(["LOW", "MEDIUM", "HIGH", "CRITICAL", "IRREVERSIBLE"]);
const isPrincipal = membership(["HUMAN", "SERVICE", "POLICY", "SANDBOX_SIM"]);
const isMode = membership(["off", "shadow", "approvals_on", "on"]);
const isVerdict = membership([
  "ALLOWED",
  "BLOCKED",
  "DEFERRED",
  "EXECUTED",
  "FAILED",
  "ROLLED_BACK",
  "SIMULATED",
]);

export interface SchemaResult {
  ok: boolean;
  errors: string[];
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !isArray(v);
}

/**
 * Own-property check (matches the hasher's `Object.keys` view; avoids prototype-chain reads).
 *
 * `Object.prototype.hasOwnProperty.call(obj, k)` was the previous body, and `.call` is a writable
 * property of `Function.prototype`: `c02_fncall_eval.mjs` poisoned it to make one input path answer
 * "absent" and flipped a policy verdict DENY → ALLOW. `hasOwn` invokes a `hasOwnProperty` captured at
 * module load through a captured `Reflect.apply`, so neither the method nor the invoker is looked up
 * at call time.
 */
function has(obj: object, k: string): boolean {
  return hasOwn(obj, k);
}

function checkExactKeys(
  obj: Record<string, unknown>,
  required: string[],
  optional: string[],
  path: string,
  errors: string[],
): void {
  const allowed = arrayConcat(required, optional);
  // CAPTURED (2026-07-29, round-2, R3-08). `for (const k of objectKeys(obj))` dispatched through
  // `%ArrayIteratorPrototype%.next`; a skipping iterator hid an unknown field so the closed-schema
  // walk never flagged it. Walked by index instead — the key list is the captured `objectKeys`, and
  // nothing is iterated through a poisonable protocol.
  const keys = objectKeys(obj);
  const kn = arrayLength(keys);
  for (let ki = 0; ki < kn; ki++) {
    const k = keys[ki]!;
    if (!arrayIncludes(allowed, k)) arrayPush(errors, `${path}: unknown field "${k}"`);
  }
  const rn = arrayLength(required);
  for (let ri = 0; ri < rn; ri++) {
    const k = required[ri]!;
    if (!has(obj, k)) arrayPush(errors, `${path}: missing required field "${k}"`);
  }
}

function str(v: unknown): v is string {
  // Reject non-well-formed strings (lone UTF-16 surrogates) at the structural layer so a
  // receipt fed directly to verifyChain (bypassing safeParse) becomes MALFORMED rather than
  // throwing a JcsError from the hashing step — keeps the public return-type contract.
  // `strIsWellFormed` captured: a live `String.prototype.isWellFormed` on a value is a dispatch
  // through a mutable slot (R3-08 class).
  return typeof v === "string" && strIsWellFormed(v);
}

/**
 * Validate one receipt's structure from its BYTES.
 *
 * This is the structural rule `verifyChain` enforces, published for direct use. It walks the value
 * many times — exact-key checks, per-field type checks, NFC checks — which is exactly why it used to
 * need an ingest boundary of its own: a flipping getter could show one shape to the key check and
 * another to the type check (review #6, C2). Over parsed bytes there is nothing to flip, so the
 * multiple walks are just walks.
 */
export function validateReceiptShape(receipt: Uint8Array | string): SchemaResult {
  const parsed = parseDocument(receipt, "receipt");
  if (!parsed.ok) return { ok: false, errors: [parsed.reason] };
  return validateReceiptShapeParsed(parsed.value);
}

/**
 * The structural validator over PARSED data. Exported for the KERNEL's own use (`verifyChain` walks
 * an already-parsed array and must not re-serialize each element to re-enter the bytes boundary),
 * and deliberately NOT re-exported from `src/index.ts` — a caller who could reach this would have
 * the old object API back under a new name.
 */
export function validateReceiptShapeParsed(value: unknown): SchemaResult {
  const errors: string[] = [];
  if (!isPlainObject(value)) {
    return { ok: false, errors: ["receipt: not an object"] };
  }
  const r = value;

  // Fail-closed: a caller-supplied LIVE object with a throwing/side-effecting accessor must yield a
  // structural rejection, never escape as a raw throw (mirrors the fail-closed Python validator).
  try {
  checkExactKeys(
    r,
    ["spec", "id", "ts", "scope", "agent", "action", "governance", "chain", "sig"],
    [],
    "receipt",
    errors,
  );

  if (r.spec !== RECEIPT_SPEC) arrayPush(errors, `receipt.spec: must be "${RECEIPT_SPEC}"`);
  // id length is bounded in CODE POINTS, not UTF-16 code units. `r.id.length` counts code UNITS, so an id of
  // astral characters (each 2 units) would be falsely rejected here while the Python verifier (len() = code
  // points) and the normative schema (maxLength on RFC-8259/JSON characters = code points) accept it — a
  // cross-impl consensus split on identical signed bytes (an astral id of 65 emoji = 65 code points = 130
  // units → TS MALFORMED, Python VALID). [...r.id].length iterates by code point, matching both. (Only true
  // char-count CAPS need this; non-empty `length===0` checks elsewhere are unit-vs-point-agnostic.)
  // CAPTURED (2026-07-29, round-2, R3-08). `[...r.id]` spread the id through the mutable string
  // iterator to count CODE POINTS; a poison that shortens `%StringIteratorPrototype%.next` made an
  // over-128-code-point id pass the cap. `strCodePointCount` folds surrogate pairs by index and
  // returns the identical count with no iterator dispatch (verified against `[...s].length`).
  if (!str(r.id) || r.id.length === 0 || strCodePointCount(r.id) > 128) arrayPush(errors, "receipt.id: non-empty string ≤128 chars");
  // R5. `isRfc3339Instant`, not `isRfc3339`: the lexical form alone accepted `2026-13-45T99:99:99Z`
  // — month 13, day 45, hour 99 — as the timestamp of a signed CRITICAL action. A `ts` that denotes
  // no instant cannot be ordered against its neighbours, so the chain's own non-monotonic warning
  // is blind to it. See src/scan.ts for why second 60 (a leap second) stays ACCEPTED.
  if (!str(r.ts) || !isRfc3339Instant(r.ts)) arrayPush(errors, "receipt.ts: must be RFC 3339 UTC timestamp");

  // scope
  if (isPlainObject(r.scope)) {
    checkExactKeys(r.scope, ["chain"], ["tenant"], "receipt.scope", errors);
    if (!str(r.scope.chain) || r.scope.chain.length === 0) arrayPush(errors, "receipt.scope.chain: non-empty string");
    if (has(r.scope, "tenant") && !str(r.scope.tenant)) arrayPush(errors, "receipt.scope.tenant: string");
  } else arrayPush(errors, "receipt.scope: object required");

  // agent
  if (isPlainObject(r.agent)) {
    checkExactKeys(r.agent, ["id", "principal"], ["model"], "receipt.agent", errors);
    if (!str(r.agent.id) || r.agent.id.length === 0) arrayPush(errors, "receipt.agent.id: non-empty string");
    if (!isPrincipal(r.agent.principal)) arrayPush(errors, "receipt.agent.principal: invalid enum");
    if (has(r.agent, "model") && r.agent.model !== null && !str(r.agent.model))
      arrayPush(errors, "receipt.agent.model: string or null");
  } else arrayPush(errors, "receipt.agent: object required");

  // action
  if (isPlainObject(r.action)) {
    checkExactKeys(
      r.action,
      ["id", "canonical", "riskClass", "paramsHash", "reversible"],
      ["rollbackRef"],
      "receipt.action",
      errors,
    );
    if (!str(r.action.id) || r.action.id.length === 0) arrayPush(errors, "receipt.action.id: non-empty string");
    if (!str(r.action.canonical) || r.action.canonical.length === 0)
      arrayPush(errors, "receipt.action.canonical: non-empty string");
    if (!isRiskClass(r.action.riskClass)) arrayPush(errors, "receipt.action.riskClass: invalid enum");
    if (!str(r.action.paramsHash) || !isParamsHash(r.action.paramsHash))
      arrayPush(errors, "receipt.action.paramsHash: must match (sha256|hmac-sha256):<64 hex>");
    if (typeof r.action.reversible !== "boolean") arrayPush(errors, "receipt.action.reversible: boolean");
    if (has(r.action, "rollbackRef") && r.action.rollbackRef !== null && !str(r.action.rollbackRef))
      arrayPush(errors, "receipt.action.rollbackRef: string or null");
  } else arrayPush(errors, "receipt.action: object required");

  // governance
  if (isPlainObject(r.governance)) {
    checkExactKeys(
      r.governance,
      ["mode", "verdict", "sandboxed"],
      ["ruleId", "approval", "compliance"],
      "receipt.governance",
      errors,
    );
    if (!isMode(r.governance.mode)) arrayPush(errors, "receipt.governance.mode: invalid enum");
    if (!isVerdict(r.governance.verdict)) arrayPush(errors, "receipt.governance.verdict: invalid enum");
    if (typeof r.governance.sandboxed !== "boolean") arrayPush(errors, "receipt.governance.sandboxed: boolean");
    if (has(r.governance, "ruleId") && r.governance.ruleId !== null && !str(r.governance.ruleId))
      arrayPush(errors, "receipt.governance.ruleId: string or null");
    if (has(r.governance, "approval") && r.governance.approval !== null) {
      if (isPlainObject(r.governance.approval)) {
        checkExactKeys(r.governance.approval, ["by", "at"], [], "receipt.governance.approval", errors);
        if (!str(r.governance.approval.by)) arrayPush(errors, "receipt.governance.approval.by: string");
        if (!str(r.governance.approval.at) || !isRfc3339Instant(r.governance.approval.at as string))
          arrayPush(errors, "receipt.governance.approval.at: RFC 3339 UTC");
      } else arrayPush(errors, "receipt.governance.approval: object or null");
    }
    if (has(r.governance, "compliance") && r.governance.compliance !== null) {
      const c = r.governance.compliance;
      if (isPlainObject(c)) {
        checkExactKeys(c, ["policyHash", "readSetHash", "inputsHash"], ["verdict"], "receipt.governance.compliance", errors);
        const cflds = ["policyHash", "readSetHash", "inputsHash"] as const;
        for (let cfi = 0; cfi < 3; cfi++) {
          const k = cflds[cfi]!;
          if (!str(c[k]) || !isSha256Hash(c[k] as string)) arrayPush(errors, `receipt.governance.compliance.${k}: sha256:<64 hex>`);
        }
        // Optional + additive: the recorded policy decision. When present it MUST be ALLOW|DENY so
        // verifyReceiptCompliance can reconcile a re-run verdict against it (spec §9).
        if (has(c, "verdict") && c.verdict !== "ALLOW" && c.verdict !== "DENY")
          arrayPush(errors, 'receipt.governance.compliance.verdict: must be "ALLOW" or "DENY"');
      } else arrayPush(errors, "receipt.governance.compliance: object or null");
    }
  } else arrayPush(errors, "receipt.governance: object required");

  /**
   * ── CROSS-FIELD COHERENCE (2026-08-14) — A SIGNED RECEIPT MAY NOT CONTRADICT ITSELF ────────────
   *
   * Every check above reads ONE field. A receipt can satisfy all of them and still be a statement
   * that argues both ways: `agent.principal: "SANDBOX_SIM"` (the actor was the sandbox simulator)
   * next to `governance.sandboxed: false` (this really happened), on a CRITICAL `wire.transfer`,
   * signed, chain-valid, verifying VALID in all five implementations. That was reproduced — five
   * such receipts, five verifiers, 25 of 25 VALID — and it is the worst failure this format can
   * have, because the whole premise of the profile is that a reader can tell a real action from a
   * rehearsal. After the fact, the producer can point at whichever field suits them.
   *
   * These belong HERE, in the shape validator, and not on the signature path, for the same reason
   * an unknown smuggled field or a malformed `paramsHash` does: they are decidable with NO KEY
   * MATERIAL AT ALL. A reader who has only the bytes can see the contradiction. Placing them here
   * also means `buildReceipt`'s fail-closed guard (builder.ts — it runs `validateReceiptShapeParsed`
   * over the finished draft and throws `BuilderError`) inherits them for free: this library can no
   * longer SIGN a receipt that contradicts itself, which is the half of the fix that stops the
   * artifacts being minted in the first place.
   *
   * Each rule is ONE-DIRECTIONAL and states which direction, because the converse is legitimate:
   * a `SERVICE` agent may well run inside a sandbox (`sandboxed: true` with a non-`SANDBOX_SIM`
   * principal is a real, VALID receipt — `conformance/golden/0.3.0/multi/chain.json` contains one),
   * and a reversible action need not carry a `rollbackRef`.
   */
  if (isPlainObject(r.agent) && isPlainObject(r.action) && isPlainObject(r.governance)) {
    const principal = r.agent.principal;
    const verdict = r.governance.verdict;
    const sandboxed = r.governance.sandboxed;
    const reversible = r.action.reversible;
    // `=== false` / `=== true` against the literal, never `!== true`: when a field failed its own
    // type check above it is neither, so a malformed receipt reports its ONE real defect rather
    // than collecting a second, misleading coherence error on top.
    const rollbackRefPresent = has(r.action, "rollbackRef") && r.action.rollbackRef !== null;

    // R1. The receipt names the SANDBOX SIMULATOR as the actor while denying it was a simulation.
    if (principal === "SANDBOX_SIM" && sandboxed === false)
      arrayPush(errors, 'receipt.governance.sandboxed: must be true when agent.principal is "SANDBOX_SIM"');
    // R2. The receipt records a SIMULATED outcome while denying it was a simulation.
    if (verdict === "SIMULATED" && sandboxed === false)
      arrayPush(errors, 'receipt.governance.sandboxed: must be true when governance.verdict is "SIMULATED"');
    // R3. An action declared impossible to undo, carrying the reference used to undo it.
    if (reversible === false && rollbackRefPresent)
      arrayPush(errors, "receipt.action.rollbackRef: must be absent or null when action.reversible is false");
    // R4. The receipt says the action WAS undone while declaring it could not be.
    if (verdict === "ROLLED_BACK" && reversible === false)
      arrayPush(errors, 'receipt.action.reversible: must be true when governance.verdict is "ROLLED_BACK"');
  }

  // chain
  if (isPlainObject(r.chain)) {
    checkExactKeys(r.chain, ["seq", "prevHash", "hash"], [], "receipt.chain", errors);
    if (typeof r.chain.seq !== "number" || !isSafeInteger(r.chain.seq) || r.chain.seq < 0)
      arrayPush(errors, "receipt.chain.seq: non-negative safe integer");
    if (r.chain.prevHash !== null && (!str(r.chain.prevHash) || !isSha256Hash(r.chain.prevHash)))
      arrayPush(errors, "receipt.chain.prevHash: sha256:<64 hex> or null");
    if (!str(r.chain.hash) || !isSha256Hash(r.chain.hash)) arrayPush(errors, "receipt.chain.hash: sha256:<64 hex>");
  } else arrayPush(errors, "receipt.chain: object required");

  // sig (mandatory)
  if (isPlainObject(r.sig)) {
    checkExactKeys(r.sig, ["alg", "kid", "value"], [], "receipt.sig", errors);
    if (r.sig.alg !== "ed25519") arrayPush(errors, 'receipt.sig.alg: must be "ed25519"');
    if (!str(r.sig.kid) || r.sig.kid.length === 0) arrayPush(errors, "receipt.sig.kid: non-empty string");
    if (!str(r.sig.value) || r.sig.value.length === 0) arrayPush(errors, "receipt.sig.value: non-empty string");
  } else arrayPush(errors, "receipt.sig: object required (signatures are mandatory in v0.1)");
  } catch (e) {
    return { ok: false, errors: [`receipt: structural-validation error: ${(e as Error).message}`] };
  }

  return { ok: errors.length === 0, errors };
}
