/**
 * `noa.action-digest/0.1` — THE ONE INTEROPERABLE CORRELATION VALUE FOR AN AUTHORIZED ACTION.
 *
 * ── WHY THIS EXISTS, STATED AS THE DEFECT IT CLOSES ──────────────────────────────────────────────
 *
 * Two planes disagreed, silently, and both were schema-legal. The kernel defines `action.id` as a
 * TOOL IDENTIFIER (`src/types.ts` `ReceiptAction.id`, e.g. `deploy.apply`). A downstream consumer
 * compared that same `action.id` against a GRANT HASH and refused the mismatch. The frozen receipt
 * schema types `action.id` as a plain string, so nothing anywhere could detect the contradiction —
 * one side stores a name, the other side expects a hash, and both validate. That is not a bug in
 * either implementation; it is a MISSING SHARED VALUE, and this module is that value.
 *
 * `docs/carlos.md` §3 (recorded 2026-07-23, never superseded; it governs per `OWNER-DECISION-REGISTER`
 * A-3 and ADR-0006 §4.1) is normative on both halves:
 *
 *     "`action.paramsHash` must not be treated as the shared action digest. It does not bind the
 *      complete authorization, tenant/chain, exact attempt, grant, or nonce and may repeat across
 *      retries."
 *
 * and then prescribes exactly this construction, with a frozen projection committing to the
 * recomputed authorization-receipt hash, tenant, chain, `action.id`, `action.canonical`,
 * `action.paramsHash`, the execution grant's id and hash, and a single-use execution nonce.
 *
 * ── THE CONSTRUCTION ─────────────────────────────────────────────────────────────────────────────
 *
 *     projection = { spec, authorizationReceiptHash, tenant, chain, actionId, actionCanonical,
 *                    actionParamsHash, executionGrantId, executionGrantHash, executionNonce }
 *
 *     digest = "sha256:" ++ hex( SHA256( UTF8("NOA-ActionDigest-v0.1-dig:") ++ SHA256(JCS(projection)) ) )
 *
 * The inner step is `signingMessage()` from `src/signing.ts` — the SAME domain-separation primitive
 * receipts, checkpoints and every §6 side artifact use. It is reused rather than re-invented for the
 * reason this repository keeps re-learning: two implementations of one rule become two rules.
 *
 * THE TAG ENDS IN `-dig`, NOT `-sig`, AND THAT IS DELIBERATE. Every existing tag names a value that
 * gets Ed25519-SIGNED. This value is HASHED and never signed, so a tag in the signing namespace
 * would invite exactly the cross-protocol confusion domain separation exists to prevent: an
 * Ed25519 signature over `NOA-ActionDigest-v0.1-sig:‖H` would be a signature over a preimage that
 * some other verifier might one day accept. Nothing signs `-dig`.
 *
 * ── WHAT THIS DOES NOT ESTABLISH (read this before relying on a match) ───────────────────────────
 *
 * `carlos.md` §3 again, verbatim: *"Digest equality is linkage/correlation only. It is not proof
 * that a controller or physical claim is true."* Concretely, and each of these is a real limit, not
 * a hedge:
 *
 *   - THE TWO ENTRY POINTS HAVE DIFFERENT TRUST CONTRACTS, and conflating them is the mistake this
 *     paragraph exists to prevent. `verifyActionDigest` AUTHENTICATES ITS OWN INPUTS: it requires a
 *     trust root, runs `verifyChain` over the supplied chain, verifies the grant's Ed25519
 *     signature through `resolveVerificationKey`, and selects the authorization by the grant's own
 *     `approvalReceiptHash`. `buildActionDigest` does NOT: it is the producer-side construction, it
 *     takes a verdict from nobody and returns no verdict, and a caller who feeds it two unverified
 *     documents gets a digest over two unverified documents.
 *
 *     An earlier revision made NEITHER entry point authenticate anything and disclosed that in
 *     prose. Round-2 QA refused it, correctly: a classification string does not enforce call
 *     ordering and does not stop document substitution, and disclosure is not a control on a
 *     surface that authorization decisions rest on.
 *   - WHAT `verifyActionDigest` STILL DOES NOT COVER, stated because a partial check described as a
 *     whole one is worse than no check: the grant's §6 SEMANTICS. The F15 signer type/role matrix,
 *     key activation windows, grant expiry and the envelope refHash chain are `verifyArtifact`'s
 *     (`packages/approval-artifacts/src/verify.ts`), which this package has no dependency edge to.
 *     Signature authenticity is checked here; grant AUTHORIZATION semantics are not.
 *   - IT IS NOT A CAPABILITY. Knowing a digest authorizes nothing; the digest is a public
 *     correlation key, safe to log and to index.
 *   - IT IS NOT PROOF THE ACTION HAPPENED. That is the execution-consumption / physical-observation
 *     layer (`carlos.md` §4), not this one.
 *
 * What it DOES establish, and what makes it strictly stronger than the `paramsHash` comparison it
 * replaces: two parties holding the same authorization receipt and the same execution grant compute
 * the same value, and any party holding a DIFFERENT authorization — different tenant, different
 * chain, different action, different attempt, different grant, different nonce — computes a
 * different one. Everything the verifier below refuses, it refuses because that property would
 * otherwise be false.
 */

import { canonicalize } from "./jcs.js";
import { sha256Prefixed } from "./hash.js";
import { signingMessage } from "./signing.js";
import { receiptHashInput } from "./canonicalize.js";
import { parseDocument } from "./bytes.js";
import { validateReceiptShapeParsed } from "./schema.js";
import { isSha256Hash, isParamsHash, isRfc3339, isHex64 } from "./scan.js";
import { verifyChain } from "./verify.js";
import { resolveVerificationKey } from "./verification-keyring.js";
import { verifyEd25519 } from "./keys.js";
import { frozenTable } from "./inert.js";
// CAPTURED INTRINSICS ONLY (ADR §5.5 / lint L8). `Array.isArray`, `JSON.stringify` and `String` are
// writable properties of a mutable global, and this file decides what bytes get hashed and whether a
// digest matches — so none of them may be looked up at call time.
import { arrayIncludes, arrayJoin, hasOwn, isArray, jsonStringify, objectCreateNull, objectGetOwnPropertyNames, strCodePointCount, strTrim } from "./intrinsics.js";
import type { Receipt } from "./types.js";

/** The spec identifier this module implements. It travels INSIDE the projection and on the claim. */
export const ACTION_DIGEST_SPEC = "noa.action-digest/0.1" as const;

/**
 * The domain-separation tag. Distinct from `NOA-Receipt-v0.1-sig`, `NOA-Checkpoint-v0.1-sig` and
 * every §6 side-artifact tag, and outside the signing namespace entirely (see the header).
 */
export const ACTION_DIGEST_DOMAIN = "NOA-ActionDigest-v0.1-dig";

/** The execution grant this digest correlates against (`packages/approval-artifacts`, §6). */
const GRANT_SPEC = "noa.execution-grant/0.1";

/**
 * THE EXACT KEY SET OF A `noa.execution-grant/0.1`, in the shipped schema's own order.
 *
 * This restates `packages/approval-artifacts/schema/noa-execution-grant-0.1.schema.json`'s
 * `required` list, and a restatement with no gate is drift with a delay — so
 * `test/action-digest.test.ts` reads that schema file and measures this module's behaviour against
 * it, key by key, including the closed-world (`additionalProperties:false`) half.
 *
 * The closed-world half is load-bearing rather than tidy: `executionGrantHash` is taken over the
 * WHOLE grant document, so an unrecognised extra field changes the digest. Accepting such a grant
 * would let two honest parties holding "the same" grant compute two different digests and conclude
 * they hold different authorizations. Refusing is the fail-closed direction.
 */
const GRANT_KEYS: readonly string[] = frozenTable([
  "spec",
  "grantId",
  "holdId",
  "paramsHash",
  "holdEnvelopeHash",
  "approvalReceiptHash",
  "issuedAt",
  "expiresAt",
  "maxUses",
  "nonce",
  "sig",
]);

/** The grant `sig` object's exact key set — `$defs.sig` in the same shipped schema, also closed. */
const GRANT_SIG_KEYS: readonly string[] = frozenTable(["alg", "kid", "value"]);

/**
 * The §6 Ed25519 signing domain for an execution grant
 * (`packages/approval-artifacts/src/domains.ts`). Restated here because the kernel root has no
 * dependency edge to that package — and gated rather than trusted: `test/action-digest.test.ts`
 * verifies THAT package's own committed `execution-grant/valid.json` signature with this constant
 * and refuses its committed tampered/wrong-key vectors, so a drift in either direction fails.
 */
const GRANT_SIG_DOMAIN = "NOA-ExecGrant-v0.1-sig";

/**
 * The only receipt verdict a grant may descend from.
 *
 * ── HIGH-1, AND WHY THIS IS A RECURRENCE RATHER THAN A NEW BUG ──────────────────────────────────
 * This module checked shape, self-hash, receipt reference, parameter equality and single-use — and
 * never read `governance.verdict`. So a correctly signed HUMAN DENIAL, wrapped in a correctly
 * gate-signed grant, correlated as an authorization: `verifyChain` VALID, `verifyArtifact` ok,
 * and `ACTION_DIGEST_LINKAGE_MATCHED`. Satisfying both of the spec's preconditions did not save it,
 * because neither precondition asks what the receipt DECIDED.
 *
 * `packages/relay/src/engine.ts` records the same class being caught before — a status plane
 * recording APPROVED over a cryptographically VALID human denial, reproduced. The lesson that did
 * not travel with it is the general one: AUTHENTICITY AND AUTHORIZATION ARE DIFFERENT QUESTIONS,
 * and every new module that consumes a receipt has to ask the second one for itself. A signature
 * proves who wrote the decision, never which decision they wrote.
 *
 * `ALLOWED` is the whole set on purpose. `BLOCKED` is a denial; `DEFERRED` is a decision not yet
 * made; `EXECUTED`/`FAILED`/`ROLLED_BACK` are outcome records that post-date authorization; and
 * `SIMULATED` is explicitly not a real action. A grant descends from the ALLOWED decision alone —
 * `packages/gate/src/grants.ts` names its own parameter `allowedReceipt`.
 */
const AUTHORIZING_VERDICT = "ALLOWED";

/** The frozen projection. JCS sorts the keys, so the declaration order below is presentational. */
export interface ActionDigestProjection {
  readonly spec: typeof ACTION_DIGEST_SPEC;
  /** F1 rule-a: the receipt's OWN `chain.hash`, RECOMPUTED here from the receipt's bytes. */
  readonly authorizationReceiptHash: string;
  readonly tenant: string;
  readonly chain: string;
  readonly actionId: string;
  readonly actionCanonical: string;
  readonly actionParamsHash: string;
  readonly executionGrantId: string;
  /** F1 rule-b: SHA-256 over JCS of the WHOLE signed grant, signature INCLUDED. */
  readonly executionGrantHash: string;
  readonly executionNonce: string;
}

export type ActionDigestBuildResult =
  | {
      readonly ok: true;
      readonly digest: string;
      readonly projection: ActionDigestProjection;
    }
  | { readonly ok: false; readonly reason: string };

export type ActionDigestVerifyResult =
  | {
      readonly ok: true;
      readonly digest: string;
      readonly projection: ActionDigestProjection;
      /**
       * Never shortened to "VERIFIED". The match establishes linkage between the two supplied
       * documents and the claimed value — not that either document is authentic (see the header).
       */
      readonly classification: "ACTION_DIGEST_LINKAGE_MATCHED";
    }
  | { readonly ok: false; readonly reason: string };

/** The verification context, supplied as BYTES like every other boundary in this package. */
export interface ActionDigestContext {
  /**
   * The receipt CHAIN containing the authorization — not a lone receipt. `verifyChain` walks
   * sequence and linkage, so a mid-chain receipt cannot be authenticated on its own (measured:
   * `verifyChain([midChainReceipt])` returns `TAMPERED — seq gap: missing seq 0`). The
   * authorization is selected from this chain by the grant's own `approvalReceiptHash`.
   */
  readonly chain: readonly unknown[];
  /** The `noa.execution-grant/0.1` document, signature included. */
  readonly grant: unknown;
  /**
   * REQUIRED trust root — a static `{kid: base64-SPKI}` map or a `noa.signing-key-lifecycle/0.1`
   * document. Resolved by this package's own `resolveVerificationKey`, so retired keys are refused
   * here exactly as they are everywhere else.
   */
  readonly keyring: unknown;
  /** Optional: passed through to `verifyChain`, upgrading VALID to "THIS agent.id signed". */
  readonly identityManifest?: unknown;
  /**
   * The tenant and chain the RELYING PARTY believes it is operating in — its own value, never read
   * off the documents. Required: a verifier that cannot say which tenant it is cannot detect a
   * cross-tenant replay, and "unknown" must not be spelled "accept".
   */
  readonly expect: { readonly tenant: string; readonly chain: string };
}

/** The claim: a version-tagged wire value, so a future `/0.2` can never be compared as a `/0.1`. */
export interface ActionDigestClaim {
  readonly spec: typeof ACTION_DIGEST_SPEC;
  readonly digest: string;
}

function fail(reason: string): { readonly ok: false; readonly reason: string } {
  return { ok: false, reason };
}

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !isArray(v);
}

/**
 * A bounded, NON-BLANK string — the shape every identifier in the grant/receipt must have.
 *
 * ── `length === 0` WAS THE WRONG EMPTINESS TEST (round-2 QA, reproduced) ─────────────────────────
 * It refused `""` and accepted `"   "` and `"\t"`. A whitespace-only tenant is not a tenant; it is
 * the SEMANTIC "unknown", spelled so that a length check cannot see it — and a receipt carrying one
 * passed `verifyChain`, `verifyArtifact` and this module together. Emptiness is a property of the
 * TRIMMED value, so that is what is measured.
 */
function boundedString(v: unknown, max: number): v is string {
  if (typeof v !== "string") return false;
  if (strTrim(v).length === 0) return false;
  return strCodePointCount(v) <= max;
}

/** Why a candidate identifier was refused — distinct reasons, because a wrong reason misleads. */
type IdVerdict = "ok" | "absent" | "blank" | "padded" | "too-long";

/**
 * A SCOPE IDENTIFIER — `tenant` and `chain`, the two values that decide which isolation boundary a
 * digest belongs to. Stricter than `boundedString`, and the extra rule is the interesting one:
 *
 *   THE VALUE MUST EQUAL ITS OWN TRIM.
 *
 * Rejecting only whitespace-ONLY values would still admit `" tenant-acme "`, which is a DIFFERENT
 * string from `"tenant-acme"` here and the SAME tenant to anything downstream that trims — an
 * aliasing channel between two tenants, which is precisely the isolation failure the mandatory
 * tenant rule exists to prevent. A padded identifier is therefore refused outright rather than
 * normalised: normalising would make this module's digest disagree with a producer that did not
 * normalise, and silently reshaping a value on a correlation path is its own defect.
 */
function scopeIdentifier(v: unknown, max: number): IdVerdict {
  if (typeof v !== "string" || v.length === 0) return "absent";
  if (strTrim(v).length === 0) return "blank";
  if (strTrim(v) !== v) return "padded";
  if (strCodePointCount(v) > max) return "too-long";
  return "ok";
}

/** One phrasing per verdict, so "too long" is never reported as "absent or empty" (round-2 QA). */
function scopeReason(field: string, verdict: IdVerdict, max: number): string {
  if (verdict === "absent") return `${field}: absent or not a string`;
  if (verdict === "blank") {
    return `${field}: blank — whitespace is not an identifier, and a digest whose scope is the semantic "unknown" is replayable across tenants`;
  }
  if (verdict === "padded") {
    return `${field}: has leading or trailing whitespace — it would alias to a different scope anywhere that trims`;
  }
  return `${field}: longer than ${max} code points`;
}

/**
 * Structural gate over an execution grant: exact keys, then the field formats the shipped schema
 * pins. Fail-closed and total — every path returns a reason, nothing throws.
 */
function checkGrant(grant: unknown): { ok: true; value: Record<string, unknown> } | { ok: false; reason: string } {
  if (!isObject(grant)) return fail("grant: not a JSON object");
  const keys = objectGetOwnPropertyNames(grant);
  for (let i = 0; i < keys.length; i++) {
    const k = keys[i] as string;
    if (!arrayIncludes(GRANT_KEYS, k)) {
      return fail(`grant: unknown property "${k}" (the grant schema is closed; an extra field moves executionGrantHash)`);
    }
  }
  for (let i = 0; i < GRANT_KEYS.length; i++) {
    const k = GRANT_KEYS[i] as string;
    if (!hasOwn(grant, k)) return fail(`grant: missing required property "${k}"`);
  }
  if (grant["spec"] !== GRANT_SPEC) return fail(`grant.spec: must be "${GRANT_SPEC}"`);
  if (!boundedString(grant["grantId"], 128)) return fail("grant.grantId: non-empty string ≤128 chars");
  if (!boundedString(grant["holdId"], 128)) return fail("grant.holdId: non-empty string ≤128 chars");
  if (typeof grant["paramsHash"] !== "string" || !isParamsHash(grant["paramsHash"])) {
    return fail("grant.paramsHash: must be (sha256|hmac-sha256):<64 hex>");
  }
  if (typeof grant["holdEnvelopeHash"] !== "string" || !isSha256Hash(grant["holdEnvelopeHash"])) {
    return fail("grant.holdEnvelopeHash: must be sha256:<64 hex>");
  }
  if (typeof grant["approvalReceiptHash"] !== "string" || !isSha256Hash(grant["approvalReceiptHash"])) {
    return fail("grant.approvalReceiptHash: must be sha256:<64 hex>");
  }
  if (typeof grant["issuedAt"] !== "string" || !isRfc3339(grant["issuedAt"])) {
    return fail("grant.issuedAt: must be an RFC 3339 timestamp");
  }
  if (typeof grant["expiresAt"] !== "string" || !isRfc3339(grant["expiresAt"])) {
    return fail("grant.expiresAt: must be an RFC 3339 timestamp");
  }
  // SINGLE USE (`carlos.md` §3: "a signed, single-use execution nonce"). The gate mints grants with
  // `maxUses:1` and the schema pins the const; restating it here means a relaxed grant cannot be
  // correlated by this construction at all, rather than being correlated and quietly reusable.
  if (grant["maxUses"] !== 1) return fail("grant.maxUses: must be exactly 1 (the digest binds a single-use grant)");
  // The nonce is the D7 correlation SEED (settlement-evidence spec §3), pinned by
  // the shipped grant schema to `^[0-9a-f]{64}$`. This is the AUTHENTICATING path: the old
  // 1-256-char rule here let a UUID-nonce grant pass `verifyActionDigest` while the settlement
  // layers refused it — a cross-implementation verdict split on the money path.
  if (!isHex64(grant["nonce"])) return fail("grant.nonce: must be exactly 64 lowercase hex characters (32 bytes — the D7 correlation seed)");
  const sig = grant["sig"];
  if (!isObject(sig)) return fail("grant.sig: not an object");
  // ── THE NESTED OBJECT IS CLOSED TOO (round-2 QA, reproduced) ────────────────────────────────────
  // Only the TOP level was closed, so `sig.extra` produced a match here while `verifyArtifact`
  // correctly refused `$.sig: unknown property "extra"`. §4.3 claims each field satisfies the
  // shipped schema, and the shipped schema's `$defs.sig` is `additionalProperties:false` — a claim
  // is not a check. `test/action-digest.test.ts` now walks the schema's nested `$defs.sig`
  // required list as well as the top level, so this cannot regress to a top-level-only closure.
  const sigKeys = objectGetOwnPropertyNames(sig);
  for (let i = 0; i < sigKeys.length; i++) {
    const k = sigKeys[i] as string;
    if (!arrayIncludes(GRANT_SIG_KEYS, k)) {
      return fail(`grant.sig: unknown property "${k}" (the sig object is closed; an extra field moves executionGrantHash)`);
    }
  }
  if (sig["alg"] !== "ed25519") return fail('grant.sig.alg: must be "ed25519"');
  if (!boundedString(sig["kid"], 128)) return fail("grant.sig.kid: non-empty string ≤128 chars");
  if (!boundedString(sig["value"], 512)) return fail("grant.sig.value: non-empty string ≤512 chars");
  return { ok: true, value: grant };
}

/**
 * Build the projection and its digest from the two source documents.
 *
 * EVERY HASH IS RECOMPUTED HERE, NEVER ACCEPTED. `carlos.md` says the projection commits to the
 * *"locally recomputed and verified"* receipt hash, and the word that matters is RECOMPUTED: a
 * builder that took `authorizationReceiptHash` as a parameter would let a caller correlate a digest
 * to a receipt it has never seen. The receipt hash is derived from the receipt's own bytes and then
 * checked against the value the receipt itself commits to, so a receipt whose body was edited after
 * signing cannot contribute a digest at all.
 *
 * @param receiptBytes the authorization receipt document (JSON bytes or text)
 * @param grantBytes   the `noa.execution-grant/0.1` document, signature included
 */
export function buildActionDigest(
  receiptBytes: Uint8Array | string,
  grantBytes: Uint8Array | string,
): ActionDigestBuildResult {
  // `parseDocument` already prefixes its reason with the `what` label, so the reason is passed
  // through verbatim — re-prefixing produced `receipt: receipt: …`, and a doubled label is how a
  // reason string stops being greppable.
  const parsedReceipt = parseDocument(receiptBytes, "receipt");
  if (!parsedReceipt.ok) return fail(parsedReceipt.reason);
  const parsedGrant = parseDocument(grantBytes, "grant");
  if (!parsedGrant.ok) return fail(parsedGrant.reason);

  const shape = validateReceiptShapeParsed(parsedReceipt.value);
  if (!shape.ok) return fail(`receipt: ${arrayJoin(shape.errors, "; ")}`);
  const receipt = parsedReceipt.value as Record<string, unknown>;

  const grantCheck = checkGrant(parsedGrant.value);
  if (!grantCheck.ok) return fail(grantCheck.reason);
  const grant = grantCheck.value;

  const scope = receipt["scope"] as Record<string, unknown>;
  const action = receipt["action"] as Record<string, unknown>;
  const chainField = receipt["chain"] as Record<string, unknown>;

  // ── TENANT IS MANDATORY HERE EVEN THOUGH THE RECEIPT SCHEMA MAKES IT OPTIONAL ──────────────────
  // `ReceiptScope.tenant` is optional in transit (`src/types.ts`), and the kernel already ships a
  // family of attack vectors for what an ABSENT tenant enables (`conformance/vectors/attack/
  // tenant-splice-via-absent*.json`). A correlation value whose tenant field is sometimes empty is
  // a correlation value that is replayable across tenants exactly when the attacker chooses, so a
  // tenant-less receipt yields no digest rather than a weaker one.
  const tenantVerdict = scopeIdentifier(scope["tenant"], 128);
  if (tenantVerdict !== "ok") return fail(scopeReason("receipt.scope.tenant", tenantVerdict, 128));
  const tenant = scope["tenant"] as string;
  const chainVerdict = scopeIdentifier(scope["chain"], 128);
  if (chainVerdict !== "ok") return fail(scopeReason("receipt.scope.chain", chainVerdict, 128));
  const chain = scope["chain"] as string;

  // ── WHAT THE RECEIPT DECIDED, NOT MERELY WHO SIGNED IT (HIGH-1) ───────────────────────────────
  // See AUTHORIZING_VERDICT above for the full account. A grant descends from an ALLOWED decision;
  // correlating one to a BLOCKED, DEFERRED or SIMULATED receipt would let a cryptographically valid
  // human DENIAL present itself as the authorization for the action it denied.
  const governance = receipt["governance"] as Record<string, unknown>;
  if (governance["verdict"] !== AUTHORIZING_VERDICT) {
    return fail(
      `receipt.governance.verdict: is ${jsonStringify(governance["verdict"]) as string}, must be "${AUTHORIZING_VERDICT}" — ` +
        "a grant descends from an ALLOWED decision, and a signature proves who wrote a decision, never which decision they wrote",
    );
  }

  // ── THE RECEIPT MUST AGREE WITH ITSELF ────────────────────────────────────────────────────────
  // F1 rule-a: the receipt's own `chain.hash` = sha256(JCS(receipt without chain.hash and
  // sig.value)). Recomputing it and requiring equality is not a signature check and does not claim
  // to be one — it is what makes `authorizationReceiptHash` a hash OF THE DOCUMENT IN HAND rather
  // than a string copied out of it. A receipt edited after signing fails here.
  const recomputed = sha256Prefixed(receiptHashInput(parsedReceipt.value as unknown as Receipt));
  const committed = chainField["hash"];
  if (recomputed !== committed) {
    return fail(
      `receipt.chain.hash: recomputed ${recomputed} does not equal the committed ${jsonStringify(committed) as string} ` +
        "(the receipt body was altered after it was hashed)",
    );
  }

  // ── THE GRANT MUST BE A GRANT *FOR THIS RECEIPT* ──────────────────────────────────────────────
  // Without this, any grant could be paired with any receipt and the pair would digest happily —
  // the digest would be self-consistent and meaningless. The grant already names its authorization
  // (`approvalReceiptHash`, F1 rule-a), so the tie is checked, not assumed.
  if (grant["approvalReceiptHash"] !== recomputed) {
    return fail(
      `grant.approvalReceiptHash: ${jsonStringify(grant["approvalReceiptHash"]) as string} does not reference this receipt (${recomputed})`,
    );
  }
  // The same tie one level down: a grant authorizes ONE exact parameter hash (D13/D18). A grant
  // whose paramsHash differs from the receipt's action would let a digest assert that an
  // authorization for parameters A covers an action with parameters B.
  if (grant["paramsHash"] !== action["paramsHash"]) {
    return fail(
      `grant.paramsHash ${jsonStringify(grant["paramsHash"]) as string} does not equal receipt.action.paramsHash ${jsonStringify(action["paramsHash"]) as string}`,
    );
  }

  const projection: ActionDigestProjection = {
    spec: ACTION_DIGEST_SPEC,
    authorizationReceiptHash: recomputed,
    tenant,
    chain,
    actionId: action["id"] as string,
    actionCanonical: action["canonical"] as string,
    actionParamsHash: action["paramsHash"] as string,
    executionGrantId: grant["grantId"] as string,
    // F1 rule-b — the hash of the signed bytes AS RECEIVED, signature included. Authority for the
    // rule: `packages/approval-artifacts/src/refhash.ts`; parity gated in `test/action-digest.test.ts`.
    executionGrantHash: sha256Prefixed(canonicalize(grant)),
    executionNonce: grant["nonce"] as string,
  };

  return { ok: true, digest: sha256Prefixed(signingMessage(ACTION_DIGEST_DOMAIN, canonicalize(projection))), projection };
}

/**
 * Verify a claimed action digest against the two documents it claims to correlate.
 *
 * BOTH ARGUMENTS ARE BYTES (ADR §3.1), and both are parsed by the same strict parser the rest of
 * the kernel uses — no live caller object reaches any comparison below. Never throws: every failure
 * is a returned `{ok:false, reason}`.
 *
 * UNLIKE `buildActionDigest`, THIS ENTRY POINT AUTHENTICATES ITS OWN INPUTS. It requires a trust
 * root and refuses anything it cannot authenticate; see steps 1-3 in the body. The residual it does
 * NOT cover is named precisely in `docs/action-digest-spec.md` §6.
 *
 * @param claimBytes   `{"spec":"noa.action-digest/0.1","digest":"sha256:<64 hex>"}`
 * @param contextBytes `{"chain":[…],"grant":{…},"keyring":{…},"expect":{"tenant":"…","chain":"…"}}`
 */
export function verifyActionDigest(
  claimBytes: Uint8Array | string,
  contextBytes: Uint8Array | string,
): ActionDigestVerifyResult {
  const parsedClaim = parseDocument(claimBytes, "claim");
  if (!parsedClaim.ok) return fail(parsedClaim.reason);
  const parsedCtx = parseDocument(contextBytes, "context");
  if (!parsedCtx.ok) return fail(parsedCtx.reason);

  const claim = parsedClaim.value;
  if (!isObject(claim)) return fail("claim: not a JSON object");
  const claimKeys = objectGetOwnPropertyNames(claim);
  if (claimKeys.length !== 2 || !hasOwn(claim, "spec") || !hasOwn(claim, "digest")) {
    return fail(`claim: must carry exactly {spec, digest} (got [${arrayJoin(claimKeys, ",")}])`);
  }
  // THE VERSION TAG IS CHECKED, NOT DECORATION. A `/0.2` construction will commit to a different
  // field set; comparing its value against a `/0.1` recomputation would be a silent false negative
  // at best and a silent false POSITIVE the day two projections coincide.
  if (claim["spec"] !== ACTION_DIGEST_SPEC) {
    return fail(`claim.spec: must be "${ACTION_DIGEST_SPEC}" (got ${jsonStringify(claim["spec"]) as string})`);
  }
  const claimed = claim["digest"];
  if (typeof claimed !== "string" || !isSha256Hash(claimed)) {
    return fail(`claim.digest: must be sha256:<64 lowercase hex> (got ${jsonStringify(claimed) as string})`);
  }

  const ctx = parsedCtx.value;
  if (!isObject(ctx)) return fail("context: not a JSON object");
  const chainDocs = ctx["chain"];
  if (!isArray(chainDocs) || chainDocs.length === 0) {
    return fail("context.chain: absent or empty — supply the receipt chain containing the authorization");
  }
  if (!hasOwn(ctx, "grant")) return fail("context.grant: absent");
  if (!hasOwn(ctx, "keyring")) {
    return fail("context.keyring: absent — this verifier authenticates its own inputs and cannot do so without a trust root");
  }
  const expect = ctx["expect"];
  if (!isObject(expect)) {
    return fail("context.expect: absent — a verifier that cannot state its own tenant and chain cannot detect a replay");
  }
  const expTenant = scopeIdentifier(expect["tenant"], 128);
  if (expTenant !== "ok") return fail(scopeReason("context.expect.tenant", expTenant, 128));
  const expChain = scopeIdentifier(expect["chain"], 128);
  if (expChain !== "ok") return fail(scopeReason("context.expect.chain", expChain, 128));

  // ── STEP 1: AUTHENTICATE THE RECEIPT CHAIN, BY DELEGATION ─────────────────────────────────────
  // Round-2 QA was right that a classification string is not a control: the previous shape verified
  // no signature and asked callers, in prose, to do it first. Prose does not enforce call ordering
  // and does not stop document substitution, and the surface carries authorization decisions.
  //
  // The fix composes rather than duplicates. `verifyChain` IS this package's receipt verifier, so
  // calling it creates no second definition of "a valid receipt" — the drift hazard that made
  // re-implementation the wrong answer never arises. The chain (not a lone receipt) is required
  // because a mid-chain receipt cannot be verified alone: measured, `verifyChain([r2])` returns
  // `TAMPERED — seq gap: missing seq 0`, so accepting a single receipt would have forced either a
  // weaker check or a private re-implementation of the chain walk.
  const keyringBytes = jsonStringify(ctx["keyring"]) as string;
  const chainVerdict = verifyChain(jsonStringify(chainDocs) as string, {
    keyring: keyringBytes,
    // Optional and strictly strengthening: with it, VALID additionally means THIS agent.id signed,
    // rather than "some keyring-trusted kid did". Passed through to the one verifier that owns it.
    ...(hasOwn(ctx, "identityManifest") ? { identityManifest: jsonStringify(ctx["identityManifest"]) as string } : {}),
  });
  if (chainVerdict.status !== "VALID" || chainVerdict.signaturesVerified !== true) {
    return fail(
      `context.chain: not authentic — verifyChain returned ${chainVerdict.status}` +
        `${chainVerdict.reason ? ` (${chainVerdict.reason})` : ""}, signaturesVerified=${chainVerdict.signaturesVerified}`,
    );
  }

  // ── STEP 2: AUTHENTICATE THE GRANT ────────────────────────────────────────────────────────────
  // The grant's full §6 semantics belong to `verifyArtifact`, which lives in a package this one has
  // no dependency edge to. What IS checkable here is the part that decides whether an outsider can
  // mint a grant at all: the Ed25519 signature under the grant's own domain tag, with the key
  // resolved by this package's `resolveVerificationKey` — so static maps, lifecycle documents and
  // RETIRED-key refusal all behave exactly as they do everywhere else in the kernel.
  //
  // WHAT THIS DELIBERATELY DOES NOT DO, because claiming it would be worse than not doing it: the
  // F15 signer TYPE/ROLE matrix, key activation windows, grant expiry and the envelope refHash
  // chain are NOT evaluated. A caller enforcing an authorization decision must still run
  // `verifyArtifact`. `docs/action-digest-spec.md` §6 states this as a residual, not as a footnote.
  const grantDoc = ctx["grant"];
  if (!isObject(grantDoc)) return fail("context.grant: not a JSON object");
  const grantSig = grantDoc["sig"];
  if (!isObject(grantSig) || typeof grantSig["kid"] !== "string" || typeof grantSig["value"] !== "string") {
    return fail("context.grant.sig: missing kid/value");
  }
  const grantKey = resolveVerificationKey(keyringBytes, grantSig["kid"]);
  if (!grantKey.ok) return fail(`context.grant: ${grantKey.reason}`);
  const grantWithoutSig = objectCreateNull<Record<string, unknown>>();
  const grantNames = objectGetOwnPropertyNames(grantDoc);
  for (let i = 0; i < grantNames.length; i++) {
    const k = grantNames[i] as string;
    if (k !== "sig") grantWithoutSig[k] = grantDoc[k];
  }
  if (!verifyEd25519(grantKey.publicKey, signingMessage(GRANT_SIG_DOMAIN, canonicalize(grantWithoutSig)), grantSig["value"])) {
    return fail(`context.grant: invalid signature (kid ${grantSig["kid"]})`);
  }

  // ── STEP 3: SELECT THE AUTHORIZATION RECEIPT FROM THE VERIFIED CHAIN ──────────────────────────
  // Not by index and not by a caller-supplied id: by the binding the grant itself carries. The
  // authorization is the receipt whose F1 rule-a hash equals `grant.approvalReceiptHash`, which
  // means the caller cannot point this verifier at a different receipt than the grant references.
  // Exactly one must match — zero is a grant for an authorization not in the supplied chain, and
  // more than one would make "the" authorization ambiguous, which must never resolve silently.
  const wanted = grantDoc["approvalReceiptHash"];
  let authorization: unknown = undefined;
  let matches = 0;
  for (let i = 0; i < chainDocs.length; i++) {
    const candidate = chainDocs[i];
    if (!isObject(candidate)) continue;
    const shapeOk = validateReceiptShapeParsed(candidate);
    if (!shapeOk.ok) continue;
    if (sha256Prefixed(receiptHashInput(candidate as unknown as Receipt)) === wanted) {
      matches++;
      authorization = candidate;
    }
  }
  if (matches === 0) {
    return fail(
      `context.chain: contains no receipt matching grant.approvalReceiptHash ${jsonStringify(wanted) as string} — ` +
        "the grant does not descend from any authorization in the supplied chain",
    );
  }
  if (matches > 1) {
    return fail(`context.chain: ${matches} receipts match grant.approvalReceiptHash — the authorization is ambiguous`);
  }

  // ── STEP 4: THE CONSTRUCTION ──────────────────────────────────────────────────────────────────
  // The selected receipt is re-serialized and re-parsed through `buildActionDigest`'s own byte
  // boundary, so the builder and the verifier see literally the same input path — the alternative
  // is a second, subtly different ingest of the same value.
  const built = buildActionDigest(jsonStringify(authorization) as string, jsonStringify(grantDoc) as string);
  if (!built.ok) return fail(built.reason);

  // ── STEP 5: THE RELYING PARTY'S OWN TENANT/CHAIN ──────────────────────────────────────────────
  // These two checks are the ONLY place where `tenant` and `chain` do work that the two
  // whole-document hashes do not already do (see docs/action-digest-spec.md §7): they answer "are
  // these documents MINE?", which no property of the digest can answer, because the digest knows
  // nothing about who is asking. `reject-cross-tenant-expectation` and
  // `reject-cross-chain-expectation` isolate exactly these two, and flip to ACCEPT when they are
  // removed.
  if (built.projection.tenant !== expect["tenant"]) {
    return fail(
      `tenant mismatch: the documents are for ${jsonStringify(built.projection.tenant) as string}, the verifier expects ${jsonStringify(expect["tenant"]) as string}`,
    );
  }
  if (built.projection.chain !== expect["chain"]) {
    return fail(
      `chain mismatch: the documents are for ${jsonStringify(built.projection.chain) as string}, the verifier expects ${jsonStringify(expect["chain"]) as string}`,
    );
  }

  if (built.digest !== claimed) {
    return fail(`action digest mismatch: claimed ${claimed}, recomputed ${built.digest}`);
  }

  return {
    ok: true,
    digest: built.digest,
    projection: built.projection,
    classification: "ACTION_DIGEST_LINKAGE_MATCHED",
  };
}
