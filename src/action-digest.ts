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
 *   - IT IS NOT AN AUTHENTICATION. This module verifies no Ed25519 signature. It cannot: the
 *     receipt's signature is `verifyChain`'s verdict (`src/verify.ts`) and the grant's is
 *     `verifyArtifact`'s (`packages/approval-artifacts/src/verify.ts`), and re-implementing either
 *     here would create the second definition this file's whole existence argues against. A caller
 *     that feeds this module two documents it has not independently verified gets a digest over two
 *     documents it has not independently verified. The successful result is therefore labelled
 *     `ACTION_DIGEST_LINKAGE_MATCHED` and never anything shorter.
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
import { isSha256Hash, isParamsHash, isRfc3339 } from "./scan.js";
import { frozenTable } from "./inert.js";
// CAPTURED INTRINSICS ONLY (ADR §5.5 / lint L8). `Array.isArray`, `JSON.stringify` and `String` are
// writable properties of a mutable global, and this file decides what bytes get hashed and whether a
// digest matches — so none of them may be looked up at call time.
import { arrayIncludes, arrayJoin, hasOwn, isArray, jsonStringify, objectGetOwnPropertyNames, strCodePointCount } from "./intrinsics.js";
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
  /** The authorization receipt document. */
  readonly receipt: unknown;
  /** The `noa.execution-grant/0.1` document, signature included. */
  readonly grant: unknown;
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

/** A bounded, non-empty string — the shape every identifier in the grant/receipt must have. */
function boundedString(v: unknown, max: number): v is string {
  if (typeof v !== "string") return false;
  if (v.length === 0) return false;
  return strCodePointCount(v) <= max;
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
  if (!boundedString(grant["nonce"], 256)) return fail("grant.nonce: non-empty string ≤256 chars");
  const sig = grant["sig"];
  if (!isObject(sig)) return fail("grant.sig: not an object");
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
  const tenant = scope["tenant"];
  if (!boundedString(tenant, 128)) {
    return fail("receipt.scope.tenant: absent or empty — an action digest without a tenant is replayable across tenants");
  }
  const chain = scope["chain"];
  if (!boundedString(chain, 128)) return fail("receipt.scope.chain: absent or empty");

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
 * @param claimBytes   `{"spec":"noa.action-digest/0.1","digest":"sha256:<64 hex>"}`
 * @param contextBytes `{"receipt":{…},"grant":{…},"expect":{"tenant":"…","chain":"…"}}`
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
  if (!hasOwn(ctx, "receipt")) return fail("context.receipt: absent");
  if (!hasOwn(ctx, "grant")) return fail("context.grant: absent");
  const expect = ctx["expect"];
  if (!isObject(expect)) {
    return fail("context.expect: absent — a verifier that cannot state its own tenant and chain cannot detect a replay");
  }
  if (!boundedString(expect["tenant"], 128)) return fail("context.expect.tenant: absent or empty");
  if (!boundedString(expect["chain"], 128)) return fail("context.expect.chain: absent or empty");

  // The two documents are re-serialized and re-parsed by `buildActionDigest`'s own byte boundary.
  // That costs one round trip and buys the property that the builder and the verifier see literally
  // the same input path — the alternative is a second, subtly different ingest for the same value.
  const built = buildActionDigest(jsonStringify(ctx["receipt"]) as string, jsonStringify(ctx["grant"]) as string);
  if (!built.ok) return fail(built.reason);

  // ── THE RELYING PARTY'S OWN TENANT/CHAIN ──────────────────────────────────────────────────────
  // Checked SEPARATELY from the digest even though `tenant` and `chain` are already inside the
  // projection, and the redundancy is the point: this check answers "are these documents mine?",
  // the projection answers "is this digest these documents'?". Either one alone refuses the
  // cross-tenant replay — `conformance/action-digest/vectors.json` carries a vector for each, and
  // the one that satisfies the expectation and still fails is the proof the projection field is
  // load-bearing rather than decorative.
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
