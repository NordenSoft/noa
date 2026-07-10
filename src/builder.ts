import type { Receipt, ReceiptScope, ReceiptAgent, ReceiptAction, ReceiptGovernance, Checkpoint } from "./types.js";
import { RECEIPT_SPEC } from "./types.js";
import { receiptHashInput, checkpointHashInput } from "./canonicalize.js";
import { sha256Hex } from "./hash.js";
import { signEd25519 } from "./keys.js";
import { signingMessage, RECEIPT_SIG_DOMAIN, CHECKPOINT_SIG_DOMAIN } from "./signing.js";
import { validateReceiptShape } from "./schema.js";

export interface Signer {
  kid: string;
  /** base64 PKCS8 DER Ed25519 private key */
  privateKey: string;
}

export interface BuildInput {
  id: string;
  ts: string;
  scope: ReceiptScope;
  agent: ReceiptAgent;
  action: ReceiptAction;
  governance: ReceiptGovernance;
}

/**
 * Thrown by `buildReceipt` / `buildCheckpoint` when the caller-supplied input would otherwise
 * produce a SIGNED artifact that the library's own structural rules (validateReceiptShape /
 * the mirrored checkpoint-shape check) would reject (A3): an untyped JS caller can pass
 * `buildReceipt` anything — a 129-code-point `id`, a `paramsHash` that isn't
 * `(sha256|hmac-sha256):<64 hex>`, an unknown-field-smuggled `action`, etc. Without this guard
 * the builder would hash + sign that garbage anyway and hand back a validly-SIGNED receipt that
 * `verifyChain` would immediately call MALFORMED — a signed-but-malformed artifact must never
 * escape the builder. Named, typed `Error` (never a bare throw), mirroring the existing
 * `JcsError` / `SafeJsonError` pattern in this package.
 */
export class BuilderError extends Error {
  constructor(
    message: string,
    /** The structural-validation error strings (schema.ts SchemaResult.errors shape, or the
     *  mirrored checkpoint-shape errors), for programmatic callers that want the detail. */
    public readonly errors: string[],
  ) {
    super(message);
    this.name = "BuilderError";
  }
}

/**
 * Build the next receipt in a chain: compute seq/prevHash from `prev`, canonicalize, hash,
 * and sign. The hash covers sig.alg + sig.kid (key-swap protection); the signature is over
 * the 32-byte digest whose hex is chain.hash.
 *
 * Two fail-closed guarantees (A3):
 *  - The caller-supplied `input` fields (`scope`/`agent`/`action`/`governance`) are
 *    `structuredClone`d before use, so the returned `Receipt` owns independent data. A caller
 *    that mutates the object it passed in *after* calling `buildReceipt` cannot retroactively
 *    corrupt an already-signed receipt (mirrors the snapshot-once pattern `verify.ts` uses on
 *    the read side).
 *  - Immediately before returning, the fully-built (hashed + signed) receipt is re-validated
 *    with `validateReceiptShape` — the exact same structural rule `verifyChain` enforces. An
 *    input that would make the library's own verifier say MALFORMED throws `BuilderError`
 *    instead of silently returning a validly-signed-but-malformed receipt. (This must run
 *    AFTER hashing/signing, not before: `validateReceiptShape` requires `chain.hash` and
 *    `sig.value` to already be populated in their final form.)
 */
export function buildReceipt(input: BuildInput, prev: Receipt | null, signer: Signer): Receipt {
  let cloned: Pick<BuildInput, "id" | "ts" | "scope" | "agent" | "action" | "governance">;
  try {
    cloned = structuredClone({
      id: input.id,
      ts: input.ts,
      scope: input.scope,
      agent: input.agent,
      action: input.action,
      governance: input.governance,
    });
  } catch (e) {
    throw new BuilderError(`buildReceipt: input is not structured-cloneable (${(e as Error).message})`, []);
  }

  const seq = prev ? prev.chain.seq + 1 : 0;
  const prevHash = prev ? prev.chain.hash : null;

  const draft: Receipt = {
    spec: RECEIPT_SPEC,
    id: cloned.id,
    ts: cloned.ts,
    scope: cloned.scope,
    agent: cloned.agent,
    action: cloned.action,
    governance: cloned.governance,
    chain: { seq, prevHash, hash: "" },
    sig: { alg: "ed25519", kid: signer.kid, value: "" },
  };

  const hashInput = receiptHashInput(draft);
  draft.chain.hash = "sha256:" + sha256Hex(hashInput);
  draft.sig.value = signEd25519(signer.privateKey, signingMessage(RECEIPT_SIG_DOMAIN, hashInput));

  const shape = validateReceiptShape(draft);
  if (!shape.ok) {
    throw new BuilderError(
      `buildReceipt: refusing to return a signed receipt that fails its own verifier's structural check: ${shape.errors.join("; ")}`,
      shape.errors,
    );
  }

  return draft;
}

const CHECKPOINT_HASH_RE = /^sha256:[0-9a-f]{64}$/;
// RFC 3339 §5.6 permits lowercase 't'/'z' (matches schema.ts RFC3339_RE / verify.ts CP_RFC3339_RE).
const CHECKPOINT_RFC3339_RE = /^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(\.\d{1,9})?([Zz]|[+-]\d{2}:\d{2})$/;

/**
 * Structural check for a fully-built Checkpoint draft, run immediately before it is returned as
 * a signed artifact. Mirrors the exact structural rules `verify.ts`'s `verifyCheckpoint`
 * enforces (spec tag, non-empty `chain`, non-negative safe-integer `highestSeq`,
 * `sha256:<hex>` `headHash`, RFC 3339 `ts`, non-empty ed25519 `sig.kid`/`sig.value`) so a
 * caller can never receive a SIGNED checkpoint the library's own verifier would call
 * "malformed checkpoint" / "bad spec" — the A3 gap, checkpoint side.
 *
 * Deliberately duplicated here rather than imported from verify.ts: builder.ts (write path)
 * stays a one-way dependency on schema.ts/types.ts only, independent of the read-path module.
 * If verify.ts's checkpoint-shape rule ever changes, this must be updated in the same PR —
 * flagged here rather than silently drifting.
 */
function checkpointDraftErrors(cp: Checkpoint): string[] {
  const errors: string[] = [];
  if (cp.spec !== "noa.checkpoint/0.1") errors.push('checkpoint.spec: must be "noa.checkpoint/0.1"');
  if (typeof cp.chain !== "string" || cp.chain.length === 0) errors.push("checkpoint.chain: non-empty string");
  if (typeof cp.highestSeq !== "number" || !Number.isSafeInteger(cp.highestSeq) || cp.highestSeq < 0)
    errors.push("checkpoint.highestSeq: non-negative safe integer");
  if (typeof cp.headHash !== "string" || !CHECKPOINT_HASH_RE.test(cp.headHash))
    errors.push("checkpoint.headHash: sha256:<64 hex>");
  if (typeof cp.ts !== "string" || !CHECKPOINT_RFC3339_RE.test(cp.ts))
    errors.push("checkpoint.ts: must be RFC 3339 UTC timestamp");
  if (cp.sig.alg !== "ed25519") errors.push('checkpoint.sig.alg: must be "ed25519"');
  if (typeof cp.sig.kid !== "string" || cp.sig.kid.length === 0) errors.push("checkpoint.sig.kid: non-empty string");
  if (typeof cp.sig.value !== "string" || cp.sig.value.length === 0)
    errors.push("checkpoint.sig.value: non-empty string");
  return errors;
}

/**
 * Build a signed checkpoint asserting the current head of a chain (tail-truncation defense).
 *
 * Same two fail-closed guarantees as `buildReceipt` (A3): the parts of `head` this function
 * reads (`scope.chain`, `chain.seq`, `chain.hash`) are `structuredClone`d before use, so a
 * caller mutating `head` after the call cannot retroactively corrupt an already-signed
 * checkpoint; and the fully-built (hashed + signed) checkpoint is re-validated with
 * `checkpointDraftErrors` immediately before returning, throwing `BuilderError` instead of
 * handing back a signed-but-malformed checkpoint.
 */
export function buildCheckpoint(head: Receipt, ts: string, signer: Signer): Checkpoint {
  let headSnap: { chain: string; seq: number; hash: string };
  try {
    headSnap = structuredClone({ chain: head.scope.chain, seq: head.chain.seq, hash: head.chain.hash });
  } catch (e) {
    throw new BuilderError(`buildCheckpoint: head is not structured-cloneable (${(e as Error).message})`, []);
  }

  const draft: Checkpoint = {
    spec: "noa.checkpoint/0.1",
    chain: headSnap.chain,
    highestSeq: headSnap.seq,
    headHash: headSnap.hash,
    ts,
    sig: { alg: "ed25519", kid: signer.kid, value: "" },
  };
  const hashInput = checkpointHashInput(draft);
  draft.sig.value = signEd25519(signer.privateKey, signingMessage(CHECKPOINT_SIG_DOMAIN, hashInput));

  const errors = checkpointDraftErrors(draft);
  if (errors.length > 0) {
    throw new BuilderError(
      `buildCheckpoint: refusing to return a signed checkpoint that fails its own verifier's structural check: ${errors.join("; ")}`,
      errors,
    );
  }

  return draft;
}
