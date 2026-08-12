/**
 * NOA Gate — WHO HOLDS THE AUTHORITY HALF OF THE GATE'S KEY MATERIAL.
 *
 * ── THE DEFECT THIS EXISTS TO CLOSE (NON-CLAIMS.md, "the authority root itself") ────────────────
 * The Execution Grant is the gate's authorization to act: `paramsHash`-bound, `maxUses:1`, and the
 * one artifact a target would ever be asked to validate. Until this file existed, the key that signs
 * it was a base64 string on the heap of the very process the grant is meant to constrain
 * (`trust.ts`, `GateKeyPair.privateKey`), so the ambient attacker who motivates the whole
 * architecture could read it and mint grants for parameters no human ever saw. An enforcement
 * boundary whose own authority root sits in the process it is defending against is not a boundary.
 *
 * ── WHY ALL FOUR EXECUTION-SIGNER ARTIFACTS MOVE, NOT JUST THE GRANT ────────────────────────────
 * MEASURED, not assumed. A relying party accepts a grant iff its `sig.kid` resolves in the tenant's
 * Key Manifest to a GATE key holding the role `execution-signer`
 * (`packages/approval-artifacts/src/verify.ts`, the F15 block). That role is ALSO what the manifest
 * must grant for the Consumption, the Execution Uncertainty and the Hold Resolution
 * (`domains.ts:79-99`) — one role, four artifacts, three of which are after-the-fact ATTESTATIONS
 * and one of which is AUTHORITY. So the frozen F15 vocabulary cannot express "may attest, may not
 * authorize": any key left in the gate process holding `execution-signer` for the attestations can
 * sign a grant with the same stroke. Splitting custody of the grant alone is therefore impossible
 * without widening the role vocabulary (which would change a published schema and its frozen
 * conformance vectors). The remaining move is the one made here: in remote mode the gate process
 * holds NO key that the manifest grants `execution-signer`, and all four artifacts are signed by the
 * sidecar — the grant behind a policy gate, the three attestations behind spec/domain validation
 * that makes them useless for minting a grant.
 *
 * ── WHY THE TRANSPORT IS SYNCHRONOUS ────────────────────────────────────────────────────────────
 * `decide()`, `reserve()` and `report()` are synchronous BY DESIGN: their compare-and-set
 * ("UNUSED→RESERVED", the one-shot terminal-report lock, "a hold is decided exactly once") are
 * atomic precisely because no `await` can split them on a single-threaded runtime
 * (`store.ts`'s corrected note, `engine.ts`'s reserve block). Making the signing call `await` would
 * introduce a suspension point inside each of those windows — trading a custody defect for a race,
 * in the same change. So the round trip blocks: a one-shot client process talks to the long-lived
 * sidecar over its Unix socket and the engine keeps every synchronous invariant it had.
 * MEASURED cost per signature (this machine, Node v23.7.0): see `test/grant-authority-root.test.ts`,
 * which prints the real number; the budget it must fit inside is the GRANT TTL (5 minutes default),
 * not a request deadline.
 */

import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { ARTIFACTS, signArtifact, signHashInput, signingMessage, verifyEd25519 } from "noa-approval-artifacts";
import { intrinsics } from "noa-receipt";
import { describeThrown } from "noa-mcp-adapter-core/safe-throw";
import { encodeDocument } from "./bytes.js";
import type { GateKeyPair } from "./trust.js";
import type { HoldEnvelope, Receipt } from "./types.js";

const { hasOwn } = intrinsics;

/**
 * The four specs an execution signer may ever sign. The list is a NULL-PROTOTYPE table probed with
 * the module-load `hasOwn` capture, never `Array.prototype.includes` — the same discipline
 * `engine.ts`'s risk lattice uses, and for the same reason: an ambient prototype method is
 * replaceable by anything else in the realm, and the thing being decided here is which domain tag a
 * key gets applied under.
 */
const EXECUTION_SIGNED_SPECS: Readonly<Record<string, true>> = Object.freeze(
  Object.assign(Object.create(null) as Record<string, true>, {
    "noa.execution-grant/0.1": true,
    "noa.execution-consumption/0.1": true,
    "noa.execution-uncertainty/0.1": true,
    "noa.hold-resolution/0.1": true,
  }),
);

/** The GRANT is authority; the other three are attestations. Kept as its own constant because two
 *  independent refusals depend on the distinction (the sidecar's op split, and this module's
 *  `signAttestation` guard). */
export const EXECUTION_GRANT_SPEC = "noa.execution-grant/0.1";

/**
 * spec → §6 domain tag, resolved from the SHIPPED authority table rather than restated at each call
 * site. `ARTIFACTS` is the one place that says which tag an artifact is signed under; a second copy
 * is how a cross-protocol-replay constant silently drifts.
 */
export function executionDomainFor(spec: unknown): string {
  if (typeof spec !== "string" || !hasOwn(EXECUTION_SIGNED_SPECS, spec)) {
    throw new Error(`execution signer: refusing to sign spec ${JSON.stringify(spec)} — not an execution-signer artifact`);
  }
  const meta = hasOwn(ARTIFACTS, spec) ? ARTIFACTS[spec] : undefined;
  if (!meta || typeof meta.domain !== "string") {
    throw new Error(`execution signer: no signing domain registered for ${spec}`);
  }
  return meta.domain;
}

/** The approver-signed material a policy-gating signer independently verifies before it will put the
 *  authority key anywhere near a grant. Every member is carried on the wire; none of it is trusted
 *  by the sidecar as trust material — the sidecar's keys are its own. */
export interface GrantApprovalProof {
  holdEnvelope: HoldEnvelope;
  decisionArtifact: Record<string, unknown>;
  deferredReceipt: Receipt;
  approvalReceipt: Receipt;
}

/**
 * The gate's execution-signer. Two implementations, one interface:
 *   - `localExecutionSigner`  — the alpha default: the key is on this heap. Honest about it.
 *   - `remoteExecutionSigner` — the key is in another process behind a policy gate.
 * Synchronous on purpose (see the module docstring).
 */
export interface ExecutionSigner {
  readonly kid: string;
  /** base64(DER SPKI) public half — what the KEY MANIFEST must publish for this kid. Exposed so the
   *  trust root can be built from the signer that was actually reached, never from a copy an
   *  operator retyped into a config file. */
  readonly publicKey: string;
  /** Sign an Execution Grant. `proof` is the approval a policy-gating implementation VALIDATES. */
  signGrant<T extends Record<string, unknown>>(doc: T, proof: GrantApprovalProof): T & { sig: { alg: "ed25519"; kid: string; value: string } };
  /** Sign a Consumption / Execution Uncertainty / Hold Resolution — attestations, never authority. */
  signAttestation<T extends Record<string, unknown>>(doc: T): T & { sig: { alg: "ed25519"; kid: string; value: string } };
}

/**
 * TODAY'S BEHAVIOUR, NAMED. The private key is a string in this process; `proof` is accepted and
 * ignored, because an in-process signer validating an approval proves nothing — the attacker who
 * can call it can also call `signArtifact` directly with the same key. This implementation is the
 * alpha default so that no existing deployment or test changes behaviour; it is NOT the thing that
 * closes the non-claim.
 */
export function localExecutionSigner(gate: GateKeyPair): ExecutionSigner {
  const sign = <T extends Record<string, unknown>>(doc: T) =>
    signArtifact<T>(encodeDocument(doc), executionDomainFor(doc["spec"]), { kid: gate.kid, privateKey: gate.privateKey });
  return {
    kid: gate.kid,
    publicKey: gate.publicKey,
    signGrant: (doc, _proof) => sign(doc),
    signAttestation: (doc) => sign(doc),
  };
}

// ── the remote (policy-gating) signer ────────────────────────────────────────────────────────────

/** One JSON line in, one JSON line out — the same wire discipline as `noa-signer-sidecar`. */
export interface GrantSignerRequest {
  op: "pubkey" | "sign-grant" | "sign-attestation";
  artifact?: Record<string, unknown>;
  proof?: GrantApprovalProof;
}

const DEFAULT_CALL_TIMEOUT_MS = 10_000;
/** Bound on a sidecar response, mirroring the gate's own `maxBodyBytes` default. A signing oracle
 *  that can be made to stream unbounded bytes into the gate is a DoS knob, not a signer. */
const MAX_RESPONSE_BYTES = 256 * 1024;

function callScriptPath(): string {
  return path.join(path.dirname(fileURLToPath(import.meta.url)), "grant-signer-call.js");
}

/**
 * A single blocking request/response against the sidecar.
 *
 * The child process is a shim that holds no key and makes no decision: it exists only because
 * `node:net` has no synchronous mode and the engine's atomicity depends on staying synchronous.
 * Everything that matters — custody, policy, the signature — happens in the sidecar on the other
 * end of the socket.
 */
function callSidecar(socketPath: string, request: GrantSignerRequest, timeoutMs: number, scriptPath: string): Record<string, unknown> {
  const res = spawnSync(process.execPath, [scriptPath, "--socket", socketPath], {
    input: JSON.stringify(request) + "\n",
    encoding: "utf8",
    timeout: timeoutMs,
    maxBuffer: MAX_RESPONSE_BYTES,
    // The child inherits nothing it does not need. `stdio` is pipes only; no shell, no argv from
    // the request, and the socket path is the single operator-supplied argument.
    stdio: ["pipe", "pipe", "pipe"],
  });
  if (res.error) throw new Error(`grant signer: sidecar call failed: ${describeThrown(res.error)}`);
  if (res.status !== 0) {
    const detail = (res.stderr ?? "").toString().replace(/\s+/g, " ").slice(0, 300);
    throw new Error(`grant signer: sidecar client exited ${String(res.status)}${detail ? `: ${detail}` : ""}`);
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse((res.stdout ?? "").toString());
  } catch (err) {
    throw new Error(`grant signer: malformed sidecar response (${describeThrown(err)})`);
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new Error("grant signer: sidecar response is not an object");
  }
  const body = parsed as Record<string, unknown>;
  if (typeof body["error"] === "string") throw new Error(`grant signer: REFUSED by the sidecar: ${body["error"]}`);
  return body;
}

/**
 * The returned artifact must be the document we asked to have signed, plus exactly one new member —
 * `sig` — carrying a signature that ACTUALLY VERIFIES under the operator-pinned public key.
 *
 * ── THIS FUNCTION USED TO CHECK EVERYTHING EXCEPT THE SIGNATURE ─────────────────────────────────
 * It compared fields, shape and `kid` and never ran Ed25519 over `sig.value` (adversarial review
 * 2026-08-12). Measured: a response echoing the exact document with `value: "not-a-signature"` made
 * `decide()` return 200 and persist an APPROVED hold with an UNUSED grant record — the gate
 * believing it held authority it had never been given. A "verified" that never verifies is worse
 * than no check, because it is quoted as one.
 *
 * The preimage is rebuilt from the SHIPPED primitives `signArtifact` itself uses — `signHashInput`
 * is `canonicalize(document without sig)` and `signingMessage` is the domain tag — so this is the
 * same construction, not a second opinion about what a signature covers.
 */
function assertSignedDocMatches(doc: Record<string, unknown>, signed: Record<string, unknown>, expectKid: string, expectPublicKey: string): void {
  for (const k of Object.keys(doc)) {
    if (JSON.stringify(signed[k]) !== JSON.stringify(doc[k])) {
      throw new Error(`grant signer: sidecar returned an artifact whose "${k}" differs from the document submitted`);
    }
  }
  for (const k of Object.keys(signed)) {
    if (k !== "sig" && !hasOwn(doc, k)) {
      throw new Error(`grant signer: sidecar returned an artifact carrying an unexpected member "${k}"`);
    }
  }
  const sig = signed["sig"];
  if (typeof sig !== "object" || sig === null || Array.isArray(sig)) throw new Error("grant signer: sidecar returned no sig");
  const s = sig as Record<string, unknown>;
  if (s["alg"] !== "ed25519" || typeof s["value"] !== "string" || s["value"].length === 0) {
    throw new Error("grant signer: sidecar returned a malformed sig");
  }
  if (s["kid"] !== expectKid) {
    throw new Error(`grant signer: sidecar signed under kid ${JSON.stringify(s["kid"])}, not the pinned kid ${JSON.stringify(expectKid)}`);
  }
  const domain = executionDomainFor(signed["spec"]);
  if (!verifyEd25519(expectPublicKey, signingMessage(domain, signHashInput(signed)), s["value"] as string)) {
    throw new Error(
      `grant signer: the signature returned for ${String(signed["spec"])} does not verify under the pinned public key for kid ${JSON.stringify(expectKid)} — ` +
        `refusing to treat an unverified blob as this gate's authority`,
    );
  }
}

export interface RemoteExecutionSignerOptions {
  socketPath: string;
  /**
   * THE OPERATOR'S PINNED IDENTITY for the signer, REQUIRED — supplied out of band, never learned
   * from the socket.
   *
   * ── WHY THIS IS NOT OPTIONAL (adversarial review 2026-08-12) ─────────────────────────────────
   * This function used to ask the socket `pubkey` and believe the answer, and the gate then MINTED
   * A KEY MANIFEST naming whatever kid came back as the tenant's only `execution-signer`. So an
   * attacker who could replace the listener (or the client shim) before startup had only to answer
   * with their own key and sign without any policy checks: the gate would publish the attacker's
   * key as its authority root and every forged grant would verify. "Pinned" meant pinned to the
   * attacker-controlled first response.
   *
   * Bootstrapping trust from the channel you are defending against is not bootstrapping trust. The
   * expected kid and public key now come from the operator, and the socket must AGREE with them or
   * this refuses to return a signer at all.
   */
  expect: { kid: string; publicKey: string };
  timeoutMs?: number;
  /** Overridable only so a test can point at a build output outside this file's own directory. */
  callScript?: string;
}

/**
 * Bind to a running grant sidecar. FAIL-CLOSED AT CONSTRUCTION, mirroring
 * `noa-signer-sidecar`'s client: an unreachable authority root must stop the gate from starting,
 * never surface as a surprise on the first human approval.
 */
export function remoteExecutionSigner(options: RemoteExecutionSignerOptions): ExecutionSigner {
  const socketPath = options.socketPath;
  if (!socketPath) throw new Error("remoteExecutionSigner: `socketPath` is required");
  const timeoutMs = options.timeoutMs ?? DEFAULT_CALL_TIMEOUT_MS;
  const scriptPath = options.callScript ?? callScriptPath();

  const expect = options.expect;
  if (!expect || typeof expect.kid !== "string" || expect.kid.length === 0 || typeof expect.publicKey !== "string" || expect.publicKey.length === 0) {
    throw new Error(
      "remoteExecutionSigner: `expect: { kid, publicKey }` is required — the signer's identity is operator-supplied trust material, " +
        "never something to learn from the socket it is meant to authenticate",
    );
  }
  const hello = callSidecar(socketPath, { op: "pubkey" }, timeoutMs, scriptPath);
  const kid = hello["kid"];
  const pub = hello["pub"];
  if (typeof kid !== "string" || kid.length === 0 || typeof pub !== "string" || pub.length === 0) {
    throw new Error("remoteExecutionSigner: sidecar's pubkey response is malformed (expected { kid, pub })");
  }
  // The socket does not get a vote on who it is. It only gets to AGREE.
  if (kid !== expect.kid || pub !== expect.publicKey) {
    throw new Error(
      `remoteExecutionSigner: the process listening on ${socketPath} presents kid ${JSON.stringify(kid)} and a public key that do not match the ` +
        `operator-pinned identity ${JSON.stringify(expect.kid)}. Refusing to start: a signer that can name itself is not an authority root.`,
    );
  }

  const ask = <T extends Record<string, unknown>>(op: "sign-grant" | "sign-attestation", doc: T, proof?: GrantApprovalProof) => {
    // Resolved HERE as well as in the sidecar: a caller must not be able to route a grant document
    // through the attestation op, and the check that refuses it should not live only on the far side
    // of a socket the caller controls.
    const spec = doc["spec"];
    executionDomainFor(spec);
    if (op === "sign-attestation" && spec === EXECUTION_GRANT_SPEC) {
      throw new Error("grant signer: an Execution Grant may never be signed through the attestation op");
    }
    const body = callSidecar(socketPath, { op, artifact: doc, ...(proof ? { proof } : {}) }, timeoutMs, scriptPath);
    const signed = body["artifact"];
    if (typeof signed !== "object" || signed === null || Array.isArray(signed)) {
      throw new Error("grant signer: sidecar response carries no artifact");
    }
    assertSignedDocMatches(doc, signed as Record<string, unknown>, expect.kid, expect.publicKey);
    return signed as T & { sig: { alg: "ed25519"; kid: string; value: string } };
  };

  return {
    kid: expect.kid,
    publicKey: expect.publicKey,
    signGrant: (doc, proof) => ask("sign-grant", doc, proof),
    signAttestation: (doc) => ask("sign-attestation", doc),
  };
}
