import type { Receipt, Checkpoint } from "./types.js";
import { validateReceiptShapeParsed } from "./schema.js";
import { receiptHashInput, checkpointHashInput } from "./canonicalize.js";
import { sha256Hex } from "./hash.js";
import { verifyEd25519, type Keyring } from "./keys.js";
import { signingMessage, RECEIPT_SIG_DOMAIN, CHECKPOINT_SIG_DOMAIN } from "./signing.js";
import { nonNfcPaths, isNFC } from "./nfc.js";
import { parseDocument } from "./bytes.js";
import { inertOptions, type OptionSchema } from "./opts.js";
import { arrayPush, arrayIncludes, arrayEvery, arrayLength, arrayJoin, publishArray, dateParse, mapHas, mapGet, mapSet, newMap, newSet, objectKeys, objectGetOwnPropertyNames, isSafeInteger, arraySlice, setAdd, setSize, isArray, isNaNValue, jsonStringify } from "./intrinsics.js";
import { isSha256Hash, isRfc3339Instant } from "./scan.js";
import { frozenTable } from "./inert.js";
import { parseVerificationKeyring, type ParsedVerificationKeyring } from "./verification-keyring.js";

export type VerifyStatus =
  | "VALID" // structure + hash-chain + signatures all verified against the supplied keyring
  | "UNVERIFIED" // hash-chain ok, but NO keyring supplied so signatures were not authenticated
  | "UNTRUSTED" // signature authenticated, but the (agent.id, sig.kid) pairing is NOT authorized by the supplied identity manifest (cross-agent impersonation)
  | "TAMPERED" // an integrity check failed (incl. an unknown signing key when a keyring IS supplied)
  | "MALFORMED"; // not a well-formed receipt chain

/**
 * ── OPTIONS ARE CONFIGURATION; DOCUMENTS ARE BYTES ───────────────────────────────────────────────
 *
 * `VerifyOptions` is still an object, because it is the CALLER's own configuration and
 * `{ maxReceipts: 10 }` is the ergonomics this API is worth having. What changed is that every
 * member which is a signed or verified DOCUMENT — the keyring, the identity manifest, the
 * checkpoint — is now `Uint8Array | string`, and the object itself is admitted only through
 * `inertOptions`, which rejects a Proxy (before any trap-firing reflection), an accessor, a
 * function, a symbol, an exotic prototype, an unknown member and an unbounded number, then converts
 * what survives ONCE into a frozen null-prototype record.
 *
 * That is what deletes the `structuredClone` machinery this file used to carry. The snapshot existed
 * because the in-process object API read the same caller object more than once and a flipping
 * accessor could show one value to authentication and another to enforcement. After this change
 * there is no caller object to read twice: the receipts came from `safeParse` over bytes, and every
 * option was read exactly once at the boundary. The defence is not improved — its reason to exist
 * is gone.
 */
export interface VerifyOptions {
  /**
   * Trust root as JSON bytes. A static consumer supplies `{ kid: base64-SPKI }`. A rotatable signer
   * supplies the atomic `noa.signing-key-lifecycle/0.1` document containing public keys plus each
   * key's `retiredAt` (`null` for a current key). The lifecycle form refuses every non-null
   * retirement outright; signer-chosen receipt/checkpoint timestamps are never retirement evidence.
   */
  keyring?: Uint8Array | string;
  /** Signed checkpoint as JSON bytes, asserting the expected head — enables tail-truncation detection. */
  checkpoint?: Uint8Array | string;
  /** Hard cap on receipts processed (DoS bound). */
  maxReceipts?: number;
  /**
   * Optional `agent.id -> authorized kid(s)` binding (a trust input, like the keyring). When supplied,
   * a receipt whose `(agent.id, sig.kid)` pairing is not authorized is rejected as UNTRUSTED — this is
   * what makes a VALID result mean "THIS agent.id signed", not just "a keyring-trusted key signed".
   * Omit it to keep kid-level attribution (the weaker, documented guarantee). Supplied as JSON bytes.
   */
  identityManifest?: Uint8Array | string;
  /**
   * Chain-wide `scope.tenant` consistency. **DEFAULT: `true` (fail-closed).**
   *
   * A `scope.tenant` that drifts from one PRESENT value to a DIFFERENT present value across one
   * `scope.chain` is rejected as `TAMPERED`, the same verdict class as a `scope.chain` partition
   * split, because it is the identical class of problem: a scope field the caller assumed was
   * chain-wide-constant, isn't.
   *
   * `scope.tenant` is OPTIONAL, so a receipt that simply OMITS it is not a cross-tenant splice — a
   * producer that starts or stops emitting an optional field is a version change, not tampering.
   * Absence is REPORTED in `warnings` and never fatal. It also does not RESET the comparison: the
   * last present value is carried across absences, so `acme -> absent -> globex` is the same splice
   * as `acme -> globex` and gets the same verdict, while `acme -> absent -> acme` (the same tenant
   * resuming) and `absent -> acme` (enrichment) stay valid.
   *
   * **BREAKING CHANGE (was `false`).** This default previously let a mixed-tenant chain return VALID
   * with only a warning. That was documented and opt-in, which is a real defence — but defaults are
   * what actually ship, and the operator most in need of the check is the least likely to know the
   * flag exists. Tenant isolation is a security boundary, and default-permissive on a security
   * boundary is the wrong posture for a product deployed multi-tenant.
   *
   * The change is LOUD, never silent: an affected caller gets a `TAMPERED` verdict with a
   * machine-readable `tenant-drift: seq A "x" -> seq B "y"` reason, not a quietly different answer.
   * A caller that genuinely intends to verify a mixed-tenant chain sets `requireTenantConsistency:
   * false` and gets the exact previous behaviour, warning included. See CHANGELOG.md for the
   * migration note.
   */
  requireTenantConsistency?: boolean;
  /**
   * Opt-in enforcement of the profile's "all strings MUST be Unicode NFC" rule (default false —
   * existing callers see no verdict change). The profile places the NFC obligation on PRODUCERS,
   * and this package's builder now refuses to sign a non-NFC payload, so nothing NOA emits can
   * violate it. Verification is deliberately asymmetric: rejecting by default would break receipts
   * that were already issued and signed, which is a worse failure than the one it prevents. By
   * default a non-NFC string is reported in `warnings` (machine-readable `non-nfc: <path>` entries)
   * and the verdict is unaffected. Set this to `true` to reject the first non-NFC receipt as
   * MALFORMED — the same class already used for "receipt contains non-canonicalizable content",
   * since this is a payload-conformance failure and not evidence of tampering.
   *
   * Relying parties that match, index, or alert on receipt fields should either enable this or
   * compare those fields as BYTES: two receipts can render identically and differ in bytes, and
   * both verify.
   */
  requireNFC?: boolean;
}

export interface VerifyResult {
  status: VerifyStatus;
  chain: string | null;
  count: number;
  /**
   * TRUE means: **this result is backed by COMPLETED signature authentication of the whole input.**
   *
   * It is NOT "a keyring was supplied", and it is NOT a progress report. It is a success-qualifier
   * that only a completed run can earn, so it is `false` on every non-VALID verdict — including a
   * failure at receipt N where receipts 1..N-1 authenticated cleanly, and including a failure whose
   * reason is not cryptographic at all (tenant drift, chain order, a malformed later field). The
   * status and `reason` carry how far the run got; this field does not.
   *
   * ── WHY THE OTHER READING IS THE DANGEROUS ONE (P1-13, adjudicated 2026-08-04) ─────────────────
   * `fail()` hardcodes `false` here at all 35 call sites, and 19 of those sit after signature
   * checking begins (`:401`), which reads like a lie. It is not, and the alternative is the defect:
   * under "a keyring was supplied", a TAMPERED verdict would carry `signaturesVerified: true` — a
   * POSITIVE SUB-CLAIM RIDING A FAILED CHECK. That is the same shape as a CI job reporting success
   * having skipped its tests. A run that did not complete must never report its sub-checks as
   * passed.
   *
   * The success path computes this meaning EXACTLY rather than loosely: loop 4c (`:481-495`) has no
   * skip path — a retired kid, an unknown kid and a bad signature all `return fail(...)` — so
   * reaching `:658` with a keyring PROVES every receipt signature authenticated. `haveKeyring` is
   * therefore an exact witness there, not a proxy. Pinned by `test/signatures-verified-contract.test.ts`.
   */
  signaturesVerified: boolean;
  /**
   * TRUE means: **an AUTHENTICATED checkpoint certified the chain head.** Same contract as
   * `signaturesVerified` above, same reasoning, same `false`-on-every-failure rule: `:620` sets it
   * from `cpVerify === "ok"` and nothing else, so an unauthenticated head match is never reported
   * as a tail check.
   *
   * ⚠ SCOPE, not strength: with no identity manifest this says the tail was certified by SOME key
   * the keyring trusts, which is only as strong as the weakest holder of any key in it — the §5b
   * genesis binding that ties checkpoint authority to the chain opener runs only when a manifest is
   * present. The warning at `:625` says so on the result itself.
   */
  tailChecked: boolean;
  badSeq?: number;
  reason?: string;
  warnings: string[];
}

export const DEFAULT_MAX_RECEIPTS = 1_000_000;

function fail(
  status: VerifyStatus,
  reason: string,
  chain: string | null,
  count: number,
  badSeq?: number,
): VerifyResult {
  // BOTH FLAGS ARE FALSE BY CONTRACT, NOT AS A PROGRESS REPORT. A failure result never carries a
  // positive sub-claim, even when the sub-check in question did pass before the run stopped — see
  // the `signaturesVerified` contract on the interface. This literal is deliberate and load-bearing;
  // making it conditional on how far the loop got is the change P1-13 considered and rejected.
  const r: VerifyResult = { status, chain, count, signaturesVerified: false, tailChecked: false, reason, warnings: [] };
  if (badSeq !== undefined) r.badSeq = badSeq;
  return r;
}

/** Human/machine-readable label for a `scope.tenant` value in a drift message: quoted string, or `(none)`. */
function describeTenant(t: string | undefined): string {
  return t === undefined ? "(none)" : (jsonStringify(t) as string);
}

/**
 * Verify a NOA receipt chain. Pure, offline, deterministic — no network, no NOA cloud.
 *
 * Trust model (stated honestly; see THREAT-MODEL.md):
 *  - The supplied keyring is the trust root. With it, every signature is authenticated and a
 *    key is held continuous per (agent.id): a mid-chain key swap is rejected, and an unknown
 *    kid is treated as TAMPERED (not silently accepted — that would be TOFU on attacker input).
 *  - Without a keyring, signatures cannot be authenticated → status UNVERIFIED (never VALID).
 *  - IDENTITY: with an `identityManifest` (agent.id -> authorized kid(s)), a receipt whose
 *    (agent.id, sig.kid) pairing is not authorized is UNTRUSTED — this upgrades attribution from
 *    "a keyring-trusted key signed" to "THIS agent.id signed". Without it, attribution is kid-level:
 *    in a multi-key keyring any trusted key can assert any agent.id (cross-agent impersonation).
 *  - Without a checkpoint, TAIL-TRUNCATION cannot be detected offline (reported in warnings).
 *  - FORK / EQUIVOCATION: an offline verifier only sees the branch it is given; it cannot know
 *    the signer also signed a different history at the same seq. Detecting that needs an
 *    external witness / transparency log (v1.0). Reported in warnings.
 *  - TENANT CONSISTENCY: `scope.tenant` IS enforced chain-wide by default (BREAKING change from
 *    earlier releases, which only warned). A chain mixing tenants — or carrying the field on some
 *    receipts and not others — is TAMPERED at the first drift, with a machine-readable
 *    `tenant-drift: seq A "x" -> seq B "y"` reason. Pass `requireTenantConsistency: false` for the
 *    previous warn-only behaviour.
 */
export function verifyChain(receipts: Uint8Array | string, opts: VerifyOptions = {}): VerifyResult {
  // ── THE BOUNDARY, IN THREE LINES ───────────────────────────────────────────────────────────────
  // Options first, because a malformed option is a caller error that should be reported before any
  // work is done on the document. `inertOptions` rejects a Proxy (before any trap-firing reflection),
  // an accessor, a function, a symbol, an exotic prototype, an unknown member and an unbounded
  // number, and returns a frozen null-prototype record whose `document` members are already decoded.
  const admitted = inertOptions<InertVerifyOptions>(VERIFY_OPTION_SCHEMA, opts, "options");
  if (!admitted.ok) return fail("MALFORMED", admitted.reason, null, 0);
  const o = admitted.value;

  // The document. `parseDocument` bounds the BYTES, decodes UTF-8 fatally, and hands the text to
  // `safeParse` — so what comes back is a null-prototype, accessor-free, duplicate-key-free,
  // depth-bounded tree. There is no live caller object anywhere below this line, which is why the
  // `structuredClone` snapshots this function used to carry are gone rather than merely tightened.
  const parsed = parseDocument(receipts, "receipts");
  if (!parsed.ok) return fail("MALFORMED", parsed.reason, null, 0);
  return verifyParsedChain(parsed.value, o);
}

/** The option members that are DOCUMENTS arrive decoded to text; the rest are scalars. */
interface InertVerifyOptions {
  readonly keyring?: string;
  readonly checkpoint?: string;
  readonly identityManifest?: string;
  readonly maxReceipts?: number;
  readonly requireTenantConsistency?: boolean;
  readonly requireNFC?: boolean;
}

/**
 * `maxReceipts` is ceilinged at `DEFAULT_MAX_RECEIPTS` rather than left open. An option whose value
 * is unbounded is a DoS knob, and raising the ceiling above the default is not a capability any
 * caller needs: `MAX_INPUT_BYTES` already bounds a document to 16 MiB, which cannot hold anywhere
 * near a million receipts. The bound is therefore unreachable in practice and fail-closed in
 * principle.
 */
const VERIFY_OPTION_SCHEMA: OptionSchema = Object.freeze(Object.assign(Object.create(null), {
  keyring: { kind: "document" },
  checkpoint: { kind: "document" },
  identityManifest: { kind: "document" },
  maxReceipts: { kind: "count", max: DEFAULT_MAX_RECEIPTS },
  requireTenantConsistency: { kind: "boolean" },
  requireNFC: { kind: "boolean" },
})) as OptionSchema;

/**
 * The chain verifier over PARSED data. Module-private on purpose: it assumes its input came from
 * `safeParse`, and that assumption is exactly what the public boundary above guarantees. Exporting
 * it would re-open the object API under a different name — the "no hidden legacy path" rule — so it
 * is reachable only through bytes.
 */
function verifyParsedChain(receipts: unknown, o: InertVerifyOptions): VerifyResult {
  const maxReceipts = o.maxReceipts ?? DEFAULT_MAX_RECEIPTS;

  if (!isArray(receipts)) return fail("MALFORMED", "input is not an array of receipts", null, 0);
  // No guard is needed around `receipts.length` any more, and the absence is the point: this array
  // came out of `safeParse`, so `length` is an ordinary own data property. The old code read it
  // inside a try/catch because a caller-supplied array-like could carry `get length(){ throw }`.
  // That input class no longer reaches this function.
  const n = receipts.length;
  if (n === 0) return fail("MALFORMED", "empty receipt array", null, 0);
  if (n > maxReceipts) return fail("MALFORMED", `too many receipts (>${maxReceipts})`, null, n);

  const receiptsSnap: unknown[] = receipts;
  let checkpointSnap: unknown;
  if (o.checkpoint !== undefined) {
    const cpParsed = parseDocument(o.checkpoint, "checkpoint");
    if (!cpParsed.ok) return fail("MALFORMED", cpParsed.reason, null, n);
    checkpointSnap = cpParsed.value;
  }

  // Validate the optional identity manifest (a trust input). Fail-closed: a malformed manifest is an
  // operator error, never silently ignored (that would re-open the very impersonation gap it closes).
  //
  // THE TOCTOU COMMENTARY THAT USED TO LIVE HERE IS GONE, AND ITS ABSENCE IS THE CHANGE. It explained
  // why each manifest entry was read exactly once into a private Map, copied by value with
  // `Array.prototype.slice.call`, and why every enforcement point read the copy rather than the live
  // object: a flipping entry accessor could authorize one kid at validation and a different one at
  // enforcement. The manifest now arrives as BYTES and is parsed by `safeParse`, so there are no
  // accessors to flip and no second read to disagree with the first. The per-entry Map is retained
  // because it is the natural shape for the lookup, not because it is defending anything.
  const haveManifest = o.identityManifest !== undefined;
  const manifest = newMap<string, string[]>();
  let list!: Receipt[];
  let chainId!: string;
  let ordered!: Receipt[];
  const tenantDriftMessages: string[] = [];
  try {
    if (haveManifest) {
      const mParsed = parseDocument(o.identityManifest, "identityManifest");
      if (!mParsed.ok) return fail("MALFORMED", mParsed.reason, null, n);
      const live = mParsed.value;
      if (typeof live !== "object" || live === null || isArray(live)) {
        return fail("MALFORMED", "identityManifest must be an object (agent.id -> kid[])", null, 0);
      }
      // Own names — `safeParse` emits null-prototype objects with enumerable own data properties
      // only, so this and `Object.entries` would now agree; own-names is kept because it is the
      // stricter of the two and costs nothing.
      // INDEX WALK (round-4, A2). Measured before the fix: a skipping iterator hid a manifest entry
      // whose VALUE was invalid, so the only control that rejects a malformed manifest never ran and
      // `MALFORMED` became `VALID` (1 poison hit). Substituting a VALID key fails closed here — the
      // read and the write both use the same yielded `aid` — which is why this site was reported
      // twice with opposite conclusions; the SKIP shape is the one that flips it.
      const aids = objectGetOwnPropertyNames(live);
      for (let ai = 0; ai < aids.length; ai++) {
        const aid = aids[ai] as string;
        const kidsLive = (live as Record<string, unknown>)[aid];
        if (!isArray(kidsLive)) {
          return fail("MALFORMED", `identityManifest["${aid}"] must be an array of kid strings`, null, 0);
        }
        const kids = arraySlice(kidsLive) as unknown[];
        // `arrayEvery` (captured), not `.every` on the copy: a poisoned `every` answering `true`
        // admits a non-string kid into the identity manifest, which is the attribution trust root.
        if (!arrayEvery(kids, (k) => typeof k === "string")) {
          return fail("MALFORMED", `identityManifest["${aid}"] must be an array of kid strings`, null, 0);
        }
        mapSet(manifest, aid, kids as string[]);
      }
    }

    // 1. Structural validation of every element (runs BEFORE any hashing).
    for (let idx = 0; idx < receiptsSnap.length; idx++) {
      const res = validateReceiptShapeParsed(receiptsSnap[idx]);
      if (!res.ok) {
        return fail("MALFORMED", `receipt[${idx}]: ${arrayJoin(res.errors, "; ")}`, null, receiptsSnap.length, idx);
      }
    }
    list = receiptsSnap as Receipt[];

    // 2. Single chain partition.
    //
    // ── INDEX WALK, NOT `for…of` (2026-07-29, round-1 re-run) ────────────────────────────────────
    // These two loops are what populate `bySeq`, and `bySeq` is what the hash and signature checks
    // below actually run over. Iterating with `for…of` resolves `next` through
    // `%ArrayIteratorPrototype%`, so a poison that SUBSTITUTES a genuine receipt object for the
    // forged one as it is yielded gets the genuine object into `bySeq` -> `ordered` -> every
    // cryptographic check, and a forged input document verifies VALID with signaturesVerified:true.
    //
    // Note the shape distinction, because it is why this survived one review: a poison that merely
    // SKIPS the forged element is caught by the seq-contiguity check below (`seq gap`), and a
    // reviewer testing only that shape correctly reported the finding as refuted. Substitution is
    // not caught by contiguity — the count and the sequence numbers are all still perfect.
    // `list` is a real array here (`receiptsSnap`), so an indexed read dispatches through nothing.
    chainId = list[0]!.scope.chain;
    for (let i = 0; i < list.length; i++) {
      const r = list[i] as Receipt;
      if (r.scope.chain !== chainId) {
        return fail("TAMPERED", "multiple chain partitions in one input", chainId, list.length);
      }
    }

    // 3. Order by seq; require contiguous 0..n-1, unique.
    const bySeq = newMap<number, Receipt>();
    for (let i = 0; i < list.length; i++) {
      const r = list[i] as Receipt;
      if (mapHas(bySeq, r.chain.seq)) return fail("TAMPERED", `duplicate seq ${r.chain.seq}`, chainId, list.length, r.chain.seq);
      mapSet(bySeq, r.chain.seq, r);
    }
    ordered = [];
    for (let s = 0; s < list.length; s++) {
      const r = mapGet(bySeq, s);
      if (!r) return fail("TAMPERED", `seq gap: missing seq ${s}`, chainId, list.length, s);
      arrayPush(ordered, r);
    }

    // 3b. Chain-wide tenant-consistency scan (A1 hardening — THREAT-MODEL.md "namespace / context
    // binding"). scope.tenant is a sibling of scope.chain in ReceiptScope but, unlike scope.chain, is
    // NOT enforced structurally: nothing today stops one scope.chain from carrying receipts for
    // DIFFERENT scope.tenant values (or some receipts with a tenant and some without) — a caller who
    // assumes tenant isolation follows chain isolation would get a silent VALID over a mixed-tenant
    // chain. This walks `ordered` (seq-order, already validated/contiguous) once and records every
    // seq-to-seq drift as a machine-readable message; by default these ONLY land in `warnings` below
    // `requireTenantConsistency` DEFAULTS TO TRUE: the FIRST drift is escalated to
    // TAMPERED — the same verdict class as the `scope.chain` partition-split check in step 2, since
    // this is the identical class of problem for the sibling scope field.
    // WHICH DRIFTS ARE FATAL. `scope.tenant` is OPTIONAL in the schema and the frozen spec never
    // declared it immutable, so the two kinds of drift are not the same event:
    //
    //   present -> DIFFERENT present   (acme -> globex)  two distinct tenants spliced into one
    //     chain. Every receipt is individually intact and correctly signed; the forgery is a
    //     property of the SET — the identical class as the `scope.chain` partition split above,
    //     which is already TAMPERED. Fail closed.
    //
    //   absent <-> present             (enrichment/omission)  a deployment that began emitting
    //     (or stopped emitting) an optional field mid-chain. That is a producer-version change,
    //     NOT a cross-tenant splice, and nothing in the frozen spec forbids it. Calling it
    //     TAMPERED would label a legitimate transition as cryptographic tampering, tell the
    //     operator to hunt a forgery that does not exist, and contradict this profile's own
    //     rule that distinct failures must not collapse onto one verdict. Report it instead.
    //
    // ── WHY THE COMPARISON IS NOT ADJACENT ────────────────────────────────────────────────────
    // That relaxation is right in principle and was wrong in its state machine. Comparing only
    // ADJACENT receipts let an omission RESET the boundary: `acme -> globex` was TAMPERED, but
    // `acme -> absent -> globex` — the same splice with one optional field left out of the receipt
    // in between — was VALID, in all five implementations. Dropping an optional field is not a
    // capability an attacker lacks, so the tolerated transition became a laundering step.
    //
    // The state machine therefore carries the LAST PRESENT tenant across absences instead of
    // forgetting it. Absence is still never fatal and is still reported; it simply no longer erases
    // what the chain has already committed to. `acme -> absent -> acme` stays VALID (the same tenant
    // resumes) and `absent -> absent -> acme` stays VALID (a producer that starts emitting the
    // field), which is exactly the legitimacy the relaxation existed to protect.
    let lastPresentTenant: string | undefined;
    let lastPresentSeq = -1;
    for (let i = 0; i < ordered.length; i++) {
      const curR = ordered[i]!;
      const curT = curR.scope.tenant;
      // adjacent transition report (unchanged): every seq-to-seq drift is machine-readable.
      if (i > 0) {
        const prevR = ordered[i - 1]!;
        if (curT !== prevR.scope.tenant) {
          arrayPush(tenantDriftMessages, 
            `tenant-drift: seq ${prevR.chain.seq} ${describeTenant(prevR.scope.tenant)} -> seq ${curR.chain.seq} ${describeTenant(curT)}`,
          );
        }
      }
      if (curT === undefined) continue; // absence never resets the boundary, and is never fatal
      if (lastPresentTenant !== undefined && curT !== lastPresentTenant) {
        const msg = `tenant-drift: seq ${lastPresentSeq} ${describeTenant(lastPresentTenant)} -> seq ${curR.chain.seq} ${describeTenant(curT)}`;
        if (o.requireTenantConsistency ?? true) {
          return fail("TAMPERED", msg, chainId, list.length, curR.chain.seq);
        }
        // opt-out: the drift is reported, never silently dropped. Named against the last PRESENT
        // value so the message identifies the actual splice, not the omission that hid it.
        if (!arrayIncludes(tenantDriftMessages, msg)) arrayPush(tenantDriftMessages, msg);
      }
      lastPresentTenant = curT;
      lastPresentSeq = curR.chain.seq;
    }
  } catch {
    // Retained as a fail-closed backstop for OUR OWN code (a bug in a helper must still return
    // MALFORMED rather than throw out of a public API), no longer as a defence against a hostile
    // accessor: `receipts` is `safeParse` output and has none.
    return fail("MALFORMED", "input object threw during validation/ordering", null, n);
  }

  const haveKeyring = o.keyring !== undefined;
  // Fail-closed on a non-object keyring: the keyring is a trust input. A
  // null / array / non-object keyring is an operator error, not "an empty trust root" — silently treating it
  // as `{}` would index `keyring[kid]` to undefined → an unknown-kid TAMPERED, diverging from the Python
  // verifier (which already returns MALFORMED on a non-dict keyring). Reject it as MALFORMED so
  // both impls agree on the SAME verdict class for the SAME malformed trust file.
  let keyring: Keyring = {};
  let verification: ParsedVerificationKeyring | undefined;
  if (haveKeyring) {
    const kParsed = parseVerificationKeyring(o.keyring, "keyring");
    if (!kParsed.ok) return fail("MALFORMED", kParsed.reason, chainId, list.length);
    verification = kParsed.value;
    keyring = verification.keyring;
  }
  // PUBLISHED as an ordinary array (round-4, A1). `arraySlice` returns an INERT-rooted copy now, and
  // `warnings` is a documented field of a PUBLIC result object — shipping an array whose
  // `instanceof Array` is false and whose `deepStrictEqual` against a literal fails is a silent
  // backward-compatibility break for every consumer. The copy is still taken through the captured
  // `arraySlice` (no live iterator spread); only the prototype of the value handed to the caller is
  // restored. Caught by measuring the public array-returning surface rather than assuming it.
  const warnings: string[] = publishArray(arraySlice(tenantDriftMessages));

  // 4. Walk the chain: hash, key-pinning, signature, linkage, timestamp monotonicity.
  const pinnedKid = newMap<string, string>(); // agent.id -> kid (key continuity)
  let prev: Receipt | null = null;

  // Fail-closed backstop for our own helpers, not a hostile-accessor guard (see above).
  try {
  // Index walk, not `for…of` (2026-07-29): this is THE hash-integrity and signature loop. A
  // substituting iterator poison hands it a genuine receipt object in place of the forged one and
  // every cryptographic check below then passes on the wrong object. `ordered` is a real array
  // built by `arrayPush`, so an indexed read dispatches through nothing.
  for (let oi = 0; oi < ordered.length; oi++) {
    const r = ordered[oi] as Receipt;
    const seq = r.chain.seq;

    // 4a. Hash integrity.
    let hashInput: string;
    try {
      hashInput = receiptHashInput(r);
    } catch {
      // canonicalization refused the content (e.g. non-well-formed Unicode that slipped past
      // structural validation) — treat as malformed, never throw out of the public API.
      return fail("MALFORMED", "receipt contains non-canonicalizable content", chainId, list.length, seq);
    }
    const recomputed = "sha256:" + sha256Hex(hashInput);
    if (recomputed !== r.chain.hash) {
      return fail("TAMPERED", "hash mismatch (content altered)", chainId, list.length, seq);
    }

    // 4a-bis. NFC conformance of the payload strings. The profile requires PRODUCERS to emit NFC;
    // this package's builder now enforces that before signing. Here the finding is REPORTED, not
    // rejected, unless the caller opted in: already-issued receipts must keep verifying, and a
    // non-NFC string is a conformance defect in the producer, not evidence of tampering. Runs after
    // the hash check so a receipt that fails integrity is reported as TAMPERED (the more serious
    // verdict) rather than as a conformance nit.
    // `sig.kid` is included: it is a producer-chosen identifier string, subject to the same MUST as
    // every other string in the receipt, and it was omitted here for the same reason both builders
    // omitted it — the scan was written against the PAYLOAD and the kid lives beside it. A kid is
    // precisely a field relying parties match and index on, so two kids that render identically and
    // differ in bytes is the hazard, not a nit. `sig.value` and the `chain` hashes stay out: base64
    // and hex are ASCII by construction, so normalization cannot apply to them.
    // CAPTURED (2026-07-29, round-2, R3-04 second sink). This used a SPREAD (`[...nonNfcPaths(...)]`)
    // and `.join`/`for…of`, every one of which dispatches through `%ArrayIteratorPrototype%.next`: an
    // empty-iterator poison collapsed the spread so the offending path never reached the length gate
    // and the non-NFC receipt passed `requireNFC:true` as VALID. `nonNfcPaths` returns a fresh array
    // built with the captured `arrayPush`, so the kid is appended into it directly and it is walked by
    // index — no spread, no `for…of`, no live `.join`.
    const nonNfc = nonNfcPaths({
      id: r.id, ts: r.ts, scope: r.scope, agent: r.agent, action: r.action, governance: r.governance,
    });
    if (!isNFC(r.sig.kid)) arrayPush(nonNfc, "sig.kid");
    if (arrayLength(nonNfc) > 0) {
      if (o.requireNFC) {
        return fail("MALFORMED", `non-NFC string(s) at seq ${seq}: ${arrayJoin(nonNfc, ", ")}`, chainId, list.length, seq);
      }
      const wn = arrayLength(nonNfc);
      for (let wi = 0; wi < wn; wi++) arrayPush(warnings, `non-nfc: seq ${seq} field ${nonNfc[wi]}`);
    }

    // 4b. Key continuity per agent.id (rejects mid-chain key swap).
    const pinned = mapGet(pinnedKid, r.agent.id);
    if (pinned === undefined) mapSet(pinnedKid, r.agent.id, r.sig.kid);
    else if (pinned !== r.sig.kid) {
      return fail("TAMPERED", `key swap for agent "${r.agent.id}" (kid ${pinned} -> ${r.sig.kid})`, chainId, list.length, seq);
    }

    // 4c. Signature. With a keyring, an unknown kid is TAMPERED, not a soft pass.
    if (haveKeyring) {
      if (verification!.retiredKids[r.sig.kid] === true) {
        return fail(
          "TAMPERED",
          `signing key "${r.sig.kid}" is retired; signer-chosen receipt time is not an independent witness`,
          chainId,
          list.length,
          seq,
        );
      }
      const pub = keyring[r.sig.kid];
      if (!pub) return fail("TAMPERED", `unknown signing key "${r.sig.kid}" not in keyring`, chainId, list.length, seq);
      const ok = verifyEd25519(pub, signingMessage(RECEIPT_SIG_DOMAIN, hashInput), r.sig.value);
      if (!ok) return fail("TAMPERED", `invalid signature (kid ${r.sig.kid})`, chainId, list.length, seq);
    }

    // 4c-bis. Identity binding — ONLY meaningful once the signature is AUTHENTICATED (gated on
    // haveKeyring, mirroring spec §5b which runs after §5). Authenticating the signature proves "a
    // keyring-trusted key signed this"; this proves "that key is AUTHORIZED to speak for THIS agent.id".
    // An authenticated-but-unauthorized pairing is exactly cross-agent impersonation → reject as
    // UNTRUSTED (distinct from TAMPERED: bytes intact + key real, BINDING not). Without a keyring the
    // kid is unauthenticated, so an UNTRUSTED verdict would overclaim authentication never performed —
    // the result stays UNVERIFIED (with a warning) instead.
    if (haveKeyring && haveManifest) {
      // ── C-02(a) SINK, CLOSED ───────────────────────────────────────────────────────────────────
      // `allowed.includes(kid)` was an AUTHORIZATION decision that dispatched through the writable
      // `Array.prototype.includes`. `c02_includes425.mjs` reassigned it and turned an UNTRUSTED
      // cross-agent impersonation (agent.id "alice", signed by bob's key) into VALID with
      // signaturesVerified:true. `arrayIncludes` / `mapGet` go through captures taken at module load.
      const allowed = mapGet(manifest, r.agent.id);
      if (allowed === undefined || !arrayIncludes(allowed, r.sig.kid)) {
        return fail("UNTRUSTED", `agent "${r.agent.id}" is not authorized for signing key "${r.sig.kid}" (identity manifest)`, chainId, list.length, seq);
      }
    }

    // 4d. Linkage.
    if (seq === 0) {
      if (r.chain.prevHash !== null) return fail("TAMPERED", "genesis prevHash must be null", chainId, list.length, 0);
    } else if (r.chain.prevHash !== prev!.chain.hash) {
      return fail("TAMPERED", `broken linkage at seq ${seq}`, chainId, list.length, seq);
    }

    // 4e. Timestamp monotonicity (soft — clocks are not a security primitive, but a regression is suspicious).
    if (prev) {
      // PRISTINE TIME (review #6, C1): a monotonicity comparison is a verdict input, so it must not
      // dispatch through the globally-mutable `Date.parse`.
      const a = dateParse(prev.ts);
      const b = dateParse(r.ts);
      if (!isNaNValue(a) && !isNaNValue(b) && b < a) {
        arrayPush(warnings, `non-monotonic timestamp at seq ${seq} (ts went backwards)`);
      }
    }
    prev = r;
  }
  } catch {
    return fail("MALFORMED", "receipt object threw during chain walk", chainId, list.length);
  }

  // 5. Tail-truncation check (only possible with a checkpoint).
  const head = ordered[ordered.length - 1]!;
  let tailChecked = false;
  if (checkpointSnap !== undefined) {
    // A non-object checkpoint (null / array / primitive) is STRUCTURALLY malformed, not a "bad checkpoint
    // statement" → MALFORMED, mirroring the Python CLI. The Python _main guard returns MALFORMED
    // (exit 3) on a non-dict checkpoint BEFORE routing into _verify_checkpoint; the TS verifyChain used to route
    // it straight into verifyCheckpoint → "malformed checkpoint" → TAMPERED (exit 2), splitting the cross-impl
    // verdict on the SAME malformed input. Reject it here as MALFORMED so both impls agree. (`checkpoint:null`
    // already reached MALFORMED-class via this path historically; this makes array /
    // number / string explicit and canonical too.)
    if (typeof checkpointSnap !== "object" || checkpointSnap === null || isArray(checkpointSnap)) {
      return fail("MALFORMED", "checkpoint must be an object", chainId, list.length);
    }
    // ONE parsed checkpoint, read by every surface: `verifyCheckpointParsed` validates it and
    // reconstructs the signature pre-image from it, and the tail-match / §5b below re-read
    // cp.chain / highestSeq / headHash / sig.kid. Those used to be reads of a live caller object, so
    // a flipping accessor could present the legit head to the signature check and the truncated head
    // to the tail-match — VALID + tailChecked over an erased tail. Parsed bytes cannot differ
    // between two reads.
    const cp = checkpointSnap as Checkpoint;
    const cpVerify = verifyCheckpointParsed(cp, verification);
    if (cpVerify === "bad spec" || cpVerify === "malformed checkpoint") {
      return fail("TAMPERED", `checkpoint invalid: ${cpVerify}`, chainId, list.length);
    }
    // The checkpoint signature is held to the SAME trust root as receipts: with a keyring, a
    // checkpoint that is not authenticated (bad signature OR a kid not in the keyring) is
    // TAMPERED — never silently honored. Otherwise an attacker could mint their own key, drop
    // the tail, and forge a checkpoint over the truncated head (a trust-root bypass on the only
    // anti-truncation control). Mirrors the receipt unknown-kid rule above.
    if (haveKeyring && cpVerify !== "ok") {
      if (cpVerify === "retired signing key") {
        return fail(
          "TAMPERED",
          `checkpoint signing key "${cp.sig.kid}" is retired; signer-chosen checkpoint time is not an independent witness`,
          chainId,
          list.length,
          head.chain.seq,
        );
      }
      return fail("TAMPERED", `checkpoint not authenticated against keyring (${cpVerify})`, chainId, list.length);
    }
    if (cp.chain !== chainId) return fail("TAMPERED", "checkpoint chain mismatch", chainId, list.length);
    if (cp.highestSeq !== head.chain.seq || cp.headHash !== head.chain.hash) {
      return fail("TAMPERED", "chain head does not match checkpoint (tail truncated/extended)", chainId, list.length, head.chain.seq);
    }
    // 5b. Checkpoint IDENTITY binding (mirrors receipt 4c-bis). Without it, B1's per-agent authorization
    // would cover receipts but NOT the checkpoint — so a co-trusted-but-unauthorized key (authorized for
    // some OTHER agent) could truncate the tail and forge a checkpoint over the truncated head, defeating
    // the only offline anti-truncation control in exactly the multi-key deployment B1 hardens. When a
    // manifest is supplied (and the signature is authenticated), the checkpoint's kid MUST be authorized
    // for the chain's GENESIS agent.id — the chain OPENER — NOT the mutable head.
    //
    // The re-heading attack: a scope.chain is a SHARED partition with no opener/ownership binding, so any
    // co-trusted key holder can APPEND its own receipt onto a victim's prefix, BECOME the head, drop the
    // victim's incriminating tail, and forge a checkpoint over its OWN head. Binding the checkpoint to the
    // HEAD agent.id then "validated" the attacker against the attacker's own authorized id → VALID +
    // tailChecked while the victim's tail was silently erased. Binding to the GENESIS agent (ordered[0],
    // the receipt that opened the chain) closes this: the opener cannot be re-written by an appended tail,
    // so a re-heading attacker's checkpoint is checked against the OPENER's authorized kid (which the
    // attacker is not), → UNTRUSTED. This strictly subsumes plain head-binding:
    // when the opener also heads + checkpoints (the legit case) genesis == head, so a legitimately-opener-
    // signed checkpoint still passes; a foreign key forged over the opener's head is still rejected.
    if (haveKeyring && haveManifest) {
      const genesis = ordered[0]!;
      // Same sink, same closure: the checkpoint's opener-binding is an authorization decision.
      const allowed = mapGet(manifest, genesis.agent.id);
      if (allowed === undefined || !arrayIncludes(allowed, cp.sig.kid)) {
        return fail("UNTRUSTED", `checkpoint signing key "${cp.sig.kid}" is not authorized for chain opener (genesis) agent "${genesis.agent.id}" (identity manifest)`, chainId, list.length, head.chain.seq);
      }
      // The checkpoint authority is opener-scoped: it certifies the opener's view of the head, but a
      // co-agent's tail on the same shared chain is NOT separately certified by it. Surface that the
      // opener could still have dropped a co-agent's tail (the residual that needs the v1.0 anchor).
      const distinctAgents = newSet<string>();
      for (let ai = 0; ai < ordered.length; ai++) setAdd(distinctAgents, (ordered[ai] as Receipt).agent.id);
      if (setSize(distinctAgents) > 1) {
        arrayPush(warnings, "checkpoint completeness is opener-scoped: the chain has more than one agent.id, and a co-agent's tail is NOT separately certified by the opener's checkpoint (the opener dropping a co-agent's tail needs the v1.0 external anchor)");
      }
    }
    // tailChecked is true ONLY for an authenticated checkpoint — an unauthenticated head match
    // is not a tail check and must not be reported as one.
    tailChecked = cpVerify === "ok";
    if (cpVerify !== "ok") {
      arrayPush(warnings, "checkpoint present but not authenticated (no keyring) — tail NOT verified");
    } else if (!haveManifest) {
      // SCOPE OF `tailChecked` WITHOUT A MANIFEST (THREAT-MODEL.md T-tail-reheading). The §5b
      // genesis binding above is the control that ties checkpoint authority to the chain OPENER,
      // and it runs ONLY when an identityManifest is supplied. Without one, checkpoint
      // authentication is KID-LEVEL: *any* key in the keyring can mint a checkpoint over *any*
      // head, so a co-trusted key holder can drop the most-recent receipts, sign its own
      // checkpoint over the truncated head, and this function returns VALID with
      // `tailChecked: true`. That verdict is correct for what was actually checked, but
      // `tailChecked: true` is exactly the field a relying party reads as "the tail was
      // verified" — so the scope of that check has to travel WITH it, not only in the threat
      // model. The pre-existing no-manifest warning below states the ATTRIBUTION consequence
      // (which agent.id signed); this states the TRUNCATION consequence, which is the sharper
      // one and was previously unstated at runtime. Additive: no verdict, no tailChecked value,
      // and no existing warning changes.
      arrayPush(warnings, 
        "checkpoint authenticated but no identityManifest supplied: the tail check is KID-LEVEL — any keyring-trusted key can mint a checkpoint over any head, so a co-trusted key holder can truncate the tail and still produce tailChecked:true (supply an identityManifest to bind checkpoint authority to the chain opener)",
      );
    }
  } else {
    arrayPush(warnings, "no checkpoint supplied: tail-truncation (deleting most-recent receipts) cannot be detected offline");
  }

  // 6. Equivocation/fork is fundamentally undetectable offline from a single branch.
  arrayPush(warnings, "fork/equivocation is not detectable offline: this verifies the branch you were given, not that the signer signed no other history at the same seq (needs an external witness — v1.0)");

  if (!haveKeyring) {
    arrayPush(warnings, "no keyring supplied: signatures were NOT authenticated (status UNVERIFIED, not VALID)");
  }
  if (!haveManifest) {
    arrayPush(warnings, "no identityManifest supplied: attribution is kid-level — a VALID result proves a keyring-trusted key signed, NOT which agent.id (cross-agent impersonation undefended in a multi-key keyring)");
  } else if (!haveKeyring) {
    arrayPush(warnings, "identityManifest supplied but no keyring: identity NOT bound — signatures are unauthenticated, so the (agent.id, kid) pairing was not enforced (status stays UNVERIFIED, never UNTRUSTED)");
  }

  const status: VerifyStatus = haveKeyring ? "VALID" : "UNVERIFIED";
  // `signaturesVerified: haveKeyring` is EXACT here, not a proxy, and the invariant that makes it so
  // is worth stating because it is invisible from this line: loop 4c above has NO SKIP PATH. A
  // retired kid, an unknown kid and a bad signature each `return fail(...)`. So control cannot reach
  // this line with a keyring unless every receipt signature authenticated — `haveKeyring` and "every
  // signature verified" are the same fact at this point. If anyone ever adds a `continue` to that
  // loop, this line silently becomes a lie and the contract on `VerifyResult.signaturesVerified`
  // breaks with it.
  return { status, chain: chainId, count: list.length, signaturesVerified: haveKeyring, tailChecked, warnings };
}

/**
 * Verify a chain from its RAW JSON text, parsed by the hardened safeParse (duplicate-key /
 * __proto__ / float / depth / size / surrogate rejection). Prefer this over
 * `verifyChain(JSON.parse(text))` for untrusted input: the strict-parse guarantees are a
 * property of THIS entry point, not of a caller's own `JSON.parse` (which silently accepts
 * duplicate keys). Returns MALFORMED instead of throwing on bad input.
 */
export function verifyChainText(text: string, opts: VerifyOptions = {}): VerifyResult {
  // Now a pure alias: `verifyChain` accepts `string` as well as `Uint8Array`, and both route through
  // the same `parseDocument`. The two entry points can no longer disagree about what a valid
  // document is, which is the property the ADR's §2.3 probes falsified for the old pair — where
  // `verifyChainText` was documented as "the immune path" while forwarding into an object API that
  // was not immune at all.
  return verifyChain(text, opts);
}

type CheckpointVerdict = "ok" | "unverified" | "retired signing key" | "bad spec" | "malformed checkpoint" | "bad checkpoint signature";

// The allow-list a checkpoint's key set is decided against — a policy table, so it is built through
// `frozenTable`: deep-frozen, re-rooted onto the inert array prototype, and refused at construction
// if it ever contains anything mutable (ADR §5.6).
const CHECKPOINT_KEYS = frozenTable(["spec", "chain", "highestSeq", "headHash", "ts", "sig"]);
// Formats are decided by hand-written scanners (src/scan.ts), never by a RegExp: `RegExp.prototype.test`
// performs a dynamic `Get(re, "exec")`, so even a CAPTURED `test` dispatches through the writable
// `RegExp.prototype.exec` — reproduced in `c02_regexp_witness.mjs` against the captured wrapper.

/**
 * Verify a signed checkpoint from its BYTES, against a keyring supplied as BYTES.
 *
 * Both arguments are documents — a checkpoint is a signed trust statement and a keyring is a trust
 * root — so neither has an object form at this boundary. Review #6's C2 was precisely an asymmetry
 * here: the checkpoint was snapshotted and the keyring was not, so the trust root a signature was
 * judged against was a live read while its subject was inert. Bytes make the asymmetry
 * unrepresentable rather than merely fixed.
 */
export function verifyCheckpoint(cp: Uint8Array | string, keyring?: Uint8Array | string): CheckpointVerdict {
  const cpParsed = parseDocument(cp, "checkpoint");
  if (!cpParsed.ok) return "malformed checkpoint";
  let verification: ParsedVerificationKeyring | undefined;
  if (keyring !== undefined) {
    const kParsed = parseVerificationKeyring(keyring, "keyring");
    if (!kParsed.ok) return "malformed checkpoint";
    verification = kParsed.value;
  }
  return verifyCheckpointParsed(cpParsed.value as Checkpoint, verification);
}

/**
 * The checkpoint verifier over PARSED data. Module-private: it assumes `safeParse` output, which is
 * what the bytes boundary above guarantees, and `verifyParsedChain` reuses it with the SAME parsed
 * keyring it authenticates receipts against.
 */
function verifyCheckpointParsed(cp: Checkpoint, verification?: ParsedVerificationKeyring): CheckpointVerdict {
  const snap = cp as unknown as Record<string, unknown>;
  // STRICT, FAIL-CLOSED structural validation: a checkpoint is a SIGNED trust statement, so it
  // gets the same discipline as a receipt — null/non-object, unknown fields (additionalProperties:false,
  // threat-model T9 "no smuggled field at any level"), and bad-typed/format fields are MALFORMED. Never a
  // raw throw (verifyCheckpoint(null) used to TypeError), never silently honored.
  const c = snap;
  if (typeof c !== "object" || c === null || isArray(c)) return "malformed checkpoint";
  // INDEX WALK (round-4, A2). This closed-schema walk is the ONLY control that rejects a checkpoint
  // carrying a smuggled field — the smuggled field is covered by the signature (`checkpointHashInput`
  // copies every own key), so re-signing keeps the signature honest and this loop is what stands in
  // the way. Measured before the fix: a skipping iterator hid `extraSmuggled` + `extraSigField` and
  // `TAMPERED` became `VALID` with `tailChecked:true` (2 poison hits).
  const cKeys = objectKeys(c);
  for (let i = 0; i < cKeys.length; i++) {
    if (!arrayIncludes(CHECKPOINT_KEYS, cKeys[i] as string)) return "malformed checkpoint";
  }
  if (c.spec !== "noa.checkpoint/0.1") return "bad spec";
  if (typeof c.chain !== "string" || c.chain.length === 0) return "malformed checkpoint";
  if (typeof c.highestSeq !== "number" || !isSafeInteger(c.highestSeq) || c.highestSeq < 0) return "malformed checkpoint";
  if (typeof c.headHash !== "string" || !isSha256Hash(c.headHash)) return "malformed checkpoint";
  if (typeof c.ts !== "string" || !isRfc3339Instant(c.ts)) return "malformed checkpoint";
  const sig = c.sig as Record<string, unknown> | undefined;
  // sig sub-object is ALSO strict (top-level strictness alone isn't enough): exactly
  // {alg,kid,value}, alg="ed25519" — closes a smuggled-field channel inside the SIGNED surface + an
  // unvalidated alg, symmetric with the receipt sig discipline (schema.ts).
  if (!sig || typeof sig !== "object" || isArray(sig)) return "malformed checkpoint";
  const sigKeys = objectKeys(sig);
  for (let i = 0; i < sigKeys.length; i++) { const k = sigKeys[i] as string; if (k !== "alg" && k !== "kid" && k !== "value") return "malformed checkpoint"; }
  if (sig.alg !== "ed25519") return "malformed checkpoint";
  if (typeof sig.kid !== "string" || sig.kid.length === 0 || typeof sig.value !== "string" || sig.value.length === 0) {
    return "malformed checkpoint";
  }
  if (verification?.retiredKids[sig.kid] === true) return "retired signing key";
  const pub = verification?.keyring[sig.kid];
  if (!pub) return "unverified";
  let msg: Buffer;
  try {
    // Hash the SNAPSHOT, not the live `cp` — same bytes the validation above accepted.
    msg = signingMessage(CHECKPOINT_SIG_DOMAIN, checkpointHashInput(snap as unknown as Checkpoint));
  } catch {
    return "malformed checkpoint";
  }
  const ok = verifyEd25519(pub, msg, sig.value);
  return ok ? "ok" : "bad checkpoint signature";
}
