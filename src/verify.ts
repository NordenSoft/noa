import type { Receipt, Checkpoint } from "./types.js";
import { validateReceiptShape } from "./schema.js";
import { receiptHashInput, checkpointHashInput } from "./canonicalize.js";
import { sha256Hex } from "./hash.js";
import { verifyEd25519, type Keyring, type IdentityManifest } from "./keys.js";
import { signingMessage, RECEIPT_SIG_DOMAIN, CHECKPOINT_SIG_DOMAIN } from "./signing.js";
import { safeParse } from "./safe-json.js";

export type VerifyStatus =
  | "VALID" // structure + hash-chain + signatures all verified against the supplied keyring
  | "UNVERIFIED" // hash-chain ok, but NO keyring supplied so signatures were not authenticated
  | "UNTRUSTED" // signature authenticated, but the (agent.id, sig.kid) pairing is NOT authorized by the supplied identity manifest (cross-agent impersonation)
  | "TAMPERED" // an integrity check failed (incl. an unknown signing key when a keyring IS supplied)
  | "MALFORMED"; // not a well-formed receipt chain

export interface VerifyOptions {
  /** Trust root: kid -> base64 SPKI public key. Supply it to authenticate signatures. */
  keyring?: Keyring;
  /** Signed checkpoint asserting the expected head — enables tail-truncation detection. */
  checkpoint?: Checkpoint;
  /** Hard cap on receipts processed (DoS bound). */
  maxReceipts?: number;
  /**
   * Optional `agent.id -> authorized kid(s)` binding (a trust input, like the keyring). When supplied,
   * a receipt whose `(agent.id, sig.kid)` pairing is not authorized is rejected as UNTRUSTED — this is
   * what makes a VALID result mean "THIS agent.id signed", not just "a keyring-trusted key signed".
   * Omit it to keep kid-level attribution (the weaker, documented guarantee).
   */
  identityManifest?: IdentityManifest;
  /**
   * Opt-in fail-closed enforcement of chain-wide `scope.tenant` consistency (A1 hardening; additive,
   * default false — existing callers see no verdict change). By DEFAULT, a `scope.tenant` that drifts
   * (or appears on some receipts and not others) across one `scope.chain` is only reported in
   * `warnings` and the verdict is unaffected (VALID stays VALID) — this is the pre-existing,
   * THREAT-MODEL-documented "namespace binding is the caller's responsibility" posture. Set this to
   * `true` to instead reject the FIRST drift as `TAMPERED` (the same verdict class already used for a
   * `scope.chain` partition split — see the chain-partition check above — since a drifting `tenant` is
   * the identical class of problem: a scope field the caller assumed was chain-wide-constant, isn't).
   */
  requireTenantConsistency?: boolean;
}

export interface VerifyResult {
  status: VerifyStatus;
  chain: string | null;
  count: number;
  signaturesVerified: boolean;
  tailChecked: boolean;
  badSeq?: number;
  reason?: string;
  warnings: string[];
}

const DEFAULT_MAX_RECEIPTS = 1_000_000;

function fail(
  status: VerifyStatus,
  reason: string,
  chain: string | null,
  count: number,
  badSeq?: number,
): VerifyResult {
  const r: VerifyResult = { status, chain, count, signaturesVerified: false, tailChecked: false, reason, warnings: [] };
  if (badSeq !== undefined) r.badSeq = badSeq;
  return r;
}

/** Human/machine-readable label for a `scope.tenant` value in a drift message: quoted string, or `(none)`. */
function describeTenant(t: string | undefined): string {
  return t === undefined ? "(none)" : JSON.stringify(t);
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
 *  - TENANT CONSISTENCY (A1 hardening): `scope.tenant` is NOT enforced chain-wide the way
 *    `scope.chain` is — a caller mixing receipts from different tenants under one chain still
 *    gets VALID by default; the drift is reported in `warnings` (machine-readable
 *    `tenant-drift: seq A "x" -> seq B "y"` entries). Set `requireTenantConsistency: true` to
 *    reject the first drift as TAMPERED instead.
 */
export function verifyChain(receipts: unknown, opts: VerifyOptions = {}): VerifyResult {
  // SNAPSHOT THE ENTIRE opts ONCE (round-17 #2/#4 — class-killer). Every opts.* field (maxReceipts, keyring,
  // checkpoint, identityManifest) is caller-supplied and was read directly off the LIVE `opts` at scattered
  // points: a throwing/Proxy getter (e.g. `get maxReceipts(){throw}`) OR a non-cloneable / Symbol-typed value
  // escaped as a RAW TypeError, violating the "never throws" public-API contract (and verifyChainText forwards
  // opts, inheriting the throw). structuredClone deep-copies opts ONCE into plain, accessor-free data — firing
  // every getter exactly once and throwing on a non-cloneable value (Symbol, function, etc.) → MALFORMED. A
  // null/undefined opts normalizes to `{}` (a default-param only fills a MISSING arg, not an explicit null).
  // EVERYTHING downstream reads ONLY from `o`, never the live `opts`, so no hostile accessor can split a
  // validate-then-enforce window or leak a throw. (verifyChainText/CLI/Python consume parse output — no
  // accessors — so are immune; this guards the in-process object API.)
  let o: VerifyOptions;
  try {
    o = (opts === null || opts === undefined) ? {} : structuredClone(opts);
  } catch {
    return fail("MALFORMED", "options not structured-cloneable (hostile accessor / non-cloneable value)", null, 0);
  }
  const maxReceipts = o.maxReceipts ?? DEFAULT_MAX_RECEIPTS;

  if (!Array.isArray(receipts)) return fail("MALFORMED", "input is not an array of receipts", null, 0);
  // Read receipts.length ONCE behind a guard, BEFORE the structuredClone snapshot below (round-18 #3). These
  // early length/maxReceipts bounds run on the LIVE caller array, so an array-like with a hostile `length`
  // getter (`get length(){ throw }`) would escape as a RAW Error here — violating the "never throws" public-API
  // contract — before the snapshot could neutralize it. Capturing it in try/catch (and keeping the bounds reading
  // this one captured value) preserves the "don't clone a >maxReceipts array" DoS optimization while staying
  // fail-closed. (verifyChainText/CLI/Python consume parse output — no accessors — so are immune.)
  let n: number;
  try {
    n = receipts.length;
  } catch {
    return fail("MALFORMED", "input array length is not readable (hostile accessor)", null, 0);
  }
  if (n === 0) return fail("MALFORMED", "empty receipt array", null, 0);
  if (n > maxReceipts) return fail("MALFORMED", `too many receipts (>${maxReceipts})`, null, n);

  // SNAPSHOT-ONCE the caller-supplied LIVE receipts array (round-15 #2 HIGH / #5 MEDIUM / #9 LOW). The
  // in-process JS API reads the same object multiple times — receipts in structural validation AND in the
  // chain walk (4b/4c/4c-bis re-read r.agent.id / r.sig.kid → #9). A flipping accessor that returns one value
  // to authentication and another to enforcement splits the two, e.g. authenticating the legit head but
  // enforcing a truncated one → VALID+tailChecked over an erased tail. structuredClone deep-copies to plain,
  // accessor-free data ONCE (here, AFTER the length check so we never clone a >maxReceipts array), and
  // EVERYTHING downstream reads only the clone — closing every TOCTOU window at the root. structuredClone also
  // throws on non-cloneable input (functions, etc.) → MALFORMED. (The checkpoint/keyring/identityManifest are
  // ALREADY accessor-free here: `o` is a deep structuredClone of opts — round-17 #2 — so they need no separate
  // clone. verifyChainText/CLI/Python are immune — they consume safeParse/JSON.parse output with no accessors.)
  let receiptsSnap: unknown[];
  try {
    receiptsSnap = structuredClone(receipts);
  } catch {
    return fail("MALFORMED", "input is not structured-cloneable (live accessor/non-cloneable value)", null, n);
  }
  const checkpointSnap: Checkpoint | undefined = o.checkpoint;

  // Validate the optional identity manifest (a trust input) AND SNAPSHOT it. Fail-closed: a malformed
  // manifest is an operator error, never silently ignored (that would re-open the very impersonation gap
  // it closes).
  //
  // TOCTOU (round-11 HIGH): read once here (validation) and again at every enforcement point. (round-17 #2:
  // `o.identityManifest` is already an accessor-free deep clone of opts.identityManifest, so the live-flipping
  // window is closed at the opts snapshot; the per-entry Map copy below is retained for defense-in-depth and so
  // a re-implementer reproduces the invariant.) Read each entry EXACTLY ONCE into a plain Map, copying the
  // array with Array.prototype.slice.call (capturing element VALUES at copy time), validate the COPY, then have
  // ALL enforcement points read ONLY from this snapshot — never the live manifest. (CLI/Python are immune: they
  // consume JSON.parse output, which has no accessors.)
  const haveManifest = o.identityManifest !== undefined;
  const manifest = new Map<string, string[]>();
  // ROBUSTNESS (round-13 #8): the manifest, the array elements, and receipt fields below are all
  // caller-supplied LIVE objects. A throwing/side-effecting accessor must yield MALFORMED, never escape
  // as a raw throw. (verifyChainText/CLI/Python are immune — parse output has no accessors.) The chain
  // walk further down has its own guard; this one covers manifest validation + structural/partition/seq.
  let list!: Receipt[];
  let chainId!: string;
  let ordered!: Receipt[];
  const tenantDriftMessages: string[] = [];
  try {
    if (haveManifest) {
      const live = o.identityManifest;
      if (typeof live !== "object" || live === null || Array.isArray(live)) {
        return fail("MALFORMED", "identityManifest must be an object (agent.id -> kid[])", null, 0);
      }
      // Validate over the SAME own-property view the enforcement points read (own names — includes
      // NON-ENUMERABLE own props). Object.entries() only sees enumerable own props, so a non-enumerable
      // own entry would escape validation yet authorize a binding.
      for (const aid of Object.getOwnPropertyNames(live)) {
        const kidsLive = (live as Record<string, unknown>)[aid]; // ONE read of the entry (fires an entry getter once)
        if (!Array.isArray(kidsLive)) {
          return fail("MALFORMED", `identityManifest["${aid}"] must be an array of kid strings`, null, 0);
        }
        // Copy by VALUE: slice materializes each element once. A later read of the live array (or its
        // element getters) cannot change what we validated/enforce against.
        const kids = Array.prototype.slice.call(kidsLive) as unknown[];
        if (!kids.every((k) => typeof k === "string")) {
          return fail("MALFORMED", `identityManifest["${aid}"] must be an array of kid strings`, null, 0);
        }
        manifest.set(aid, kids as string[]);
      }
    }

    // 1. Structural validation of every element (runs BEFORE any hashing). Reads the SNAPSHOT, not the
    // live array — downstream (walk/tail-match/§5b) reads the same snapshot, so what we validate is exactly
    // what we enforce (round-15 #2/#9: closes the live-object TOCTOU at the root).
    for (let idx = 0; idx < receiptsSnap.length; idx++) {
      const res = validateReceiptShape(receiptsSnap[idx]);
      if (!res.ok) {
        return fail("MALFORMED", `receipt[${idx}]: ${res.errors.join("; ")}`, null, receiptsSnap.length, idx);
      }
    }
    list = receiptsSnap as Receipt[];

    // 2. Single chain partition.
    chainId = list[0]!.scope.chain;
    for (const r of list) {
      if (r.scope.chain !== chainId) {
        return fail("TAMPERED", "multiple chain partitions in one input", chainId, list.length);
      }
    }

    // 3. Order by seq; require contiguous 0..n-1, unique.
    const bySeq = new Map<number, Receipt>();
    for (const r of list) {
      if (bySeq.has(r.chain.seq)) return fail("TAMPERED", `duplicate seq ${r.chain.seq}`, chainId, list.length, r.chain.seq);
      bySeq.set(r.chain.seq, r);
    }
    ordered = [];
    for (let s = 0; s < list.length; s++) {
      const r = bySeq.get(s);
      if (!r) return fail("TAMPERED", `seq gap: missing seq ${s}`, chainId, list.length, s);
      ordered.push(r);
    }

    // 3b. Chain-wide tenant-consistency scan (A1 hardening — THREAT-MODEL.md "namespace / context
    // binding"). scope.tenant is a sibling of scope.chain in ReceiptScope but, unlike scope.chain, is
    // NOT enforced structurally: nothing today stops one scope.chain from carrying receipts for
    // DIFFERENT scope.tenant values (or some receipts with a tenant and some without) — a caller who
    // assumes tenant isolation follows chain isolation would get a silent VALID over a mixed-tenant
    // chain. This walks `ordered` (seq-order, already validated/contiguous) once and records every
    // seq-to-seq drift as a machine-readable message; by default these ONLY land in `warnings` below
    // (additive, verdict unaffected). `requireTenantConsistency: true` escalates the FIRST drift to
    // TAMPERED — the same verdict class as the `scope.chain` partition-split check in step 2, since
    // this is the identical class of problem for the sibling scope field.
    for (let i = 1; i < ordered.length; i++) {
      const prevR = ordered[i - 1]!;
      const curR = ordered[i]!;
      if (curR.scope.tenant !== prevR.scope.tenant) {
        const msg = `tenant-drift: seq ${prevR.chain.seq} ${describeTenant(prevR.scope.tenant)} -> seq ${curR.chain.seq} ${describeTenant(curR.scope.tenant)}`;
        tenantDriftMessages.push(msg);
        if (o.requireTenantConsistency) {
          return fail("TAMPERED", msg, chainId, list.length, curR.chain.seq);
        }
      }
    }
  } catch {
    return fail("MALFORMED", "input object threw during validation/ordering", null, receipts.length);
  }

  const haveKeyring = o.keyring !== undefined;
  // Fail-closed on a non-object keyring (round-15 #7): the keyring is a trust input (kid -> base64 SPKI). A
  // null / array / non-object keyring is an operator error, not "an empty trust root" — silently treating it
  // as `{}` would index `keyring[kid]` to undefined → an unknown-kid TAMPERED, diverging from the Python
  // verifier (which already returns MALFORMED on a non-dict keyring, round-13 #6). Reject it as MALFORMED so
  // both impls agree on the SAME verdict class for the SAME malformed trust file.
  if (haveKeyring && (typeof o.keyring !== "object" || o.keyring === null || Array.isArray(o.keyring))) {
    return fail("MALFORMED", "keyring must be an object (kid -> base64 SPKI)", chainId, list.length);
  }
  // The keyring is read by TWO authenticated surfaces — the chain walk (`keyring[r.sig.kid]`) AND
  // verifyCheckpoint(cp, keyring) — so both MUST see the SAME accessor-free bytes (round-16 #1 HIGH: a flipping
  // `keyring[kid]` getter could give the REAL pubkey to the walk and an ATTACKER pubkey to the checkpoint check
  // → VALID+tailChecked over an erased tail). `o.keyring` is already a deep structuredClone of opts (round-17
  // #2), so it is accessor-free and shared by both surfaces — no separate clone needed; the non-object guard
  // above runs first, so a non-cloneable keyring already failed at the opts snapshot → MALFORMED.
  const keyring: Keyring = o.keyring === undefined ? {} : o.keyring;
  const warnings: string[] = [...tenantDriftMessages];

  // 4. Walk the chain: hash, key-pinning, signature, linkage, timestamp monotonicity.
  const pinnedKid = new Map<string, string>(); // agent.id -> kid (key continuity)
  let prev: Receipt | null = null;

  // Robustness (round-12): a caller-supplied LIVE receipt object with a throwing/side-effecting accessor
  // must yield MALFORMED, never escape as a raw throw. verifyChainText/CLI/Python are immune (they consume
  // safeParse/JSON.parse output, which has no accessors); this guards the direct verifyChain(object) path.
  try {
  for (const r of ordered) {
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

    // 4b. Key continuity per agent.id (rejects mid-chain key swap).
    const pinned = pinnedKid.get(r.agent.id);
    if (pinned === undefined) pinnedKid.set(r.agent.id, r.sig.kid);
    else if (pinned !== r.sig.kid) {
      return fail("TAMPERED", `key swap for agent "${r.agent.id}" (kid ${pinned} -> ${r.sig.kid})`, chainId, list.length, seq);
    }

    // 4c. Signature. With a keyring, an unknown kid is TAMPERED, not a soft pass.
    if (haveKeyring) {
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
      const allowed = manifest.get(r.agent.id); // snapshot read — immune to live-object TOCTOU
      if (allowed === undefined || !allowed.includes(r.sig.kid)) {
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
      const a = Date.parse(prev.ts);
      const b = Date.parse(r.ts);
      if (!Number.isNaN(a) && !Number.isNaN(b) && b < a) {
        warnings.push(`non-monotonic timestamp at seq ${seq} (ts went backwards)`);
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
    // statement" → MALFORMED, mirroring the Python CLI (round-17 #3). The Python _main guard returns MALFORMED
    // (exit 3) on a non-dict checkpoint BEFORE routing into _verify_checkpoint; the TS verifyChain used to route
    // it straight into verifyCheckpoint → "malformed checkpoint" → TAMPERED (exit 2), splitting the cross-impl
    // verdict on the SAME malformed input. Reject it here as MALFORMED so both impls agree. (`checkpoint:null`
    // already reached MALFORMED-class via this path historically per the round-15 test; this makes array /
    // number / string explicit and canonical too.)
    if (typeof checkpointSnap !== "object" || checkpointSnap === null || Array.isArray(checkpointSnap)) {
      return fail("MALFORMED", "checkpoint must be an object", chainId, list.length);
    }
    // Read the cloned checkpoint EVERYWHERE (round-15 #2 HIGH): verifyCheckpoint validates + reconstructs the
    // sig-preimage from it, and the tail-match / §5b below re-read cp.chain/highestSeq/headHash/sig.kid. A
    // flipping accessor on the live checkpoint could present the legit head to the signature check and the
    // truncated head to the tail-match → VALID+tailChecked over an erased tail. The snapshot makes both reads
    // see identical, accessor-free bytes.
    const cp = checkpointSnap;
    // Pass the SNAPSHOT keyring (round-16 #1 HIGH), NOT opts.keyring — both this checkpoint authentication and
    // the receipt walk above read the SAME read-once trust root, so a flipping keyring cannot split them.
    const cpVerify = verifyCheckpoint(cp, keyring);
    if (cpVerify === "bad spec" || cpVerify === "malformed checkpoint") {
      return fail("TAMPERED", `checkpoint invalid: ${cpVerify}`, chainId, list.length);
    }
    // The checkpoint signature is held to the SAME trust root as receipts: with a keyring, a
    // checkpoint that is not authenticated (bad signature OR a kid not in the keyring) is
    // TAMPERED — never silently honored. Otherwise an attacker could mint their own key, drop
    // the tail, and forge a checkpoint over the truncated head (a trust-root bypass on the only
    // anti-truncation control). Mirrors the receipt unknown-kid rule above.
    if (haveKeyring && cpVerify !== "ok") {
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
    // Round-10 audit: a scope.chain is a SHARED partition with no opener/ownership binding, so any
    // co-trusted key holder can APPEND its own receipt onto a victim's prefix, BECOME the head, drop the
    // victim's incriminating tail, and forge a checkpoint over its OWN head. Binding the checkpoint to the
    // HEAD agent.id then "validated" the attacker against the attacker's own authorized id → VALID +
    // tailChecked while the victim's tail was silently erased. Binding to the GENESIS agent (ordered[0],
    // the receipt that opened the chain) closes this: the opener cannot be re-written by an appended tail,
    // so a re-heading attacker's checkpoint is checked against the OPENER's authorized kid (which the
    // attacker is not), → UNTRUSTED. This strictly subsumes the old head-binding for the round-7 cases:
    // when the opener also heads + checkpoints (the legit case) genesis == head, so a legitimately-opener-
    // signed checkpoint still passes; a foreign key forged over the opener's head is still rejected.
    if (haveKeyring && haveManifest) {
      const genesis = ordered[0]!;
      const allowed = manifest.get(genesis.agent.id); // snapshot read — immune to live-object TOCTOU
      if (allowed === undefined || !allowed.includes(cp.sig.kid)) {
        return fail("UNTRUSTED", `checkpoint signing key "${cp.sig.kid}" is not authorized for chain opener (genesis) agent "${genesis.agent.id}" (identity manifest)`, chainId, list.length, head.chain.seq);
      }
      // The checkpoint authority is opener-scoped: it certifies the opener's view of the head, but a
      // co-agent's tail on the same shared chain is NOT separately certified by it. Surface that the
      // opener could still have dropped a co-agent's tail (the residual that needs the v1.0 anchor).
      const distinctAgents = new Set(ordered.map((r) => r.agent.id));
      if (distinctAgents.size > 1) {
        warnings.push("checkpoint completeness is opener-scoped: the chain has more than one agent.id, and a co-agent's tail is NOT separately certified by the opener's checkpoint (the opener dropping a co-agent's tail needs the v1.0 external anchor)");
      }
    }
    // tailChecked is true ONLY for an authenticated checkpoint — an unauthenticated head match
    // is not a tail check and must not be reported as one.
    tailChecked = cpVerify === "ok";
    if (cpVerify !== "ok") {
      warnings.push("checkpoint present but not authenticated (no keyring) — tail NOT verified");
    }
  } else {
    warnings.push("no checkpoint supplied: tail-truncation (deleting most-recent receipts) cannot be detected offline");
  }

  // 6. Equivocation/fork is fundamentally undetectable offline from a single branch.
  warnings.push("fork/equivocation is not detectable offline: this verifies the branch you were given, not that the signer signed no other history at the same seq (needs an external witness — v1.0)");

  if (!haveKeyring) {
    warnings.push("no keyring supplied: signatures were NOT authenticated (status UNVERIFIED, not VALID)");
  }
  if (!haveManifest) {
    warnings.push("no identityManifest supplied: attribution is kid-level — a VALID result proves a keyring-trusted key signed, NOT which agent.id (cross-agent impersonation undefended in a multi-key keyring)");
  } else if (!haveKeyring) {
    warnings.push("identityManifest supplied but no keyring: identity NOT bound — signatures are unauthenticated, so the (agent.id, kid) pairing was not enforced (status stays UNVERIFIED, never UNTRUSTED)");
  }

  const status: VerifyStatus = haveKeyring ? "VALID" : "UNVERIFIED";
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
  let parsed: unknown;
  try {
    parsed = safeParse(text);
  } catch (e) {
    return { status: "MALFORMED", chain: null, count: 0, signaturesVerified: false, tailChecked: false, reason: (e as Error).message, warnings: [] };
  }
  return verifyChain(parsed, opts);
}

type CheckpointVerdict = "ok" | "unverified" | "bad spec" | "malformed checkpoint" | "bad checkpoint signature";

const CHECKPOINT_KEYS = ["spec", "chain", "highestSeq", "headHash", "ts", "sig"];
const CP_HASH_RE = /^sha256:[0-9a-f]{64}$/;
// RFC 3339 (lowercase t/z accepted), matching schema.ts RFC3339_RE.
const CP_RFC3339_RE = /^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(\.\d{1,9})?([Zz]|[+-]\d{2}:\d{2})$/;

export function verifyCheckpoint(cp: Checkpoint, keyring?: Keyring): CheckpointVerdict {
  // SNAPSHOT-ONCE the caller-supplied LIVE checkpoint (round-15 #5 MEDIUM). This is a public export called
  // directly too, so a throwing/flipping accessor on `cp` must yield "malformed checkpoint", never escape as
  // a RAW Error (violating the "never throws / fail-closed" invariant) and never split validation from the
  // sig-preimage read below (checkpointHashInput). structuredClone deep-copies to plain, accessor-free data
  // ONCE; every read below uses the clone. (verifyChain already passes its own clone; this guards direct use.)
  let snap: Record<string, unknown>;
  try {
    snap = structuredClone(cp) as unknown as Record<string, unknown>;
  } catch {
    return "malformed checkpoint";
  }
  // STRICT, FAIL-CLOSED structural validation (round-12): a checkpoint is a SIGNED trust statement, so it
  // gets the same discipline as a receipt — null/non-object, unknown fields (additionalProperties:false,
  // threat-model T9 "no smuggled field at any level"), and bad-typed/format fields are MALFORMED. Never a
  // raw throw (round-12 #9: verifyCheckpoint(null) used to TypeError), never silently honored.
  const c = snap;
  if (typeof c !== "object" || c === null || Array.isArray(c)) return "malformed checkpoint";
  for (const k of Object.keys(c)) {
    if (!CHECKPOINT_KEYS.includes(k)) return "malformed checkpoint";
  }
  if (c.spec !== "noa.checkpoint/0.1") return "bad spec";
  if (typeof c.chain !== "string" || c.chain.length === 0) return "malformed checkpoint";
  if (typeof c.highestSeq !== "number" || !Number.isSafeInteger(c.highestSeq) || c.highestSeq < 0) return "malformed checkpoint";
  if (typeof c.headHash !== "string" || !CP_HASH_RE.test(c.headHash)) return "malformed checkpoint";
  if (typeof c.ts !== "string" || !CP_RFC3339_RE.test(c.ts)) return "malformed checkpoint";
  const sig = c.sig as Record<string, unknown> | undefined;
  // sig sub-object is ALSO strict (round-12 #11 only covered the top level; round-13 #4): exactly
  // {alg,kid,value}, alg="ed25519" — closes a smuggled-field channel inside the SIGNED surface + an
  // unvalidated alg, symmetric with the receipt sig discipline (schema.ts).
  if (!sig || typeof sig !== "object" || Array.isArray(sig)) return "malformed checkpoint";
  for (const k of Object.keys(sig)) { if (k !== "alg" && k !== "kid" && k !== "value") return "malformed checkpoint"; }
  if (sig.alg !== "ed25519") return "malformed checkpoint";
  if (typeof sig.kid !== "string" || sig.kid.length === 0 || typeof sig.value !== "string" || sig.value.length === 0) {
    return "malformed checkpoint";
  }
  const pub = keyring?.[sig.kid];
  if (!pub) return "unverified";
  let msg: Buffer;
  try {
    // Hash the SNAPSHOT (round-15 #5), not the live `cp` — same bytes the validation above accepted.
    msg = signingMessage(CHECKPOINT_SIG_DOMAIN, checkpointHashInput(snap as unknown as Checkpoint));
  } catch {
    return "malformed checkpoint";
  }
  const ok = verifyEd25519(pub, msg, sig.value);
  return ok ? "ok" : "bad checkpoint signature";
}
