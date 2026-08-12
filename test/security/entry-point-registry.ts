/**
 * THE ENTRY-POINT REGISTRY — every exported function of every package entry point, classified.
 *
 * WHY A REGISTRY AND NOT SIX MORE FIXES. Review #2 closed a mechanism. Review #3 found the same class
 * through a different mechanism. Review #4, #5 and #6 did it again — and #6's C2 was literally "the
 * fourth entry point exists, and a fifth". Routing the entry points a reviewer happened to reproduce
 * is not a fix; it is a queue. The reviewer's own words: *a test that fails when a new export takes
 * attacker input without ingesting is worth more than six fixes.*
 *
 * WHAT THIS IS. Every function reachable from a package's `exports` map is listed here with a
 * CLASSIFICATION. `entry-point-coverage.test.ts` enumerates the real exports at runtime and fails if:
 *   • an export exists that is not listed here (a NEW export cannot be added silently); or
 *   • a listed export no longer exists (the registry cannot rot); or
 *   • an export classified `ingests` fails its live probe.
 *
 * THE PROBES ARE DYNAMIC, NOT DECLARATIVE. `bytes-in` is not a promise, it is measured. For each such
 * export the coverage test calls it with an argument carrying a COUNTING GETTER and asserts the getter
 * fired **ZERO** times, and calls it again with an argument whose getter throws a REVOKED PROXY and
 * asserts nothing escapes as a raw `TypeError`. A classification that has stopped being true fails.
 *
 * ── THE THRESHOLD MOVED FROM "AT MOST ONCE" TO "ZERO" (2026-07-28) ──────────────────────────────
 * The old class was `ingests` and the old assertion was `reads <= 1`, because the old boundary
 * TRAVERSED a caller object exactly once and the defect being measured was a SECOND, disagreeing
 * read. One read was the best that design could do — reading a live object at all gives the attacker
 * a turn, and the whole of ADR §2.3 is about that turn being the route by which untrusted data
 * executes code.
 *
 * Bytes-in removes the turn. A security-sensitive entry point now takes `Uint8Array | string`, so a
 * caller-owned object is REFUSED at the boundary and its getters never run. The probe threshold is
 * therefore ZERO, and a single fire is a finding — it would mean some path still traverses. Leaving
 * the assertion at `<= 1` would have kept a passing test that no longer measured the property the
 * migration bought.
 *
 * THE CLASSES:
 *   bytes-in       — a security-sensitive entry point taking `Uint8Array | string`. Probed: a caller
 *                    object must be refused with the hostile getter firing ZERO times.
 *   dataless       — every parameter is a primitive / Buffer / absent. Nothing to flip.
 *   producer-inert — takes caller data, and its OUTPUT is not a security verdict; it either signs
 *                    from a snapshot or its result is re-verified downstream before anyone acts on
 *                    it. Requires `why`.
 *   caller-owned   — the parameter is the CALLER'S OWN configuration (its keyring, its store, its
 *                    transport), not evidence supplied by the party being judged. An attacker who
 *                    controls it has already replaced the verifier. Requires `why`.
 *   unrouted       — takes hostile-capable data and does NOT ingest. Every entry here is an OPEN
 *                    FINDING with an owner, not an exemption; `why` must say what it would take.
 *                    The test prints them as a standing report so the count can only go down.
 *
 * ── WHAT A GREEN REGISTRY DOES AND DOES NOT MEAN (added 2026-07-30) ─────────────────────────────
 * ADR-0002 §3 (ratified 2026-07-29) required this correction on four surfaces. `README.md`,
 * `THREAT-MODEL.md` and `NON-CLAIMS.md` got it the same day. THIS FILE — named in that list — did
 * not, and the omission mattered in a specific way: everything above reads like a proof. A class
 * called `bytes-in`, a probe that fires ZERO times, a count that can only go down. A reader who does
 * not already know the architecture would reasonably conclude the registry demonstrates that hostile
 * input cannot reach a decision. It does not.
 *
 * Every classification here is a statement about what happens AFTER `noa-receipt` has loaded. The
 * intrinsic captures the whole scheme rests on are themselves snapshots taken at module evaluation,
 * so an adversary evaluated FIRST hands them a poisoned value to snapshot, and none of the probes
 * below can see it — they run inside the same compromised realm and measure a library that is
 * already lying. Measured and re-runnable: `r7-exploits/o01_preload_includes.mjs`, pinned OPEN.
 *
 * So the in-realm security objective is UNMET and this package makes no in-realm security claim.
 * What the registry genuinely delivers is narrower and still worth having: a NEW export cannot be
 * added without a classification, a classification that has stopped being true fails, and the
 * `unrouted` count is a standing debt rather than a memory. That is hygiene against our own drift.
 * The security property belongs to the isolated Go kernel, which shares no realm with the caller.
 */

export type EntryClass = "bytes-in" | "dataless" | "producer-inert" | "caller-owned" | "unrouted";

export interface EntryPoint {
  /** exported name, exactly as the entry module exports it */
  name: string;
  cls: EntryClass;
  /** required for every class except `dataless` */
  why?: string;
  /**
   * For `bytes-in`: the argument index that carries caller evidence, and a factory producing an
   * otherwise-valid call so the probe reaches the boundary. Omitted ⇒ probe with a bare object at
   * index 0 and accept any non-throwing outcome.
   */
  probe?: { argIndex: number; args: () => unknown[] };
}

/** `noa-receipt` — `src/index.ts` (the package's only exports entry). */
export const NOA_RECEIPT: EntryPoint[] = [
  // ── verifiers: ingest ──────────────────────────────────────────────────────────────────────────
  { name: "verifyChain", cls: "bytes-in", why: "receipts are Uint8Array|string; every document option is decoded once at the boundary" },
  { name: "verifyChainText", cls: "bytes-in", why: "a pure alias for verifyChain; the two entry points can no longer disagree about what a valid document is" },
  { name: "verifyCheckpoint", cls: "bytes-in", why: "checkpoint AND keyring are both documents; review #6 C2 was exactly the asymmetry of snapshotting one and not the other" },
  { name: "verifyCompleteness", cls: "bytes-in", why: "head, anchors and trustSet are all bytes; freshness is admitted by the option schema" },
  { name: "verifyChainWitnessed", cls: "bytes-in", why: "chain, keyring, anchors and trustSet are bytes; the head is derived from the SAME bytes verifyChain parsed" },
  { name: "verifyReceiptCompliance", cls: "bytes-in", why: "receipt, policy and inputs are three documents; options are schema-admitted" },
  { name: "resolveVerificationKey", cls: "bytes-in", why: "the keyring/lifecycle trust root is a byte document; retired state is resolved without traversing a caller object" },
  { name: "validateReceiptShape", cls: "bytes-in", why: "the structural walk runs over safeParse output, so its many passes cannot disagree" },
  { name: "receiptFromCose", cls: "bytes-in", why: "COSE bytes were always inert; the keyring and identityManifest are now documents too" },
  { name: "coseSign1Verify", cls: "bytes-in", why: "COSE bytes were always inert; the keyring is now a document too" },
  { name: "anchorForChainHead", cls: "producer-inert", why: "the signer's own chain (ADR §3.3); it serialises ONCE, so the verified bytes and the signed bytes are literally the same bytes" },
  { name: "buildAnchor", cls: "producer-inert", why: "the signer's own frontier (ADR §3.3); read once into locals, so checked == signed" },

  // ── producers: sign from a snapshot ────────────────────────────────────────────────────────────
  { name: "buildReceipt", cls: "producer-inert", why: "BuildInput cloned in buildDraft; output is re-verified by verifyChain before anyone acts on it" },
  { name: "buildReceiptAsync", cls: "producer-inert", why: "same as buildReceipt" },
  { name: "buildCheckpoint", cls: "producer-inert", why: "the three signed head fields are cloned before signing" },
  { name: "receiptToCose", cls: "producer-inert", why: "canonicalizes once; the envelope is re-verified by coseSign1Verify/receiptFromCose" },
  { name: "complianceCommit", cls: "producer-inert", why: "producer of a commitment that verifyReceiptCompliance re-derives from scratch" },
  { name: "receiptHashInput", cls: "producer-inert", why: "structuredClone at the top; pure preimage derivation" },
  { name: "checkpointHashInput", cls: "producer-inert", why: "structuredClone at the top; pure preimage derivation" },
  { name: "canonicalize", cls: "producer-inert", why: "a single depth-bounded walk; JCS is a pure function of one traversal, so there is no second read to disagree with" },
  { name: "nonNfcPaths", cls: "producer-inert", why: "single walk; advisory output, never a verdict" },
  { name: "deepFreeze", cls: "producer-inert", why: "in-place freeze of the CALLER'S OWN constant table; explicitly not the ingest boundary (see its docstring)" },
  { name: "anchorSigningInput", cls: "producer-inert", why: "reads the four frontier fields once into the preimage; callers (buildAnchor, verifyCompleteness) ingest first" },

  // ── noa.action-digest/0.1 (docs/action-digest-spec.md) ─────────────────────────────────────────
  // Both take documents, so both are `bytes-in`. The BUILDER is deliberately NOT `producer-inert`:
  // it is handed the receipt and grant of the party being correlated, not the caller's own data, so
  // calling it a producer would claim a trust relationship it does not have.
  { name: "buildActionDigest", cls: "bytes-in", why: "receipt and grant are both documents; every hash in the projection is recomputed from those bytes and never accepted from a caller" },
  { name: "verifyActionDigest", cls: "bytes-in", why: "claim and context are both documents; the two source documents re-enter through buildActionDigest's own byte boundary, so builder and verifier cannot disagree about what they read" },

  // ── policy surface ─────────────────────────────────────────────────────────────────────────────
  { name: "evaluate", cls: "bytes-in", why: "policy and inputs are documents; the rule walk runs over safeParse output" },
  { name: "validatePolicy", cls: "bytes-in", why: "the validated bytes ARE the supplied bytes" },
  { name: "assertValidPolicy", cls: "bytes-in", why: "delegates to validatePolicy; RETURNS the parsed Policy, because an `asserts p is Policy` signature cannot survive bytes-in honestly" },
  { name: "policyHash", cls: "producer-inert", why: "pure hash of one canonicalization; the verdict-bearing callers ingest first" },
  { name: "readSet", cls: "producer-inert", why: "pure derivation; verdict-bearing callers ingest first" },
  { name: "readSetHash", cls: "producer-inert", why: "pure hash of one canonicalization" },

  // ── inert-data primitives ──────────────────────────────────────────────────────────────────────
  { name: "makeInertArray", cls: "caller-owned", why: "operates on the caller's own array by design" },
  { name: "isInertArray", cls: "dataless" },
  { name: "frozenSet", cls: "caller-owned", why: "builds the caller's own policy table" },
  { name: "isFrozenSet", cls: "dataless" },
  { name: "frozenTable", cls: "caller-owned", why: "builds the caller's own policy table; refuses anything mutable" },
  { name: "inertViolations", cls: "caller-owned", why: "a read-only audit walk over the caller's own exports" },

  // ── primitives ─────────────────────────────────────────────────────────────────────────────────
  { name: "safeParse", cls: "dataless" },
  // THE BYTE BOUNDARY ITSELF, published 2026-07-28 so `packages/evidence` stops re-creating it.
  // `dataless` in the sense this registry means: their parameter is bytes or text, and the whole
  // point of `decodeDocument` is to DECIDE whether an arbitrary value is one — so the `unknown` in
  // its signature is the job, not an unrouted surface. Probing it with a hostile object is exactly
  // what `test/security/bytes-boundary.test.ts` already does, in more detail than a generic probe
  // could: it asserts the refusal, that no `toJSON`/`toString` is called, that the type test reads an
  // internal slot rather than a forgeable tag, and that the ceiling is enforced BEFORE the decode.
  { name: "decodeDocument", cls: "dataless" },
  { name: "parseDocument", cls: "dataless" },
  { name: "isUint8Array", cls: "dataless" },
  { name: "isNFC", cls: "dataless" },
  { name: "sha256Hex", cls: "dataless" },
  { name: "sha256Prefixed", cls: "dataless" },
  { name: "sha256Digest", cls: "dataless" },
  { name: "generateKeyPair", cls: "dataless" },
  { name: "signEd25519", cls: "dataless" },
  { name: "verifyEd25519", cls: "dataless" },
  { name: "coseSign1", cls: "dataless" },
  { name: "encInt", cls: "dataless" },
  { name: "encBstr", cls: "dataless" },
  { name: "encTstr", cls: "dataless" },
  { name: "encArray", cls: "dataless" },
  { name: "encMap", cls: "dataless" },
  { name: "encTag", cls: "dataless" },
  { name: "decode", cls: "dataless" },
];

/** `noa-approval-artifacts` — `src/index.ts`. */
export const NOA_APPROVAL_ARTIFACTS: EntryPoint[] = [
  { name: "verifyArtifact", cls: "bytes-in", why: "artifact AND context are bytes; the ctx.schemas exclusion that C-03 went through no longer exists" },
  { name: "signArtifact", cls: "bytes-in", why: "the document is bytes parsed once, so guarded == signed == returned by construction" },
  { name: "evalSchema", cls: "producer-inert", why: "a single structural walk with no second read; every verdict-bearing caller (verifyArtifact, verifyEvidence) ingests first" },
  { name: "canonicalize", cls: "producer-inert", why: "one depth-bounded traversal; pure" },
  { name: "refHash", cls: "producer-inert", why: "pure hash of one canonicalization" },
  { name: "virtualHash", cls: "producer-inert", why: "pure hash of one canonicalization" },
  { name: "receiptRefHash", cls: "producer-inert", why: "structuredClone at the top" },
  { name: "signHashInput", cls: "producer-inert", why: "structuredClone at the top" },
  { name: "sha256Hex", cls: "dataless" },
  { name: "sha256Prefixed", cls: "dataless" },
  { name: "sha256Digest", cls: "dataless" },
  { name: "signingMessage", cls: "dataless" },
  { name: "generateKeyPair", cls: "dataless" },
  { name: "signEd25519", cls: "dataless" },
  { name: "verifyEd25519", cls: "dataless" },
];

/** `noa-approval-evidence` — `src/index.ts`. */
export const NOA_APPROVAL_EVIDENCE: EntryPoint[] = [
  { name: "verifyEvidence", cls: "bytes-in", why: "bundle + opts snapshotted; schemas excluded as verifier-owned" },
  { name: "loadSchemas", cls: "dataless" },
  { name: "asRootKeyEntryMap", cls: "bytes-in", why: "snapshots the raw trust root before normalising it" },
  { name: "asStringKeyring", cls: "bytes-in", why: "snapshots the raw keyring before normalising it" },
  { name: "buildResolvedKeyring", cls: "bytes-in", why: "snapshots the root keyring, delegation and manifest" },
  { name: "buildReceiptKeyring", cls: "bytes-in", why: "snapshots the manifest" },
  { name: "assertReceiptRole", cls: "bytes-in", why: "snapshots the bundle; index.ts advertises it for direct downstream reuse, so it cannot rely on verifyEvidence having ingested" },
];
