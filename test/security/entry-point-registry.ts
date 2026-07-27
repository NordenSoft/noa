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
 * THE PROBES ARE DYNAMIC, NOT DECLARATIVE. `ingests` is not a promise, it is measured. For each such
 * export the coverage test calls it with an argument carrying a COUNTING GETTER and asserts the getter
 * fired AT MOST ONCE (two reads is the flipping-getter class, by definition), and calls it again with
 * an argument whose getter throws a REVOKED PROXY and asserts nothing escapes as a raw `TypeError`
 * (fail-closed, the review-#6 ingest defect). A classification that has stopped being true fails.
 *
 * THE CLASSES:
 *   ingests        — takes caller data AND routes it through the ingest boundary. Probed.
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
 */

export type EntryClass = "ingests" | "dataless" | "producer-inert" | "caller-owned" | "unrouted";

export interface EntryPoint {
  /** exported name, exactly as the entry module exports it */
  name: string;
  cls: EntryClass;
  /** required for every class except `dataless` */
  why?: string;
  /**
   * For `ingests`: the argument index that carries caller evidence, and a factory producing an
   * otherwise-valid call so the probe reaches the ingest. Omitted ⇒ probe with a bare object at
   * index 0 and accept any non-throwing outcome.
   */
  probe?: { argIndex: number; args: () => unknown[] };
}

/** `noa-receipt` — `src/index.ts` (the package's only exports entry). */
export const NOA_RECEIPT: EntryPoint[] = [
  // ── verifiers: ingest ──────────────────────────────────────────────────────────────────────────
  { name: "verifyChain", cls: "ingests", why: "snapshots receipts + opts behind the maxReceipts DoS pre-guard" },
  { name: "verifyChainText", cls: "ingests", why: "text is inert; opts snapshotted by verifyChain" },
  { name: "verifyCheckpoint", cls: "ingests", why: "checkpoint and keyring both snapshotted" },
  { name: "verifyCompleteness", cls: "ingests", why: "head/anchors/trustSet/opts snapshotted at the top" },
  { name: "verifyChainWitnessed", cls: "ingests", why: "opts + keyring snapshotted; chain delegated to verifyChain's bounded ingest" },
  { name: "verifyReceiptCompliance", cls: "ingests", why: "receipt/policy/inputs/opts all snapshotted" },
  { name: "snapshotImmutable", cls: "ingests", why: "IS the boundary" },
  { name: "tryIngest", cls: "ingests", why: "IS the boundary (non-throwing form)" },
  { name: "validateReceiptShape", cls: "ingests", why: "snapshots before the structural walk" },
  { name: "receiptFromCose", cls: "ingests", why: "COSE bytes are inert; keyring + identityManifest snapshotted" },
  { name: "coseSign1Verify", cls: "ingests", why: "COSE bytes are inert; keyring snapshotted" },
  { name: "anchorForChainHead", cls: "ingests", why: "receipts snapshotted before verifyChain and before the head walk" },
  { name: "buildAnchor", cls: "ingests", why: "frontier + signer snapshotted before validation, so checked bytes == signed bytes" },

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

  // ── policy surface ─────────────────────────────────────────────────────────────────────────────
  { name: "evaluate", cls: "ingests", why: "policy + inputs snapshotted before the rule walk" },
  { name: "validatePolicy", cls: "ingests", why: "snapshots before validating, so the validated bytes are the canonicalized bytes" },
  { name: "assertValidPolicy", cls: "ingests", why: "delegates to validatePolicy" },
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
  { name: "isIngestError", cls: "dataless" },

  // ── primitives ─────────────────────────────────────────────────────────────────────────────────
  { name: "safeParse", cls: "dataless" },
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
  { name: "verifyArtifact", cls: "ingests", why: "artifact + ctx snapshotted; schemas excluded as verifier-owned" },
  { name: "signArtifact", cls: "ingests", why: "doc + signer snapshotted, so guarded == signed == returned bytes" },
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
  { name: "verifyEvidence", cls: "ingests", why: "bundle + opts snapshotted; schemas excluded as verifier-owned" },
  { name: "loadSchemas", cls: "dataless" },
  { name: "asRootKeyEntryMap", cls: "ingests", why: "snapshots the raw trust root before normalising it" },
  { name: "asStringKeyring", cls: "ingests", why: "snapshots the raw keyring before normalising it" },
  { name: "buildResolvedKeyring", cls: "ingests", why: "snapshots the root keyring, delegation and manifest" },
  { name: "buildReceiptKeyring", cls: "ingests", why: "snapshots the manifest" },
  { name: "assertReceiptRole", cls: "ingests", why: "snapshots the bundle; index.ts advertises it for direct downstream reuse, so it cannot rely on verifyEvidence having ingested" },
];
