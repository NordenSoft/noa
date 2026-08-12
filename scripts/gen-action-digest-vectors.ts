/**
 * Deterministic conformance-vector generator for `noa.action-digest/0.1` (docs/action-digest-spec.md).
 *
 * Output (`conformance/action-digest/vectors.json`) is COMMITTED so anyone can re-derive and diff it;
 * CI regenerates and fails on drift, so nothing here may depend on the clock, on randomness, or on
 * `generateKeyPair()`.
 *
 * GROUND TRUTH. Receipts are built by the kernel's own `buildReceipt` and grants are signed with the
 * §6 execution-grant domain tag, both under the FIXED seeded Ed25519 keys in
 * `test/federation/_seeded-keys.ts`. Every rejection vector is therefore a cryptographically
 * well-formed pair of documents that fails a SEMANTIC rule — never a broken blob. That distinction
 * is the whole value of a rejection corpus: a verifier can refuse garbage by accident.
 *
 * Each vector pins the SUBSTRING of the refusal reason it is testing. A rejection vector that only
 * asserts `ok:false` passes when an unrelated earlier check fires, which is how a corpus starts
 * measuring nothing while still going green.
 */

import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { buildReceipt } from "../src/builder.js";
import { canonicalize } from "../src/jcs.js";
import { sha256Prefixed } from "../src/hash.js";
import { signingMessage } from "../src/signing.js";
import { signEd25519 } from "../src/keys.js";
import { receiptHashInput } from "../src/canonicalize.js";
import {
  ACTION_DIGEST_DOMAIN,
  ACTION_DIGEST_SPEC,
  buildActionDigest,
} from "../src/action-digest.js";
import type { Receipt } from "../src/types.js";
import { keyFromSeed } from "../test/federation/_seeded-keys.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const OUT_DIR = join(__dirname, "..", "..", "conformance", "action-digest");

// Test-only, seeded, PUBLIC on purpose — never reuse. Distinct from the federation witness seeds so
// a key from one corpus can never verify a document from the other.
const GATE = keyFromSeed("gate-prod-1", "00".repeat(31) + "11");
const GRANT_SIG_DOMAIN = "NOA-ExecGrant-v0.1-sig";

const TS = "2026-07-14T11:55:00.000Z";
const PARAMS_A = "sha256:" + "aa".repeat(32);
const PARAMS_B = "sha256:" + "bb".repeat(32);
const ENVELOPE_HASH = "sha256:" + "cc".repeat(32);

interface Grant {
  spec: "noa.execution-grant/0.1";
  grantId: string;
  holdId: string;
  paramsHash: string;
  holdEnvelopeHash: string;
  approvalReceiptHash: string;
  issuedAt: string;
  expiresAt: string;
  maxUses: 1;
  nonce: string;
  sig: { alg: "ed25519"; kid: string; value: string };
}

/** An authorization receipt: an ALLOWED, human-approved decision — the thing a grant descends from. */
function authorizationReceipt(args: {
  id: string;
  tenant?: string;
  chain: string;
  actionId: string;
  actionCanonical: string;
  paramsHash: string;
}): Receipt {
  return buildReceipt(
    {
      id: args.id,
      ts: TS,
      scope: args.tenant === undefined ? { chain: args.chain } : { tenant: args.tenant, chain: args.chain },
      agent: { id: "approver-a", model: null, principal: "HUMAN" },
      action: {
        id: args.actionId,
        canonical: args.actionCanonical,
        riskClass: "HIGH",
        paramsHash: args.paramsHash,
        reversible: false,
        rollbackRef: null,
      },
      governance: {
        mode: "on",
        verdict: "ALLOWED",
        ruleId: "human-approved",
        approval: { by: "HUMAN:approver-1-device-2", at: TS },
        sandboxed: false,
      },
    },
    null,
    { kid: GATE.kid, privateKey: GATE.privateKey },
  );
}

/** A gate-signed `noa.execution-grant/0.1` for a given receipt — real signature, §6 domain tag. */
function issueGrant(args: { grantId: string; holdId: string; nonce: string; receipt: Receipt; paramsHash?: string }): Grant {
  const doc = {
    spec: "noa.execution-grant/0.1" as const,
    grantId: args.grantId,
    holdId: args.holdId,
    paramsHash: args.paramsHash ?? args.receipt.action.paramsHash,
    holdEnvelopeHash: ENVELOPE_HASH,
    approvalReceiptHash: sha256Prefixed(receiptHashInput(args.receipt)),
    issuedAt: TS,
    expiresAt: "2026-07-14T12:30:00.000Z",
    maxUses: 1 as const,
    nonce: args.nonce,
  };
  const value = signEd25519(GATE.privateKey, signingMessage(GRANT_SIG_DOMAIN, canonicalize(doc)));
  return { ...doc, sig: { alg: "ed25519", kid: GATE.kid, value } };
}

function digestOf(receipt: Receipt, grant: Grant): string {
  const built = buildActionDigest(JSON.stringify(receipt), JSON.stringify(grant));
  if (!built.ok) throw new Error(`generator: expected a buildable digest, got: ${built.reason}`);
  return built.digest;
}

// ── THE AUTHORIZATIONS ──────────────────────────────────────────────────────────────────────────
// A: tenant-acme / chain-acme-1, attempt 1.
const receiptA = authorizationReceipt({
  id: "rcpt_allowed_a",
  tenant: "tenant-acme",
  chain: "chain-acme-1",
  actionId: "deploy.apply",
  actionCanonical: "deploy.apply:prod/api",
  paramsHash: PARAMS_A,
});
const grantA = issueGrant({ grantId: "grant-001", holdId: "hold-001", nonce: "grant-nonce-01", receipt: receiptA });
const digestA = digestOf(receiptA, grantA);

// A′: the SAME tenant, chain, action AND paramsHash — a RETRY. Only the grant differs (new id, new
// single-use nonce), which is precisely the case `carlos.md` §3 says `paramsHash` cannot separate.
const grantARetry = issueGrant({ grantId: "grant-002", holdId: "hold-001", nonce: "grant-nonce-02", receipt: receiptA });
const digestARetry = digestOf(receiptA, grantARetry);

// B: a DIFFERENT tenant, everything else identical — the cross-tenant replay subject.
const receiptB = authorizationReceipt({
  id: "rcpt_allowed_a",
  tenant: "tenant-globex",
  chain: "chain-acme-1",
  actionId: "deploy.apply",
  actionCanonical: "deploy.apply:prod/api",
  paramsHash: PARAMS_A,
});
const grantB = issueGrant({ grantId: "grant-001", holdId: "hold-001", nonce: "grant-nonce-01", receipt: receiptB });

// C: same tenant, DIFFERENT chain — chain is a separate commitment from tenant.
const receiptC = authorizationReceipt({
  id: "rcpt_allowed_a",
  tenant: "tenant-acme",
  chain: "chain-acme-2",
  actionId: "deploy.apply",
  actionCanonical: "deploy.apply:prod/api",
  paramsHash: PARAMS_A,
});
const grantC = issueGrant({ grantId: "grant-001", holdId: "hold-001", nonce: "grant-nonce-01", receipt: receiptC });

// D: an unrelated, itself-perfectly-valid authorization — the source of the "swapped digest" value.
const receiptD = authorizationReceipt({
  id: "rcpt_allowed_d",
  tenant: "tenant-acme",
  chain: "chain-acme-1",
  actionId: "wire.transfer",
  actionCanonical: "wire.transfer:acct-99",
  paramsHash: PARAMS_B,
});
const grantD = issueGrant({ grantId: "grant-777", holdId: "hold-777", nonce: "grant-nonce-77", receipt: receiptD });
const digestD = digestOf(receiptD, grantD);

// E: `action.id` and `action.canonical` TRANSPOSED. Both are strings, both are schema-legal, and the
// projection labels them — so a construction that concatenated instead of labelling would collide.
const receiptTransposed = authorizationReceipt({
  id: "rcpt_allowed_a",
  tenant: "tenant-acme",
  chain: "chain-acme-1",
  actionId: "deploy.apply:prod/api",
  actionCanonical: "deploy.apply",
  paramsHash: PARAMS_A,
});
const grantTransposed = issueGrant({
  grantId: "grant-001",
  holdId: "hold-001",
  nonce: "grant-nonce-01",
  receipt: receiptTransposed,
});

// F: no tenant at all (the receipt schema allows it; this construction does not).
const receiptNoTenant = authorizationReceipt({
  id: "rcpt_allowed_a",
  chain: "chain-acme-1",
  actionId: "deploy.apply",
  actionCanonical: "deploy.apply:prod/api",
  paramsHash: PARAMS_A,
});
const grantNoTenant = issueGrant({
  grantId: "grant-001",
  holdId: "hold-001",
  nonce: "grant-nonce-01",
  receipt: receiptNoTenant,
});

// G: a receipt edited AFTER hashing — genuine signature, genuine committed chain.hash, altered body.
const receiptTampered = JSON.parse(JSON.stringify(receiptA)) as Receipt;
(receiptTampered.action as { riskClass: string }).riskClass = "LOW";

const ACME = { tenant: "tenant-acme", chain: "chain-acme-1" };

interface Vector {
  name: string;
  note: string;
  claim?: unknown;
  claimText?: string;
  context?: unknown;
  contextText?: string;
  expect: { ok: boolean; reasonContains?: string; digest?: string };
}

const claimOf = (digest: string): unknown => ({ spec: ACTION_DIGEST_SPEC, digest });

const vectors: Vector[] = [
  {
    name: "valid",
    note: "A well-formed digest over a real authorization receipt and its real single-use execution grant.",
    claim: claimOf(digestA),
    context: { receipt: receiptA, grant: grantA, expect: ACME },
    expect: { ok: true, digest: digestA },
  },
  {
    name: "reject-swapped-digest",
    note:
      "The digest of a DIFFERENT, itself-valid authorization (wire.transfer) presented against this one. " +
      "Substituting one valid correlation value for another must not survive recomputation.",
    claim: claimOf(digestD),
    context: { receipt: receiptA, grant: grantA, expect: ACME },
    expect: { ok: false, reasonContains: "action digest mismatch" },
  },
  {
    name: "reject-cross-tenant-replay",
    note:
      "THE KNOCKOUT VECTOR for the projection's tenant field. tenant-acme's digest is replayed against " +
      "tenant-globex's documents AND the verifier is told to expect tenant-globex — so the explicit " +
      "tenant check PASSES and only the tenant inside the projection can refuse it.",
    claim: claimOf(digestA),
    context: { receipt: receiptB, grant: grantB, expect: { tenant: "tenant-globex", chain: "chain-acme-1" } },
    expect: { ok: false, reasonContains: "action digest mismatch" },
  },
  {
    name: "reject-cross-tenant-expectation",
    note:
      "The mirror control: honest tenant-acme documents presented to a verifier that believes it is " +
      "tenant-globex. Refused before the digest is even compared.",
    claim: claimOf(digestA),
    context: { receipt: receiptA, grant: grantA, expect: { tenant: "tenant-globex", chain: "chain-acme-1" } },
    expect: { ok: false, reasonContains: "tenant mismatch" },
  },
  {
    name: "reject-cross-chain-replay",
    note: "Same tenant, different hash-chain. `chain` is a separate commitment and must separate.",
    claim: claimOf(digestA),
    context: { receipt: receiptC, grant: grantC, expect: { tenant: "tenant-acme", chain: "chain-acme-2" } },
    expect: { ok: false, reasonContains: "action digest mismatch" },
  },
  {
    name: "reject-retry-identical-params",
    note:
      "THE `carlos.md` §3 VECTOR. Attempt 2 of the same action: identical tenant, chain, action.id, " +
      "action.canonical AND action.paramsHash — only the grant (id + single-use nonce) differs. " +
      "`paramsHash` cannot tell these apart; the action digest must.",
    claim: claimOf(digestA),
    context: { receipt: receiptA, grant: grantARetry, expect: ACME },
    expect: { ok: false, reasonContains: "action digest mismatch" },
  },
  {
    name: "reject-retry-digest-is-distinct",
    note:
      "The positive half of the same property, asserted as a refusal in the other direction: the RETRY's " +
      "own digest does not verify against attempt 1's grant. Two attempts, two values.",
    claim: claimOf(digestARetry),
    context: { receipt: receiptA, grant: grantA, expect: ACME },
    expect: { ok: false, reasonContains: "action digest mismatch" },
  },
  {
    name: "reject-action-fields-transposed",
    note:
      "action.id and action.canonical swapped in the source receipt. Both are plain strings and both are " +
      "schema-legal; the projection LABELS them, so the transposition changes the digest instead of " +
      "colliding with it — the failure a concatenation-based construction would have.",
    claim: claimOf(digestA),
    context: { receipt: receiptTransposed, grant: grantTransposed, expect: ACME },
    expect: { ok: false, reasonContains: "action digest mismatch" },
  },
  {
    name: "reject-truncated-digest",
    note: "63 hex characters instead of 64. A near-miss must not be a near-accept.",
    claim: { spec: ACTION_DIGEST_SPEC, digest: "sha256:" + "a".repeat(63) },
    context: { receipt: receiptA, grant: grantA, expect: ACME },
    expect: { ok: false, reasonContains: "claim.digest" },
  },
  {
    name: "reject-uppercase-digest",
    note: "The same digest in uppercase hex. One value, one spelling — otherwise two stores disagree.",
    claim: { spec: ACTION_DIGEST_SPEC, digest: "sha256:" + digestA.slice(7).toUpperCase() },
    context: { receipt: receiptA, grant: grantA, expect: ACME },
    expect: { ok: false, reasonContains: "claim.digest" },
  },
  {
    name: "reject-malformed-claim-bytes",
    note:
      "Truncated JSON. The refusal comes from the shared byte boundary (`parseDocument`), and the " +
      "pinned reason says so — a generic `claim:` prefix would also match three later checks, which " +
      "would let this vector pass while measuring one of those instead.",
    claimText: '{"spec":"noa.action-digest/0.1","digest":',
    context: { receipt: receiptA, grant: grantA, expect: ACME },
    expect: { ok: false, reasonContains: "unexpected end of input" },
  },
  {
    name: "reject-malformed-context-bytes",
    note: "The same at the context boundary. Both arguments are bytes and both are parsed strictly.",
    claim: claimOf(digestA),
    contextText: '{"receipt":',
    expect: { ok: false, reasonContains: "unexpected end of input" },
  },
  {
    name: "reject-cross-chain-expectation",
    note:
      "The chain mirror of reject-cross-tenant-expectation: honest chain-acme-1 documents presented " +
      "to a verifier that believes it is on chain-acme-2. Without this vector the expected-CHAIN " +
      "check is unmeasured — the cross-chain replay vector is caught by the digest and would stay " +
      "green if the check were deleted.",
    claim: claimOf(digestA),
    context: { receipt: receiptA, grant: grantA, expect: { tenant: "tenant-acme", chain: "chain-acme-2" } },
    expect: { ok: false, reasonContains: "chain mismatch" },
  },
  {
    name: "reject-wrong-domain-tag",
    note:
      "THE DOMAIN-SEPARATION VECTOR. The byte-identical projection, hashed under the RECEIPT signing tag " +
      "instead of NOA-ActionDigest-v0.1-dig. If the tag were dropped from the construction this value " +
      "would verify.",
    claim: claimOf(
      sha256Prefixed(
        signingMessage(
          "NOA-Receipt-v0.1-sig",
          canonicalize((buildActionDigest(JSON.stringify(receiptA), JSON.stringify(grantA)) as { projection: unknown }).projection),
        ),
      ),
    ),
    context: { receipt: receiptA, grant: grantA, expect: ACME },
    expect: { ok: false, reasonContains: "action digest mismatch" },
  },
  {
    name: "reject-no-domain-tag",
    note:
      "The same projection with NO tag at all — what an implementation that skipped domain separation " +
      "would emit. It is a different value, and it is refused.",
    claim: claimOf(
      sha256Prefixed(
        canonicalize((buildActionDigest(JSON.stringify(receiptA), JSON.stringify(grantA)) as { projection: unknown }).projection),
      ),
    ),
    context: { receipt: receiptA, grant: grantA, expect: ACME },
    expect: { ok: false, reasonContains: "action digest mismatch" },
  },
  {
    name: "reject-claim-spec-version",
    note: "A /0.2 claim compared by a /0.1 verifier. The version tag on the wire value is checked.",
    claim: { spec: "noa.action-digest/0.2", digest: digestA },
    context: { receipt: receiptA, grant: grantA, expect: ACME },
    expect: { ok: false, reasonContains: "claim.spec" },
  },
  {
    name: "reject-grant-for-another-receipt",
    note:
      "A grant whose approvalReceiptHash names a DIFFERENT authorization, paired with this receipt. " +
      "Without the tie the pair would digest happily and the digest would correlate nothing.",
    claim: claimOf(digestA),
    context: { receipt: receiptA, grant: grantD, expect: ACME },
    expect: { ok: false, reasonContains: "does not reference this receipt" },
  },
  {
    name: "reject-grant-params-mismatch",
    note:
      "A correctly-bound grant whose paramsHash is for different parameters — an authorization for A " +
      "must not correlate to an action with parameters B.",
    claim: claimOf(digestA),
    context: {
      receipt: receiptA,
      grant: issueGrant({
        grantId: "grant-001",
        holdId: "hold-001",
        nonce: "grant-nonce-01",
        receipt: receiptA,
        paramsHash: PARAMS_B,
      }),
      expect: ACME,
    },
    expect: { ok: false, reasonContains: "does not equal receipt.action.paramsHash" },
  },
  {
    name: "reject-tenant-absent",
    note:
      "A receipt with no scope.tenant — legal under the frozen receipt schema, refused here: a " +
      "correlation value whose tenant is sometimes empty is replayable exactly when it matters.",
    claim: claimOf(digestA),
    context: { receipt: receiptNoTenant, grant: grantNoTenant, expect: ACME },
    expect: { ok: false, reasonContains: "replayable across tenants" },
  },
  {
    name: "reject-receipt-edited-after-hashing",
    note:
      "riskClass rewritten HIGH -> LOW after the receipt was hashed and signed. The committed chain.hash " +
      "and the signature are the genuine ones; only the body moved.",
    claim: claimOf(digestA),
    context: { receipt: receiptTampered, grant: grantA, expect: ACME },
    expect: { ok: false, reasonContains: "receipt.chain.hash" },
  },
  {
    name: "reject-grant-extra-property",
    note:
      "An otherwise-valid grant carrying one extra field. The grant schema is closed and the grant hash " +
      "covers the whole document, so accepting it would let two honest parties compute two digests.",
    claim: claimOf(digestA),
    context: { receipt: receiptA, grant: { ...grantA, priority: "high" }, expect: ACME },
    expect: { ok: false, reasonContains: "unknown property" },
  },
  {
    name: "reject-grant-multi-use",
    note: "maxUses relaxed past 1. `carlos.md` §3 requires a SINGLE-USE nonce; a reusable grant is not one.",
    claim: claimOf(digestA),
    context: { receipt: receiptA, grant: { ...grantA, maxUses: 2 }, expect: ACME },
    expect: { ok: false, reasonContains: "grant.maxUses" },
  },
  {
    name: "reject-expectation-absent",
    note:
      "No context.expect at all. A verifier that cannot state which tenant it is cannot detect a replay, " +
      "and 'unknown' must not be spelled 'accept'.",
    claim: claimOf(digestA),
    context: { receipt: receiptA, grant: grantA },
    expect: { ok: false, reasonContains: "context.expect" },
  },
];

const out = {
  spec: ACTION_DIGEST_SPEC,
  domain: ACTION_DIGEST_DOMAIN,
  generatedFrom: "scripts/gen-action-digest-vectors.ts",
  note:
    "Generated, committed and diff-gated. Keys are FIXED test-only seeds (test/federation/_seeded-keys.ts) " +
    "so regeneration is byte-identical; their private halves are public on purpose and must never be reused.",
  vectors,
};

mkdirSync(OUT_DIR, { recursive: true });
writeFileSync(join(OUT_DIR, "vectors.json"), JSON.stringify(out, null, 2) + "\n");
console.error(`wrote conformance/action-digest/vectors.json — ${vectors.length} vectors`);
