#!/usr/bin/env node
/**
 * Deterministic conformance-vector generator for `reconcileSettlementEvidence` (S4, layers 4+6,
 * D7 correlation). Output (`conformance/settlement-evidence/vectors.json`) is COMMITTED; the
 * runner (`test/settlement-evidence-conformance.test.mjs`) re-derives the corpus in memory and
 * fails on any drift, so nothing here may depend on the clock, on randomness, or on
 * `generateKeyPair()`.
 *
 * GROUND TRUTH. Receipts are built by the kernel's own `buildReceipt`, grants and observer
 * signatures are REAL Ed25519 under the shipped domain tags, all under FIXED seeded keys (the
 * `test/federation/_seeded-keys.ts` recipe, replicated here because that fixture deliberately
 * does not ship in the public API). Every rejection vector is therefore a cryptographically
 * well-formed document set that fails a SEMANTIC rule — never a broken blob — and every vector
 * asserts the CODE, not the boolean, so a defect caught for the wrong reason fails.
 *
 * TWO DOCUMENTED ADAPTATIONS OF THE SPEC'S §12.2 TABLE (each is the R-CODE-1-consistent reading):
 *  - `reject-allowed-receipt-wrong-verdict` expects `SETTLEMENT_RECEIPT_ROLE_UNFIT` (the table's
 *    own preamble and §6.3's R-8 note demand the distinct code; the table row's
 *    AUTHORIZATION_RECEIPT_MISMATCH spelling would leave SETTLEMENT_RECEIPT_ROLE_UNFIT with no
 *    vector and fail the registry test's own rule).
 *  - `reject-two-transfer-logs` presents the two qualifying transfers the only way the verbatim
 *    `noa.chain-facts/0.1` schema can carry them — a `transfer` that is not the single-object
 *    shape — and the record is refused as `SETTLEMENT_CHAIN_CONTRADICTED`: the single-transfer
 *    record shape IS R-19(b)'s uniqueness rule at the record boundary; the verifier never picks.
 */

import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { createPrivateKey, createPublicKey } from "node:crypto";
import {
  buildReceipt,
  canonicalize,
  sha256Prefixed,
  sha256Hex,
  sha256Digest,
  signEd25519,
} from "noa-receipt";
import { deriveCorrelationNonce } from "../src/correlation-nonce.mjs";

// ── deterministic seeded Ed25519 (the _seeded-keys.ts recipe; test-only, public on purpose) ─────
const PKCS8_ED25519_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
function keyFromSeed(kid, seedHex) {
  const der = Buffer.concat([PKCS8_ED25519_PREFIX, Buffer.from(seedHex, "hex")]);
  const priv = createPrivateKey({ key: der, format: "der", type: "pkcs8" });
  const pub = createPublicKey(priv);
  return {
    kid,
    publicKey: pub.export({ type: "spki", format: "der" }).toString("base64"),
    privateKey: priv.export({ type: "pkcs8", format: "der" }).toString("base64"),
  };
}

// Distinct from every other corpus' seeds. NEVER reuse outside test vectors.
const GATE = keyFromSeed("gate-prod-1", "00".repeat(31) + "31");
const OBSERVER = keyFromSeed("gate-observer-2", "00".repeat(31) + "32");
const KEYRING = { [GATE.kid]: GATE.publicKey, [OBSERVER.kid]: OBSERVER.publicKey };

const GRANT_SIG_DOMAIN = "NOA-ExecGrant-v0.1-sig";
const OBSERVER_SIG_DOMAIN = "NOA-SettlementEvidence-v0.1-sig";
/** The kernel's `signingMessage` construction (domain-tagged digest). Self-gating: if this ever
 *  drifted from the kernel's, `verifyActionDigest` would refuse every fixture's grant signature
 *  and the whole corpus would go red — the parity is measured on every run, not trusted. */
const signingMessage = (domain, jcs) => Buffer.concat([Buffer.from(domain + ":", "utf8"), sha256Digest(jcs)]);

// ── fixed coordinates ───────────────────────────────────────────────────────────────────────────
const TENANT = "tenant-acme";
const TENANT_B = "tenant-globex";
const CHAIN = "chain-acme-1";
const NETWORK = "eip155:8453";
const TOKEN = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"; // Base mainnet USDC
const ASSET = `${NETWORK}/erc20:${TOKEN}`;
const NETWORK_TESTNET = "eip155:84532";
const TOKEN_TESTNET = "0x036cbd53842c5426634e7929541ec2318f3dcf7e"; // Base Sepolia USDC
const ASSET_TESTNET = `${NETWORK_TESTNET}/erc20:${TOKEN_TESTNET}`;
const FAKE_TOKEN = "0x00000000000000000000000000000000deadbeef";
const PAYER = "0x1111111111111111111111111111111111111111";
const PAYEE = "0x2222222222222222222222222222222222222222";
const MALLORY = "0x3333333333333333333333333333333333333333";

const T_APPROVE = "2026-08-13T10:00:00.000Z";
const T_GRANT_EXPIRES = "2026-08-13T10:30:00.000Z";
const T_SETTLED = "2026-08-13T10:05:04.000Z";
const T_SETTLED_NOFRAC = "2026-08-13T10:05:04Z"; // the SAME instant, a different string (R-20 pin)
const T_BEFORE_GRANT = "2026-08-13T09:59:00.000Z";
const T_AFTER_EXPIRY = "2026-08-13T10:40:00.000Z";
const T_OBSERVED = "2026-08-13T10:06:00.000Z";
const T_QUERIED = "2026-08-13T10:06:30.000Z";
const T_NOW = "2026-08-13T10:10:00.000Z";
const T_OBSERVED_LATE = "2026-08-13T10:41:00.000Z";
const T_QUERIED_LATE = "2026-08-13T10:41:30.000Z";
const T_NOW_LATE = "2026-08-13T10:45:00.000Z";
const BLOCK = 33554432;
const TX = "0x" + "3f".repeat(32);
const TX_OTHER = "0x" + "4a".repeat(32);

const GRANT_NONCE = "9c".repeat(32);           // 64 lowercase hex — the D7 seed
const GRANT_NONCE_RETRY = "8b".repeat(32);
const SIBLING_SEED = "7a".repeat(32);          // same grant, DIFFERENT seed — never derivable

const PREIMAGE = {
  payer: PAYER,
  payee: PAYEE,
  assetCaip19: ASSET,
  networkCaip2: NETWORK,
  maxAmountMinorUnits: "10000000",
  resource: "https://vendor.example/invoice/42",
};

// ── builders ────────────────────────────────────────────────────────────────────────────────────
function mintReceipt(o) {
  const scope = o.omitTenant ? { chain: o.chain ?? CHAIN } : { tenant: o.tenant ?? TENANT, chain: o.chain ?? CHAIN };
  return buildReceipt(
    {
      id: o.id ?? "rcpt_payment_1",
      ts: T_APPROVE,
      scope,
      agent: { id: "approver-a", model: null, principal: "HUMAN" },
      action: {
        id: "payment.x402",
        canonical: o.canonical ?? "payment.x402:vendor-42",
        riskClass: "HIGH",
        paramsHash: o.paramsHash,
        reversible: false,
        rollbackRef: null,
      },
      governance: {
        mode: "on",
        verdict: o.verdict ?? "ALLOWED",
        ruleId: "human-approved",
        approval: { by: "HUMAN:approver-1", at: T_APPROVE },
        sandboxed: false,
      },
    },
    null,
    { kid: GATE.kid, privateKey: GATE.privateKey },
  );
}

function mintEnvelope(o = {}) {
  return {
    spec: "noa.hold-envelope/0.1",
    holdId: o.holdId ?? "hold-001",
    tenant: o.tenant ?? TENANT,
    mode: o.mode ?? "ENFORCED",
    keyManifestVersion: 1,
    expiresAt: T_GRANT_EXPIRES,
    nonce: o.nonce ?? "env-nonce-1",
  };
}

function mintResolution(o = {}) {
  return {
    spec: "noa.hold-resolution/0.1",
    holdId: o.holdId ?? "hold-001",
    reasonCode: o.reasonCode ?? "HUMAN_APPROVED_INTENT_NOT_EXECUTION_BOUND",
    receivedAt: T_APPROVE,
  };
}

function mintGrant(o) {
  const doc = {
    spec: "noa.execution-grant/0.1",
    grantId: o.grantId ?? "grant-001",
    holdId: o.holdId ?? "hold-001",
    paramsHash: o.paramsHash,
    holdEnvelopeHash: sha256Prefixed(canonicalize(o.envelope)),
    approvalReceiptHash: o.receipt.chain.hash,
    issuedAt: T_APPROVE,
    expiresAt: T_GRANT_EXPIRES,
    maxUses: 1,
    nonce: o.nonce ?? GRANT_NONCE,
  };
  if (o.mutate) o.mutate(doc);
  const value = signEd25519(GATE.privateKey, signingMessage(GRANT_SIG_DOMAIN, canonicalize(doc)));
  return { ...doc, sig: { alg: "ed25519", kid: GATE.kid, value } };
}

/** The action-digest construction, replicated for fixture minting where the builder's own semantic
 *  gates refuse (extra member / multi-use vectors need the executionGrantHash of the OFFENDING
 *  grant). On the well-formed valid case the runner's acceptance proves parity with the kernel. */
function digestOf(receipt, grant) {
  const projection = {
    spec: "noa.action-digest/0.1",
    authorizationReceiptHash: receipt.chain.hash,
    tenant: receipt.scope.tenant,
    chain: receipt.scope.chain,
    actionId: receipt.action.id,
    actionCanonical: receipt.action.canonical,
    actionParamsHash: receipt.action.paramsHash,
    executionGrantId: grant.grantId,
    executionGrantHash: sha256Prefixed(canonicalize(grant)),
    executionNonce: grant.nonce,
  };
  return sha256Prefixed(signingMessage("NOA-ActionDigest-v0.1-dig", canonicalize(projection)));
}

function d7Nonce(digest, seedHex, network = NETWORK, token = TOKEN, payer = PAYER) {
  return deriveCorrelationNonce({
    chainId: Number(network.slice("eip155:".length)),
    tokenAddress: token,
    payerAddress: payer,
    dispatchId: digest,
    seed: Uint8Array.from(Buffer.from(seedHex, "hex")),
  }).nonce;
}

function signArtifact(doc, key = OBSERVER) {
  const value = signEd25519(key.privateKey, signingMessage(OBSERVER_SIG_DOMAIN, canonicalize(doc)));
  return { ...doc, sig: { alg: "ed25519", kid: key.kid, value } };
}

const RAIL_RECEIPT_FULL = {
  disclosure: "FULL",
  format: "x402-offer-receipt/eip712",
  encoding: "base64",
  bytes: Buffer.from('{"receipt":"demo","payTo":"0x2222222222222222222222222222222222222222"}', "utf8").toString("base64"),
};

function mintArtifact(o) {
  const witness = {
    status: "SETTLED",
    network: NETWORK,
    asset: ASSET,
    payer: PAYER,
    payee: PAYEE,
    amount: "1000000",
    txHash: TX,
    blockNumber: BLOCK,
    settledAt: T_SETTLED,
    ...(o.witness ?? {}),
  };
  const doc = {
    spec: "noa.settlement-evidence/0.1",
    tenant: o.tenant ?? TENANT,
    chain: o.chain ?? CHAIN,
    authorizationReceiptHash: o.authorizationReceiptHash,
    executionGrantHash: o.executionGrantHash,
    correlation: o.correlation,
    railFamily: o.railFamily ?? "x402/exact/eip3009",
    chainWitness: witness,
    railReceipt: o.railReceipt === undefined ? RAIL_RECEIPT_FULL : o.railReceipt,
    observerKid: o.observerKid ?? OBSERVER.kid,
    observedAt: o.observedAt ?? T_OBSERVED,
  };
  return signArtifact(doc, o.signerKey ?? OBSERVER);
}

function mintChainFacts(o = {}) {
  return {
    spec: "noa.chain-facts/0.1",
    network: o.network ?? NETWORK,
    asset: o.asset ?? ASSET,
    authorizationState: o.authorizationState ?? true,
    // Used logs carry the (nonce, authorizer) they were emitted for; the default is the base
    // mandate's correlation + payer, overridable per vector.
    authorizationUsedLogs: o.usedLogs ?? [
      { txHash: TX, blockNumber: BLOCK, logIndex: 7, blockTimestamp: o.blockTimestamp ?? T_SETTLED, txStatus: o.txStatus ?? "SUCCESS",
        nonce: o.nonce ?? correlation, authorizer: o.authorizer ?? PAYER },
    ],
    authorizationCanceledLogs: o.canceledLogs ?? [],
    // The transfer names the transaction it was recovered from (default: the used log's).
    transfer: o.transfer === undefined
      ? { source: "CALLDATA", address: o.transferAddress ?? TOKEN, logIndex: 8, from: PAYER, to: PAYEE, value: o.value ?? "1000000",
          txHash: o.transferTxHash ?? TX, blockNumber: o.transferBlockNumber ?? BLOCK }
      : o.transfer,
    headBlockNumber: o.headBlockNumber ?? BLOCK + 30,
    queriedAt: o.queriedAt ?? T_QUERIED,
  };
}

// ── the base (mainnet, ENFORCED) case ───────────────────────────────────────────────────────────
const preimageText = canonicalize(PREIMAGE);
const paramsHash = "sha256:" + sha256Hex(preimageText);
const receipt = mintReceipt({ paramsHash });
const envelope = mintEnvelope();
const resolution = mintResolution();
const grant = mintGrant({ receipt, envelope, paramsHash });
const digest = digestOf(receipt, grant);
const correlation = d7Nonce(digest, GRANT_NONCE);
const grantHash = sha256Prefixed(canonicalize(grant));

const baseInput = (over = {}) => ({
  artifact: over.artifact ?? mintArtifact({
    authorizationReceiptHash: receipt.chain.hash,
    executionGrantHash: grantHash,
    correlation,
    ...(over.artifactOver ?? {}),
  }),
  receiptChain: over.receiptChain ?? [receipt],
  grant: over.grant ?? grant,
  keyring: over.keyring ?? KEYRING,
  holdEnvelope: over.holdEnvelope ?? envelope,
  holdResolution: over.holdResolution === undefined ? resolution : over.holdResolution,
  chainFacts: over.chainFacts === undefined ? mintChainFacts() : over.chainFacts,
  chainFactsOrigin: over.chainFactsOrigin === undefined ? "RELYING_PARTY_NODE" : over.chainFactsOrigin,
  paramsPreimage: over.paramsPreimage === undefined ? preimageText : over.paramsPreimage,
  expect: over.expect ?? { tenant: TENANT, chain: CHAIN },
  minConfirmations: over.minConfirmations === undefined ? 12 : over.minConfirmations,
  now: over.now ?? T_NOW,
  freshnessWindowMs: over.freshnessWindowMs === undefined ? 3600000 : over.freshnessWindowMs,
});

// ── secondary mandates ──────────────────────────────────────────────────────────────────────────
// Retry of the SAME action: identical paramsHash, new grant (id + nonce) — the NC-2.7 case.
const grantRetry = mintGrant({ receipt, envelope, paramsHash, grantId: "grant-002", nonce: GRANT_NONCE_RETRY });
// Mandate D — a different, itself-valid mandate whose real nonce gets filed against the base one.
const preimageD = { ...PREIMAGE, payee: MALLORY, resource: "https://vendor.example/invoice/77" };
const preimageDText = canonicalize(preimageD);
const paramsHashD = "sha256:" + sha256Hex(preimageDText);
const receiptD = mintReceipt({ id: "rcpt_payment_d", canonical: "payment.x402:vendor-77", paramsHash: paramsHashD });
const grantD = mintGrant({ receipt: receiptD, envelope, paramsHash: paramsHashD, grantId: "grant-777", nonce: "6e".repeat(32) });
const digestD = digestOf(receiptD, grantD);
const correlationD = d7Nonce(digestD, "6e".repeat(32));
// Tenant B — the cross-tenant-correlation subject.
const receiptB = mintReceipt({ tenant: TENANT_B, paramsHash });
const grantB = mintGrant({ receipt: receiptB, envelope: mintEnvelope({ tenant: TENANT_B }), paramsHash });
// RAW-mode hold — grant BINDS the RAW envelope, everything else green (hand-assembled: no honest
// gate emits this pair; a bundle is not a gate).
const envelopeRaw = mintEnvelope({ mode: "RAW", nonce: "env-nonce-raw" });
const grantRaw = mintGrant({ receipt, envelope: envelopeRaw, paramsHash, grantId: "grant-raw", nonce: "5f".repeat(32) });
const digestRaw = digestOf(receipt, grantRaw);
const correlationRaw = d7Nonce(digestRaw, "5f".repeat(32));
// hmac-sha256 paramsHash — legal in the frozen receipt schema; blocks bounds AND derivation.
const paramsHashHmac = "hmac-sha256:" + "ee".repeat(32);
const receiptHmac = mintReceipt({ id: "rcpt_payment_hmac", paramsHash: paramsHashHmac });
const grantHmac = mintGrant({ receipt: receiptHmac, envelope, paramsHash: paramsHashHmac, grantId: "grant-hmac", nonce: "4d".repeat(32) });
/**
 * Three encodings of the SAME six approved parameters that are not JCS. Each is committed by its own
 * receipt in the vector below, so the hash rule cannot be what refuses it — only the canonical-form
 * rule can. JCS fixes all three axes: no insignificant whitespace, members sorted by code unit, and
 * minimal string escaping. A verifier that skips the re-canonicalization accepts all three.
 */
const NONCANONICAL_PREIMAGES = [
  // (a) insignificant whitespace — the same document, one space after the opening brace.
  { label: "whitespace", seed: "1b", text: preimageText.replace('{"', '{ "') },
  // (b) member order — JCS sorts by code unit; this writes the six members in declaration order.
  { label: "member-order", seed: "2d", text: JSON.stringify(PREIMAGE) },
  // (c) string escaping — JCS requires minimal escapes; "\u0068ttps://…" parses to the same string.
  { label: "escaping", seed: "3e", text: canonicalize(PREIMAGE).replace('"https://', '"\\u0068ttps://') },
];

// 7-member preimage committed by its own receipt — R-HASH-2(2)'s unknown-member refusal.
const preimage7 = { ...PREIMAGE, memo: "extra" };
const preimage7Text = canonicalize(preimage7);
const paramsHash7 = "sha256:" + sha256Hex(preimage7Text);
const receipt7 = mintReceipt({ id: "rcpt_payment_7", paramsHash: paramsHash7 });
const grant7 = mintGrant({ receipt: receipt7, envelope, paramsHash: paramsHash7, grantId: "grant-007", nonce: "3c".repeat(32) });
const digest7 = digestOf(receipt7, grant7);
const correlation7 = d7Nonce(digest7, "3c".repeat(32));
// Tenant-less receipt — schema-legal, digest-refused (R-AD-6's narrowing, visible as a vector).
const receiptNoTenant = mintReceipt({ id: "rcpt_payment_nt", paramsHash, omitTenant: true });
const grantNoTenant = mintGrant({ receipt: receiptNoTenant, envelope, paramsHash, grantId: "grant-nt", nonce: "2b".repeat(32) });
// Offending grants, signed WITH the offending member so only the closed-world rule refuses them.
const grantExtra = mintGrant({ receipt, envelope, paramsHash, grantId: "grant-ex", nonce: "1a".repeat(32), mutate: (d) => { d.priority = "high"; } });
const grantMulti = mintGrant({ receipt, envelope, paramsHash, grantId: "grant-mu", nonce: "0f".repeat(32), mutate: (d) => { d.maxUses = 2; } });
// Testnet-consistent case for reject-chainid-from-artifact: the artifact and the chain facts are
// UNIFORMLY testnet — exactly what an implementation lifting derivation inputs from the artifact
// would accept — while the VERIFIED preimage says mainnet.
const correlationTestnet = d7Nonce(digest, GRANT_NONCE, NETWORK_TESTNET, TOKEN_TESTNET);
// The grant signer's PUBLIC KEY registered under a SECOND kid — the alias evasion of
// a kid-string R-16 cap, and simultaneously the legitimate dual-role configuration (one key, both
// roles, which under a kid-keyed manifest means two kids). The byte-level cap must catch both.
const OBSERVER_ALIAS = { kid: "gate-observer-alias", publicKey: GATE.publicKey, privateKey: GATE.privateKey };
const KEYRING_WITH_ALIAS = { ...KEYRING, [OBSERVER_ALIAS.kid]: GATE.publicKey };
// A chainId inside the schema grammar (≤19 digits) but ABOVE 2^53-1 — the
// derivation refuses non-safe integers, so this coordinate set is fail-closed by arithmetic.
const NETWORK_UNSAFE = "eip155:9007199254740993";
const ASSET_UNSAFE = `${NETWORK_UNSAFE}/erc20:${TOKEN}`;
const preimageUnsafe = { ...PREIMAGE, networkCaip2: NETWORK_UNSAFE, assetCaip19: ASSET_UNSAFE };
const preimageUnsafeText = canonicalize(preimageUnsafe);
const paramsHashUnsafe = "sha256:" + sha256Hex(preimageUnsafeText);
const receiptUnsafe = mintReceipt({ id: "rcpt_payment_u", paramsHash: paramsHashUnsafe });
const grantUnsafe = mintGrant({ receipt: receiptUnsafe, envelope, paramsHash: paramsHashUnsafe, grantId: "grant-u", nonce: "5e".repeat(32) });
// A fabricated in-window settledAt that contradicts the real block time as INSTANTS.
const T_SETTLED_PLUS_1S = "2026-08-13T10:05:05.000Z";
// A grant whose OWN window sits in proleptic year 0099, so the ordering arm does not mask the
// Date.UTC year-aliasing: the artifact's settledAt (0099) and the chain's blockTimestamp (1999) name
// instants 1900 years apart, and before parseInstant set the true year both parsed to 1999.
const grantY99 = mintGrant({ receipt, envelope, paramsHash, grantId: "grant-y99", nonce: "2c".repeat(32),
  mutate: (d) => { d.issuedAt = "0099-01-01T00:00:00.000Z"; d.expiresAt = "0099-12-31T23:59:59.000Z"; } });
const digestY99 = digestOf(receipt, grantY99);
const correlationY99 = d7Nonce(digestY99, "2c".repeat(32));
const T_SETTLED_Y0099 = "0099-08-13T10:05:04.000Z";
const T_BLOCK_1999 = "1999-08-13T10:05:04.000Z";

function vec(name, description, expect, expectCode, input, extra = {}) {
  return { name, description, expect, expectCode, input, ...extra };
}

export function buildCorpus() {
  const vectors = [
    // ── THE ONE ACCEPT ──────────────────────────────────────────────────────────────────────────
    vec("valid-reconfirmed",
      "R-18..R-22, B1-B6 all green: CALLDATA route, depth >= minConfirmations, txStatus SUCCESS, ENFORCED hold, independent observer kid.",
      "ACCEPT", "SETTLEMENT_CORRELATED_AND_RECONFIRMED", baseInput(), {
        expectChainStatus: "RECONFIRMED",
        expectBoundsStatus: "WITHIN",
        expectRailReceiptStatus: "PROVIDED_UNVALIDATED",
        expectObserverRelationship: "SAME_ADMINISTRATIVE_PARTY",
        expectReconciled: true,
      }),

    // ── correlation (D7) ────────────────────────────────────────────────────────────────────────
    vec("reject-correlation-mismatch",
      "§9.5 — the correlation mutated by one byte; recomputation from the bundle's own receipt+grant disagrees.",
      "REJECT", "SETTLEMENT_CORRELATION_MISMATCH",
      baseInput({ artifactOver: { correlation: correlation.slice(0, -1) + (correlation.endsWith("0") ? "1" : "0") } })),
    vec("reject-sibling-seed",
      "REVISION 3 — same grant, DIFFERENT seed; the sibling nonce settles on-chain for real, and recomputation from grant.nonce still yields THE one nonce. The D7 seed-pin knockout vector.",
      "REJECT", "SETTLEMENT_CORRELATION_MISMATCH",
      baseInput({ artifactOver: { correlation: d7Nonce(digest, SIBLING_SEED) } })),
    vec("reject-digest-over-other-grant",
      "A genuine settlement of mandate D filed as evidence for the base mandate: both reference hashes point at the base bundle, correlation carries D's on-chain value. Recomputation refuses. Knockout: accept a supplied correlation instead of recomputing -> GREEN.",
      "REJECT", "SETTLEMENT_CORRELATION_MISMATCH",
      baseInput({ artifactOver: { correlation: correlationD } })),
    vec("reject-cross-tenant-correlation",
      "§9.2 — tenant A's on-chain value re-filed under tenant B's bundle and tenant field; the digest recomputed over tenant B's receipt derives different bytes.",
      "REJECT", "SETTLEMENT_CORRELATION_MISMATCH",
      baseInput({
        artifact: mintArtifact({
          tenant: TENANT_B,
          authorizationReceiptHash: receiptB.chain.hash,
          executionGrantHash: sha256Prefixed(canonicalize(grantB)),
          correlation,
        }),
        receiptChain: [receiptB],
        grant: grantB,
        holdEnvelope: mintEnvelope({ tenant: TENANT_B }),
        expect: { tenant: TENANT_B, chain: CHAIN },
      })),
    vec("reject-grant-extra-member",
      "R-12's inherited closed-world refusal: a grant carrying a twelfth member would let two honest parties compute two different digests.",
      "REJECT", "SETTLEMENT_CORRELATION_MISMATCH",
      baseInput({
        grant: grantExtra,
        artifactOver: { executionGrantHash: sha256Prefixed(canonicalize(grantExtra)) },
      })),
    vec("reject-grant-multi-use",
      "R-12's inherited single-use refusal: maxUses != 1 is not the grant the digest binds.",
      "REJECT", "SETTLEMENT_CORRELATION_MISMATCH",
      baseInput({
        grant: grantMulti,
        artifactOver: { executionGrantHash: sha256Prefixed(canonicalize(grantMulti)) },
      })),
    vec("reject-tenantless-receipt",
      "R-AD-6 — a schema-conformant receipt with scope.tenant absent produces NO digest; the narrowing is a vector, not a runtime surprise.",
      "REJECT", "SETTLEMENT_CORRELATION_MISMATCH",
      baseInput({
        receiptChain: [receiptNoTenant],
        grant: grantNoTenant,
        artifactOver: {
          authorizationReceiptHash: receiptNoTenant.chain.hash,
          executionGrantHash: sha256Prefixed(canonicalize(grantNoTenant)),
        },
      })),

    // ── tenant / linkage ────────────────────────────────────────────────────────────────────────
    vec("reject-cross-tenant-field",
      "R-11 — the artifact's own tenant does not equal the verifier's expected value; caught offline with no chain access.",
      "REJECT", "SETTLEMENT_TENANT_MISMATCH",
      baseInput({ expect: { tenant: TENANT_B, chain: CHAIN } })),
    vec("reject-retry-replay",
      "§9.3 — retry #1's settlement presented on retry #2's bundle: identical paramsHash (NC-2.7), different grant. Only the grant reference can separate retries, and it does.",
      "REJECT", "EXECUTION_GRANT_MISMATCH",
      baseInput({ grant: grantRetry })),
    vec("reject-grant-ref-mismatch",
      "§9.4 — executionGrantHash re-pointed at another value; F1 rule-b recomputation refuses.",
      "REJECT", "EXECUTION_GRANT_MISMATCH",
      baseInput({ artifactOver: { executionGrantHash: sha256Prefixed(canonicalize(envelope)) } })),
    vec("reject-authorization-ref-mismatch",
      "§9.4 — authorizationReceiptHash names a different authorization than the bundle's receipt.",
      "REJECT", "AUTHORIZATION_RECEIPT_MISMATCH",
      baseInput({ artifactOver: { authorizationReceiptHash: receiptD.chain.hash } })),
    vec("reject-allowed-receipt-wrong-verdict",
      "R-8's concern in this package: the hash-bound receipt attests EXECUTED, not ALLOWED — cryptographically bound, semantically contradictory. Its OWN code (see the generator header).",
      "REJECT", "SETTLEMENT_RECEIPT_ROLE_UNFIT",
      (() => {
        const r = mintReceipt({ id: "rcpt_payment_x", paramsHash, verdict: "EXECUTED" });
        const g = mintGrant({ receipt: r, envelope, paramsHash, grantId: "grant-x", nonce: "9d".repeat(32) });
        return baseInput({
          receiptChain: [r],
          grant: g,
          artifactOver: {
            authorizationReceiptHash: r.chain.hash,
            executionGrantHash: sha256Prefixed(canonicalize(g)),
            correlation: d7Nonce(digestOf(r, g), "9d".repeat(32)),
          },
        });
      })()),
    vec("reject-envelope-hash-mismatch",
      "R-23(i) — a supplied holdEnvelope whose refHash != grant.holdEnvelopeHash; otherwise R-23 reads mode off an envelope nothing binds.",
      "REJECT", "EXECUTION_GRANT_MISMATCH",
      baseInput({ holdEnvelope: mintEnvelope({ nonce: "env-nonce-other" }) })),

    // ── §7 preimage / bounds ────────────────────────────────────────────────────────────────────
    vec("reject-hmac-params-hash",
      "§7 step 1 (offline) — a keyed paramsHash is not third-party checkable: boundsStatus UNCHECKED, no positive, offline tier.",
      "REJECT", "SETTLEMENT_BOUNDS_UNCHECKABLE",
      (() => {
        const g = grantHmac;
        return baseInput({
          receiptChain: [receiptHmac],
          grant: g,
          chainFacts: null,
          paramsPreimage: preimageText,
          artifactOver: {
            authorizationReceiptHash: receiptHmac.chain.hash,
            executionGrantHash: sha256Prefixed(canonicalize(g)),
            correlation,
          },
        });
      })()),
    vec("reject-hmac-params-derivation",
      "REVISION 3 — the keyed form blocks the D7 DERIVATION too, not only bounds: a real on-chain settlement is supplied and the result is still SETTLEMENT_BOUNDS_UNCHECKABLE, never a positive.",
      "REJECT", "SETTLEMENT_BOUNDS_UNCHECKABLE",
      (() => {
        const g = grantHmac;
        return baseInput({
          receiptChain: [receiptHmac],
          grant: g,
          paramsPreimage: preimageText,
          artifactOver: {
            authorizationReceiptHash: receiptHmac.chain.hash,
            executionGrantHash: sha256Prefixed(canonicalize(g)),
            correlation,
          },
        });
      })()),
    vec("reject-no-params-preimage",
      "§7 step 1 — no preimage supplied: the bounds were never compared, so no positive is reachable.",
      "REJECT", "SETTLEMENT_BOUNDS_UNCHECKABLE",
      baseInput({ paramsPreimage: null })),
    vec("reject-params-preimage-hash-mismatch",
      "§7 step 1 — a preimage whose SHA-256 does not equal action.paramsHash: not one field is read from it.",
      "REJECT", "SETTLEMENT_BOUNDS_UNCHECKABLE",
      baseInput({ paramsPreimage: canonicalize({ ...PREIMAGE, maxAmountMinorUnits: "10000001" }) })),
    vec("reject-params-preimage-extra-member",
      "R-HASH-2(2) — a hash-matching preimage carrying an unknown member is a refusal, not a tolerance.",
      "REJECT", "SETTLEMENT_BOUNDS_UNCHECKABLE",
      baseInput({
        receiptChain: [receipt7],
        grant: grant7,
        paramsPreimage: preimage7Text,
        artifactOver: {
          authorizationReceiptHash: receipt7.chain.hash,
          executionGrantHash: sha256Prefixed(canonicalize(grant7)),
          correlation: correlation7,
        },
      })),
    // R-HASH-2's CANONICAL half. Each preimage below parses to the right six members AND hashes to
    // its own receipt's paramsHash, so the hash rule and every field rule pass — only the canonical
    // -encoding rule can refuse it. Without that rule "canonical JCS" is a claim about the producer's
    // intent rather than a property of the bytes, and one parameter set can carry several different
    // accepted hashes: the same ambiguity the unknown-member refusal exists to prevent, by another door.
    ...NONCANONICAL_PREIMAGES.map(({ label, text, seed }) => {
      const ph = "sha256:" + sha256Hex(text);
      const r = mintReceipt({ id: `rcpt_payment_${seed}`, paramsHash: ph });
      const g = mintGrant({ receipt: r, envelope, paramsHash: ph, grantId: `grant-${seed}`, nonce: seed.repeat(32) });
      return vec(`reject-params-preimage-noncanonical-${label}`,
        `R-HASH-2 canonical form (${label}) — the bytes parse to the six approved members and hash to their own receipt's paramsHash, but they are not the JCS encoding of that document. Accepting them lets one set of parameters carry more than one valid paramsHash.`,
        "REJECT", "SETTLEMENT_BOUNDS_UNCHECKABLE",
        baseInput({
          receiptChain: [r],
          grant: g,
          paramsPreimage: text,
          artifactOver: {
            authorizationReceiptHash: r.chain.hash,
            executionGrantHash: sha256Prefixed(canonicalize(g)),
            correlation: d7Nonce(digestOf(r, g), seed.repeat(32)),
          },
        }));
    }),
    vec("reject-chainid-from-artifact",
      "REVISION 3 — a UNIFORMLY testnet-consistent artifact + chain facts (what an implementation lifting derivation inputs from the artifact would accept) against a preimage that says mainnet: the verified preimage wins.",
      "REJECT", "SETTLEMENT_NETWORK_UNEXPECTED",
      baseInput({
        artifactOver: {
          correlation: correlationTestnet,
          witness: { network: NETWORK_TESTNET, asset: ASSET_TESTNET },
        },
        chainFacts: mintChainFacts({ network: NETWORK_TESTNET, asset: ASSET_TESTNET, transferAddress: TOKEN_TESTNET, nonce: correlationTestnet }),
      })),
    vec("reject-unsafe-chainid",
      "A chainId the schema grammar admits (19 digits max) but the derivation refuses (> 2^53-1, non-safe integer): fail-closed by arithmetic, and this vector is what makes that documented claim measured. No silent misderivation band exists — any inexact Number() rounding lands on a non-safe integer.",
      "REJECT", "SETTLEMENT_CORRELATION_MISMATCH",
      baseInput({
        receiptChain: [receiptUnsafe],
        grant: grantUnsafe,
        paramsPreimage: preimageUnsafeText,
        chainFacts: null,
        artifactOver: {
          authorizationReceiptHash: receiptUnsafe.chain.hash,
          executionGrantHash: sha256Prefixed(canonicalize(grantUnsafe)),
          correlation,
          witness: { network: NETWORK_UNSAFE, asset: ASSET_UNSAFE },
        },
      })),
    vec("reject-testnet-as-mainnet",
      "B1 — testnet coordinates presented for a mainnet mandate.",
      "REJECT", "SETTLEMENT_NETWORK_UNEXPECTED",
      baseInput({ artifactOver: { witness: { network: NETWORK_TESTNET, asset: ASSET_TESTNET } } })),
    vec("reject-counterfeit-asset",
      "§9.6 / B2 — a look-alike EIP-3009 token emits a genuine AuthorizationUsed(payer, correlation); the asset bound against the verified preimage is what refuses it.",
      "REJECT", "SETTLEMENT_ASSET_UNEXPECTED",
      baseInput({ artifactOver: { witness: { asset: `${NETWORK}/erc20:${FAKE_TOKEN}` } } })),
    vec("reject-wrong-payer",
      "B3 — a third party burned an equal nonce from its own address; (authorizer, nonce) is the namespace.",
      "REJECT", "SETTLEMENT_PAYER_UNEXPECTED",
      baseInput({ artifactOver: { witness: { payer: MALLORY } } })),
    vec("reject-wrong-payee",
      "B4 — the observer reports a payee the mandate never approved; caught offline.",
      "REJECT", "SETTLEMENT_BOUNDS_EXCEEDED",
      baseInput({ artifactOver: { witness: { payee: MALLORY } } })),
    vec("reject-amount-over-bound",
      "B5 — reported amount above maxAmountMinorUnits.",
      "REJECT", "SETTLEMENT_BOUNDS_EXCEEDED",
      baseInput({ artifactOver: { witness: { amount: "10000001" } }, chainFacts: mintChainFacts({ value: "10000001" }) })),
    vec("reject-zero-value-burn",
      "§9.6 / B6 — a zero-value transferWithAuthorization consumes the nonce for free; 0 <= max means B5 alone cannot catch it.",
      "REJECT", "SETTLEMENT_BOUNDS_EXCEEDED",
      baseInput({ artifactOver: { witness: { amount: "0" } }, chainFacts: mintChainFacts({ value: "0" }) })),

    // ── self-consistency ────────────────────────────────────────────────────────────────────────
    vec("reject-status-inconsistent",
      "R-9 — NOT_OBSERVED with a non-null txHash is a self-contradicting artifact.",
      "REJECT", "SETTLEMENT_STATUS_INCONSISTENT",
      baseInput({ artifactOver: { witness: { status: "NOT_OBSERVED", payee: null, amount: null, blockNumber: null, settledAt: null } }, chainFacts: null })),
    vec("reject-settled-missing-amount",
      "R-10 — SETTLED with amount null: 'settled, amount unknown' must never be accepted as a positive.",
      "REJECT", "SETTLEMENT_STATUS_INCONSISTENT",
      baseInput({ artifactOver: { witness: { amount: null } } })),
    vec("reject-amount-over-uint256",
      "R-11b — a 78-digit amount the schema regex admits and no EIP-3009 contract could emit.",
      "REJECT", "SETTLEMENT_STATUS_INCONSISTENT",
      baseInput({ artifactOver: { witness: { amount: "2" + "0".repeat(77) } } })),
    vec("reject-asset-network-mismatch",
      "R-11c — asset on eip155:8453 under network eip155:84532; the two patterns do not enforce agreement.",
      "REJECT", "SETTLEMENT_NETWORK_UNEXPECTED",
      baseInput({ artifactOver: { witness: { network: NETWORK_TESTNET } } })),
    vec("reject-settled-before-grant",
      "R-13 — a settlement that predates its authorization is incoherent.",
      "REJECT", "SETTLEMENT_ORDERING_INVALID",
      baseInput({ artifactOver: { witness: { settledAt: T_BEFORE_GRANT } }, chainFacts: mintChainFacts({ blockTimestamp: T_BEFORE_GRANT }) })),
    vec("reject-unknown-rail-family",
      "R-6 — an unknown rail family fails CLOSED: different rails bind the correlation with different strength.",
      "REJECT", "SETTLEMENT_RAIL_FAMILY_UNKNOWN",
      baseInput({ artifactOver: { railFamily: "x402/upto/eip3009" } })),
    vec("reject-observer-identity-split",
      "The document names one observer and is signed by another; without this the R-16 cap is dodged by naming a different kid.",
      "REJECT", "SETTLEMENT_OBSERVER_IDENTITY_SPLIT",
      baseInput({ artifactOver: { observerKid: OBSERVER.kid, signerKey: GATE } })),
    vec("reject-malformed-base64",
      "R-RAIL-2(i) — OUR OWN artifact malformed: bytes that fail the strict base64 round-trip. Buffer.from(s, 'base64') never throws, so the round-trip is the check.",
      "REJECT", "ARTIFACT_TAMPERED",
      baseInput({ artifactOver: { railReceipt: { ...RAIL_RECEIPT_FULL, bytes: "AB" } } })),
    vec("reject-impossible-settledAt",
      "settledAt names a day that does not exist (2026-07-44). Date.UTC used to NORMALIZE it to Aug 13 — the base fixture's real block time — and the artifact earned the positive; the strict calendar parser refuses the string outright.",
      "REJECT", "ARTIFACT_TAMPERED",
      baseInput({ artifactOver: { witness: { settledAt: "2026-07-44T10:05:04.000Z" } } })),

    // ── layer 6 ─────────────────────────────────────────────────────────────────────────────────
    vec("reject-substituted-payment",
      "§9.1 — authorizationState false, zero logs, artifact claims SETTLED: a different payment carries different bytes.",
      "REJECT", "SETTLEMENT_CHAIN_CONTRADICTED",
      baseInput({ chainFacts: mintChainFacts({ authorizationState: false, usedLogs: [], transfer: null }) })),
    vec("reject-substituted-txhash",
      "§9.1(2) / R-20 — the coordinates resolve tx X; the artifact reports tx Y. A facilitator can settle a different payment and return its txHash; a reported value can only contradict, never establish.",
      "REJECT", "SETTLEMENT_CHAIN_CONTRADICTED",
      baseInput({ artifactOver: { witness: { txHash: TX_OTHER } } })),
    vec("reject-state-false-with-log",
      "ONE SUCCESS AuthorizationUsed log with authorizationState false: EIP-3009 sets the state bit when it emits the log, so this record describes an impossible chain state and fails CLOSED. Knockout: skip the conjunction -> this vector earns the positive.",
      "REJECT", "SETTLEMENT_CHAIN_CONTRADICTED",
      baseInput({ chainFacts: mintChainFacts({ authorizationState: false }) })),
    vec("reject-log-wrong-nonce",
      "The used log carries a DIFFERENT on-chain nonce than the recomputed correlation: a log lifted from an unrelated transaction is a different payment, and without the binding field the record could not even express the difference.",
      "REJECT", "SETTLEMENT_CHAIN_CONTRADICTED",
      baseInput({ chainFacts: mintChainFacts({ nonce: "0x" + "77".repeat(32) }) })),
    vec("reject-log-wrong-authorizer",
      "The used log's authorizer is not the approved payer: EIP-3009 uniqueness is per (authorizer, nonce), so a third party's log for an equal nonce is a different fact.",
      "REJECT", "SETTLEMENT_CHAIN_CONTRADICTED",
      baseInput({ chainFacts: mintChainFacts({ authorizer: MALLORY }) })),
    vec("reject-transfer-foreign-tx",
      "The recovered transfer names a DIFFERENT transaction than the AuthorizationUsed log: the same-block decoy in another tx satisfies every value bound while the settling transaction paid someone else. Knockout: drop the txHash binding -> GREEN.",
      "REJECT", "SETTLEMENT_CHAIN_CONTRADICTED",
      baseInput({ chainFacts: mintChainFacts({ transferTxHash: TX_OTHER }) })),
    vec("reject-settledAt-contradicts-blocktime",
      "R-20's settledAt arm — a fabricated in-window settledAt contradicting the real blockTimestamp as INSTANTS; nothing else catches this fabrication, and before this vector no test executed the arm.",
      "REJECT", "SETTLEMENT_CHAIN_CONTRADICTED",
      baseInput({ chainFacts: mintChainFacts({ blockTimestamp: T_SETTLED_PLUS_1S }) })),
    vec("reject-cancel-foreign-nonce",
      "A SUCCESSFUL AuthorizationCanceled log carrying a FOREIGN (payer, nonce): before the binding fields it burned THIS correlation on an unrelated cancel (SETTLEMENT_CORRELATION_BURNED). The schema now requires the pair on canceled logs and the reconciler asserts it against the recomputed correlation, so a cancel for a different authorization contradicts the record rather than burning ours. Knockout: drop the canceled-log nonce binding -> this vector burns.",
      "REJECT", "SETTLEMENT_CHAIN_CONTRADICTED",
      baseInput({
        artifactOver: { witness: { status: "NOT_SETTLED_AT_OBSERVATION", payee: null, amount: null, txHash: null, blockNumber: null, settledAt: null } },
        chainFacts: mintChainFacts({
          usedLogs: [],
          canceledLogs: [{ txHash: TX_OTHER, blockNumber: BLOCK + 2, logIndex: 1, blockTimestamp: T_SETTLED, txStatus: "SUCCESS", nonce: "0x" + "77".repeat(32), authorizer: PAYER }],
          transfer: null,
        }),
      })),
    vec("reject-year-0099-not-1999",
      "Date.UTC(year,...) maps years 0000-0099 onto 1900-1999, so a settledAt of 0099-08-13 and a resolved blockTimestamp of 1999-08-13 (instants 1900 years apart) both parsed to 1999 and the R-20 corroboration passed -> a positive. The grant's OWN window is in year 0099, so the ordering arm does not mask it. parseInstant now sets the true year explicitly, so the two disagree as instants.",
      "REJECT", "SETTLEMENT_CHAIN_CONTRADICTED",
      baseInput({
        grant: grantY99,
        artifactOver: {
          executionGrantHash: sha256Prefixed(canonicalize(grantY99)),
          correlation: correlationY99,
          witness: { settledAt: T_SETTLED_Y0099 },
        },
        chainFacts: mintChainFacts({ nonce: correlationY99, blockTimestamp: T_BLOCK_1999 }),
      })),
    vec("reject-two-logs",
      "R-18 — two AuthorizationUsed entries for one single-use (payer, nonce): the caller's record is wrong, or the coordinates are.",
      "REJECT", "SETTLEMENT_CHAIN_CONTRADICTED",
      baseInput({
        chainFacts: mintChainFacts({
          usedLogs: [
            { txHash: TX, blockNumber: BLOCK, logIndex: 7, blockTimestamp: T_SETTLED, txStatus: "SUCCESS", nonce: correlation, authorizer: PAYER },
            { txHash: TX_OTHER, blockNumber: BLOCK + 1, logIndex: 2, blockTimestamp: T_SETTLED, txStatus: "SUCCESS", nonce: correlation, authorizer: PAYER },
          ],
        }),
      })),
    vec("reject-reverted-tx",
      "R-19b — txStatus REVERTED: a reverted transaction changes no state; a log read that ignores status is the naive check.",
      "REJECT", "SETTLEMENT_CHAIN_CONTRADICTED",
      baseInput({ chainFacts: mintChainFacts({ txStatus: "REVERTED" }) })),
    vec("reject-decoy-transfer-log",
      "R-19(b) — a batched transaction carrying a worthless-token Transfer payer->approved-payee for a compliant amount; log.address == asset refuses it. Knockout: drop the address constraint -> GREEN and the money went to mallory.",
      "REJECT", "SETTLEMENT_ASSET_UNEXPECTED",
      baseInput({
        chainFacts: mintChainFacts({ transfer: { source: "TRANSFER_LOG", address: FAKE_TOKEN, logIndex: 9, from: PAYER, to: PAYEE, value: "1000000", txHash: TX, blockNumber: BLOCK } }),
      })),
    vec("reject-two-transfer-logs",
      "R-19(b) uniqueness — two qualifying transfers, presented the only way the record can carry them; the record is refused, the verifier never picks (see the generator header).",
      "REJECT", "SETTLEMENT_CHAIN_CONTRADICTED",
      baseInput({
        chainFacts: mintChainFacts({
          transfer: [
            { source: "TRANSFER_LOG", address: TOKEN, logIndex: 8, from: PAYER, to: PAYEE, value: "1000000", txHash: TX, blockNumber: BLOCK },
            { source: "TRANSFER_LOG", address: TOKEN, logIndex: 9, from: PAYER, to: MALLORY, value: "1000000", txHash: TX, blockNumber: BLOCK },
          ],
        }),
      })),
    vec("reject-chainfacts-from-bundle",
      "R-17b — the fact record travelled inside the evidence bundle, i.e. was supplied by the party being judged.",
      "REJECT", "SETTLEMENT_CHAIN_FACTS_UNTRUSTED",
      baseInput({ chainFactsOrigin: "BUNDLE" })),
    vec("reject-insufficient-depth",
      "R-17c — a one-block-deep settlement against minConfirmations 12: never RECONFIRMED at unknown depth.",
      "REJECT", "SETTLEMENT_CORRELATED_UNRECONFIRMED",
      baseInput({ chainFacts: mintChainFacts({ headBlockNumber: BLOCK }) }),
      { expectChainStatus: "UNRECONFIRMED" }),
    vec("reject-no-min-confirmations",
      "R-17c — the caller supplied no depth policy; no upgrade.",
      "REJECT", "SETTLEMENT_CORRELATED_UNRECONFIRMED",
      baseInput({ minConfirmations: null }),
      { expectChainStatus: "UNRECONFIRMED" }),
    vec("reject-settledAt-format-variance",
      "R-20 regression pin (a non-rejection): '…04.000Z' vs '…04Z' are the SAME instant and different strings. Knockout: compare as strings -> this vector goes RED with a manufactured rejection.",
      "CONTROL", "SETTLEMENT_CORRELATED_AND_RECONFIRMED",
      baseInput({ chainFacts: mintChainFacts({ blockTimestamp: T_SETTLED_NOFRAC }) })),
    vec("reject-raw-mode-hold",
      "R-23 — hand-assembled RAW envelope under a grant that binds it, everything else green INCLUDING the chain. The cap sets chainStatus AND code AND warning together (R-22).",
      "REJECT", "SETTLEMENT_CORRELATED_UNRECONFIRMED",
      baseInput({
        receiptChain: [receipt],
        grant: grantRaw,
        holdEnvelope: envelopeRaw,
        holdResolution: null,
        chainFacts: mintChainFacts({ nonce: correlationRaw }),
        artifactOver: {
          executionGrantHash: sha256Prefixed(canonicalize(grantRaw)),
          correlation: correlationRaw,
        },
      }),
      { expectChainStatus: "UNRECONFIRMED", expectWarning: "SETTLEMENT_OVER_RAW_MODE_HOLD" }),
    vec("reject-holdresolution-unenforced",
      "R-23b — the gate-signed resolution attests HUMAN_ACK_UNENFORCED: strictly stronger than reading mode, because it is what the gate itself said.",
      "REJECT", "SETTLEMENT_CORRELATED_UNRECONFIRMED",
      baseInput({ holdResolution: mintResolution({ reasonCode: "HUMAN_ACK_UNENFORCED" }) }),
      { expectChainStatus: "UNRECONFIRMED", expectWarning: "SETTLEMENT_OVER_RAW_MODE_HOLD" }),

    // ── controls (each MUST return the stated code, never a rejection) ──────────────────────────
    vec("control-transfer-log-route",
      "R-19 route (b) with all three constraints met: address == asset, from == payer, exactly one.",
      "CONTROL", "SETTLEMENT_CORRELATED_AND_RECONFIRMED",
      baseInput({ chainFacts: mintChainFacts({ transfer: { source: "TRANSFER_LOG", address: TOKEN, logIndex: 9, from: PAYER, to: PAYEE, value: "1000000", txHash: TX, blockNumber: BLOCK } }) }),
      { expectChainStatus: "RECONFIRMED" }),
    vec("control-rail-receipt-absent",
      "R-RAIL-1 — absence must not block the positive.",
      "CONTROL", "SETTLEMENT_CORRELATED_AND_RECONFIRMED",
      baseInput({ artifactOver: { railReceipt: null } }),
      { expectRailReceiptStatus: "NOT_PROVIDED" }),
    vec("control-rail-receipt-garbage",
      "R-RAIL-2(ii) — the counterparty has no denial-of-verification switch: unparseable bytes are a warning, never a rejection.",
      "CONTROL", "SETTLEMENT_CORRELATED_AND_RECONFIRMED",
      baseInput({ artifactOver: { railReceipt: { ...RAIL_RECEIPT_FULL, bytes: Buffer.from("not json at all", "utf8").toString("base64") } } }),
      { expectRailReceiptStatus: "PROVIDED_UNPARSEABLE", expectWarning: "RAIL_RECEIPT_PROVIDED_UNPARSEABLE" }),
    vec("control-rail-receipt-wrong-signer",
      "R-RAIL-3 — signed by an address that is not payTo; we never checked, and the verdict is unmoved.",
      "CONTROL", "SETTLEMENT_CORRELATED_AND_RECONFIRMED",
      baseInput({ artifactOver: { railReceipt: { ...RAIL_RECEIPT_FULL, bytes: Buffer.from('{"receipt":"demo","signedBy":"0x00000000000000000000000000000000deadbeef"}', "utf8").toString("base64") } } }),
      { expectRailReceiptStatus: "PROVIDED_UNVALIDATED" }),
    vec("control-rail-receipt-hash-only",
      "R-RAIL-5 — the HASH_ONLY branch records a commitment and claims nothing about the withheld bytes.",
      "CONTROL", "SETTLEMENT_CORRELATED_AND_RECONFIRMED",
      baseInput({ artifactOver: { railReceipt: { disclosure: "HASH_ONLY", format: "x402-offer-receipt/eip712", bytesHash: "sha256:" + sha256Hex("withheld") } } }),
      { expectRailReceiptStatus: "HASH_ONLY" }),
    vec("control-no-chainfacts-offline",
      "R-22 — a perfect artifact with no chain access earns NO upgrade: the OFFLINE tier's best result.",
      "CONTROL", "SETTLEMENT_CORRELATED_UNRECONFIRMED",
      baseInput({ chainFacts: null }),
      { expectChainStatus: "UNRECONFIRMED" }),
    vec("control-same-key-observer",
      "R-16 — the observer kid IS the execution signer's kid, WITH green chain facts: capped, warned, never positive.",
      "CONTROL", "SETTLEMENT_CORRELATED_UNRECONFIRMED",
      baseInput({ artifactOver: { observerKid: GATE.kid, signerKey: GATE } }),
      { expectChainStatus: "UNRECONFIRMED", expectObserverRelationship: "SAME_SIGNING_KEY", expectWarning: "SETTLEMENT_OBSERVER_SAME_KEY_AS_EXECUTION_SIGNER" }),
    vec("control-alias-kid-observer",
      "The grant signer's PUBLIC KEY registered under a SECOND kid holding the observer role; the artifact is signed with that key under the alias. This is BOTH the alias evasion of a kid-string R-16 cap AND the legitimate dual-role configuration (one key, both roles, two kids): the byte-level cap catches both. Knockout: revert the cap to kid-string equality -> this vector earns the positive.",
      "CONTROL", "SETTLEMENT_CORRELATED_UNRECONFIRMED",
      baseInput({ keyring: KEYRING_WITH_ALIAS, artifactOver: { observerKid: OBSERVER_ALIAS.kid, signerKey: OBSERVER_ALIAS } }),
      { expectChainStatus: "UNRECONFIRMED", expectObserverRelationship: "SAME_SIGNING_KEY", expectWarning: "SETTLEMENT_OBSERVER_SAME_KEY_AS_EXECUTION_SIGNER" }),
    vec("control-not-observed",
      "§3.2's three-value status: 'we did not look' is NOT 'it did not happen' — and no code containing DID_NOT or FAILED exists to return.",
      "CONTROL", "SETTLEMENT_NOT_OBSERVED",
      baseInput({ artifactOver: { witness: { status: "NOT_OBSERVED", payee: null, amount: null, txHash: null, blockNumber: null, settledAt: null } }, chainFacts: null })),
    vec("control-not-settled-at-observation",
      "The third status value finally has somewhere to surface — distinguishable from the no-chain-facts case.",
      "CONTROL", "SETTLEMENT_NOT_SETTLED_AT_OBSERVATION",
      baseInput({ artifactOver: { witness: { status: "NOT_SETTLED_AT_OBSERVATION", payee: null, amount: null, txHash: null, blockNumber: null, settledAt: null } }, chainFacts: null })),
    vec("control-correlation-cancelled",
      "R-21b — authorizationState true, zero AuthorizationUsed, one AuthorizationCanceled: burned without payment, terminal, NOT 'not yet'. Knockout: drop the cancel branch -> UNRECONFIRMED forever.",
      "CONTROL", "SETTLEMENT_CORRELATION_BURNED",
      baseInput({
        artifactOver: { witness: { status: "NOT_SETTLED_AT_OBSERVATION", payee: null, amount: null, txHash: null, blockNumber: null, settledAt: null } },
        chainFacts: mintChainFacts({
          usedLogs: [],
          canceledLogs: [{ txHash: TX_OTHER, blockNumber: BLOCK + 2, logIndex: 1, blockTimestamp: T_SETTLED, txStatus: "SUCCESS", nonce: correlation, authorizer: PAYER }],
          transfer: null,
        }),
      }),
      { expectChainStatus: "CANCELLED" }),
    vec("control-reverted-cancel-ignored",
      "A REVERTED cancelAuthorization entry alongside the genuine settlement: a reverted transaction changed no state, so it neither contradicts the settlement nor counts toward a burn. A post-settlement cancel reverting with 'authorization already used' is a real, observable chain event; flipping an honest settlement on it manufactures a rejection from an honest state.",
      "CONTROL", "SETTLEMENT_CORRELATED_AND_RECONFIRMED",
      baseInput({
        chainFacts: mintChainFacts({
          canceledLogs: [{ txHash: TX_OTHER, blockNumber: BLOCK + 2, logIndex: 1, blockTimestamp: T_SETTLED, txStatus: "REVERTED", nonce: correlation, authorizer: PAYER }],
        }),
      }),
      { expectChainStatus: "RECONFIRMED" }),
    vec("control-reverted-cancel-foreign-nonce",
      "The precedence rule, pinned from the other side: a REVERTED cancelAuthorization entry carrying a FOREIGN (payer, nonce) alongside the genuine settlement. Its sibling control proves a reverted cancel with OUR coordinates is ignored; this one proves the coordinate binding is checked FIRST and on EVERY canceled entry, because a record assembled for one authorization that carries another authorization's log is a broken record whatever that log's transaction did. Knockout: apply the binding only to SUCCESS cancels -> a record naming somebody else's authorization earns the positive.",
      "REJECT", "SETTLEMENT_CHAIN_CONTRADICTED",
      baseInput({
        chainFacts: mintChainFacts({
          canceledLogs: [{ txHash: TX_OTHER, blockNumber: BLOCK + 2, logIndex: 1, blockTimestamp: T_SETTLED, txStatus: "REVERTED", nonce: "0x" + "77".repeat(32), authorizer: PAYER }],
        }),
      }),
      { expectChainStatus: "CONTRADICTED" }),
    vec("control-settled-after-grant-expiry",
      "R-13 SHOULD — facilitator delay pushed settlement past the grant window; the single-use burn already happened at dispatch. A warning, not a rejection — named so nobody tightens it into a false negative.",
      "CONTROL", "SETTLEMENT_CORRELATED_AND_RECONFIRMED",
      baseInput({
        artifactOver: { witness: { settledAt: T_AFTER_EXPIRY }, observedAt: T_OBSERVED_LATE },
        chainFacts: mintChainFacts({ blockTimestamp: T_AFTER_EXPIRY, queriedAt: T_QUERIED_LATE }),
        now: T_NOW_LATE,
      }),
      { expectWarning: "SETTLEMENT_AFTER_GRANT_EXPIRY" }),
  ];

  return {
    spec: "noa.settlement-evidence/0.1",
    correlationContract: "D7 — deriveCorrelationNonce({chainId, tokenAddress, payerAddress, dispatchId: the action-digest string, seed: hex-decoded grant.nonce})",
    generatedFrom: "packages/rail-x402/conformance/gen-settlement-evidence-vectors.mjs",
    keyring: KEYRING,
    note:
      "Generated, committed and drift-gated (the runner re-derives this corpus in memory and diffs). " +
      "Keys are FIXED test-only seeds; their private halves are effectively public and must never be reused. " +
      "Exactly ONE vector has expect=ACCEPT; controls that share the positive code assert the code, not acceptance.",
    vectors,
  };
}

// ── CLI: write the committed corpus ─────────────────────────────────────────────────────────────
const isMain = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];
if (isMain) {
  const __dirname = dirname(fileURLToPath(import.meta.url));
  const outDir = join(__dirname, "settlement-evidence");
  const corpus = buildCorpus();
  mkdirSync(outDir, { recursive: true });
  writeFileSync(join(outDir, "vectors.json"), JSON.stringify(corpus, null, 2) + "\n");
  console.error(`wrote conformance/settlement-evidence/vectors.json — ${corpus.vectors.length} vectors`);
}
