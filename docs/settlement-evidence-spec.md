# `noa.settlement-evidence/0.1` — settlement-evidence reconciliation (layers 4+6, `noa-rail-x402`)

Key words **MUST**, **MUST NOT**, **SHOULD**, **MAY** are to be interpreted as in RFC 2119.

This document is the public, self-contained specification for the reconciler shipped in
`packages/rail-x402/src/settlement-evidence.mjs` (`reconcileSettlementEvidence`) and its
conformance corpus (`packages/rail-x402/conformance/settlement-evidence/vectors.json`). It pins,
byte for byte, the one thing two independent implementations must never disagree on: **how the
on-chain correlation nonce is composed from the mandate documents**.

## 1. The claims ceiling, stated first

The honest ceiling of this artifact class is:

> **At most one settlement is correlatable to this grant.**

Never "exactly one settlement per mandate" — a compromised gate can still mint additional grants,
each of which derives its own nonce and needs its own real settlement — and never a human-approval
claim. The only outer product sentence remains `packages/rail-x402/README.md`'s: *Base consensus
proves that a payer-authorized USDC transfer, matching a locally correlated mandate artifact,
settled.* Nothing here proves service delivery, and nothing here proves the approver authorised
the payment (the correlation proves the payer key signed; the link to the mandate rests on
locally-held documents). See `NON-CLAIMS.md` §NC-S4 for the full non-claims register.

**And the ceiling has a precondition, which is part of the claim.** Every verdict below assumes an
unpoisoned runtime. A party that can execute code inside the verifier's own process, before or
during verification, can rewrite the language's built-in operations and manufacture any verdict on
evidence it never had to forge — reproduced, end to end, against this document's own corpus. This
implementation therefore performs every verdict-bearing computation through bindings captured when
the module loaded, and a source-level gate blocks new live ones; that raises the cost of an
in-process attack and is not a boundary. Where the answer is worth money it belongs somewhere the
counterparty cannot run code. Stated in full as `NON-CLAIMS.md` §NC-S4.16, which governs.

## 2. The artifact

`noa.settlement-evidence/0.1` is an observer-signed side artifact with root members
`spec` · `tenant` · `chain` · `authorizationReceiptHash` (`sha256:<64hex>`, rule (a): the ALLOWED
receipt's own `chain.hash`) · `executionGrantHash` (`sha256:<64hex>`, rule (b): SHA-256 over the
JCS of the WHOLE signed grant) · `correlation` · `railFamily` · `chainWitness` · `railReceipt` ·
`observerKid` · `observedAt` · `sig`.

- **`correlation` is the on-chain nonce in its `0x<64hex>` form** — lowercase; uppercase is a
  refusal, not a normalization.
- `chainWitness` carries nine always-present members (`status`, `network`, `asset`, `payer`,
  `payee`, `amount`, `txHash`, `blockNumber`, `settledAt`), the last five nullable.
  `status` has THREE values — `SETTLED`, `NOT_SETTLED_AT_OBSERVATION`, `NOT_OBSERVED` — and
  deliberately no `FAILED`: the chain can witness a non-consumption-so-far, never a failure.
  `amount` is a decimal string of minor units, never a JSON number (`uint256` exceeds every
  float-safe integer range and canonical JSON refuses unsafe numbers).
- `railReceipt` is `null`, a `FULL` branch (strict base64 of the counterparty's receipt bytes,
  exactly as received) or a `HASH_ONLY` branch (`sha256:` of the raw received bytes). It is
  **structurally non-load-bearing** (§7).

The chain-facts input has its own normative schema:
`packages/rail-x402/schema/noa-chain-facts-0.1.schema.json` (`noa.chain-facts/0.1`), enforced by
the strict hand-rolled validator exported as `validateChainFacts` and kept in lock-step by a
field-by-field mirror test.

## 3. The correlation derivation — pinned byte for byte

The nonce is the output of the shipped derivation (`deriveCorrelationNonce`,
`packages/rail-x402/src/correlation-nonce.mjs`), whose preimage is a SHA-256 over
**length-prefixed fields in a fixed order**. Each field is encoded as:

```
utf8(label) ‖ utf8(":") ‖ utf8(decimal byte length of value) ‖ utf8(":") ‖ value-bytes
```

and the six fields are hashed in exactly this order:

| # | label | value-bytes |
|---|---|---|
| 1 | `domain` | `utf8("noa.x402.correlation-nonce/0.1")` — any change to the derivation is a NEW tag |
| 2 | `chainId` | `utf8(decimal ASCII chainId)` — e.g. `8453`, no leading zeros, no hex |
| 3 | `token` | `utf8(lowercased 0x-ASCII token contract address)` — 42 characters |
| 4 | `payer` | `utf8(lowercased 0x-ASCII payer address)` — 42 characters |
| 5 | `dispatch` | `utf8(dispatchId)` — see below |
| 6 | `seed` | the 32 raw seed bytes |

```
nonce = "0x" ‖ lowercase-hex( SHA256( field1 ‖ field2 ‖ field3 ‖ field4 ‖ field5 ‖ field6 ) )
```

**`dispatchId` is the `noa.action-digest/0.1` value AS ITS ASCII STRING `"sha256:<64hex>"` — the
`sha256:` prefix IS part of the preimage.** It is the exact output of the kernel's action-digest
construction over the ALLOWED receipt and the signed execution grant (see
`docs/action-digest-spec.md`); it is 71 ASCII characters, so field 5 is always
`dispatch:71:sha256:<64hex>`.

**The seed is the 32 bytes hex-decoded from `grant.nonce`.** The execution-grant schema pins
`nonce` to `^[0-9a-f]{64}$` (exactly 32 bytes, lowercase hex, minted from a CSPRNG). There is no
seed field in any artifact: **the grant IS the pre-dispatch seed commitment**. One grant → exactly
one derivable nonce, so per-grant settlement singularity is enforced by arithmetic, not by prose.
A sibling-seed settlement (same grant, different seed) can settle on-chain and can NEVER earn a
positive verdict, because recomputation from the bundle's own documents yields THE one nonce.

**Derivation-input provenance is normative.** `chainId`, `token` and `payer` come ONLY from the
hash-verified canonical params preimage (§4):

- `chainId` = the decimal tail of the preimage's `networkCaip2` (`"eip155:8453"` → `8453`).
  The CAIP-2 grammar admits up to 19 decimal digits, but the derivation refuses any chainId above
  2^53−1 (non-safe integer) — such a coordinate set is FAIL-CLOSED (`SETTLEMENT_CORRELATION_MISMATCH`,
  vector `reject-unsafe-chainid`); no silent misderivation band exists, because any inexact
  `Number()` rounding lands on a non-safe integer;
- `token` = the address tail of the preimage's `assetCaip19`
  (`"eip155:8453/erc20:0x…"` → `0x…`);
- `payer` = the preimage's `payer`.

Never from the artifact, and never from `receipt.scope.chain` (an opaque receipt-chain identifier
unrelated to any EVM chainId). A verifier that reads these three from the artifact will accept a
testnet settlement as mainnet; the conformance vector `reject-chainid-from-artifact` pins the
refusal.

## 4. The canonical params preimage

The approved bounds come from a caller-supplied byte string, verified BEFORE one field is read:

```
"sha256:" ++ lowercase-hex(SHA256(preimage bytes)) == allowedReceipt.action.paramsHash
```

The preimage MUST parse (strict JSON: duplicate keys refused) to an object with **exactly six
members, all strings**: `payer`, `payee`, `assetCaip19`, `networkCaip2`, `maxAmountMinorUnits`,
`resource` — canonicalized with JCS (RFC 8785). **An unknown member is a refusal, not a
tolerance**: an accepted extra member lets two honest parties holding "the same" params compute
two different `paramsHash` values.

If `action.paramsHash` uses the keyed `hmac-sha256:` form, the preimage is not third-party
checkable: the result is `boundsStatus: UNCHECKED` with code `SETTLEMENT_BOUNDS_UNCHECKABLE`, and
— because the derivation inputs live in the preimage — **the keyed form blocks the D7 derivation
too, not only the bounds**. The same code covers a missing preimage and a hash mismatch.

## 5. Verification

Verification of the full artifact is the AND of six layers. **Layers 1–3 and 5 (schema, observer
signature and F15 trust matrix, reference-hash linkage, time policy) are owned by the generic
side-artifact verifier and the evidence pipeline. `reconcileSettlementEvidence` implements layers
4 and 6 over PRE-VERIFIED inputs, and its positive result over unauthenticated inputs means
nothing.** Provisioning a `settlement-observer` key is an OPERATOR CEREMONY: no gate constructor
in this repository mints one, so a deployment built from this repository alone rejects every
settlement-evidence artifact at the F15 role check — fail-closed by design — until the operator
enrolls an observer key in the tenant key manifest. What it does authenticate itself is the pair of bundle documents the correlation is
recomputed from: the receipt chain and the grant go through the kernel's `verifyActionDigest`
(bytes-in; runs the receipt-chain verification and the grant's Ed25519 signature against the
caller keyring) — never the bare digest builder.

The reconciler's obligations, in evaluation order:

1. **Byte boundary.** Every document input is bytes and is strictly parsed before any field is
   read. The reconciler never throws; every outcome is the §6 envelope.
2. **Self-consistency.** `observerKid == sig.kid`; the rail family is in the shipped set
   (`{"x402/exact/eip3009"}`, fail-closed); `tenant`/`chain` equal the verifier's OWN expected
   values (never lifted from the bundle); a non-`SETTLED` status forces the five reported fields
   to null and `SETTLED` forbids null `payee`/`amount`; amounts parse within `uint256`; `asset`
   begins with `network + "/"`.
3. **Authenticate + recompute.** `verifyActionDigest` over the receipt chain, grant and keyring;
   then the artifact's two reference hashes must equal the RECOMPUTED receipt/grant hashes, and
   the supplied hold envelope's hash must equal `grant.holdEnvelopeHash`.
4. **Bounds (§4 preimage).** B1 network == approved network · B2 asset == approved asset ·
   B3 payer == approved payer · B4 payee == approved payee · B5 amount <= approved max
   (`<=`, deliberately: a mandate bounds a payment; exactness is the caller's opt-in via
   `expectedAmountMinorUnits`) · B6 amount > 0 (a zero-value settlement is a free nonce burn).
   The six run offline against the artifact's reported fields, and again against the chain facts
   when present. Addresses and CAIP identifiers compare lowercased on both sides; amounts compare
   as arbitrary-precision integers; instants compare as parsed time.
5. **The correlation.** Recompute the D7 nonce (§3) from the verified preimage, the recomputed
   digest and the grant's seed; compare byte-exact on the 64 lowercase hex characters against
   `correlation`. Any disagreement — including a sibling-seed nonce that really settled — is
   `SETTLEMENT_CORRELATION_MISMATCH`. A supplied correlation is NEVER accepted.
6. **Chain reconciliation (layer 6).** The verifier performs no network I/O. Chain facts arrive
   as a byte-parsed `noa.chain-facts/0.1` record that MUST originate from the relying party's own
   node — a record supplied by the bundle producer, observer, facilitator or payee is refused
   (`SETTLEMENT_CHAIN_FACTS_UNTRUSTED`). The positive `chainStatus: RECONFIRMED` requires the
   full conjunction, bound to ONE successful transaction (revised 2026-08-13 — the binding fields
   below are what MAKE "one transaction" checkable rather than asserted):
   `authorizationState == true` (checked on the one-log path BEFORE the log is processed) AND
   exactly one `AuthorizationUsed` log AND its `nonce == the recomputed D7 correlation nonce` AND
   its `authorizer == the approved payer` AND its `txStatus == "SUCCESS"` AND zero SUCCESSFUL
   `AuthorizationCanceled` logs (a REVERTED cancel changed no state: it neither contradicts a
   settlement nor counts toward a burn) AND a transfer recovered under the route constraints
   (`transfer.address == approved token contract`, `transfer.from == approved payer`,
   `transfer.txHash == the used log's txHash` and `transfer.blockNumber == the used log's
   blockNumber` — same transaction, same block — exactly one; the single-transfer record shape IS
   the uniqueness rule) AND every reported-field corroboration agreed (reject-only, normalized
   domains) AND the caller's depth (`minConfirmations`) and freshness (`now` +
   `freshnessWindowMs` over `queriedAt` and `observedAt`) thresholds were supplied and met AND
   `boundsStatus == WITHIN`.
   `authorizationState == true` alone is NEVER settlement: cancellation sets the same bit; a
   burned correlation (zero used logs, ≥1 SUCCESSFUL canceled log) is `chainStatus: CANCELLED`
   with `SETTLEMENT_CORRELATION_BURNED` — terminal, not "not yet". Every `AuthorizationCanceled`
   log carries the same `(nonce, authorizer)` binding a used log does, and it is asserted against
   the recomputed correlation and the approved payer BEFORE the cancel may burn or contradict: a
   cancel that names a different `(payer, nonce)` describes an unrelated authorization and is a
   `SETTLEMENT_CHAIN_CONTRADICTED`, never a burn of this one.

   **The precedence of the two cancel rules, stated so it cannot be read two ways.** The
   coordinate binding and the `txStatus` filter answer different questions, and they run in this
   order:

   1. **Binding FIRST, on EVERY canceled entry, whatever its `txStatus`.** A record submitted for
      the adjudicated `(payer, nonce)` may not contain an entry naming a different one. That is a
      property of the RECORD, not of the entry's outcome: the relying party's node was asked for
      one authorization's logs and handed back somebody else's, so the record is broken and the
      verifier refuses it — `SETTLEMENT_CHAIN_CONTRADICTED`. A reverted transaction is still a
      real, attributable chain event carrying a real `(authorizer, nonce)`; "it reverted" says
      nothing about whether the record describes the right authorization.
   2. **`txStatus` SECOND, among the entries that ARE ours.** Only a `SUCCESS` cancel changed any
      state, so only a `SUCCESS` cancel counts toward the burn or contradicts a settlement. A
      `REVERTED` cancel carrying OUR coordinates is a NON-EVENT: it neither contradicts a genuine
      settlement (a post-settlement cancel reverting with "authorization already used" is exactly
      what an honest chain looks like) nor satisfies the burn.

   So a `REVERTED` cancel is ignored when it is ours and refused when it is not, and the two
   sentences do not conflict: the first rule is about record INTEGRITY, the second about entry
   OUTCOME. Both are pinned by vectors — `control-reverted-cancel-ignored` and
   `control-reverted-cancel-foreign-nonce`.
7. **Caps.** Each cap sets `chainStatus` (to `UNRECONFIRMED`) AND the code
   (`SETTLEMENT_CORRELATED_UNRECONFIRMED`) AND its warning, together:
   - the **same-signing-key observer** — the observer key and the execution-signer key are **the
     same KEY**, compared as resolved public-key MATERIAL through the verifier keyring (kid equality
     is only a same-kid fast path: two equal kids name one key by construction). The cap keys on the
     RELATIONSHIP, not on how the role was obtained, so it MUST fire on the legitimate dual-role
     configuration too — one key registered under two kids, one saying "I dispatched it" and the
     other "and it settled". A kid-string-only comparison is evaded by that alias registration and
     is NOT conforming; and
   - the **RAW-mode hold** (envelope `mode != "ENFORCED"`, or a gate-signed hold resolution carrying
     `HUMAN_ACK_UNENFORCED`).

   Only `chainStatus: RECONFIRMED` may upgrade any outcome anywhere.

## 6. The result envelope

Every return carries every field (never absent, never null except where typed so):

```json
{
  "purpose": "PAYMENT_SETTLEMENT",
  "artifactStatus":       "VALID | INVALID",
  "linkageStatus":        "MATCH | MISMATCH | UNCHECKED",
  "correlationStatus":    "MATCH | MISMATCH | UNCHECKED",
  "boundsStatus":         "WITHIN | EXCEEDED | UNCHECKED",
  "chainStatus":          "RECONFIRMED | UNRECONFIRMED | CONTRADICTED | CANCELLED",
  "railReceiptStatus":    "NOT_PROVIDED | PROVIDED_UNVALIDATED | PROVIDED_UNPARSEABLE | HASH_ONLY | UNCHECKED",
  "witnessTrustStatus":   "UNKNOWN",
  "purposeStatus":        "SUFFICIENT | INSUFFICIENT",
  "observerRelationship": "SAME_SIGNING_KEY | SAME_ADMINISTRATIVE_PARTY | UNKNOWN",
  "observerRelationshipSource": "VERIFIER_DERIVED",
  "trustPolicyHash":      "sha256:…",
  "registrySnapshotHash": "sha256:…",
  "reconciled":           { "amountMinorUnits": "…", "payee": "0x…", "asset": "…", "network": "…",
                            "txHash": "0x…", "blockNumber": 0, "logIndex": 0 },
  "code":                 "<stable code>",
  "reason":               "<refusal cause, verbatim> | null",
  "warnings":             ["…"]
}
```

- A status field the evaluation never reached reads `"UNCHECKED"`; `witnessTrustStatus` is
  constantly `"UNKNOWN"` in this reconciler because the observer trust matrix is layer 2's and a
  value this function did not derive would be a claim without a control.
- `reconciled` is `null` unless `chainStatus` is `RECONFIRMED` — a positive verdict that cannot
  say what settled is not auditable evidence.
- `observerRelationship` is verifier-derived and travels with the policy identity
  (`trustPolicyHash` over the caller's own thresholds, `registrySnapshotHash` over the supplied
  keyring bytes). There is deliberately no `INDEPENDENT_ORGANIZATION` value: the system cannot
  currently derive one, and an underivable enum member is an invitation to claim it.

### Stable codes

Positive (exactly one): `SETTLEMENT_CORRELATED_AND_RECONFIRMED`.

Non-positive, not failures: `SETTLEMENT_CORRELATED_UNRECONFIRMED` ·
`SETTLEMENT_NOT_OBSERVED` · `SETTLEMENT_NOT_SETTLED_AT_OBSERVATION` ·
`SETTLEMENT_BOUNDS_UNCHECKABLE` · `SETTLEMENT_CORRELATION_BURNED`.

Rejections: `ARTIFACT_TAMPERED` · `AUTHORIZATION_RECEIPT_MISMATCH` · `EXECUTION_GRANT_MISMATCH` ·
`SETTLEMENT_RECEIPT_ROLE_UNFIT` · `SETTLEMENT_CORRELATION_MISMATCH` ·
`SETTLEMENT_TENANT_MISMATCH` · `SETTLEMENT_STATUS_INCONSISTENT` · `SETTLEMENT_ORDERING_INVALID` ·
`SETTLEMENT_BOUNDS_EXCEEDED` · `SETTLEMENT_ASSET_UNEXPECTED` · `SETTLEMENT_NETWORK_UNEXPECTED` ·
`SETTLEMENT_PAYER_UNEXPECTED` · `SETTLEMENT_CHAIN_CONTRADICTED` ·
`SETTLEMENT_RAIL_FAMILY_UNKNOWN` · `SETTLEMENT_OBSERVER_IDENTITY_SPLIT` ·
`SETTLEMENT_CHAIN_FACTS_UNTRUSTED`.

Warnings (never rejections): `SETTLEMENT_AFTER_GRANT_EXPIRY` ·
`SETTLEMENT_OBSERVER_SAME_KEY_AS_EXECUTION_SIGNER` · `RAIL_RECEIPT_PROVIDED_UNPARSEABLE` ·
`SETTLEMENT_OVER_RAW_MODE_HOLD`.

There is deliberately no `SETTLEMENT_DID_NOT_OCCUR` and no `FAILED` code: absence of a settlement
observation is not evidence of non-payment. The registry is mechanically closed: the conformance
runner asserts every code above is emitted by at least one committed vector and every emitted code
is registered.

## 7. The rail receipt is never load-bearing

The x402 rail receipt is signed by the party being paid. No conforming verifier validates its
signature, parses it for a load-bearing fact, or lets its presence, absence, content or format
move any status field other than `railReceiptStatus` — and `railReceiptStatus` gates no positive
code. Malformed base64 in OUR OWN artifact (strict round-trip) is `ARTIFACT_TAMPERED`; bytes that
do not parse as the declared format are a warning, never a rejection — rejecting would hand the
counterparty a denial-of-verification switch.

## 8. Conformance corpus

`packages/rail-x402/conformance/settlement-evidence/vectors.json` — deterministic (fixed seeded
keys, fixed timestamps, no randomness at generation time), regenerated by
`packages/rail-x402/conformance/gen-settlement-evidence-vectors.mjs` and drift-gated by the
runner. Exactly ONE vector is an ACCEPT; every vector asserts the CODE, not a boolean; the
anti-vacuity knockouts (the D7 seed pin, the R-19(b) address constraint, the transfer-transaction
binding, the state conjunction, the byte-level same-key cap, the settledAt instant arm, the
canceled-log (nonce, authorizer) binding, and the proleptic-year parse) are registered in the
repository's control-knockout registry and are proven to turn named vectors red.

A second suite alongside the corpus (`packages/rail-x402/test/poison-resistance.test.mjs`)
re-runs, as regression pins, each in-process attack that was reproduced flipping a real verdict on
these vectors: a substituted text decoder, a rewritten byte compare, a fabricated timestamp match,
a constant epoch, a recorded-and-replayed correlation derivation, a rewritten address
normalisation, and a decode rewritten to make the artifact's own base64 round-trip a tautology.
An independent implementation is not required to reproduce those tests, but it IS subject to the
same ceiling: see §1 and `NON-CLAIMS.md` §NC-S4.16.

## 9. Non-claims (summary — the register in `NON-CLAIMS.md` §NC-S4 governs)

`RECONFIRMED` is a statement about the caller's chain facts, not about the chain · the
correlation proves the payer key signed, not that the approver authorised · the observer and the
execution signer are not independent parties today · disclosing an evidence bundle discloses the
payer-wallet link permanently (the grant's seed makes the on-chain lookup computable by every
bundle holder) · there is no minimized (commitment-only) presentation tier in v0.1 — the
disclosed grant nonce is load-bearing for verification, and a minimized tier is a /0.2 schema
event · activity outside enforced gateways is outside coverage · **every verdict assumes an
unpoisoned runtime: a party that can run code inside the verifier's process can manufacture any
verdict on evidence it never had to forge, and no in-process defence closes that.**
