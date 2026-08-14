# noa-rail-x402

Correlate a NOA mandate with **one** x402 (EIP-3009) settlement on an allowlisted asset, and
reconcile a nonce somebody else burnt first.

## The one sentence this supports

> **Base consensus proves that a payer-authorized USDC transfer, matching a locally correlated
> mandate artifact, settled.**

Read what that does *not* say. It does not say the chain knows a NOA mandate was approved — the chain
has never heard of a mandate. It does not say a service was delivered. The correlation is **local**:
it holds because we derived the nonce and kept the seed, not because anyone on-chain attests to it.

An earlier draft of this scope sentence read "the chain proves the approved payment settled". That
was overstated and was rewritten after an adversarial review; the wording above is the one that
survived.

## How the correlation works

x402's `exact`/`eip3009` scheme has the **payer** sign an EIP-712 `TransferWithAuthorization`
containing a client-chosen `bytes32 nonce`. The token contract verifies that signature on-chain and
emits `AuthorizationUsed(address indexed authorizer, bytes32 indexed nonce)`.

Putting our correlation value in that field means the correlation is enforced by the **token
contract** and recoverable from public chain state by an indexed log filter — with no custom
settlement contract, no facilitator-supplied transaction hash, and no cooperation from the party
being paid. That last part is the point: the counterparty is precisely who has a reason not to
cooperate.

## Why the nonce is not `sha256(mandate)`

Because a bare digest of the deal is deterministic and, once used, **public forever**:

- **It leaks equality.** Two settlements carrying the same nonce prove the same mandate to anyone
  watching. "Did they pay this vendor again" becomes a public query.
- **It permits dictionary recovery.** Payment parameters are low-entropy. An observer who can guess
  them confirms the guess by recomputing the digest and matching it against the chain.

The derivation therefore binds six inputs — a domain-separation tag, `chainId`, token address, payer
address, a unique dispatch id, and a **high-entropy seed the payer keeps**. The seed is what defeats
both attacks; the other five are all guessable by anyone who knows the deal.

`deriveCorrelationNonce` returns a **seed commitment** alongside the nonce, so the payer can store it
beside the mandate and later prove the nonce came from that seed without publishing the seed.

**Losing the seed loses the ability to re-derive the nonce.** There is no fallback derivation, and
that is deliberate: a fallback would be a nonce someone else can also derive, which is the attack.

### The mandate composition contract (D7) — what `dispatchId` and `seed` ARE

When the correlation ties a NOA mandate to a settlement (the `noa.settlement-evidence/0.1` path,
`reconcileSettlementEvidence`), two of the six inputs are **pinned, not caller-chosen**:

- **`dispatchId` = the `noa.action-digest/0.1` value as its ASCII string `"sha256:<64hex>"`** —
  the `sha256:` prefix IS part of the preimage. The digest is a pure function of the ALLOWED
  receipt and the signed execution grant, so a retry (new grant) is a new dispatch id by
  construction.
- **`seed` = the 32 bytes hex-decoded from `grant.nonce`** (the grant schema pins
  `^[0-9a-f]{64}$`, minted from a CSPRNG). There is no seed field in any artifact: **the grant IS
  the pre-dispatch seed commitment.** One grant derives exactly one nonce; a sibling-seed
  settlement (same grant, different seed) can exist on-chain and can never earn a positive
  verdict, because verification recomputes the nonce from the bundle's own documents.
- `chainId`, token and payer derive ONLY from the hash-verified canonical params preimage — never
  from the artifact, never from `receipt.scope.chain`.

The octet framing (length-prefixed `label:byteLength:` fields, decimal-ASCII chainId, lowercased
0x-ASCII addresses) is pinned byte-for-byte in
[`docs/settlement-evidence-spec.md`](../../docs/settlement-evidence-spec.md) §3, together with the
verification algorithm, the result envelope and the stable codes. Because `grant.nonce` is the
seed, it is **confidentiality-critical**: whoever holds the bundle can locate the settlement
on-chain, permanently — stated as a non-claim, not papered over.

## What counts as proof

`authorizationState == true` is **not** proof. Circle's implementation sets the same state bit for
**cancellation** as for use, so a called-off payment and a settled one are indistinguishable through
it.

Proof is a conjunction of four observations, all from chain state rather than from the facilitator's
report:

1. an `AuthorizationUsed(authorizer, nonce)` log for our (payer, nonce)
2. that log's transaction succeeded (status 1)
3. the decoded call is the `transferWithAuthorization` we authorized — same token, payer, payee, value
4. a matching ERC-20 `Transfer(from, to, value)` in the same transaction

Each part is separately tested by removing it and asserting the proof is lost.

## Nonce-burning via front-running, and the reconciliation it forces

x402 uses `transferWithAuthorization`, and EIP-3009's own security-considerations section warns that
such an authorization can be extracted and front-run — `receiveWithAuthorization` exists precisely to
prevent this class.

Anyone holding the signed payload can submit it **first** and consume the nonce. **Nothing is
stolen:** payee, value, token, chain and validity window are all signature-bound, so the front-runner
pays our payee our amount and gains nothing.

The damage is to the truth. The facilitator re-verifies, sees a consumed nonce, and reports failure
**without locating the transaction that consumed it** — so the system tells a human "your payment
failed" about a payment that actually happened, and they may pay twice. For a product whose whole
claim is honest evidence of what occurred, a false negative is worse than a missing feature.

`reconcileConsumedNonce` is the required answer, and it has three outcomes, not two:

| outcome | meaning |
|---|---|
| `SETTLED` | our payment did happen; the facilitator's "failed" was a false negative |
| `NOT_OURS` | the nonce was consumed by something that is not our payment |
| `UNRESOLVED` | nothing found, or an observation missing — **never** reported as "failed" |

`UNRESOLVED` exists because the honest answer to "we could not see it" is that we could not see it.
Collapsing it into failure re-creates exactly the false negative this function removes.

## Scope: allowlisted assets only

Only assets whose EIP-3009 behaviour has been read and pinned — Base USDC on mainnet and Sepolia.
Never generic. Permit2 signs a `uint256` nonce but emits no indexed full-nonce event and its bitmap
leaks only word/bit position, so the correlation property does not survive there. An unlisted asset is
**refused rather than attempted**, because a silent attempt produces an unfalsifiable "we could not
find it" for a payment that may well have settled.

## Honest limits

- **The network is behind an injected boundary and is not exercised here.** `reconcileConsumedNonce`
  takes a `chain.findAuthorizationUse` reader. Every decision in this package is tested without a
  chain, which is correct for the logic and means the *chain-facing* half has no test in this
  package at all.
- **Hosted-facilitator nonce policy — MEASURED 2026-08-14 for one deployment; every other
  deployment stays unverified until measured.** The canonical Go facilitator's `verifyEIP3009`
  never inspects nonce content — the helpers check only 32-byte length and not-already-used. The
  hosted facilitator at `x402.org` (scheme `exact`, network `eip155:84532`) was measured with three
  signed `TransferWithAuthorization` structures from one unfunded throwaway key, differing only in
  the nonce: a DERIVED value (this package's `deriveCorrelationNonce`), a freshly random value, and
  a structured low-entropy control. All three were refused identically at the token contract's
  balance simulation (`invalid_exact_evm_insufficient_balance`) with the nonce passed through
  verbatim — no content policy was applied, and the derived nonce was signature-valid past the
  contract's signer recovery. Reproduction:
  `docs/reproductions/repro-p21-hosted-facilitator-nonce-policy.mjs` (broadcasts nothing, needs no
  funds, generates its own key). A deployment that DOES reject derived nonces loses the correlation
  property there — the payment rail is not lost; re-run the three-way comparison against any
  facilitator before publishing an availability claim for it.
- **No mandate approval is proven by any of this**, and no service delivery. See the scope sentence
  at the top, and `NON-CLAIMS.md` in the repository root.
