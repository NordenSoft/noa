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
- **[UNVERIFIED] hosted-facilitator nonce policy.** The canonical Go facilitator's `verifyEIP3009`
  never inspects nonce content — the helpers check only 32-byte length and not-already-used. Whether
  a **hosted** facilitator (Coinbase CDP, thirdweb, Cloudflare) adds a randomness or entropy check
  that would reject a derived nonce is **not verified**. One testnet round-trip through the intended
  facilitator settles it, and that round-trip has not been run. If a hosted facilitator does reject
  derived nonces, the correlation property is lost — the payment rail is not.
- **No mandate approval is proven by any of this**, and no service delivery. See the scope sentence
  at the top, and `NON-CLAIMS.md` in the repository root.
