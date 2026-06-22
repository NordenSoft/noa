# NOA Counterparty Co-Attestation — a PRIVATE DORMANT pilot (Track A2)

### Narrowing the input-authenticity gap on ONE field, with a counterparty's independent signature

> **Status banner.** This is a **private, dormant pilot**, not a shipped feature. Its only
> implementation lives at [`test/dogfood/co-attestation.ts`](../test/dogfood/co-attestation.ts); it
> is **not** in the published package (`package.json` `files` ships `dist/src`, `schema`, and a
> fixed doc set that does **not** include `test/` or this file), it is **not** exported from
> [`src/index.ts`](../src/index.ts), and it is **not** wired into any production verification path.
> It exists to exercise, in-process, how a counterparty signature on a single input field would
> narrow the input-authenticity gap. It must not be read as a normative format. Track A2.

---

## 1. Purpose

The core honesty limit of a NOA receipt — stated plainly in
[THREAT-MODEL.md](../THREAT-MODEL.md) ("L2 input-authenticity / the oracle limit") and the
[receipt-spec §9](./receipt-spec.md) honesty razor — is this: a receipt proves **"with these
inputs, this policy produced this verdict," on an authenticated carrier**. It does **not** prove
the inputs were *true*. A compromised or lying agent can emit a fully-valid, fully-verifying
receipt over inputs it fabricated (for example, a refund amount it invented). L2 policy-compliance
certifies *consistency of a self-reported decision*; it cannot certify that the recorded amount was
the amount the counterparty actually agreed to.

This pilot narrows that gap on **one** input slice by introducing a second, independent signer. A
counterparty to the action — the payment receiver/payee, or the payment rail — co-signs one input
field (the integer-minor-unit amount) of a receipt. The receipt then carries that co-attestation,
so a verifier can confirm that this particular field was attested by the **counterparty** (under
its own key, in a trust root distinct from the receipt's keyring) — not merely asserted by the
agent's operator.

This **narrows** the oracle gap on that one field. It does **not** close it. Every field the
counterparty did not attest stays exactly as operator-asserted as before.

## 2. Status

PRIVATE DORMANT pilot. Specifically:

- **Not published.** The implementation lives at `test/dogfood/co-attestation.ts`. `package.json`
  `files` ships `dist/src`, `schema`, `docs/receipt-spec.md`, `LICENSE`, `NOTICE`, `README.md`,
  `THREAT-MODEL.md`, and `SECURITY.md`. `test/` is excluded, so this code — and this document —
  never reach an installed package.
- **Not exported.** No symbol from this module appears in `src/index.ts`. The public API surface is
  unchanged.
- **Not wired to any production path.** Nothing in `src/` imports or references it; no verifier,
  CLI, or COSE path consumes a `CoAttestation`.
- **Track A2.** A dogfood exercise, not a format commitment.

The cross-references below to L2, the federation, and the threat model point at the *governed*
layers; this pilot touches only already-public primitives and invents nothing in their territory
(see §6).

## 3. The artifact

A `CoAttestation` is a detached Ed25519 signature by a counterparty, binding one attested value to
one exact receipt.

### Object fields

| Field | Type | Meaning |
|---|---|---|
| `spec` | literal `"noa.co-attestation/0.1"` | Artifact kind + version; inside the signed surface. |
| `receiptHash` | `sha256:<64 hex>` | **MUST equal** the carrier receipt's `chain.hash`. |
| `field` | non-empty string | The attested input slice (a key in the receipt's decision `params`), e.g. `"amountMinor"`. |
| `value` | safe integer | The attested value in **integer minor units**. Money is never a float. |
| `currency` | ISO-4217 (`[A-Z]{3}`) | So the same numeric value is not replayable across currencies. |
| `ts` | RFC-3339 UTC | When the counterparty attested. Signer-asserted, like receipt `ts`; not trusted wall-clock. |
| `sig.alg` | `"ed25519"` | Signature algorithm; inside the signed surface. |
| `sig.kid` | non-empty string | Counterparty key id; resolved against a **separate** receiver keyring. Inside the signed surface. |
| `sig.value` | base64 | Ed25519 over the domain-separated preimage. **Excluded** from the signed surface. |

### The exact signed surface

The signature covers the JCS-canonical form of the object with **only `sig.value` removed**
(`coAttestationHashInput`). This mirrors `receiptHashInput`: `sig.alg` and `sig.kid` **remain
inside** the signed bytes, binding the counterparty's key identity into the signature — an attacker
cannot strip the signature, swap to a different `kid`, and re-sign, because doing so changes the
signed surface. The signed surface is therefore:

```
JCS({ spec, receiptHash, field, value, currency, ts, sig: { alg, kid } })
```

The preimage is domain-separated, exactly as receipts and checkpoints are (`src/signing.ts`):

```
sig.value = Ed25519_sign( receiverPrivkey,
              "NOA-CoAttestation-v0.1-sig:" ++ sha256( JCS( coAtt \ sig.value ) ) )
```

- **Domain-separation tag `NOA-CoAttestation-v0.1-sig`** is distinct from `NOA-Receipt-v0.1-sig`
  and `NOA-Checkpoint-v0.1-sig`. A co-attestation signature can therefore never be replayed as a
  receipt/checkpoint signature, or vice-versa (THREAT-MODEL T11; exercised by the domain-separation
  test in `co-attestation.test.ts`).
- **`receiptHash` binding.** `receiptHash` is **recomputed** from the carrier receipt at mint time
  (`"sha256:" + sha256(JCS(receipt \ chain.hash \ sig.value))`), so the co-att binds to the
  receipt's actual content — not a stale hash field. It equals the carrier's `chain.hash`, which
  itself covers `action.paramsHash`; transitively, the attested value is pinned to the operator's
  *committed* params for that receipt.
- **Separate trust root.** `sig.kid` is resolved against `receiverKeyring` — a `kid → base64 SPKI
  public key` map that is a **distinct trust root** from the carrier's `receiptKeyring`. The
  counterparty's key is not the operator's key; trusting one does not imply trusting the other.

This is a plain detached Ed25519 signature over a canonical, domain-separated payload. It is
**not** a cryptographic commitment (no Pedersen / range-proof material). "Commitment" in this
document refers only to the receipt's existing `paramsHash` bind, which this pilot **reuses, not
re-derives**.

## 4. Verification

`verifyCoAttestation(coAtt, ctx)` is **fail-closed and never throws**: the entire body runs under
`try/catch`, and every bad path — including any thrown error — yields `{ ok: false, reason }`. The
carrier's hash is recomputed **once** and read by both the carrier-auth and the binding checks.
Checks run in this fixed order, short-circuiting on the first failure:

1. **Structure.** `spec === "noa.co-attestation/0.1"`; `receiptHash` matches `^sha256:[0-9a-f]{64}$`;
   `field` is a non-empty string; `value` is a safe integer; `currency` matches `^[A-Z]{3}$`
   (ISO-4217); `ts` matches RFC-3339; `sig` is `{ alg: "ed25519", non-empty kid, non-empty value }`.
2. **Carrier authenticity (optional).** Only when `ctx.receiptKeyring` is supplied:
   `validateReceiptShape(receipt)` must pass; the receipt's recomputed hash must equal
   `receipt.chain.hash`; `receiptKeyring[receipt.sig.kid]` must exist; and the carrier's Ed25519
   signature must verify under **`NOA-Receipt-v0.1-sig`**. A non-authentic carrier ⇒ `{ ok: false }`.
   This mirrors `verifyReceiptCompliance(…, { keyring })` / THREAT-MODEL T12 — never trust a co-att
   claim off an un-authenticated carrier. **Omit `receiptKeyring` only if the caller has already run
   `verifyChain([receipt], { keyring })` and required `VALID`.**
3. **Receipt binding.** `coAtt.receiptHash` must equal the carrier receipt's actual `chain.hash`. A
   co-att re-targeted at a different receipt is rejected (exercised by the re-target test).
4. **Counterparty signature.** `receiverKeyring[coAtt.sig.kid]` must exist — an unknown `kid`
   yields `{ ok: false }` with **no silent TOFU** (mirrors `verifyChain`'s no-silent-trust rule) —
   and the Ed25519 signature must verify under **`NOA-CoAttestation-v0.1-sig`** over
   `coAttestationHashInput(coAtt)`. A tampered attested value is caught here: the receiver never
   signed the new bytes (exercised by the tamper test).
5. **Params agreement.** `sha256(JCS(ctx.params))` must equal `receipt.action.paramsHash` (the
   supplied params are the operator's *committed* ones — anti params-swap), **and**
   `ctx.params[coAtt.field] === coAtt.value` (the attested value is the value at that committed
   path — a second, independent catch for an operator that swaps the amount post-hoc).

`ok: true` ⇒ all five hold.

## 5. What it PROVES — and what it does NOT

This is the honesty razor. Read it literally.

**A verified co-attestation PROVES, and only proves:**

> Counterparty **C**, under key **kid_c** (trusted in `receiverKeyring`), attested value **V** for
> input field **F** of receipt **R**, and **R**'s committed params carry **V** at **F**.

It converts **F** — for this one receipt — from **operator-ASSERTED** to **counterparty-ATTESTED**.
The same field an attacker could previously fabricate freely now carries a signature from a second
party who would have had to co-sign the fabrication.

**It does NOT prove, and must not be reported as proving:**

- **That the action settled.** A receipt records what was authorized/decided, not that the
  downstream system executed it (THREAT-MODEL, "Truthfulness of the action"). A co-signed amount is
  still a *recorded* amount.
- **Any other field.** Every input field the counterparty did not attest stays operator-asserted,
  exactly as before. Co-signing the amount says nothing about, e.g., the payee identity, the
  currency actually debited, or the settlement timestamp.
- **That C is independent, honest, uncompromised, or uncoerced.** The proof assumes the
  counterparty is a genuine independent party. Operator–counterparty collusion, coercion of C, or a
  C that is secretly the operator all defeat this on the attested slice. The mechanism *shifts
  trust* on F from the operator to the counterparty; it does not *remove* trust.
- **That the oracle gap is closed.** It is narrowed on F only. The input-authenticity limit
  (THREAT-MODEL "L2 input-authenticity / the oracle limit"; receipt-spec §9; federation-spec §9)
  remains wide open on every uncovered input. Closing it across the read-set is explicitly future,
  separately-governed work (federation-spec §9–§10).

### Scope precision — what the verifier reconciles, and what it does not

A cross-family adversarial review surfaced three honest boundaries that callers must not over-read.
None is a bug in the intended use (honest in-process fixtures, a receiver keyring holding only the
intended counterparty, a carrier authenticated either inline or via a prior `verifyChain → VALID`);
all three are stated here so the PROVES claim is not read as stronger than the mechanism.

- **`currency` is the counterparty's *signed assertion*, not reconciled against the carrier.**
  Because `currency` is inside the signed surface, the same signature bytes cannot be lifted to a
  different currency (anti-signature-replay holds). But `verifyCoAttestation` does **not** check
  `coAtt.currency` against any currency on the carrier receipt or its params. `ISO4217_RE` is a
  shape check only (`^[A-Z]{3}$` accepts unassigned codes). The proof is *"C signed value V in
  currency X for field F"* — not *"the receipt's own currency is X"*.
- **The verifier trusts the keyring, not a receipt-designated payee.** `ok:true` means *a key
  present in `receiverKeyring` signed* — it does **not** prove that key belongs to the receipt's
  legitimate payee (the pilot binds to no payee field). With a multi-key `receiverKeyring`, a
  different trusted receiver could co-attest. The verified key is returned as `result.kid`; put
  only the intended counterparty's key in `receiverKeyring`, or check `result.kid`.
- **Carrier authentication is opt-in.** Step 2 runs only when `receiptKeyring` is supplied. If it
  is omitted, you **must** have already run `verifyChain([receipt], { keyring }) → VALID`; otherwise
  a forged-but-self-consistent carrier plus an attacker-held receiver key yields `ok:true`. Prefer
  passing `receiptKeyring` so carrier authenticity is enforced in one call.

## 6. Pilot-grade caveats

This pilot is deliberately thin and reuses only what the public package already exposes.

- **Public primitives only.** It imports `canonicalize`, `signingMessage`, `signEd25519` /
  `verifyEd25519`, `sha256Hex` / `sha256Prefixed`, `receiptHashInput`, `validateReceiptShape`, and
  `RECEIPT_SIG_DOMAIN` — nothing private, nothing new on the crypto path.
- **It authors no crown-jewel construction.** It specifies **no** new replay wire-spec, **no**
  integer-commitment construction, and **no** redaction scheme. Those are gated under the
  crown-jewel boundary ([federation-spec §10](./federation-spec.md)) and governed separately; this
  pilot references the L2/replay layer *by name only* and is silent on its internals. The
  co-attestation is a plain detached Ed25519 signature — not a cryptographic commitment.
- **Not TOCTOU-hardened like the production verifier.** `src/verify.ts` snapshots every
  caller-supplied live object once (`structuredClone`) and is fail-closed on accessor-flip/throw —
  a deliberate defense against in-process hostile getters (THREAT-MODEL, "In-process-API
  hostile-getter residual"). **This pilot does not replicate that hardening.** It is throw-free and
  fail-closed, but it is built for **honest, in-process fixtures**: feed it plain deserialized
  objects, not attacker-influenced live objects with flipping accessors.
- **Mint throws; verify never does.** `createCoAttestation` *throws* on a non-safe-integer `value`
  (fail-fast at the signer — money is integer minor units). `verifyCoAttestation` never throws;
  every failure is `{ ok: false, reason }`. This asymmetry is intentional and stated, not hidden.

## 7. Usage

The example mirrors the executed dogfood test (`test/dogfood/co-attestation.test.ts`). The carrier
harness (`emitReceipt`, `refundRequest`, `refundGuardPolicy`, `newDogfoodSigner`) and the
co-attestation functions are **pilot-only** — they live under `test/` and are not in the published
package.

```ts
// Pilot-only (Track A2): lives under test/, NOT in the published package.
import { generateKeyPair } from "../../src/keys.js";
import { verifyChain } from "../../src/verify.js";
import { newDogfoodSigner, refundRequest, refundGuardPolicy, emitReceipt } from "./proxy.js";
import { createCoAttestation, verifyCoAttestation, type ReceiverKeyring } from "./co-attestation.js";

// 1. Carrier receipt: the operator signs a $42.00 refund decision.
//    Money is INTEGER minor units — 4_200, never the float 42.00.
const signer = newDogfoodSigner("operator-key");
const receiver = generateKeyPair("receiver-payee");          // a SEPARATE trust root
const receiverKeyring: ReceiverKeyring = { [receiver.kid]: receiver.publicKey };

const { receipt, inputs } = emitReceipt(
  refundRequest(4_200, { id: "rc_1", ts: "2026-06-22T10:00:00.000Z" }), // 4_200 == $42.00
  refundGuardPolicy(),
  signer,
  null,
);

// 2. Authenticate the carrier FIRST (T12): never trust a co-att off an un-authenticated receipt.
if (verifyChain([receipt], { keyring: signer.keyring }).status !== "VALID") {
  throw new Error("carrier not authentic");
}

// 3. The counterparty (receiver) co-attests the amount field of THIS receipt.
const coAtt = createCoAttestation(
  { receipt, field: "amountMinor", value: 4_200, currency: "USD", ts: "2026-06-22T10:00:01.000Z" },
  { kid: receiver.kid, privateKey: receiver.privateKey },
);

// 4. Verify: carrier authenticated via receiptKeyring; receiver key trusted in its own keyring.
const ok = verifyCoAttestation(coAtt, {
  receipt,
  params: inputs,
  receiverKeyring,
  receiptKeyring: signer.keyring,
});
// ok.ok === true  →  "receiver-payee attested 4_200 for amountMinor, bound to this receipt,
//                     whose committed params carry 4_200 at amountMinor."

// 5. Tamper the attested value → the receiver never signed it → the signature fails.
const tampered = structuredClone(coAtt);
tampered.value = 9_999_999;                                   // an inflated refund
const bad = verifyCoAttestation(tampered, { receipt, params: inputs, receiverKeyring });
// bad.ok === false,  bad.reason =~ /signature did not verify/
```

`4_200` minor units denotes `$42.00`. Never express money as a float: `createCoAttestation` throws
on a non-safe-integer, and JCS rejects floats at the canonicalization step regardless.

---

*Companion documents: [receipt-spec.md](./receipt-spec.md) (normative v0.1 format; §9 L2 honesty
razor) · [federation-spec.md](./federation-spec.md) (§9–§10 crown-jewel boundary) ·
[THREAT-MODEL.md](../THREAT-MODEL.md) (T11 cross-protocol reuse; "L2 input-authenticity / the
oracle limit") · source: [`test/dogfood/co-attestation.ts`](../test/dogfood/co-attestation.ts) ·
proof: [`test/dogfood/co-attestation.test.ts`](../test/dogfood/co-attestation.test.ts).*
