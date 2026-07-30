# Adversarial test requirements — intent binding

| Field | Value |
|---|---|
| **Status** | REQUIREMENTS ONLY. No implementation — source changes are not authorized. |
| **Date** | 2026-07-29 |
| **Authority** | Owner instruction 2026-07-29. Gates any future implementation of `docs/ADR-0004-intent-binding.md`. |
| **Invariant under test** | `approval_intent_digest == grant_intent_digest == execution_intent_digest`, and: no component claims `HUMAN_APPROVED` unless that equality is independently established. |

---

## 0. Why these rules exist before the tests do

Five adversarial rounds produced a repeated failure that had nothing to do with missing tests: **tests
that could not fail were read as tests that passed.** Concretely, in this repository —

- a knockout ran against a stale snapshot and reported green because the build had already failed;
- a species-poisoning fixture reported `clean verifyChain(tampered) -> VALID` because the replacement
  string never matched the file;
- `deriveParamsHash` compares the caller's hash to the caller's own hash, so the shipped D14 check
  **cannot fail** — and its README calls it "the load-bearing guarantee";
- a reviewer process exited cleanly having written nothing, which is indistinguishable from a
  reviewer that examined everything and found no problems.

Therefore **every requirement below has three mandatory parts**, and a test missing any one of them
does not count as coverage:

1. **ATTACK** — the adversary, what they control, what they achieve.
2. **OBSERVABLE** — the exact signal separating pass from fail. Not "it works": a value, a status, a
   refusal reason.
3. **ANTI-VACUITY CONTROL** — the honest path must still **succeed** in the same run. A suite where
   everything is refused proves nothing; it is indistinguishable from a broken fixture.

A fourth rule, learned the same way: **the poison must be shown to fire.** Where a test poisons or
substitutes something, it must instrument that the substitution was actually reached (a counter, a
sentinel). Zero hits is an inconclusive run, never a refutation.

---

## T-1 — Display substitution

**ATTACK.** Attacker controls the caller. They cause the human to be shown a benign description while
the authority commits to a different action. This is the measured defect that killed ADR-0003
(`engine.ts:202-209`): `display` and `paramsHash` were independent caller inputs.

**OBSERVABLE.** The request carrying an independent `display` is **rejected at the API boundary**
(422-class), not merely ignored. Under ADR-0004 §3 the field does not exist on the wire, so the test
asserts the field is *unaccepted*, not that it is *overridden* — an overridden field still proves the
server accepted it.

**ANTI-VACUITY.** A well-formed request with no `display` field produces an approval whose rendered
text is byte-identical to a deterministic re-render of the same `ActionIntent`.

**MUST ALSO COVER.** Every field the human can read — recipient, amount, currency, action type,
tenant, risk class. A test that binds only the amount leaves the recipient free.

---

## T-2 — Recipient and amount mutation

**ATTACK.** Attacker approves `{to: alice, amount: 10}` and executes `{to: mallory, amount: 9999}` —
by mutating the params object after approval (TOCTOU, see T-7), by presenting a grant against
different params, or by executing something unrelated to both.

**OBSERVABLE.** Refusal **before any side effect**, with the refusing component named. The current
design cannot satisfy this: `wrapper.ts:122` declares `execute: () => Promise<...>` — **no
arguments** — so the wrapper hands control to an opaque caller closure and has no idea what ran. The
test must therefore assert against the *executed* action as observed **at the target**, never as
reported by the caller.

**ANTI-VACUITY.** The approved `{to: alice, amount: 10}` executes successfully and appears at the
target exactly once.

---

## T-3 — Unknown / unregistered projection fallback

**ATTACK.** Attacker submits an action type with no registered projection, or names a projection that
does not exist, and relies on the system falling back to a permissive path. Today this is trivially
available: `projections.ts:98` registers exactly **one** projection, and `engine.ts:164` reads `mode`
from **caller input** — so the caller simply asks for `RAW`.

**OBSERVABLE.** Fail **closed**: no grant issued, no approval receipt, and specifically **no
`HUMAN_APPROVED` claim**. A `DENY` verdict is a pass; a grant with a weaker reason code is a **fail**
unless that reason code is normatively defined as non-approval.

**ANTI-VACUITY.** A registered action type completes end-to-end in the same run — otherwise the suite
cannot distinguish "fails closed correctly" from "nothing works".

**MUST ALSO COVER.** `mode` must not be caller-selectable. A test that registers a projection and
checks it works, without checking that the caller cannot opt out of it, misses the actual bypass.

---

## T-4 — Caller-supplied hash substitution

**ATTACK.** Attacker supplies the digest instead of letting the boundary derive it, or supplies one
alongside a snapshot hoping it is preferred.

**OBSERVABLE.** The supplied digest is **rejected**, not merely overridden. Distinguish the two by
sending a digest that *matches* what the boundary would derive: if the request succeeds, the field is
still being accepted, and acceptance is the vulnerability — a matching value today is a mismatching
value tomorrow.

**ANTI-VACUITY.** The boundary-derived digest, with no caller digest present, produces a valid grant.

---

## T-5 — Canonicalization divergence

**ATTACK.** Two byte-sequences that a human reads as identical produce different digests, or two that
differ produce the same digest. Measured facts in this repository that make this concrete: JCS treats
`10.00` as `10` but rejects `10.01` outright; `buildReceipt` rejects non-NFC input while
`signArtifact` accepts it; JCS sorts keys by UTF-16 code unit while `policy-spec.md` §3.1 mandates
code-point order — these disagree on astral characters.

**OBSERVABLE.** Digest equality is decided **only** by canonical bytes. Requirements: a
`{amount: 10.00}` / `{amount: 10}` pair must be either both-rejected or provably identical in meaning
(integer minor units); a non-NFC and NFC pair of the same display string must not produce two
different valid grants; a key set containing astral characters must produce the same digest under an
independent implementation, or the schema must forbid such keys.

**ANTI-VACUITY.** A normal ASCII intent round-trips to a stable digest across two independent
implementations.

**NOTE.** This requirement is why the oracle commission (task #33) is load-bearing rather than
optional: canonicalization divergence is invisible to a single implementation testing itself.

---

## T-6 — Replay

**ATTACK.** Attacker records a valid grant and re-presents it: same process, different process, after
a restart, after a VM snapshot rollback, on a different connection, or against a different target.

**OBSERVABLE.** The second presentation is refused **by the party that holds the authoritative
record**. Refusal by the caller's own bookkeeping does not count — the caller is the adversary.
`maxUses: 1` on the grant is a **declaration**, not an enforcement; `engine.ts:635-646` states that
`reserve()` "is a voluntary call the executing party alone decides whether to make."

**ANTI-VACUITY.** The first presentation succeeds.

**MUST ALSO COVER.** Cross-target replay. `ExecutionGrant` (`types.ts:91-103`) has **no audience and
no executor field**, so a grant minted for one target is a bearer token at any other target that
trusts the same key. A replay suite that only tests the same target will pass while this hole is open.

---

## T-7 — TOCTOU

**ATTACK.** Params are mutated between the moment the digest is derived and the moment the action
executes — by mutating the object, by a getter with side effects, by a `Proxy`, or by racing a
concurrent request.

**OBSERVABLE.** The executed action still matches the approved intent, **verified at the target**.
The snapshot must be genuinely immutable: a test that mutates a plain object proves less than one
that installs a `Proxy` whose `get` returns different values on successive reads — the second is the
attack that four rounds of this project's history actually produced.

**ANTI-VACUITY.** An unmutated params object executes successfully.

---

## T-8 — Key extraction

**ATTACK.** Attacker with code execution in the caller's process reads the grant-signing key and mints
grants indistinguishable from genuine ones — correct signature, correct digest for the attacker's
intent, fresh `grantId`. Today this is a read: `trust.ts:23-29` holds `privateKey: string` in the Node
process.

**OBSERVABLE.** No code path in the caller-controlled process can yield the private key bytes.
Requirements: a memory/heap-dump test finds no key material; the key file (if any) is unreadable by
the process uid; and the signing component refuses to export.

**ANTI-VACUITY.** Legitimate signing continues to work through the intended interface.

---

## T-9 — Unrestricted online signing

**ATTACK.** The key is non-exportable, so the attacker does not steal it — they **use** it. They call
the signing service with an attacker-chosen intent and receive a genuine signature. This is the owner's
conclusion 6 and it is live today: `sidecar.mjs` accepts `{"op":"sign","message":"<base64>"}` — it
signs **arbitrary bytes**.

**OBSERVABLE.** The signer refuses to sign a grant whose intent it did not itself derive and whose
approval proof it did not itself verify. Requirements: blind signing of arbitrary bytes must be
**refused for the grant key**; the signer must build its own pre-image; and a request with a valid
approval proof but a substituted intent must be refused.

**ANTI-VACUITY.** A genuine approval yields a genuine signed grant.

**THIS IS THE REQUIREMENT MOST LIKELY TO BE FAKED.** Moving a key into an HSM and declaring victory
satisfies T-8 while leaving T-9 wide open, and the two look identical in a status report. They must be
tested and reported separately.

---

## T-10 — Execution mismatch

**ATTACK.** Everything upstream is correct — the human approved the real intent, the grant binds the
real digest — and the executed action is still different, because nothing downstream checks.

**OBSERVABLE.** The **target** (or the trusted dispatch boundary) refuses an action that does not
match the granted intent, and the refusal is observed **at the target**, not reported by the caller.
Where the third party validates nothing, the test must demonstrate that dispatch happens **from within
the boundary**, with the caller never holding a usable credential.

**ANTI-VACUITY.** A matching action executes and is observed at the target exactly once.

**OPEN AND UNRESOLVED.** ADR-0004 §5.3 concedes that class-scoped credentials (an STS-style session
policy) can be perfectly intent-bound at issuance and unbounded in use. This requirement therefore
has **no known passing implementation** for providers whose native mechanism cannot express a
single-action grant. That is a genuine gap, not a test to be written around — it is recorded here so
the suite cannot report green while the gap is open.

---

## Cross-cutting acceptance rules

1. **No test may accept the caller's own report of what happened.** The caller is the adversary in
   every requirement above. Observations come from the target, the signer, or an independent record.
2. **Every suite run reports its anti-vacuity controls separately** from its attack results. A run
   showing 10 refusals and 0 successful honest paths is a **failed** run, not a perfect score.
3. **A skipped or errored test is a failure**, never a pass. This project has twice read an empty
   result as a green one.
4. **`HUMAN_APPROVED` requires positive proof of the three-way equality.** Absence of a detected
   mismatch is not proof. If the equality cannot be established, the reason code must say so.
5. **Coverage claims name what was not covered.** Any bound — action types not exercised, providers
   not tested, canonicalization classes skipped — is stated in the run output, because silent
   truncation reads as completeness.
