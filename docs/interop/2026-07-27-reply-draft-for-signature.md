# DRAFT REPLY — for the principal's signature

**Status:** DRAFT. Not sent. Not to be sent without the principal's explicit instruction.
**To:** the ARP interop thread (Hillier + participants)
**Covers:** the three naming questions, the proposed new axis, the two §7.2 asks of our -01, and
the "no rush before the 15th" reference.

**Notes to the principal before you read it** — these are decisions I made in drafting that you
may want to reverse:

1. I answered the naming questions with reasons rather than votes, because the thread is
   explicitly asking for argument. If you would rather stay lighter-touch on someone else's
   draft, cut sections 1–3 to their first sentences; the vector contribution in section 4 is the
   part that carries weight regardless.
2. I did **not** raise F1 (the construction-id contradiction) in this reply. It is a defect in
   Hillier's unsent artifacts, and the memo goes to him privately. Putting it on the thread would
   embarrass him for an error he has not yet made publicly. **If he sends before reading the memo,
   this reply needs a rewrite** — see the note at the end.
3. The "15th" — I could not find any referent. It appears in his e-mail addressed to you and
   nowhere else in the artifact set, the filed -01, or the corpora. I have written it as a
   question rather than assuming a deadline we have not agreed to.

---

Joel, all —

Thank you for running this against the published vectors instead of the argument. The Appendix D
result is the one number in this thread nobody had measured, and measuring it is worth more than
another round of position papers.

We reproduced the parts that touch our corpus, from your pinned commits. The
`noa.receipt/0.1` characterisation is accurate, including the three-way authorization result on
the valid chain, and the `cross-chain-splice` framing — "the forgery is a property of the set" —
is the sharpest statement of that problem I have seen. It is exactly why we built that vector.

## 1. `agent-credential-absent` — we think it is two axes

The strongest argument for splitting is in your own run. The axis fires on our valid chain's
genesis receipt, which we publish as legitimate: `verdict = DEFERRED`,
`ruleId = high-risk-deferral`. That is a high-risk action correctly held for approval — the
control working, not failing. The same axis fires on `reject_lifecycle_*`, where a required
signoff genuinely does not exist.

Those are opposite fault models under one name, and the first is arguably indeterminate-class
rather than failure-class — the same treatment you already give `human-authorization-unproven`.
We would keep `agent-credential-absent` for "no authorising credential exists" and add an
indeterminate-class axis for "awaiting an authorisation that is expected".

There is a practical benefit too: as it stands, that row is the one place in the run where ARP
returns REFUSE on a receipt whose issuer publishes it as valid, and nothing in the disposition
column lets a reader tell that apart from a real credential failure. Splitting removes the only
false-positive-shaped result in the corpus.

## 2. `version-replay` — two axes, and the run supplies the evidence

`reject_unsupported_version` is a format-gate event. An unknown or future version replays
nothing; the name describes something that did not happen.

More decisive: the run maps `reject_tampered_anchor` to `version-replay` as well
(`arp_run_output.txt:51`), and that vector's own description is "the Merkle proof does not
reconstruct the claimed root". So one axis is currently carrying three distinct things —
unsupported version, legacy anchor refused by default, and a proof failure. We suggest
`version-unsupported` for the gate and `downgrade-to-legacy` for the actual downgrade defence,
with the tampered-anchor case re-mapped onto the anchor axes where it belongs.

## 3. `canonicalization-gate-failed` — three

Parse-failed, profile-violated, and representation-noncanonical happen at different pipeline
stages with different attacker models, and your §6.1/§6.2 already document why the merge costs
something real: seven of the nine `malformed/*` files are refused at a generic shape gate rather
than a purpose-built parse check, and the current name "implies a check which did not run".

That is the parser-differential problem — CPython's `json.loads` accepts duplicate member names
and lone surrogates where our `strict_load_text` rejects them at the parse boundary. An axis that
cannot distinguish "could not parse this at all" from "parsed it, but the encoding is
non-canonical" collapses precisely the distinction a relying party needs in order to know whether
it is looking at a broken producer or a hostile one.

## 4. `anchor-leaf-not-bound-to-payload` — adopt it, and here is the vector that settles it

We agree the distinction from `log-proof-broken` is real: a valid inclusion proof for a leaf
nobody tied to this payload survives a log audit, which is exactly why merging the two loses the
information that matters.

You said the corpus has no vector isolating it, so the distinction was argued rather than
demonstrated. **We have built the isolating vector and are contributing it.**
`reject_v2_unbound_leaf_proof_valid`, in EP-RECEIPT-v1 shape: the signature verifies, the
inclusion proof reconstructs the declared root **exactly**, and the only defect is that the leaf
proven is not this receipt's payload. Its leaf, sibling and root are `frozen-v1`'s own published
values for `accept_with_merkle_anchor_v2`, so the proof is a genuine proof about a genuine leaf
in a genuine tree — it just proves someone else's payload. Test-only key material is deterministic
from a published seed, so anyone can regenerate it byte-for-byte and contradict us.

Two things fell out of building it that we think belong in -02.

**First, the gap is wider than one vector.** `reject_v2_unbound_leaf` is indeed both unbound and
proof-broken, as you noted. So is `reject_tampered_anchor` — its declared leaf is also not the
payload's leaf. So the corpus currently isolates neither side of the distinction: not
`anchor-leaf-not-bound-to-payload`, and not `log-proof-broken` either. Both need a clean vector.

**Second, in EP-RECEIPT-v1 the signature covers `JCS(payload)` only** — the anchor sits outside
the signed surface. We confirmed this by reconstructing the preimage for `accept_minimal`. That
means any validly signed receipt can carry any anchor anyone cares to attach, with no signature to
break. It may well be intentional, since the log is a separate authority, but it is what makes
this axis a reachable condition rather than a theoretical one, and it deserves an explicit
sentence.

## 5. On the two asks of our -01

Both are sound and both are now implemented in our working draft.

**Canonicalization parameters carried with the digest construction.** Agreed without reservation,
and your §1 is the argument for it. We have added a section that pins every parameter of the
`noa.receipt/0.1` construction normatively and exhaustively: RFC 8785 serialization; **UTF-16
code-unit member sort**, stated explicitly as *not* code-point, since the two diverge for astral
characters; integer-only numbers bounded at 2^53−1; **no normalization applied by the
canonicalizer**, with producers required to emit NFC and verifiers required not to normalize;
RFC 8785 string escaping; unpaired surrogates rejected; duplicate member names rejected at the
parse boundary rather than resolved last-wins; and the domain-separation tags.

We also drew the boundary you would have drawn for us: **`action.paramsHash` is not a shared
action digest.** It is a per-producer commitment under that producer's own parameters, it does not
commit to tenant, chain, authorization, attempt or nonce, and it may legitimately repeat across
retries. The draft now says so, and says that any future cross-producer action digest MUST carry
its canonicalization parameters and a construction identifier on the wire, with a digest under a
non-matching identifier treated as non-matching rather than compared.

**The four chain-level axes.** Agreed, and this is the more interesting of the two, because you
are right that they are the failures no per-receipt verifier can reach. Our verifier already
implements all of them; what was missing was naming them in the specification. The draft now
carries a chain-level failure-axis section with `chain-link-broken`,
`chain-sequence-duplicate`, `chain-sequence-gap`, `chain-scope-mismatch` and
`chain-head-truncated`, stating that a conforming verifier MUST detect all five and SHOULD report
them distinctly — because `chain-sequence-duplicate` and `chain-scope-mismatch` indicate a splice
of two genuine histories where every receipt verifies in isolation, while `chain-link-broken`
indicates alteration and `chain-head-truncated` indicates deletion. Those call for different
operator responses, and one verdict cannot express them.

On the drafting of the `MUST NOT` you propose for -02: "the Claim Hash and the subject digest MUST
NOT be substituted for one another" has no testable actor as written. We would recast it as
verifier behaviour — artifacts MUST carry the construction identifier; a verifier presented with a
digest under an unrecognised or non-matching identifier MUST treat the comparison as non-matching
and MUST NOT compare the values. That version is vector-testable, which is what makes it worth
filing. It does depend on the identifier derivation being specified, which we do not think it is
anywhere yet.

## 6. The two missing interop-set behaviours

`controller-reported outcome` and `physical-completion non-claim` are EP-BOUNDARY vectors, so they
are not ours to contribute, and we would rather say that plainly than go quiet on your §7 ask.

We do have a worked position, if it is useful to whoever writes them. We would keep the base
receipt frozen and carry the two claims as separate signed artifacts, because a controller
reporting `SUCCEEDED` and a witness reporting `OBSERVED_NOT_COMPLETED` can both be cryptographically
valid, and the composed result has to be a named conflict rather than an erasure of either claim.
We would also keep `NOT_CLAIMED`, `NOT_PROVIDED`, `NOT_APPLICABLE` and `INDETERMINATE` distinct:
"the verifier did not receive acceptable evidence" is not "no evidence exists", and collapsing
them is how an absence becomes a negative claim. Our implementation of that layer is deliberately
deferred, so we are offering a design position, not an artifact.

## 7. The 15th

You mention no rush before the 15th. I do not have a referent for that date — it does not appear
in the write-up, the filed -01, or anything else in the thread I have. If there is a milestone I
should be working to, tell me what it is and I will hold to it; if it was shorthand for something
already agreed elsewhere, point me at it and I will catch up.

Best,
Tora Toraman
NordenSoft / NOA

---

## Standing instruction for whoever sends this

- **Attach** `conformance/interop/ep-receipt-v1/unbound-proof-valid.vector.json` and
  `gen-unbound-proof-valid.mjs`. The generator is the point: it proves the construction against
  EMILIA's published vector before it mints anything, so the contribution is checkable rather than
  assertable.
- **Do not attach or quote the findings memo.** That is a private note to Hillier about artifacts
  he has not sent.
- **If Hillier has already sent the run with the contradictory `arp_run.json`**, do not send this
  as written. The thread will be discussing F1 within the day, and a reply that talks past it
  reads as either inattentive or complicit. Add a short, non-punitive paragraph noting the
  discrepancy and that a corrected artifact set is coming — his to announce, ours to have noticed
  quietly first.
