# Findings on the ARP reconciliation run (27 July 2026)

**To:** Joel Hillier, Certisyn, Inc.
**From:** NordenSoft / NOA
**Re:** `ARP_run_report.pdf`, `arp_run.json`, `arp_run_output.txt`, and the covering e-mail
**Status:** review notes — nothing here has been sent to the thread

---

## Before the findings

This is good work and the intent of these notes is to keep it that way. The run does the thing
the thread needed and nobody had done: it measures Appendix D's premise against a deployed
corpus instead of arguing about it, and it reports its own limits in §6 with more discipline
than most published interop reports manage. The 22/22 result is real — we reproduced it — and
§6 is the reason the rest of the document is credible.

Every claim below is written so you can check it against your own attachments without taking
our word for anything. Where we say something is wrong, there is a command you can run. Where
we could not verify something, it is marked `[UNVERIFIED]` rather than asserted.

One item is a send-blocker (**F1**), because it is the kind of error a hostile reader finds in
about two minutes with `jq` and then uses to discredit everything else in the package. Two more
(**F2**, **F3**) will be found by anyone who tries to reproduce or who diffs the report against
the filed text. The rest are improvements, ordered by severity and marked so you can triage.

Findings are grouped by who owns the fix: **your artifacts** (F1–F3, F5), **your e-mail body**
(F4, F6, F7, F9, F10 — with suggested replacement wording, since precise wording saves a round
trip), and **the naming questions** you asked, answered with reasons rather than votes.

---

# CRITICAL

## F1 — `arp_run.json` contradicts the e-mail, the console, and the PDF on the `arp-subject-digest/1` construction id

**Severity:** CRITICAL · send-blocker
**Where:** `arp_run.json` → `constructions."arp-subject-digest/1".id`; `arp_run_output.txt:9`;
PDF p.4 §1.3; e-mail item 2.

The e-mail, the console output and the PDF all state:

```
arp-subject-digest/1   id=f23ecefd99c54182   App.D, SHA-256(JCS(action))
```

The attached JSON states a different id for the same construction. One command, against your own
attachments:

```
python3 -c "import json;d=json.load(open('arp_run.json'));print(d['constructions']['arp-subject-digest/1']['id'])"
```

```
7630fc125d8b77a0
```

```
grep -n "arp-subject-digest/1" arp_run_output.txt
```

```
9:  arp-subject-digest/1       id=f23ecefd99c54182  draft-hillier-scitt-arp-01 App.D subject_digest = SHA-256(JCS(action))
```

The string `7630fc12` does not appear anywhere in the PDF (checked by full-text extraction). The
other two ids — `7d90aa1cbee90ef9` and `dc7df29214870f78` — match across all four surfaces, so
this is isolated to the one construction that matters most.

The `spec` strings also differ. The JSON reads `"App.D subject digest, read as RFC 8785 JCS"`;
the console reads `"App.D subject_digest = SHA-256(JCS(action))"`. Two different descriptions of
the same construction, in two files that `arp_run_output.txt:190` says were produced by one run
("machine-readable result written to arp_run.json"). They were not.

**Why this one blocks.** §1.3's entire argument is that the identifier commits to the declared
canonicalization parameters *so that a consumer can determine compatibility rather than assume
it*. Shipping two different identifiers for one construction is the checkability mechanism
failing its own check, in the document proposing it. A reader who finds this does not conclude
"stale file"; they conclude the numbers were not produced the way the report says.

**Correction.** Regenerate the console, the JSON, and the PDF's figures from a single harness
execution, then machine-diff every hex string across all three before sending. Not a hand-edit
of the JSON — that trades a visible contradiction for an unverifiable provenance story, which is
worse.

---

# HIGH

## F2 — the reproducibility promise is unbacked: the harness is not in the artifact set, and the id derivation is specified nowhere

**Severity:** HIGH · send-blocker
**Where:** PDF p.1 reproduce block; PDF p.14 ("Harness: `arp_reconcile.py` … All reproducible
from the pinned commits above").

The attachment set is the PDF, the JSON and the console text. `arp_reconcile.py` is not in it.
The corpora are public and we cloned both at your pinned commits without difficulty, but the
harness is what performed the 18 cryptographic verifications, the Section 2 digests, the
self-check, and every construction id — and none of that is reproducible from the corpora alone.

We tried to re-derive the three ids from the JSON's own declared parameter maps under several
natural derivations (JCS of the parameter object with and without the construction name, hash of
the `spec` string, and combinations). None reproduces any of the three. So as shipped, "each
digest commits to the declared canonicalization parameters" is not a checkable claim — it is an
assertion about three opaque 16-hex-character strings.

**This is the item with teeth, and it is bigger than reproducibility.** §1.3 proposes that -02
carry the construction identifier on the wire, and your §7 asks the thread to adopt it. An
identifier whose derivation is unspecified cannot be independently computed, which means a
consumer cannot *determine* compatibility — it can only compare a string it was handed against a
string it was handed, and trust that both producers derived it the same way. That is the failure
mode the identifier exists to remove, reintroduced one layer up. **-02 must define the identifier
derivation function normatively, or the identifiers are opaque labels no one can dispute or
confirm.** We would rather this were fixed than used against you.

Two smaller defects in the same block: the reproduce block clones both repositories but never
checks out the pinned commits (so it reproduces `HEAD`, not the run), and it pins neither the
Python version nor the `cryptography` dependency. The Python version is load-bearing for the
claim in §6.1 — the `json.loads` behaviour you rely on there is CPython-specific:

```
python3 -c "import json; print(json.loads('{\"a\":1,\"a\":2}'))"     # -> {'a': 2}
python3 -c "import json; print(repr(json.loads('\"\\\\ud800\"')))"    # -> accepted, lone surrogate
```

**Correction.** Attach `arp_reconcile.py`, or publish it at a pinned public commit and cite that
commit. Add `git checkout <commit>` lines. Pin the Python version and `cryptography`. State the
id-derivation function in the write-up, and carry it into -02 normatively.

## F3 — PDF p.2 "The profile is named: RFC 8785 JCS" is false against the filed -01, and p.13 concedes it

**Severity:** HIGH · send-blocker
**Where:** PDF p.2 §1; contradicted by PDF p.13.

We fetched the filed `draft-hillier-scitt-arp-01`. Appendix D writes
`subject_digest = SHA-256(JCS(action))` at line 1301, but:

```
grep -c "8785" draft-hillier-scitt-arp-01.txt
```

```
0
```

"8785" occurs zero times in the filed document. `JCS` occurs exactly once — at line 1301, the
formula itself — and is never expanded or cited. So the profile is *not* named in -01; the token
`JCS` is used as though it were self-defining.

The PDF then says on p.13 that "ARP-02 will pin Appendix D's canonicalization profile by
normative reference", which concedes it is not pinned now, and contradicts p.2. A hostile reader
diffs the two pages and the filed text and wins on both.

Note the **e-mail is safe here** — it claims only that Appendix D pins
`subject_digest = SHA-256(JCS(action))`, which is verbatim true. Only the PDF overstates. The
JSON's own softer formulation, "read as RFC 8785 JCS", is the correct one.

**Suggested replacement (PDF p.2):**

> The token used is `JCS`. Read as RFC 8785 — the only standardised JSON Canonicalization
> Scheme — it interoperates with the EP profile on 22 of 22 pinned vectors. -01 does not cite
> RFC 8785; -02 will pin it by normative reference.

## F3b — RFC 8259 is doing normative work from the Informative References section

**Severity:** HIGH (specification defect in the filed -01; not a send-blocker for the e-mail)

Verified, and it is a real defect rather than a formatting quibble. §2 defines the Canonical
Claim as including "canonical JSON [RFC8259] number rendering" (line 312) — a normative
construction rule for a hash that indexes the Settlement-Layer Ledger. But `[RFC8259]` is listed
at line 1076, which falls under §9.2 **Informative** References (§9.1 Normative ends at line
1025).

```
grep -n "Normative References\|Informative References" draft-hillier-scitt-arp-01.txt
# 974:9.1.  Normative References
# 1025:9.2.  Informative References
grep -n "RFC8259" draft-hillier-scitt-arp-01.txt | tail -2      # -> 1076, i.e. inside 9.2
```

Worse, the referent does not exist: **RFC 8259 defines no canonical number rendering.** RFC 8785
does. So §2 names a normative rule, sources it to an informative reference, and that reference
does not contain the rule. This is the same class of defect as F3 and should be fixed in the same
pass: move RFC 8259 to normative if it is load-bearing, and cite RFC 8785 for number rendering —
or state explicitly which of the two is normative for §2, since the run substituted RFC 8785/ES6
rendering (your own §6.8 discloses the substitution).

---

# MEDIUM

## F4 — "all 95 mapping to a named axis" is true, but not reproducible from the attached JSON

**Severity:** MEDIUM · e-mail body
**Where:** e-mail item 5; PDF p.8 handles it correctly.

The 95 is **correct** — we counted it independently by direct census of the `frozen-v1` tree at
your pinned commit `125e4f43…`: 16 suite files, `TOTAL reject_ = 95`, of which
`canonicalization.v1.json` contributes 13 (35 ids = 22 accept + 13 reject).

But a recipient who runs `jq` over `arp_run.json` gets **82**, because the 13 canonicalization
`reject_*` vectors are excluded from the JSON entirely — its canonicalization array is exactly
the 22 accept vectors. 82 = 73 (`other`) + 9 (`receipts`). Their mapping to
`canonicalization-gate-failed` is, in the PDF's own honest words, "a property of the table,
checked separately", and no artifact evidences that separate check.

The PDF discloses this (p.8, two accounting notes). The e-mail compresses it away, which turns a
correct number into an apparent overclaim.

**Suggested replacement (e-mail item 5), one clause:**

> 95 `reject_*` identifiers across the 16 EMILIA suites, all 95 mapping to a named ARP
> divergence axis — 82 of them exercised in the run's own outputs, the 13 canonicalization
> parse-boundary ids by the §5 mapping table (the accounting is in the write-up).

## F5 — PDF p.8 "the run emits 20 distinct axes" is wrong; the run emits 29

**Severity:** MEDIUM · PDF

Computed across every leg of every entry in the attached JSON:

```
python3 -c "
import json; d=json.load(open('arp_run.json')); axes=set()
def w(o):
    if isinstance(o,dict):
        for k,v in o.items():
            axes.add(v) if k=='axis' and isinstance(v,str) else w(v)
    elif isinstance(o,list):
        [w(x) for x in o]
w(d); print(len(axes))"
```

```
29
```

The 20 figure is correct but scoped: the console applies it to section 1d (the expectation-derived
suites) and is right to. The PDF generalises it to "the run". The nine additional axes are the
ones the real-crypto paths emit — `anchor-leaf-not-bound-to-payload`, `caid-binding-unverified`,
`attribution-substituted-for-authorization`, `machine-decision-not-human-authorization`,
`human-authorization-unproven`, and the four `chain-*` set axes.

There is a second, smaller inconsistency in the same sentence: the PDF says "18 substantive"
where the console says 19 and the JSON's own `axes_substantive` array has 19 (the PDF re-classes
`currency-unknown`). Three artifacts, three phrasings, one number.

**Correction.** "The expectation-derived path emits 20 distinct axes (19 substantive plus a
provenance placeholder); the full run emits 29." Then harmonise the substantive count across all
three artifacts.

## F6 — "the two divergences are collisions" needs sort-scoping, and "collision" needs one disarming word

**Severity:** MEDIUM · e-mail body

Both collisions are real and we verified both byte-for-byte:

- `S2(accept_nfd_decomposed)` = `a84c1745…` = EP's pinned digest for `accept_nfc_composed`
- `S2(accept_angstrom_sign_not_normalized)` = `08eb5b93…` = EP's pinned digest for
  `accept_latin_a_ring_distinct` — a vector EMILIA names `_distinct` precisely to keep apart

Two problems, both cheap to fix. First, the e-mail gives both 19/22 and 20/22 and then says "the
two divergences": under the code-point sort there are **three** divergences and only two are
collisions (`accept_astral_key_utf16_sort_order` → `628a8a16…` matches no EP pin). As written it
invites the pedant. Second, "collision" unqualified will draw "you found SHA-256 collisions?" —
these are pre-image foldings in the canonicalization map, by design, not hash collisions.

**Suggested replacement:**

> The two divergences under the UTF-16 sort are collisions in the canonicalization map — not in
> SHA-256: Section 2 assigns a single Claim Hash to pairs of inputs the EP profile deliberately
> pins apart. (Under a code-point sort there are three divergences, of which these same two are
> collisions.)

That formulation is also the sharper security point, and it is what makes the `MUST NOT` in -02
necessary rather than tidy.

## F7 — "signatures verified" and the row-3 axis attribution each read as more than they are

**Severity:** MEDIUM · e-mail body

The e-mail introduces the five EP-BOUNDARY vectors with "signatures actually verified rather
than assumed", then lists rows in which rows 3 and 4 carry `signature:no-match[signature-invalid]`
by design. Your meaning is "verification was performed"; the surface reading is "all five
signatures are good".

Separately, the e-mail attributes row 3's REFUSE to `raw-claim-not-covered-by-signature` alone,
while the console (line 31) shows the signature *also* independently fails, and your own PDF p.5
discloses that this axis currently fires on the **presence** of self-asserting fields — "a
field-name heuristic rather than a coverage computation". The e-mail should not be more confident
than the PDF it is summarising.

**Suggested replacement:**

> Real Ed25519 verification was performed on all five (two fail by construction). … On
> `raw_claim_pass_through` the signature also fails independently; the
> `raw-claim-not-covered-by-signature` leg currently keys on the presence of self-asserting
> fields rather than computing signature coverage — see §5 of the write-up. That should be
> tightened before the axis is standardised.

---

# LOW

## F8 — the INDETERMINATE-control claim is true in the data; the "self-check asserts it" half depends on F2

**Severity:** LOW

We checked this mechanically across all 182 entries in the JSON: exactly four APPROVEs exist
(`accept_minimal`, `accept_nested_context`, `accept_key_order_independent`,
`accept_with_merkle_anchor_v2`), and **zero** APPROVE carries any non-match leg. The invariant
"no case APPROVEd while carrying an unproven binding" genuinely holds in the shipped data, and
`accept_pre_execution_receipt` is held INDETERMINATE with the `caid-binding-unverified` leg
present in both the console (line 29) and the JSON. This is the strongest structural claim in the
package and it survives checking.

`[UNVERIFIED: whether the self-check COMPUTES this invariant or prints a constant — the console
lines 184-189 are indistinguishable between the two without the harness source.]` This resolves
the moment F2 is fixed; it is not a separate task. We flag it only because "the self-check
asserts it" is doing real rhetorical work in item 5 of the e-mail, and it is the one load-bearing
sentence whose evidence is not in the attachment set.

## F9 — five omissions a hostile reader converts into attacks

**Severity:** LOW · e-mail body · all five are one-line fixes

1. **No "22 of 35" disclosure.** The e-mail gives the inclusion criterion for the
   canonicalization measurement but not the excluded count. Your PDF §6.6 has it. Add:
   *"…measured against the 22 of 35 EP-CANONICALIZATION-v1 vectors that carry a pinned digest
   and a parseable input."*
2. **No pointer to the §6 limitations.** Your own PDF says "Read it before quoting anything from
   §1–§5", and the e-mail quotes §1–§5 without pointing at §6. This is the cheapest credibility
   win available: *"§6 of the write-up lists every place this run is weaker than it looks —
   please read it before quoting §1–§5."*
3. **No attachment list and no run date** in the e-mail body. The PDF is dated; the e-mail is
   not.
4. **The control result is missing from item 4.** `valid-chain.json` emitted zero integrity axes
   — the clean control against the 23 adversarial files. It is the strongest available evidence
   against a cherry-picking accusation, and it is not in the e-mail. Add:
   *"The clean control, `valid-chain.json`, emitted no integrity-class axis at all."*
5. **A sixth filed axis exists.** "Five of the axes the corpus exercises are already normative in
   filed text" is verified TRUE (`agent-action-scope-divergence` ×4,
   `agent-impersonation-suspected` ×4, `agent-principal-unverifiable` ×3,
   `agent-credential-absent` ×3, `freshness-stale` ×1). But your own PDF §5.1 table lists a
   **sixth** filed axis, `register-record-absent` (×1 in -01, no vector in `frozen-v1`). A reader
   who has the write-up open will quote your table at your e-mail. One parenthetical fixes it:
   *"(a sixth, `register-record-absent`, is filed but has no vector in frozen-v1)"*.

## F10 — tone and positioning

**Severity:** LOW · none of this blocks sending · entirely your call

Four observations, offered because the empiricist posture is this mail's single greatest asset
and these are the only places it slips:

1. **"Anton — this settles the CPB Related Work question in your favour … Use the wording as
   drafted"** and **"Iman — … it lands on your side"** adjudicate other people's disputes and
   award victories. To the recipients not being told they were right, that reads as
   coalition-building rather than measurement. "Confirms your reading" and "matches your
   guardrail" carry the identical factual content at no cost.
2. **The subject line carries raw commit hashes.** Unconventional; the pinned commits are in the
   body and the PDF.
3. **The closing "Ask:" carries one of the five asks** the PDF §7 makes. Either mirror all five
   or defer to §7 explicitly — a reader who acts on the e-mail alone will miss four requests
   directed at named people.
4. **The Tora paragraph is accurate and we are glad to have it.** No change requested. It
   characterises our scope boundary correctly (see the reply for detail).

## F11 — fold the `reject_tampered_anchor` → `version-replay` mapping into §5.2's "worth arguing" list

**Severity:** LOW · pre-empts an attack on the naming section

`arp_run_output.txt:51` maps `reject_tampered_anchor` to `version-replay`:

```
reject_tampered_anchor   REFUSE   artifact-class:match  signature:match  anchor:no-match[version-replay]
```

A vector whose own description is "the Merkle proof does not reconstruct the claimed root",
reported under an axis named for replay, reads as a mislabel on sight — and it is the first thing
someone will pick at in the naming discussion. It is much stronger raised by you, in §5.2, as
evidence *for* splitting `version-replay`, than left for someone else to find. See the
`version-replay` answer below, where this is the decisive argument.

---

# The three naming questions, and the new axis

You asked for these to be argued rather than assumed. Our positions, with the reasons:

## 1. `agent-credential-absent` — split it

**Two axes.** Your own run supplies the argument. The axis fires on the *valid* chain's genesis
receipt, whose issuer publishes it as legitimate: `governance.verdict = DEFERRED`,
`ruleId = high-risk-deferral` — an action correctly awaiting approval, which is the control
working, not failing. It also fires on `reject_lifecycle_*`, where a required signoff artifact is
genuinely missing. Same name, opposite fault models.

The first is arguably indeterminate-class rather than failure-class — exactly parallel to
`human-authorization-unproven`, which you already treat that way. Keep `agent-credential-absent`
for the failure case (no authorising credential exists) and add an indeterminate-class axis for
the deferred/awaiting state.

This also removes the one row in the whole run that a hostile reader can call a false positive:
ARP currently returns REFUSE on a receipt whose issuer publishes it as valid, and the disposition
column gives no way to tell that apart from a real credential failure.

## 2. `version-replay` — split it, and F11 is the proof

**Two axes.** `reject_unsupported_version` is a format-gate event: an unknown or future version
replays nothing, so the name is semantically wrong there. And the run maps `reject_tampered_anchor`
to the same axis (F11), which is a third distinct thing — a proof failure — collected under a name
that describes neither. One axis is currently absorbing "unsupported version", "legacy anchor
refused by default", and "tampered anchor".

Propose `version-unsupported` for the gate and `downgrade-to-legacy` for the actual
replay/downgrade defence, and re-map `reject_tampered_anchor` onto the anchor axes where it
belongs.

## 3. `canonicalization-gate-failed` — three axes

**Three.** They occur at different pipeline stages with different attacker models:

- **parse-failed** — not well-formed JSON at all
- **profile-violated** — well-formed, breaks an I-JSON profile predicate (unsafe integer,
  non-integer real)
- **representation-noncanonical** — in-profile but non-canonically encoded (a timestamp without
  an offset, `required_approvals` as a string)

This run *demonstrated* why the merge is costly: your §6.1/§6.2 disclose that seven of the nine
`malformed/*` files are refused at a generic shape gate rather than by a purpose-built parse
check, and that the current axis name "implies a check which did not run". That is the
parser-differential problem (CPython vs our `strict_load_text`) and a merged axis papers over
exactly the distinction a relying party needs. An axis that cannot distinguish "could not parse"
from "parsed but non-canonical" reintroduces the ambiguity ARP exists to remove.

## 4. `anchor-leaf-not-bound-to-payload` — adopt it, and here is the vector

**Adopt.** The kind-distinction from `log-proof-broken` is real: a valid inclusion proof for a
leaf nobody tied to this payload survives a log audit, which is precisely why conflating the two
loses the information a relying party acts on.

Your §3 is right that the corpus does not currently isolate it, and you were right to say so.
**We have built the isolating vector and it is attached to this memo.** Three things it
establishes, each independently checkable:

**First, the construction is confirmed rather than assumed.** Our generator recomputes EMILIA's
own published `accept_with_merkle_anchor_v2` under `leaf = SHA-256(0x00 ‖ JCS(payload))`,
`branch = SHA-256(0x01 ‖ leftHex ‖ rightHex)` and reproduces both the published leaf and the
published root byte-for-byte. It refuses to emit anything if that check fails.

**Second, neither published anchor-negative vector isolates the two failure modes** — and this is
one step beyond your §3 caveat:

| vector | leaf bound to payload? | proof reconstructs root? | isolates? |
|---|---|---|---|
| `accept_with_merkle_anchor_v2` | yes | yes | — |
| `reject_v2_unbound_leaf` | **no** | **no** | no |
| `reject_tampered_anchor` | **no** | **no** | no |

Your §3 says `reject_v2_unbound_leaf` "is both unbound and proof-broken … on manual inspection".
That is now measured rather than inspected. But note the second row: **`reject_tampered_anchor`
is also both**, despite being the vector whose description is specifically about a proof that
does not reconstruct the root. So the corpus currently isolates *neither* axis — not
`anchor-leaf-not-bound-to-payload`, and not `log-proof-broken` either. That strengthens your
case: this is not one missing vector, it is a gap on both sides of the distinction you are
drawing.

**Third, the new vector isolates cleanly.** `reject_v2_unbound_leaf_proof_valid`: the signature
verifies, the inclusion proof reconstructs the declared root **exactly**, and the only defect is
that the proven leaf is not this receipt's payload. The anchor's leaf, sibling and root are your
corpus's own published values, so the proof is a genuine proof about a genuine leaf in a genuine
tree — it simply proves someone else's payload. Key material is deterministic from a published
test-only seed, so you can regenerate it byte-for-byte and contradict us if we have it wrong.

A verifier that reports `log-proof-broken` on this vector is wrong. A verifier that reports valid
is worse. That is the axis, demonstrated.

**One observation that emerged while building it**, and we think it belongs in -02: in
EP-RECEIPT-v1 the signature covers `JCS(payload)` **only** — the anchor is outside the signed
surface. We verified this by reconstructing the preimage for `accept_minimal` and confirming
Ed25519 verification succeeds over `JCS(payload)` and fails over every document-level candidate
we tried. So any validly-signed receipt can have any anchor attached to it by anyone, with no
signature to break. That is not a defect in the vector set — it may well be intentional, since
the log is a separate authority — but it is the reason `anchor-leaf-not-bound-to-payload` is a
*reachable* condition rather than a theoretical one, and it deserves a sentence in the spec.

## On the two missing interop-set behaviours

`controller-reported outcome` and `physical-completion non-claim` are EP-BOUNDARY-v1 vectors —
EMILIA's corpus, not ours. We are not contributing them, and want to be explicit about why rather
than going quiet: NOA has a worked design position on both (separate signed controller-outcome and
physical-observation artifacts, the base receipt left frozen, and a
`NOT_CLAIMED` / `NOT_PROVIDED` / `NOT_APPLICABLE` / `INDETERMINATE` distinction that we think the
absence semantics require), but the implementation is deliberately deferred in our repository.
Authoring vectors for claim types we have not implemented would produce exactly the artifact this
whole exchange is arguing against — one that cannot demonstrate what it exists to demonstrate. The
design position is yours to use if it is helpful.

---

# On -02's normative language

RFC 8174 boilerplate is present in -01 (two occurrences), so the machinery is there. One
substantive note on the drafting: **"the Claim Hash and the subject digest MUST NOT be substituted
for one another" has no testable actor as written.** A `MUST NOT` needs a subject who can violate
it and a verifier who can detect the violation.

Recast it as verifier behaviour:

> An artifact carrying a digest MUST carry the construction identifier under which it was
> computed. A verifier presented with a digest under a construction identifier it does not
> recognise, or that does not match the construction it is comparing against, MUST treat the
> comparison as non-matching and MUST NOT compare the digest values.

That version is vector-testable, which is what makes it worth filing. It also makes F2 existential
rather than administrative: this normative text is unimplementable until the identifier derivation
is specified, because a verifier cannot recognise an identifier it cannot compute.

---

# Summary

| # | Severity | Owner | Item |
|---|---|---|---|
| F1 | CRITICAL | artifacts | `arp_run.json` construction id contradicts e-mail, console, PDF |
| F2 | HIGH | artifacts + -02 | harness not attached; id derivation unspecified anywhere |
| F3 | HIGH | PDF | "profile is named RFC 8785 JCS" false against filed -01; p.2 vs p.13 |
| F3b | HIGH | -01/-02 | RFC 8259 normative work from an informative reference; referent does not exist |
| F4 | MEDIUM | e-mail | 95 correct but unreproducible from the JSON (82) |
| F5 | MEDIUM | PDF | "20 distinct axes" → 29; substantive count 18 vs 19 |
| F6 | MEDIUM | e-mail | collisions need sort-scoping and a "not SHA-256" qualifier |
| F7 | MEDIUM | e-mail | "signatures verified"; row-3 axis attribution |
| F8 | LOW | — | invariant holds in data; "self-check asserts it" resolves with F2 |
| F9 | LOW | e-mail | five one-line omissions (22-of-35, §6 pointer, attachments/date, control result, sixth axis) |
| F10 | LOW | e-mail | tone: adjudication, subject line, one-of-five asks |
| F11 | LOW | PDF §5.2 | fold the `reject_tampered_anchor` → `version-replay` mapping in as evidence |

F1–F3 before sending. The rest are worth the same pass.

---

## What we checked and could not fault

Recorded because a review that only lists defects misrepresents the work:

- **Every load-bearing number reproduces.** 22/22, 20/22, 19/22, 5/13/111/129, 18 = 5+13, 23/23,
  14+9 files, 16 suites, and the disputed 95 by direct census at your pinned commit. The commit
  dates in the PDF match `git show` exactly. Both collision digest equalities are byte-true.
- **The verified/declared firewall is held with unusual discipline** — `provenance:
  expectation-derived` on every consumed leg in the JSON, §0 and §6.3 in plain words, and console
  section 1d saying outright "they are NOT evidence that ARP verified anything."
- **§6 as a genre.** A limitations section that pre-empts nearly every attack we were asked to
  mount is rare. Keep it exactly as it is; it is the reason the rest of the document survives
  adversarial reading.
- **`cross-chain-splice` is the strongest single demonstration in the package** — both receipts
  hash and verify correctly in isolation, and the forgery is a property of the set. We are glad
  it is our corpus that furnishes it.
- **The `noa.receipt/0.1` characterisation is verbatim-accurate.** The three-way authorization
  result (`DEFERRED` → `agent-credential-absent`, `approval.by = HUMAN:…` → match, `low-risk-auto`
  → `human-authorization-unproven`) matches our `valid-chain.json` exactly, including
  `approval.by = "HUMAN:hmac-sha256:ef5b…"`.

## Marked `[UNVERIFIED]`

- **(a)** Whether the harness self-check computes its invariant or prints it. Settled only by the
  harness source (F2/F8).
- **(b)** The six-behaviour interop set has no public referent we can find — it exists in the
  participants' correspondence. Internally consistent everywhere it appears; we simply cannot
  check it against anything, and neither can a new reader. A one-line definition in -02 or the
  write-up would fix that.
- **(c)** The id-derivation function is unspecified in the artifact set, the filed -01, and the
  write-up. This is F2's core, restated here so it is not lost as residue: it is the one item that
  blocks a normative -02 rather than just this send.
