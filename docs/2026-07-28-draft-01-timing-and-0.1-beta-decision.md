# Decision analysis — when to file `draft-noa-scitt-ai-agent-receipt-01`, and what `0.1-beta` is

| | |
|---|---|
| **Status** | OPINION AND PLAN ONLY. No code, no schema, no draft edits, no commits, nothing filed or published. Untracked file. |
| **Date** | 2026-07-28 |
| **Decision owner** | The principal. §11 lists exactly which decisions are his. |
| **Evidence labels** | `[VERIFIED]` fetched or measured today · `[PROJECT CLAIM]` asserted by this project's own docs/commits, not independently re-run · `[INFER]` architectural inference from verified facts · `[ASSUME]` flagged assumption · `[INSUFFICIENT EVIDENCE]` could not check |

---

## 0. The decision, up front

**File `draft-noa-scitt-ai-agent-receipt-01` on Wednesday 2026-08-12.**
Earliest defensible: 2026-08-05. Latest safe: 2026-10-26. Hard stop: 2026-11-02 23:59 UTC
(IETF 127 I-D cutoff). The date is two weeks out not because the text needs writing — it is
written and committed — but because the two weeks buy the three things that make the filing
defensible instead of merely fast: the interop branch landing on main, a conformance-evidence
sweep over every new normative MUST, and the principal's sign-offs (§9).

**Cut `0.1-beta` on Friday 2026-08-28, gated on evidence, not the calendar.** `0.1-beta` is a
**profile-maturity milestone of `noa.receipt/0.1`** — a git tag plus VERSIONING/CHANGELOG
entries — NOT an npm version and NOT a new package release (§6). It ships when every
normative MUST in the filed -01 has a passing mechanical check in all five sibling
implementations. If that evidence exists sooner, cut sooner; if it does not exist on
2026-08-28, the date slips to the evidence, never the reverse.

New expiry created by an 2026-08-12 filing: **2027-02-13** (185 days), covering IETF 127
(Nov 14–20) with three months to spare.

---

## 1. Evidence base

### IETF mechanics
- `-00` was submitted to the datatracker on **2026-06-23** — same day as the render commit
  `4e77fc4` — and **expires 2026-12-25**, as an active individual I-D with no WG association.
  `[VERIFIED]` — datatracker doc page, cross-checked against the filed TXT's own masthead
  (`docs/ietf/draft-noa-scitt-ai-agent-receipt-00.txt:8` "Expires: 25 December 2026") and the
  standard boilerplate at line 44: "Internet-Drafts are draft documents valid for a maximum of
  six months and may be updated, replaced, or obsoleted by other documents at any time."
- **IETF 127: 2026-11-14 to 2026-11-20, San Francisco. I-D submission cutoff: Monday
  2026-11-02 23:59 UTC.** `[VERIFIED]` — datatracker important-dates page + upcoming-meetings
  page, fetched separately and agreeing. IETF 126 (Vienna) is already past (July 2026; its
  cutoff was 2026-07-06). When exactly the submission tool reopens after the 127 cutoff:
  `[INSUFFICIENT EVIDENCE]` — not stated on the fetched pages; plan assumes nothing about it.
- What expiry costs mechanically: the datatracker help page lists "Expired" as a state but the
  fetched excerpt carried no definition, and the mail-archive/author-resources pages I tried
  returned 403/404. Whether a post-expiry -01 submission reactivates the document without
  special procedure: `[INSUFFICIENT EVIDENCE]`. The plan therefore treats **2026-12-25 as a
  real deadline** rather than leaning on resurrection folklore. What IS verified is the
  boilerplate above: an expired draft is, by its own text, inappropriate to cite except as
  work in progress — which is exactly the state the principal wants to avoid.

### SCITT WG state
- The WG's core is finishing: **RFC 9943 (architecture), RFC 9942 (COSE receipts), RFC 9995
  (hash envelope) published; SCRAPI in the RFC Editor queue; CCF profile at the IESG.**
  `[VERIFIED]` — WG documents page + IETF 126 session minutes (session held 2026-07-24).
- At IETF 126 the chairs floated continuing the WG on "application-level interoperability
  conventions" above the opaque-payload layer; the room poll was **11 yes / 6 no / 5 abstain —
  tentative interest, no rechartering decision.** An MMR profile adoption call is going to the
  list. `[VERIFIED]` — minutes.
- **Neither our draft nor draft-hillier-scitt-arp appears in the 126 minutes.** The AI item
  discussed was an "AI model bill of materials" proposal. `[VERIFIED]` — minutes.
- No SCITT session is yet listed for IETF 127 — expected, since 127 sessions are not yet
  scheduled; this is absence of scheduling, not absence of a session. `[VERIFIED]` fetch,
  `[INFER]` interpretation.
- The individual-draft neighborhood is real and active: **draft-hillier-scitt-arp-01** (filed
  2026-07-23, expires 2027-01-24, standards-track intent, individual);
  **draft-kamimura-scitt-vcp-03** (SCITT profile for algorithmic-trading audit trails, updated
  2026-07-21); **draft-nelson-agent-delegation-receipts-10** (AI-agent authorization receipts,
  revision ten, references SCITT for transparency). `[VERIFIED]` — datatracker pages. We are
  not alone in front of this WG, and the others are revising actively.
- Mentions of either our draft or ARP on scitt@ietf.org: `[INSUFFICIENT EVIDENCE]` — the
  archive search endpoint returns 403; a web search surfaced no list mention of ours.

### Our own delta (measured, not estimated)
`git diff 4e77fc4 HEAD -- docs/ietf/draft-noa-scitt-ai-agent-receipt.md`:
**+104 / −12 lines** in the mmark source, across three commits — `d6fd4be` (2026-06-24,
Option B verifier forward-compat), `7018c4d` (2026-07-10, contact address), `1769b99`
(2026-07-27, canonicalization parameters + chain axes + alg-note correction). `[VERIFIED]`
Full inventory in §2. Note: `1769b99` exists **only on branch `arp-interop-response-20260727`**
(pushed); `origin/main` does not have it. The branch is ~20 commits ahead of main, most of
them breaking security work. `[VERIFIED]`

### Implementation truth behind the -01 text
- The kid/forward-compat behavior the -01 text normatively requires (Option B) **is contained
  in the published npm 0.5.0**: `git merge-base --is-ancestor d6fd4be v0.5.0` → yes.
  `[VERIFIED]`
- The `-8`→`-19` alg migration shipped in package 0.3.0 (VERSIONING.md) — so -01's corrected
  alg note describes published reality, and -00's "migration in progress" note is the stale
  claim. `[PROJECT CLAIM]` (VERSIONING/CHANGELOG; not re-run today).
- The five chain-level failure axes are implemented in the verifier ("Our verifier already
  implements all five; they were unnamed in the spec" — `1769b99` commit message).
  `[PROJECT CLAIM]` — this is precisely what the §9 pre-filing evidence sweep converts into
  `[VERIFIED]` before submission.
- Bytes-in migration status: **NOT IMPLEMENTED** — 21 of 24 security-sensitive entry points
  not yet bytes-in; package still 0.5.0; and the migration's load-bearing promise is "**No
  receipt bytes change. Ever, in this migration.**" (`docs/MIGRATION-1.0.0.md` §0–§1).
  `[PROJECT CLAIM]`
- External consumers of the published packages: **zero verified**; ADR §10.6 marks this
  `INSUFFICIENT_EVIDENCE` and download counts can only ever give a lower bound.
  `[PROJECT CLAIM]`

### Decision-context documents (all dated 2026-07-27/28, all awaiting the principal)
- ADR-0001 **Amendment 1 (PROPOSED)**: authority rule, correlation-sidecar rejection, and the
  **six-condition threshold for `noa.receipt/0.2`** (A1.3) — until all six hold, "the existing
  normative reservation in the working draft is the entire 0.2 roadmap." Priority order A1.4:
  bytes-in · KMS custody · chain persistence · RFC 3161 · SCITT registration, all ahead of the
  correlation topic. `[VERIFIED]` — file read today.
- **CAID reply** (to Iman Schrock / Emilia, re: his 2026-07-28 mapping review): drafted, for
  the principal's signature, unsent. It answers his two questions against the filed -00 and
  cites the -01 working-copy text by branch commit SHA, with provenance openly disclosed.
  `[VERIFIED]`
- **ARP thread reply**: drafted, unsent, sequenced after the private findings memo goes to
  Hillier. It references a "**15th**" in Hillier's mail whose referent could not be found in
  any artifact — the reply asks rather than assumes. `[VERIFIED]` that the referent is
  unfound; the date's meaning is `[INSUFFICIENT EVIDENCE]`.
- Hillier's run report makes **two asks of our -01**; both are implemented by `1769b99`
  (that commit's stated purpose). `[VERIFIED]` — commit message + diff content match the asks
  as described in the reply drafts.

---

## 2. Change inventory since the filed -00, with classifications

From the measured diff (+104/−12). Classification: **MUST-BE-IN-01** · **COULD-WAIT** ·
**MUST-NOT-GO-IN-YET**.

| # | Change | Size | Class | Why |
|---|---|---|---|---|
| 1 | docName/seriesInfo bumped to -01 | 2 lines | MUST | Mechanical. |
| 2 | Author email → toratoraman@gmail.com | 1 line | MUST (principal confirms) | Deliberate single-monitored-contact decision (`7018c4d`); masthead identity is the principal's call, §11. |
| 3 | §payload NFC rewording: producers MUST emit NFC, verifiers MUST NOT normalize | ~4 lines | MUST | -00's "all strings MUST be Unicode NFC" misstates what the verifier enforces; this is a correction of a filed normative sentence, not a feature. |
| 4 | **New §canon-params**: 9-parameter normative table (JCS, UTF-16 code-unit sort, integer bound, surrogate/duplicate rejection, domain-separation tags) | ~35 lines | MUST | The externally-requested core. Two independent interop efforts (ARP run report; Emilia's CAID review) hit the same defect class — "digest compared without a pinned construction" — within days. This section is the answer both asked for. |
| 5 | `paramsHash` boundary paragraph: per-producer commitment, NOT a shared action digest; future cross-producer digest MUST carry construction identifier | in §canon-params | MUST | This paragraph **is** the "existing normative reservation" that Amendment A1.3 designates as the entire 0.2 roadmap. Filing it makes the reservation public and stable instead of a branch SHA. |
| 6 | COSE header rewrite: kid protected-or-unprotected, resolve from either, prefer protected; MUST NOT reject extra registered protected headers unless in `crit` | ~15 lines | MUST | Fixes an RFC 2119 self-contradiction in -00 and documents behavior already shipped in npm 0.5.0 (`[VERIFIED]` above). |
| 7 | **New §chain-axes**: five named chain-level failure axes, MUST detect all five, SHOULD report distinctly | ~28 lines | MUST | Implemented but previously unnamed; one of Hillier's two asks. |
| 8 | §security: checkpoint-scope paragraph (scope of a checkpoint check = scope of the signing key; manifest-less limitation MUST be surfaced) | ~12 lines | MUST | Narrows a guarantee -00 left overstated. Honesty corrections do not wait. |
| 9 | §security: non-NFC byte-equality paragraph (visual equality ≠ byte equality; compare as bytes) | ~5 lines | MUST | Direct consequence of #3; omitting it would leave #3 a trap. |
| 10 | Implementation-status alg note corrected: `-19` migration is complete; -00's "in progress" claim explicitly retired in-text | ~11 lines | MUST | -00 currently makes a false-in-the-stale-direction claim about our own implementation. Fixing the filed record is by itself sufficient reason for a -01. |

**COULD-WAIT (deliberately deferred, with target revision):**
- Acknowledgments naming Hillier/Certisyn or Schrock/Emilia → **-02 at the earliest, only
  with their explicit consent**. Their artifacts are private or unsent; naming them now would
  breach the standing instruction in the reply drafts.
- An interoperability-note section describing the CAID mapping outcome ("fields absent by
  design; INDETERMINATE is correct") → **-02, and only if Emilia's exchange concludes and both
  sides want it recorded**. See §5.
- Any IANA action (e.g. a construction-identifier registry) → **the revision that defines a
  shared digest, i.e. 0.2-era, behind the six conditions**.

**MUST-NOT-GO-IN-YET (the 0.2 red line, checked against the working copy):**
- `target_ref` or any acted-upon-object field; a shared cross-producer action digest; a
  parameter-normalization construction — all gated by Amendment A1.3's six conditions.
- The correlation sidecar in any form — **rejected** by A1.2 (`MAPPING_PROFILE_ONLY` verdict,
  accepted by the principal 2026-07-28).
- Any claim of external consumers/adoption (zero verified), any SCITT-registration timing
  promise, any digest-equivalence attestation (A1.5 non-claim).
- **Line-by-line check of the diff: nothing currently in the working copy crosses the line.**
  The only future-facing sentence is the conditional reservation in #5, which constrains a
  future 0.2 rather than promising one — that is the reservation A1.3 depends on, and it
  stays. `[VERIFIED]` — full diff read; no other future-tense normative material present.

---

## 3. Q1 — earliest defensible and latest safe dates

**Earliest defensible: 2026-08-05.** The text is committed and internally QA'd; the render
pipeline is proven (`4e77fc4` produced a zero-error xml2rfc render via the author-tools API);
submission is open now (126's cutoff has passed). One week suffices mechanically. What makes
Aug 5 *defensible-but-thin* rather than right: the conformance-evidence sweep (§9 item 3)
would be compressed, and filing normative MUSTs whose mechanical checks haven't been run is
the exact overclaim failure mode this project spent the last week paying down.

**Recommended: 2026-08-12.** See §0 and §9.

**Latest safe: 2026-10-26** — one week of buffer before the 2026-11-02 23:59 UTC cutoff, so a
submission-tool problem or a render failure has recovery room. After the cutoff the tool is
closed until around the meeting (reopening time `[INSUFFICIENT EVIDENCE]`), which would push
filing into Nov 14+, six weeks before expiry, over the year-end holidays — still possible, but
by then the filing is deadline-driven archaeology-prevention rather than participation.

**What lateness actually costs, in order of reality:** (1) the live interop exchange keeps
citing git branch SHAs instead of a stable archived document for months; (2) if the WG's
tentative rechartering conversation (11/6/5 poll) continues at 127, the profiles on the table
will be the *active, current* ones — VCP is at -03, ARP at -01, delegation-receipts at -10,
and we would be the -00 from June that never moved; (3) only last, and only after 2026-12-25,
the expiry itself.

---

## 4. Q2 — why this -01 is worth the slot

A revision slot is wasted on typos and spent well on exactly three things, and this -01 has
all three:
1. **A correction of the filed record** (#3, #10): -00 currently misstates both a normative
   requirement and our own implementation status. The alg note even says migration completion
   is "a precondition for any normative revision" — the precondition is met and the -01 says
   so with the receipt.
2. **Externally-requested normative substance** (#4, #5, #7): two independent counterparties
   asked for precisely this material within one week. A -01 whose delta was demanded by
   people trying to interoperate is the strongest revision class an individual draft can
   ship.
3. **Nothing promissory**: every normative sentence in the delta describes behavior that is
   implemented and (for #6) published. The one forward-looking sentence is a constraint on a
   future revision, not a promise of one. This is the anti-overclaim posture the project has
   ratified, applied to the standards track.

---

## 5. Q4 — how the CAID exchange bears on the date

**It does not gate -01, and -01 does not gate it — but filing order slightly favors -01
first, and the recommended date achieves that without coupling.**

- Amendment A1.3's condition 3 (CAID response sent + Emilia's reply establishing an *actual*
  interoperability requirement) gates **`noa.receipt/0.2`**, not -01. -01 contains no 0.2
  material (§2), so the exchange has no veto over the filing.
- Nothing from the exchange belongs *in* -01: the counterparty artifacts are private or
  unsent, consent is absent, and the intellectual output of the exchange — the
  construction-identifier requirement — is already in the -01 text in general form. An
  interop note is -02 material at the earliest (§2 COULD-WAIT).
- The CAID reply should be sent **when the principal signs it, without waiting for the
  filing**: responsiveness to a review received 2026-07-28 outranks citation elegance, and
  the draft reply already handles the -00/-01 provenance honestly. If it happens to go out
  after 2026-08-12, one line can upgrade the SHA citation to "-01, §Canonicalization
  parameters" — a strengthening, not a dependency.
- The ARP thread reply is sequenced behind the private memo to Hillier (standing
  instruction), and Hillier's unexplained "15th" is the one calendar ghost in the file. If it
  means 2026-08-15, an -01 filed on the 12th lets the thread reply cite a filed document
  days before that date; if it means something else, the 12th costs nothing. The date is
  robust under both readings of an unverifiable referent — which is what makes it decidable
  despite the `[INSUFFICIENT EVIDENCE]`.
- The unsent standards-question draft (demand-gauging for a normalization profile) is
  strictly *better* asked with a filed -01 to point at: the reservation it presupposes would
  be public. Recommend it wait for the filing; principal's call (§11).

---

## 6. Q5 — what `0.1-beta` is

The string "0.1-beta" appears **nowhere in the repository** (`grep` across docs/, README,
VERSIONING, CHANGELOG — zero hits). `[VERIFIED]` It is unbound, so this section proposes the
binding and §11 hands it to the principal for ratification.

**What it cannot be:** an npm version. The package namespace is at 0.5.0 (`[VERIFIED]` npm);
publishing anything called 0.1-beta there is a semver-ordering absurdity. The project's own
VERSIONING.md separates the **package version** (0.5.0) from the **wire-format version**
(`noa.receipt/0.1`, inside the signed bytes). `0.1-beta` can only meaningfully attach to the
second.

**Proposed definition — `0.1-beta` is the declared maturity state of the `noa.receipt/0.1`
profile:**
1. `-01` is filed — because §canon-params is what makes the profile independently
   implementable *from the spec alone*, without reverse-engineering the reference
   implementation. Pre-canon-params, two conformant implementations could disagree on bytes;
   that is the definition of alpha. Post-pinning is the alpha→beta line.
2. **Every normative MUST in the filed -01 has a conformance vector or mechanical test, and
   the checks pass in all five sibling implementations** (TS, Python, Go, Rust, C#) — the
   five-verifier agreement is already "the strongest correctness control the project has"
   (MIGRATION-1.0.0 §7); beta extends it to the newly named MUSTs (surrogate/duplicate/
   integer-bound rejection; the five chain axes).
3. The published packages' behavior matches the -01 text (Option B already verified in
   0.5.0).

**Shipping it means:** a git tag (suggest `spec/noa.receipt-0.1-beta`), a VERSIONING.md
paragraph, a CHANGELOG entry. Nothing published to npm; no announcement implied.

**What it commits us to:** semantic freeze of 0.1 — any field-set or canonicalization change
henceforth requires `noa.receipt/0.2` under the six conditions. That is a cheap commitment
because it is already the project's frozen-format promise; the tag makes it citable. It does
**not** claim production-grade custody (the KMS/persistence gaps remain open and documented),
does not signal 1.0, and claims no adoption.

**Date: 2026-08-28**, two weeks after filing, gated on condition 2's 5/5 evidence. The TS and
Python checks should already exist or be created for the pre-filing sweep (§9); the two weeks
are for Go/Rust/C# vector parity. Evidence early → cut early; evidence missing → the tag
waits, and no interim "basically beta" language is used anywhere.

---

## 7. Q6 — sequencing against the security work

**-01 precedes the bytes-in migration, deliberately, and this is not a credibility risk —
because of what the draft is about.** The draft documents the wire format and verification
semantics. The bytes-in migration changes the TypeScript API boundary and, by its own
load-bearing promise, changes **no receipt bytes, ever** (MIGRATION-1.0.0 §1). The subject
matter of -01 is therefore *invariant* under the rewrite: there is no state of the migration,
including its failure, in which a sentence of -01 becomes false. "Spec ahead of a mid-rewrite
implementation" is only expensive when the spec describes the thing being rewritten; here it
does not.

Conversely, chaining -01 behind bytes-in (not implemented, 21 entry points to go, no landing
date) would couple a days-cheap document to an unbounded engineering timeline and burn the
window in which two external parties are actively reading our -00.

Amendment A1.4's priority order (bytes-in · KMS · chain persistence · RFC 3161 · SCITT
registration) is not violated: A1.4 sequences **implementation effort on the correlation
topic**, and -01 is not correlation work — it is the reservation that *prevents* correlation
work from starting prematurely. Filing consumes render-and-checklist hours, not implementer
weeks. The one A1.4 item -01 touches at all is SCITT registration, and -01 stays silent on
registration timing (§2 MUST-NOT list).

`0.1-beta` likewise precedes bytes-in — its conformance evidence lives in the five sibling
implementations, which "need zero migration" (MIGRATION-1.0.0 §5).

---

## 8. Q7 — what a mature standards participant does here

The observable field norm, from the datatracker `[VERIFIED]`: active individual SCITT-adjacent
drafts revise on feedback within weeks — ARP went -00→-01 by 2026-07-23, VCP is at -03 as of
2026-07-21, the delegation-receipts draft is at -10. A -00 filed in June that responds to two
independent reviews with an August -01 reads as a participant; one that reappears in December,
days before expiry, reads as a tombstone-refresh. Revision cadence *driven by interop
feedback* — never by the calendar alone — is exactly the pattern that distinguishes the two.

The WG context sharpens this: SCITT's core documents are done or in the queue, and the open
question at 126 was precisely whether the WG takes on "application-level interoperability
conventions" (poll 11/6/5, undecided). If that conversation continues at 127, the profiles in
the room will be the ones that are current and evidenced. Neither our draft nor ARP has yet
been mentioned in minutes or (as far as searchable) on the list — visibility is currently
zero, which cuts both ways: no momentum lost, and the first list posting will be the actual
introduction.

Two customary follow-ons, both the principal's call (§11), both cheap and standard practice:
a short post to scitt@ietf.org in filing week (what changed in -01 and why — interop-driven),
and a decision by mid-October on whether to request a few minutes in the SCITT session at 127
(agenda-request deadlines for 127: `[INSUFFICIENT EVIDENCE]`, typically weeks before the
session — check when the 127 agenda process opens).

---

## 9. Dependency chain and pre-filing checklist for 2026-08-12

Ordered; owners in brackets. None of it is started by this document.

1. **Principal decisions batch** (§11) — ideally this week: Amendment 1 ratify/reject; the
   three letters send/hold; confirm masthead email; approve the filing itself. [principal]
2. **Land `1769b99` on main** — via the `arp-interop-response-20260727` PR if its security
   review completes in time; otherwise cherry-pick the single-file docs commit to main. The
   fallback keeps the date immune to the 20-commit security review's timeline. [lead]
3. **Conformance-evidence sweep** — for each normative MUST in the -01 delta, point to the
   mechanical check that enforces it (TS + Python minimum): surrogate rejection, duplicate
   member rejection, integer bound, no-normalization, the five chain axes, Option B header
   acceptance, `-19`-only. Any MUST with no check: add the vector or soften the sentence
   **before** filing — never file, then backfill. This converts §1's `[PROJECT CLAIM]` rows
   to `[VERIFIED]` and is the item most likely to move the date (§12). [lead]
4. **Mechanical render** — bump the date field, regenerate TXT/XML through the IETF
   author-tools pipeline that produced the zero-error -00 render, run idnits, diff the
   rendered -01 against the source for drift. [lead; hours]
5. **Submit 2026-08-12** via datatracker; the submission is made under the principal's name
   and happens only on his go. [principal-gated]
6. Same week, if approved: scitt@ietf.org note; CAID/ARP letters upgraded to cite the filed
   -01 if they have not yet gone out. [principal-gated]

---

## 10. Risks

**Filing too early (before the checklist closes):** a normative MUST ships without its
mechanical check — the precise overclaim class this project has spent a week eradicating,
now in an archived public document with our name on the masthead. Or the draft file ships
from an unmerged branch and main subsequently diverges from the filed text. Both are
self-inflicted and both are what the two-week buffer exists to prevent.

**Filing too late:** the interop exchange cools with our best text stranded on a branch;
127 arrives with us as the stale profile in an active neighborhood; the Nov 2 cutoff turns a
missed week into a six-week blackout; and past Dec 25 the -00 becomes, by its own boilerplate,
a document inappropriate to cite — with the CAID review having revision-pinned exactly that
document.

**Residual risks at the recommended date:** Hillier's reply to the private memo could raise
new substantive findings after 2026-08-12 — policy: they go to -02; -01 does not chase a
moving conversation. The "15th," if it means something other than a date, costs nothing.
A stalled security-review PR is defused by the cherry-pick fallback (§9.2).

---

## 11. The principal's decisions — not mine

1. **Ratify or reject ADR-0001 Amendment 1** (authority rule, sidecar rejection, six-condition
   0.2 threshold). The -01 filing does not depend on it, but the reservation-as-roadmap logic
   in §2 leans on A1.3 being the ratified rule.
2. **Approve the -01 submission itself and its date** — a public act under his name.
3. **Sign/send or hold each letter**: the private ARP memo, the ARP thread reply (memo-first
   sequencing stands), the CAID reply, and the unsent standards question.
4. **Masthead contact**: keep toratoraman@gmail.com (the 7018c4d single-monitored-address
   decision) or revert.
5. **Ratify the `0.1-beta` definition** (§6) — the term is his; this document only proposes
   its binding.
6. **External visibility**: the scitt@ list post; whether to seek 127 agenda time.

## 12. What moves the dates

| Trigger | Effect |
|---|---|
| Evidence sweep (§9.3) finds an unimplemented MUST | Date slips week-for-week with the fix — or the sentence is softened honestly; whichever, the filed text and the mechanical checks agree on filing day. Hard stop 2026-10-26. |
| Principal decision batch not available by 2026-08-08 | Slip to the Wednesday after the batch lands; same hard stop. |
| Hillier or Emilia surfaces a *defect in the -01 text itself* before filing | Fix in place and keep the date if it fits the checklist; else slip one week. New *requests* (not defects) → -02. |
| The "15th" turns out to be a real pre-Aug-15 obligation | No change — the 12th already precedes it. |
| SCITT rechartering news (list adoption calls, 127 agenda opening) | No change to -01; may advance the §8 visibility decisions. |
| 5/5 vectors green before 2026-08-28 | Cut `0.1-beta` early, same gate. |
