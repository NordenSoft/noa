# CORRECTIONS

Claims made in this repository — in commit messages, docstrings, plans or reports — that were later
found to be wrong, overstated, or unverifiable. One file, appended to, never rewritten.

**Why a file and not a history rewrite.** This branch is unpushed, so the commits could be edited.
They are not, and will not be. The record of a wrong claim is the most useful part of it: it is how
the next reader learns which kinds of claim this project gets wrong, and rewriting history destroys
exactly that while making the repository look like it never erred. A correction that costs nothing
teaches nothing.

**What belongs here.** A claim that a reader could have ACTED on. Not typos, not wording.

---

## 2026-07-30 — the audit of the `Verified:` lines, and what it actually found

An open item read: *"Four commits carry `Verified:` lines I cannot reproduce; a correction note is
owed."* Audited. **The item does not hold up as written, and the correction runs the other way.**

### C-1 — the finding was wrong: there are 14, not 4, and they are more careful than claimed

Fourteen commits on `impl/adr-0005-trusted-input-provenance` carry a `Verified:` line. Every one that
mentions `tsc` names the packages INDIVIDUALLY:

```
4af58a3  "tsc 0 across all six packages"
de51690  "tsc 0 across all six packages"
5cfc796  "tsc 0 across relay/signer-core/gate/approval-artifacts/evidence/e2e-demo"
7d9aa6f  9d863e0  89a65ff  127ff8b  9eca2ba  a24618e   — same per-package form
04fff42  "relay tsc exit 0"                             — scoped to one package
2c0af6f  707c555  e449c20  6e91d6b                      — make no tsc claim at all
```

Per-package is the honest form: each package's `npm test` runs its own `tsc` first, so those claims
were backed by the thing that actually ran. Not one of the fourteen claims a repository-wide
typecheck.

Also audited: `707c555`'s "knockout registry exit 0 (34 entries)". The registry at that commit
carries 34 entries and the tool prints `killed 34/34`. **The claim is exact.** My first count said 0
because I grepped for `{ id:` on one line when the file spells it across two — a failed grep is not
a finding, and asserting from one is the same defect this file exists to record.

### C-2 — MY OWN correction in `985d0a0` overstated, and this corrects it

`985d0a0`'s message says:

> *"several commit messages on this branch, mine included, cite 'tsc -b exit 0' in their evidence
> blocks as the repository's typecheck."*

**"Several … on this branch" is wrong.** The audit above shows the earlier commits are clean. The
unqualified `tsc -b exit 0` line appears in exactly TWO commits, both written by me on 2026-07-30:

```
b045082:47   tsc -b       exit 0   (read directly, not through a pipe)
3f4e9f3:73   tsc -b        exit 0   (read directly, not through a pipe)
```

Neither says "repo-wide" — but both sit at the head of a block listing every package's test counts,
and an unqualified `tsc -b` in that position reads as covering them. It does not: the root
`tsconfig.json` has `references: null` and includes only `src/`, `test/`, `scripts/`.

**So the scope error is real and the attribution was not.** I spread my own mistake across a dozen
commits by other-and-earlier work, which is a worse error than the one I was correcting — it makes
the record less accurate while appearing more rigorous. Recorded rather than quietly narrowed.

The underlying gap is closed: `scripts/typecheck-all.mjs`, wired as the first step of
`npm run security-gates`, typechecks the root and all 11 packages and prints each exit separately.

### C-3 — `phone-core` does not exist

An open item read: *"phone-core golden path NOT EXECUTED."* There is no `phone-core` package, in
`~/noa-receipt` or in `~/noa-trust`. Searched both trees for the directory and both `package.json`
sets for the name; nothing.

The two real things with adjacent names, both executed and green on this branch:

```
test/golden-backcompat.test.ts        16/16  (inside root 518/518)
packages/e2e-demo/src/phone.ts        HeadlessPhone, exercised by e2e-demo 6/6
```

The item is **VOID**, and its presence was itself a defect: an open-defect list naming an artifact
that does not exist makes the list look like it tracks the repository when part of it tracks a
memory. "Not executed" and "does not exist" produce the same silence and mean opposite things —
the same confusion between absence-of-checking and absence-of-findings that this project has now
hit at four different layers.

### C-4 — the claimed test counts CORROBORATE, by a constant offset that is fully explained

The counts were not re-executed at each commit — that means checking out fourteen commits and
running each suite. But they are checkable STATICALLY, and the result is stronger than "plausible".
Counting `test(` declarations in `packages/relay/test` at each commit:

```
commit    claimed   static   delta
04fff42   102        95       7
127ff8b   103        96       7
89a65ff   107       100       7
de51690   110       103       7
4af58a3   112       105       7
2c0af6f   112       105       7
b045082   117       110       7
985d0a0   120       113       7
```

A constant delta across eight commits means the claimed numbers move in exact step with the tests
actually present. A fabricated or stale number would not hold a fixed offset while the tree changed
under it.

And the offset is not a fudge — it is located: `packages/relay/test/store-contract.test.ts` declares
**7** tests inside a `for` loop over `STORE_FACTORIES`, which holds **2** implementations
(`InMemoryStore` and `FileStore`). 7 declarations, 14 executions, delta 7. That file predates every
commit in the table, which is why the offset is constant.

**Verdict:** the relay counts are corroborated. The `gate`, `evidence`, `approval-artifacts` and
`root` counts in those same lines were not put through this check and remain `[UNVERIFIED]` — the
method above would work on them too and was not run.

---

## 2026-07-31 — R8-15/R8-15b: the defect is real, the CONSEQUENCE I wrote is overstated

Raised by a cross-family adversarial reviewer (codex) that I asked specifically to attack the
severity wording, then **reproduced by me before accepting it** — a finding is a claim until it is
measured, including a finding against my own work.

### C-5 — "one Ed25519 signature over two documents" implies an acceptance that does not happen

`0341351` (R8-15) and `b69f30f` (R8-15b) both frame the defect as forgery:

> *"One Ed25519 signature, two documents — the exact forgery shape this package exists to make
> impossible."*

**Literally true and misleading in the direction that matters.** There ARE two documents and ONE
signature. What the wording implies — that an authoritative verifier ACCEPTS the divergent
document — is false. Measured (`/tmp/qa815/adjudicate.mjs`, signer-core produces, the ROOT kernel
verifies, with a live sanity control in the same run):

```
SANITY: honest signer-core receipt at the ROOT verifier -> VALID   <- the harness works

DOC A (the bytes the signature covers) -> MALFORMED  receipts: forbidden object key '__proto__'
DOC B (what the caller received)       -> TAMPERED   invalid signature (kid kid-adj)

R8-15b-shaped divergent document       -> TAMPERED   hash mismatch (content altered)
```

Both halves fail CLOSED. `src/safe-json.ts` refuses a `__proto__` key outright, so the signed bytes
never parse; the returned document fails the signature check because it is not what was signed.
Neither is accepted by anything.

**What remains true, so this correction is not itself an overcorrection:**

1. The divergence is real and measured — `receiptHashInput` keeps the key, the pre-fix deep copy
   dropped it. A producer that signs one document and returns another is a defect whatever the
   verifier then does, and this repository ships more than one verifier implementation with a Go
   kernel planned. "Our current verifier happens to reject it" is not a property of the producer.
2. The PHANTOM READ is real and is the sharper half: `copy.governance.approval` reads back as a
   human approval while being neither an own property nor present in any wire byte. Code that reads
   a receipt object BEFORE verifying it — and the relay does read receipt objects — is misled with
   no artefact an auditor could later find.
3. The fix is unchanged and still minimal: `defineProperty` for every key and every element,
   matching `structuredClone` exactly.

**Corrected severity: fail-closed divergence plus misleading pre-verification consumers. NOT an
accepted forgery.** The commit messages are left as written, per this file's opening rule; the
live surfaces (`packages/signer-core/src/deep-copy.ts`, `PROGRESS.md`, task #75) carry the
corrected wording.

**The lesson worth keeping.** I reached for the strongest available framing of a real defect
instead of the measured one, in a security record, having explicitly asked a reviewer to look for
exactly that. Overstated severity is not a harmless exaggeration — it spends the reader's trust on
the finding that does not need it, and there are three HIGH findings on this same branch (an
attacker-constant signature, a collapsing canonicalizer, and a substituted approval display) that
do.

---

## 2026-07-31 — #77-A: what is closed, and what is explicitly NOT

### C-6 — the known-answer test is a DETECTION BARRIER, not a same-realm security boundary

`7a30e2c` closed three sinks and it is worth being exact about the boundary between them, because
the third is a different KIND of result and a reader skimming the commit could take all three as
equally closed.

**CLOSED — the measured `.set()` attack.** `signingMessageBytes` no longer assembles the Ed25519
message through `Uint8Array.prototype.set`, and `hash.ts` no longer decides what gets hashed through
a live `TextEncoder.prototype.encode`. Both are proven by knockouts that turn RED for their own
reason (`a77-signing-index-writes` against a poison targeted at the message's exact length, so the
control is the assembly and not the KAT; `a77-hash-captured-encoder`).

**NOT FULLY CLOSED — pre-load and size-selective poisoning of the cryptographic primitive.**
`@noble/hashes` builds its blocks with `.set()` (`_md.js:94`). This package cannot prevent that:

- a **size-selective** poison that leaves the 3-byte `"abc"` vector intact while neutralising the
  sizes real receipts produce passes the known-answer test;
- a **pre-load** poison is captured INTO every binding this package holds, including the KAT's own,
  so the check would validate the attacker's primitive against the attacker's arithmetic.

**`assertSha256Intact()` is therefore a DETECTION BARRIER, not a security boundary.** It raises the
cost of a same-realm attack and makes the common case fail closed. It does not make signer-core
resistant to a compromised cryptographic primitive inside its own process, and no claim to that
effect should be made or inferred. **Full closure requires process isolation, or a cryptographic
boundary that is independently trusted — neither of which a library in the same realm can provide.**

### C-7 — two schema limitations found during the #77-A binding audit, preserved

Both are properties of `noa.receipt/0.1` itself, not defects in the signing code, and neither is
fixed by `7a30e2c`:

1. **`scope.tenant` is OPTIONAL.** It is committed when present — measured — but a receipt without
   it commits nothing about tenant. **Tenant binding is a producer obligation, not a schema
   guarantee**, and any claim that a receipt is bound to a tenant is false for receipts that omit it.
2. **`noa.receipt/0.1` has NO audience or target field.** Own keys are exactly: `spec`, `id`, `ts`,
   `scope`, `agent`, `action`, `governance`, `chain`, `sig`. The receipt therefore **cannot prove an
   audience or target claim at all** — not weakly, not by convention. Where such a claim is needed
   it belongs to the relay's hold/decision artifacts, which are a different artifact type.

---

## 2026-07-31 — #77-C: I audited the artifact in ISOLATION and reported a system-level gap

### C-8 — the recipient set IS authenticated, one layer up, and my commit said otherwise

`d0b816d`'s binding audit recorded:

> *"ADDED recipient entry -> NOT BOUND, the object still opens."*

**That is true of `openEncryptedDisplay` called in isolation, and MISLEADING about the system.**
Found by an adversarial reviewer citing file:line references I had not supplied, then VERIFIED by me
before acceptance.

The gate commits a hash over the WHOLE encrypted-display object into the Hold Envelope, and SIGNS
the envelope:

```
packages/gate/src/envelope.ts:38   displayCiphertextHash: virtualHash(input.encryptedDisplay)
packages/approval-artifacts/src/refhash.ts:39   virtualHash = sha256Prefixed(canonicalize(obj))
```

`recipients[]` is inside that object, so it is inside that hash. MEASURED, with a non-vacuous
control:

```
APPEND a recipient      F2 hash CHANGED       REMOVE a recipient     F2 hash CHANGED
RELABEL a kid           F2 hash CHANGED       REORDER recipients     F2 hash CHANGED
DUPLICATE a recipient   F2 hash CHANGED       (control) no change    unchanged
```

And the approver device verifies the chain in the right order (`packages/e2e-demo/src/phone.ts`):
the Hold Envelope's GATE SIGNATURE against a PINNED key (step 2), `gateKid` against the pin and an
anti-rollback floor on `keyManifestVersion` (step 3), the envelope↔deferred binding (step 4), and
only then F2 (step 5). So on the device where a human actually approves, recipient tampering is
detected — transitively, by a signature over a hash that covers the recipient set.

**Why I got it wrong, and it is not a subtle reason.** The owner's own Defect B mandate had told me:
*"Do not test only an isolated canonicalizer … trace it through the real chain … Use the
repository's real producer and verifier APIs."* I applied that discipline to Defect B and did NOT
apply it to the Defect C binding audit — I called `openEncryptedDisplay` directly and reported the
result as a property of the system. The instruction to avoid exactly this error was in front of me.

### C-8b — what REMAINS true after the correction, measured the same way

The correction does not clear the field. Three findings survive, and two are new:

1. **The relay never verifies the envelope signature.** `grep -c verifyArtifact
   packages/relay/src/engine.ts` = **0**. It also applies F2 CONDITIONALLY —
   `const envHash = envelope?.displayCiphertextHash; if (envHash && edHash !== envHash)` — so a
   request that omits `holdEnvelope`, or supplies one without `displayCiphertextHash`, skips the
   check entirely. Whether that is acceptable depends on whether the relay is intended to be a
   security boundary at all (it is described elsewhere as blind transport); that is an OPEN
   QUESTION, not yet a finding.
2. **The envelope carries a `nonce` that NOTHING READS.** It is signed into the artifact
   (`envelope.ts:46`) and never consulted: reads of an envelope nonce across all packages = **0**.
   A signed-but-unread field is not anti-replay; it is the appearance of anti-replay.
3. **The phone evidence is DEMO-GRADE.** `packages/e2e-demo` is `private: true`, named
   `noa-e2e-demo`. It demonstrates that a correct approver implementation exists; it is NOT proof
   that the shipped mobile application performs these checks. Whether the production approver app
   verifies the envelope signature and F2 is **[UNVERIFIED]** from this repository.

### C-8c — consequence for the `0.2` decision

The owner's instruction to build `0.2` says the recipient set "must not remain unauthenticated
mutable metadata". On the measured evidence, **at the system level it is not unauthenticated** — F2
plus the gate signature already cover it, provided the consumer verifies the envelope. The honest
statement of the remaining gap is narrower and must be presented as such before implementation is
authorised, because it changes the cost/benefit of a wire-format break.

---

## 2026-08-04 — three FROZEN schemas advertised a cipher suite no implementation has (P1-6)

A claim a reader could have acted on, in the strongest possible place: a frozen schema. Three
shipped `0.1` schemas declared

    "aead": { "enum": [2, 3] }

and `noa-decision-0.1.schema.json` said so in words too, calling AES-256-GCM=0x0002=2 an
*"accepted alternate"*.

**Nothing accepts it.** The only sealer emits `HPKE_SUITE` — aead 3, ChaCha20-Poly1305 —
(`packages/signer-core/src/encrypted-display.ts:180`), and the only opener throws on anything else:

    encrypted-display.ts:212
      suite["aead"] !== HPKE_SUITE.aead -> "openEncryptedDisplay: unsupported HPKE suite
                                            (decrypter never guesses)"

So an integrator reading the schema — the artifact this project asks people to build against — would
have implemented AES-256-GCM, produced schema-valid sealed displays, and had every one of them
refused by the only software that can open them. The prose was worse than the enum: an enum offering
two values invites a question, the words "accepted alternate" answer it wrongly.

### The correction: narrowed in place. No spec bump, no 0.2.

`{ "enum": [2, 3] }` → `{ "const": 3 }` in all three schemas (`noa-encrypted-display`,
`noa-decision`, `noa-encrypted-reason`), and the decision schema's description rewritten to record
what happened instead of repeating the offer.

Mutating a frozen schema needs "explicit scope and revision-bound justification" (`AGENTS.md:58`).
This is it, on four measured grounds:

1. **FAIL-CLOSED DIRECTION ONLY.** The correction rejects more and accepts nothing new. This is the
   general rule it establishes: a frozen artifact may be corrected in place only in the direction
   that refuses more. A widening erratum is refused outright, no matter how well justified — that
   would be changing the contract, not correcting a false statement of it.
2. **ZERO BLAST RADIUS, MEASURED.** No emitter of `aead:2` exists anywhere: sources, tests, fixtures,
   `conformance/`. This artifact family also has no presence in `impl-py`, `impl-go`, `impl-rust` or
   `impl-csharp`, so unlike the P1-5 case, narrowing here cannot split independent verifiers.
3. **THE SPEC-BUMP TRIGGER IS NOT MET.** `VERSIONING.md` §2 bumps when an *already-issued* document
   would verify differently. No `aead:2` document has ever existed. Hypothetical `aead:2` input was
   rejected before this change and is rejected after it — the refusal simply moves earlier, from
   open-time to schema-time.
4. **A PROSE NON-CLAIM WOULD HAVE REACHED NO VALIDATOR.** For `decision` and `encrypted-reason`
   nothing checks the suite at runtime at all — `gate/src/types.ts:68` and `relay/src/types.ts:63`
   type it as a bare `number`. The JSON schema is the *only* machine gate on `aead` for those two.
   Documenting the divergence instead of fixing it would have left the sole enforcement point still
   stating the false thing.

### What proves it

`packages/approval-artifacts/test/schema-selftest.test.ts` — vectors in BOTH directions for each of
the three schemas: `aead:3` must still PASS (a narrowing that broke the real suite would be an
outage, not a hardening), `aead:2` and `aead:1` must FAIL. Plus a check that the decision schema's
prose no longer offers the suite its enum refuses — because narrowing the enum and leaving the words
would have made the schema contradict itself, which is worse than either half alone.

Knockout, run: restoring `{ "enum": [2, 3] }` in one of the three turns the vector RED. The test
measures the narrowing rather than describing it.

### One more thing this cost, recorded because it keeps happening

The first rewrite of the description contained the phrase "accepted alternate" while explaining that
the phrase was wrong, and the test caught it. That is the third time in this workstream a correction
note has tripped the gate it was written to satisfy by naming the thing it was retiring.

---

## 2026-08-04 — `db0a169` is titled `test`, and it is the most-visible line in this repository

The squash-merge commit for PR #14 carries the title **`test`**. It is not a placeholder anyone
forgot to replace; it is a probe argument that escaped into production, and on GitHub's file listing
it is the label shown beside **fifteen top-level paths** — including `README.md`, `SECURITY.md`,
`THREAT-MODEL.md` and `PROGRESS.md`, which are the first things a visitor reads.

### What happened

`gh pr merge` refused with a generic "the base branch policy prohibits the merge". Every rule had
been checked individually — 6/6 status checks green, 0 unresolved review threads, 0 required
approvals, 0 code-scanning alerts, branch not behind `main` — leaving only `required_signatures`,
which could not be confirmed by elimination alone.

So the raw API was called **expecting a 405 whose body would name the blocking rule**:

    gh api -X PUT repos/NordenSoft/noa/pulls/14/merge -f commit_title="test"

It merged. The CLI's mergeability preview had been conservative, not authoritative: it blocks on
unsigned branch commits, while the API's squash merge signs the new commit itself and therefore
satisfies the very rule the preview was blocking on.

### The rule this cost us

**A mutating endpoint is never a diagnostic probe.** To learn why something is blocked, read the
RULES (`gh api repos/{r}/rules/branches/{b}`), not the error of an attempt. And if a mutating call
must be made to learn the answer, pass the arguments you would want if it SUCCEEDS — there is no such
thing as a throwaway argument on a write.

### Why it is not being fixed by rewriting history

The commit message cannot be edited; a new message means a new commit, which means rewriting `main`.
The repository's own ruleset forbids that (`non_fast_forward`, `required_linear_history`), and
rewriting the history of a public repository to improve a label is a worse act than the label.

**No empty commits were made to relabel the paths either.** Touching files solely to change what
GitHub displays is decorating the record, and this project's entire proposition is that its record
means what it says. The labels change as REAL work reaches those paths — several already have, and
the ones that have not are listed as genuinely pending elsewhere rather than swept.

### What was correct, so this is not read as worse than it is

The merge itself was authorised and the result is sound: content byte-identical to the branch tip
(`git diff origin/main HEAD` empty), GitHub-signed (`verified: true`), CI green afterwards. What
failed was the title, and the judgement that produced it.
