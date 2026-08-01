# The codex working contract — read this ONCE, at the top of every task

Every brief points here in one line instead of repeating it. If a brief and this file disagree, the
brief wins for that task and you must say so in your report.

---

## 1. What this product is, so you judge severity correctly

NOA Trust is the approval/evidence layer between a privileged request — an AI agent moving money,
deleting data, deploying — and real execution. A human approves on a phone; the system produces
cryptographic evidence that **that** human approved **that** action.

**The catastrophic failure is a FORGED or MISATTRIBUTED approval, not downtime.**

⚠ **CORRECTED 2026-08-01. The withdrawn sentence, verbatim: *"Five customers go live on request and
expect hostile traffic immediately."*** That was written here as a statement of fact and it is not
one. **NOA Trust has NO customers and is NOT launched** — owner statement 2026-07-20, and the
production database was measured read-only the same day: **0 organizations · 0 users · 0 members ·
0 holds · 0 decisions · 0 grants.** The "5 customers" in `PROGRESS.md` means *ready to go live on
request* — a plan, not a live population.

**Why this correction is in the contract rather than quietly deleted:** the false version was copied
into every brief for a day and was given to two independent advisors as fact; both built release
plans around notifying customers who do not exist. An unverified claim that travels is exactly the
defect class this file exists to prevent, and it travelled from here.

**What it changes:** the pre-launch window is OPEN. There is no backward-compatibility debt, no
migration debt, and no customer to protect. A breaking change is not an objection right now — it is
the cheapest it will ever be. **Exception:** `noa-receipt` and `noa-mcp-proxy` ARE published on npm,
so the published wire spec and package APIs still have external consumers who may exist. The window
is open for the console, the phone app and the relay; it is NOT open for a published spec.

Two repositories, symlinked together:
- `~/noa-receipt` — the engine and the published npm packages. **PUBLIC on GitHub.**
- `~/noa-mobile` — the shipped phone app. Its tests resolve `noa-receipt` through
  `node_modules/noa-receipt -> ../../noa-receipt`, so it runs against the LIVE working tree.

## 2. The rule that outranks the others

**A false claim is treated as severely as a bug.** The worst defect ever found here was a source
comment asserting a test that did not exist. The second worst was a comment claiming "this can never
be recorded" over code that recorded it.

So: **no claim — closed, verified, enforced, covered, fail-closed, complete, atomic, cannot, never,
always — may appear in code, a test name, a doc or a commit message unless something that actually
runs actually asserts it.** If you cannot prove it, write what you measured instead.

Corollary, learned the expensive way: **absence of a finding is not absence of the property.** A
green result from an instrument that never ran the check means nothing. Four controls in this repo
were nearly deleted as "not load-bearing" when the truth was that the runner had silently ignored
half of each mutation.

## 3. Anti-vacuity — mandatory on every attack test

Every attack case needs a **control that passes in the same run**. Without it, "it refused" proves
nothing: it may have refused for an unrelated reason.

A complete probe looks like this:
```
CONTROL  the honest path            -> accepted    (the harness can produce an acceptance)
CONTROL  a well-formed rejection    -> refused     (the check under test genuinely runs)
ATTACK   the malformed case         -> refused     (the property holds)
CONTROL  an unrelated bad input     -> refused     (for its own existing reason)
```

## 4. The three traps that produced FALSE "not reproduced" results here

1. **Blanket poisoning.** Overriding a global broadly breaks unrelated machinery, so the run fails
   for the wrong reason. Poison **narrowly**, one method, restore immediately in a `finally`.
2. **Wrong layer.** Probing `verifyArtifact` when the defect surfaces through `verifyEvidence`, or
   calling an advisory tier when the authority is elsewhere. Confirm which function the value
   actually flows through before concluding.
3. **Stale build.** A `node -e` probe against `dist/` after reverting source measures the OLD build.
   Rebuild, or read source.

And one that fools auditors, not authors: while a knockout run is in flight, `git status` shows
mutated files that are NOT edits. Re-sample — transient entries flicker, real edits stay.

## 5. Order of work, always

**RED first.** Write the failing test, RUN it, paste the red output. Then fix. Then green. A fix
without an observed red proves only that the code changed.

## 6. What every brief will give you, and what it will not

You get: **FILES + the boundary · the DEFECT at file:line · EVIDENCE already measured · INVARIANTS
that must not change · the DONE command.**

You will **not** get a tour of the codebase. Read the files named. Do not explore beyond them —
exploration is where tokens go and where wrong guesses come from.

**If the brief is contradictory, incomplete, or would produce a worse design: STOP and report. Do
not decide alone and do not silently improve it.** This has happened three times and the brief was
wrong all three times. Stopping is cheaper than rework, and it is not a failure — it is the job.

## 7. Scope

Touch **only** the files the brief authorises. If you believe another file must change, **STOP and
report** — do not edit it. Never change production source to make a test or a gate pass; that
inverts the exercise.

## 8. Standing prohibitions — no brief overrides these without an explicit owner instruction

**Do not** push · merge · publish · deploy · release to npm · touch Railway or production · change
secrets, keys, KMS, IAM, roles, grants or migrations · silently change `noa.encrypted-display/0.1`
wire bytes · implement ADR-0006 · freeze Stage 1 · start the Go kernel.

## 9. Known-red baselines — these are NOT yours to fix

| suite | baseline |
|---|---|
| `packages/gate` | 214 pass / **2 fail** — the owner-deferred ADR-0006 pair, by name |
| `noa-mobile` `signer-parity` | **2 fail** / 3 pass — pre-existing, proven not ours, tracked separately |
| `noa-mobile` full suite | ~41 further failures are `listen EPERM`, managed-runtime environment |

If one of these moves **in either direction**, stop and report — that is information, not noise.

## 10. Your report — the format, every time

```
WHAT       file:line for each change
EVIDENCE   the RED output before and the GREEN after, PASTED, plus the DONE command outputs
DECISIONS  what you chose and the measured basis — not the reasoning, the numbers
RISKS      what you checked, and what you could NOT check
SELF-QA    what you tried to break, and whether it broke
OPEN       anything unverified, marked [UNVERIFIED]
```

Be honest about what you did not verify. **An unverified claim stated confidently is the worst
possible output here** — worse than saying "I could not check this".

Reply in English. Ignore the `.codex-session-ledger.lock` `EPERM`; it is outside these repositories
and affects nothing.
