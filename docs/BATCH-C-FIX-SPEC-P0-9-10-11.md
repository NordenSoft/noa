# Micro-batch B + C — fix spec, pre-derived by the coordinating seat

Prepared while the batch-A QA ran. Everything below is **measured, not recalled**. Fable owns the
implementation; this exists so the lead does not spend a second round re-deriving what is already
reproduced. Treat it as evidence, not as instructions — if a measurement here disagrees with the
repo, the repo wins and the disagreement is a finding.

## The three defects, at their exact lines

| ID | file:line | the code | why it fails |
|---|---|---|---|
| **P0-9** | `packages/approval-artifacts/src/verify.ts:135` | `const iso = new Date(ms).toISOString();` | `Date` and `Date.prototype.toISOString` are **live mutable globals** on the security path. Poisoning `toISOString` flips the `2026-02-30` vector from refused to `{ok:true}`. |
| **P0-10** | `packages/approval-artifacts/src/verify.ts:351-356` | `if (Number.isNaN(t) \|\| t < min \|\| t > max)` | `min`/`max` are parsed but never NaN-checked. `NaN` makes **both** comparisons false, so a window the verifier cannot evaluate is treated as **satisfied**. |
| **P0-11** | `packages/approval-artifacts/src/verify.ts:130` | `CANONICAL_INSTANT` allows only `Z` | `evidence/cli.ts:54` documents `--now` as RFC 3339. The identical instant as `+02:00` now returns INVALID where `Z` returns `VALID_FULL_CHAIN`. A regression the previous lead introduced. |

### The detail that matters for P0-10

`mustBeAfter`, **five lines above** at `:345-349`, does it correctly:

```ts
if (Number.isNaN(t) || Number.isNaN(limit) || t <= limit) {   // :347 — CORRECT
```

`mustBeWithin` at `:355` omits exactly that guard. This is the **fourth** occurrence of the
"fix landed on one sibling but not the other" pattern in this codebase (P0-1 → P0-5 → P0-8 → this).
The fix is one line; the *lesson* is that the two loops should not be able to drift again — consider
a shared `withinBounds(t, min, max)` helper so there is one comparison site, not two.

## Recommended fix for P0-9 — arithmetic, not capture

The obvious fix is to capture `Date` + `toISOString` at module load like
`inert-core/intrinsics.ts:238` already does for `Date.parse` / `Date.now`. **I recommend against
stopping there**, for a reason this project already recorded: `CORRECTIONS.md` **C-6** states
capture defends POST-load only — a pre-load poison is captured *into* the binding. Capture is a
detection barrier, not a boundary.

`CANONICAL_INSTANT` already pins the syntax exactly. The **only** thing the `toISOString` round trip
adds is rejecting a syntactically well-formed but **non-existent calendar date** (`2026-02-30`,
`2026-13-01`, `2026-01-32`). That is pure arithmetic and needs **no global at all**:

- month ∈ 1..12 · day ∈ 1..daysInMonth(y, m) with the real leap rule (`y%4==0 && (y%100!=0 || y%400==0)`)
- hour ≤ 23 · minute ≤ 59 · second ≤ 59 (decide leap seconds explicitly: `60` accepted or refused — state which)
- compute epoch ms from the components directly, so even `Date.parse` is off the path

That closes P0-9 *by removing the dependency* rather than by hardening it, and it needs no capture,
no `Reflect.apply`, and no knockout against a poisoned prototype to stay true.

**Whichever route is chosen, it must be stated which one and why** — a capture-based fix is
defensible, but then it inherits C-6 and the fix comment must say so rather than claim closure.

## P0-11 — the compatibility decision

Two coherent options. My recommendation is **(a)**.

**(a) Accept RFC 3339 offsets in the parser.** Widen the regex to allow `Z|[+-]HH:MM`, and fold the
offset into the arithmetic epoch computation. Strictly more permissive than today, so it breaks
nothing that currently verifies; the 1727 shipped `Z` timestamps are unaffected; the CLI's
documented contract becomes true again. **Emit stays `Z`** — this widens acceptance, not output.
Security check: comparisons are on the *instant*, so `14:00+02:00` and `12:00Z` compare identically
and correctly. The one trap: the exactness check must then compare **instants, not string prefixes**
— the current `iso.slice(0,19) === v.slice(0,19)` is string-shaped and would be wrong for offsets.

**(b) Narrow the CLI contract deliberately.** Change `evidence/cli.ts:54` to document `Z`-only and
record the break in `CORRECTIONS.md`. Cheaper, but it makes the product less compatible with the
standard it names, for no security gain.

## THE METHOD WARNING — read this before reporting "not reproduced"

While verifying these three I produced **three vacuous reproductions in a row**, each of which said
"not reproduced" *falsely*:

1. **Blanket poison.** Overriding a prototype method globally broke unrelated machinery, so the run
   failed for the wrong reason. Poison **narrowly and targeted** — one method, restored immediately.
2. **Wrong layer.** I probed `verifyArtifact` when the defect surfaced through `verifyEvidence`
   (or vice versa). Confirm which function the vector actually flows through before concluding.
3. **Missing harness params.** The probe omitted a required context field, so the call refused
   early for an unrelated reason that *looked* like the control working.

**Every attack run needs a control that passes in the same run.** If the clean case does not produce
the expected acceptance, the attack result means nothing — regardless of what it printed.

## Reproductions already banked (read-only, by the coordinating seat)

```
P0-9   targeted toISOString poison:  clean -> refused | poisoned -> ACCEPTED | restored -> refused
P0-10  min NaN / max NaN / both:     ACCEPTED;  well-formed excluding window -> refused (control)
P0-11  same instant:                 "…Z" -> VALID_FULL_CHAIN | "+02:00" and "-05:00" -> INVALID
```

## Out of batch B/C scope, but related — logged as task #83

`~/noa-mobile/src/core/pairingVerify.ts` (the SHIPPED app) contains the **same P0-10 and P0-6
defects** in the phone's conformance **oracle**. Measured `ok = true` on malformed bounds, with both
controls green. It has **zero non-test callers**, so it is P1 not P0 — but it is the second half of
a *differential* parity test, and a differential in which both sides share a defect agrees for the
wrong reason. Fix it in the same sweep as P0-10 so the two implementations do not diverge again, and
add malformed-bound vectors to the **shared** corpus so the differential can actually catch the class.

Checked and **REJECTED_WITH_EVIDENCE** in the same pass, so it is not re-opened: the phone's *real*
enforcement path is sound. `manifestChain.ts:460-464` fails closed on an unparseable time
explicitly; `:522-524` looks unguarded but is unreachable — `asDelegation` (`:270`) requires
`isRfc3339`, which is regex **and** `Number.isFinite(Date.parse(v))` (`:228-230`).
