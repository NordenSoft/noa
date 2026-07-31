# PRODUCER LEDGER — who authored what

**Why this file exists.** From 2026-07-31 the operating model is: **codex implements, the Fable 5
lead directs and supervises, and there are NO per-batch QA rounds until every task is finished**
(owner directive). That makes codex a **PRODUCER**. When the owner's final QA runs, a producer may
not sit in judgement of its own code — so the final reviewer needs to know, precisely, which lines
codex authored and which the lead authored.

**The rule this protects.** Producer independence is not a formality: four consecutive
self-approved batches each shipped a material defect, usually a CLAIM rather than a bug. Under the
new model independence is preserved STRUCTURALLY (codex writes, the lead checks) instead of
post-hoc. If, at final QA, no non-producer voice is reachable, **report the gap — do not fill the
panel with a producer.**

**How to read it.** Every row is one supervised codex run. "Lead corrections" records what the
supervisor sent back — an empty cell there means the diff was accepted as written, which is itself
a fact the final reviewer should weigh.

| # | Batch / root cause | Files codex authored | Lead corrections applied | Commit |
|---|---|---|---|---|
| — | *(micro-batches A, B, B2 — all pre-directive)* | **none — authored entirely by the Fable 5 lead** | n/a | `3c7fd08`, `eac7d6f`, `0bb1715` |
| 1 | **C / P0-10** — `mustBeWithin` did not NaN-check its bounds | `packages/approval-artifacts/src/verify.ts` (added `hasInvalidTime`, applied to both TIME loops) · `packages/approval-artifacts/test/activation-window-strict.test.ts` (+2 tests, appended) | none — diff accepted as written. Lead verified independently: only the 2 authorised files touched; RED-before-fix re-measured by the lead by reverting src alone (1 fail, anti-vacuity control still green), src restored byte-exact (`c522e09c…`); suite 172/172. | *(pending batch-C commit)* |
| 2 | **C / P0-9** — `parseTime` validated dates through the live mutable `Date.prototype.toISOString` | `packages/approval-artifacts/src/verify.ts` (removed the `Date` round trip and the `pristineDateParse` import; added `integerQuotient` / `isLeapYear` / `daysInMonth` / `daysFromCivil`; `parseTime` now computes calendar validity and the epoch arithmetically) · `packages/approval-artifacts/test/activation-window-strict.test.ts` (+1 test, appended) | none — diff accepted as written. Lead verified independently: (a) only the 2 authorised files touched; (b) RED isolated by restoring the P0-10-fixed parser so **exactly one** test failed — P0-9's own; (c) **differential audit the tests do not perform** — the new epoch arithmetic compared against `Date.parse` over **1836** canonical instants spanning years 0/1900/1970/2000/2400/9999 and every month boundary: all match; the leap rule matches for 509 consecutive years. Chose the arithmetic route over capture, so CORRECTIONS.md C-6 does not apply. **Independently re-verified by the coordinating seat at larger scale: 73,439 canonical instants (every day 1900-01-01..2100-12-31 plus time-of-day/millisecond coverage on leap days, century boundaries and the epoch day) → 0 mismatches; anti-vacuity: a deliberately +1-day variant of the same algorithm mismatches 2/2, so the 0 is meaningful; 8/8 impossible dates refused incl. 1900-02-29, 3/3 real ones accepted incl. 2000-02-29; and with `Date.parse`, `Date.now` AND `Date.prototype.toISOString` poisoned SIMULTANEOUSLY, `parseTime` still returns the correct value.** STATED LIMIT of that check, carried per its author: the algorithm was copied verbatim out of the diff and tested standalone, so it proves the ALGORITHM, not the integration — the integration is proven by the lead's suite runs (approval-artifacts 173/173 · evidence 128/128 · gate 214/2 baseline · e2e-demo 12/12 · typecheck:all 0). | *(pending batch-C commit)* |

## Lead-authored surfaces (NOT codex work)

Everything on this branch up to and including `0bb1715` was written by the lead seat:
`scripts/lint-resolver-parity.mjs` · `scripts/lib/resolver-scan.mjs` ·
`scripts/lib/proof-resolve.mjs` + its selftest · `scripts/resolver-inventory.json` ·
the parity/activation tests in `packages/{gate,e2e-demo,approval-artifacts,evidence}/test/` ·
the knockout entries added in those batches. A final reviewer judging THOSE is judging the lead's
work, not codex's — and the lead is equally a producer with respect to them.
