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
