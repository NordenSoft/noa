# Release readiness review — `noa-receipt@0.6.0` + `noa-mcp-adapter-core@0.3.0` + `noa-mcp-proxy@0.3.0`

| Field | Value |
|---|---|
| **Prepared** | 2026-08-03 |
| **Commit** | `0003ae6` on `impl/adr-0005-trusted-input-provenance`, PR #14 open to `main` |
| **Type** | Security release. Behaviour is deliberately stricter; one input-type change is BREAKING. |
| **Decision required from** | the owner (hello@ordeliya.com) — see §6 |
| **Current state** | **All technical criteria MET except G1. G1 is a judgement call, not a measurement.** |

---

## 1. Why this release exists

`noa-mcp-proxy@0.2.0` is live on npm **and exploitable today**. Eight CRITICAL forged-approval paths
were found and closed (`docs/SECURITY-AUDIT-2026-08.md`). Publishing is the only step in this plan
that protects anyone outside this machine.

The counter-pressure is equally real: the last two audit rounds each found a working forgery in code
the previous round had already reviewed and the lead had already "fixed". Shipping a *new* CRITICAL
while closing an old one is not progress.

**This document exists so that trade-off is decided against written criteria rather than a mood.**

## 2. Go / no-go criteria

Each is binary, measurable, and reproducible by the reader. No criterion is satisfied by an assertion.

| # | Criterion | How it is checked | State |
|---|---|---|---|
| **G1** | An adversarial review round returns **zero** findings | a round is dispatched and its report says so | ❌ **NOT MET** — round 4 returned NO-GO; round 5 not yet run against `0003ae6` |
| **G2** | All CRITICAL and HIGH findings closed, each with a regression test | audit §4; tests named in the commits | ✅ MET |
| **G3** | All mechanical gates green | commands in §3 | ✅ MET |
| **G4** | Published surface carries no forbidden language | `npm run lint:publish-surface` on all 3 packages | ✅ MET — 0 findings |
| **G5** | Published tarballs carry no local-path dependency | `lint-publish-tarball-deps.mjs`, run by the workflow post-rewrite | ✅ enforced in CI, fails closed |
| **G6** | The registry copy of the kernel matches this tree | `npm run lint:release-parity` | ⏳ correctly FAILS until `v0.6.0` is tagged and published — this is the gate working |
| **G7** | Every breaking change documented with a migration a consumer can run | `CHANGELOG.md` `[0.6.0]`, verified by executing the snippet | ✅ MET |
| **G8** | Each published package has consumer-facing release notes | root + adapter-core + mcp-proxy `CHANGELOG.md`, all three shipped in `files[]` | ✅ MET |
| **G9** | Release is reproducible and attributable | OIDC trusted publishing, SLSA provenance, no long-lived token | ✅ MET — `noa-mcp-proxy@0.2.0` already carries a provenance attestation, so the mechanism is proven |
| **G10** | Rollback is a single named action | §5 | ✅ MET |
| **G11** | What the release does NOT fix is written down | audit §6, `NON-CLAIMS.md`, mcp-proxy changelog "Known limitation" | ✅ MET |

**G1 is the only open criterion, and it cannot be closed by working harder.** Four rounds have been
run; each found something. The owner's standing instruction is that rounds continue until one is
clean. §6 states the decision that implies.

## 3. Gate evidence — reproducible by the reader

```
npm run build && npm test                    kernel 531/531
(cd packages/adapter-core && npm test)       331/331
(cd packages/mcp-proxy && npm test)          104/104
npm run lint:security-gates                  exit 0 · 270 warn within budget
npm run lint:verdict-differential            0 EXPLOITABLE · 7 HELD · 97 UNMEASURED · 0 BROKEN
npm run lint:publish-surface                 0 findings / 72 packed files
npm run lint:release-parity                  selftest 9/9; gate fails on untagged v0.6.0 (correct)
npm run typecheck:all                        0
npm run lint:knockout                        66/66 proven load-bearing
```

Known-red and unchanged across all four rounds: `packages/gate` 214 pass / 2 fail (the owner-deferred
ADR-0006 pair, by name); L9 `wrapper.ts:135`; `noa-mobile` signer-parity 2 fail.

## 4. Release sequence

The order is **forced by the dependency graph**, not preference: `adapter-core`'s published tarball
depends on `noa-receipt@^0.6.0` resolved from the *registry*. Publishing the mcp packages against an
unreleased kernel ships an import nobody can install.

| Step | Action | Trigger | Reversible? |
|---|---|---|---|
| 1 | tag `v0.6.0` | `publish.yml` — OIDC, provenance, no token | **NO** — an npm version cannot be reused |
| 2 | verify provenance attestation on the published kernel | `npm view noa-receipt@0.6.0 dist.attestations` | n/a |
| 3 | tag `mcp-v0.3.0` | `publish-mcp.yml` — publishes adapter-core then mcp-proxy | **NO** |
| 4 | `npm deprecate` 0.1.x / 0.2.x with a message naming the class | manual | yes |
| 5 | publish the security advisory | GitHub Security Advisory | effectively no |
| 6 | merge PR #14 | GitHub | yes |
| 7 | deploy | **NOT SCHEDULED** — production has 0 tenants; deploying an unlaunched product to an empty environment adds a live surface and gains nothing | yes |

**Steps 4–5 must follow step 3 closely.** The working exploit reproductions are already public in the
pushed git history; the patched release must reach the registry before attention is drawn to them.

## 5. Rollback

| Failure | Action |
|---|---|
| a gate fails during `publish.yml` | nothing was published — the workflow dies before `npm publish`. Fix and re-tag. |
| the kernel published, the mcp packages failed | the workflow's skip-if-published guard makes a re-run safe. No rollback needed. |
| a defect is found *after* publishing | `npm deprecate <pkg>@<version> "<reason>"` and publish a fixed patch. **A published version cannot be withdrawn after 72 hours and its number is permanently consumed.** |
| the branch needs reverting | `git revert <sha>` — every commit in this release states its own single-command rollback |

## 6. Decision required from the owner

**G1 will not close on its own.** Round 4 found three CRITICALs in the fixes for round 3's three
CRITICALs. Rounds are not converging to zero as fast as they are finding things, and each round costs
hours. Two defensible positions, stated with their consequences:

**(a) Hold until a round returns zero.** Honours the standing instruction exactly. Cost: `0.2.0`
stays live and exploitable for as long as it takes, and there is no evidence the next round will be
the clean one.

**(b) Ship now, keep auditing.** Every criterion except G1 is met; the current tree is strictly and
measurably safer than what is on the registry today. Cost: G1 is knowingly waived, and a defect found
after publishing costs a deprecation and a patch rather than a re-tag.

**The lead's recommendation is (b), with steps 4–5 executed immediately after step 3.** The argument
is not that the code is clean — the audit says plainly that it is not proven clean. It is that the
comparison is not "this release vs. perfect", it is "this release vs. `0.2.0`, which is live and
exploitable now".

Whichever is chosen, it is the owner's call and it is recorded here rather than inferred from
silence. `npm publish` is not run by the lead.

## 7. Support posture — stated because omitting it would imply one

- **No SLA.** This is a pre-launch project with **0 tenants** in production (measured). There is no
  uptime commitment, no support window, and no response-time guarantee, and none is claimed anywhere
  in the published surface.
- **Security contact:** `SECURITY.md`.
- **What is claimed, and what is not:** `NON-CLAIMS.md` is authoritative and is shipped in the
  tarball. The published surface is linted against absolute security language
  (`lint-published-surface.mjs`) precisely so this document and the package cannot drift apart.
- **Compliance:** no certification, no third-party attestation, no audit by an accredited body. The
  audit in `SECURITY-AUDIT-2026-08.md` is an internal adversarial review and says so on its first line.

## 8. Sign-off

| Role | Name | Date | Decision |
|---|---|---|---|
| Lead (technical) | Fable 5 — lead seat | 2026-08-03 | technically ready; G1 open; recommends (b) |
| Reviewer, round 1 | codex (cross-family) | 2026-08-01 | NO-GO — all findings since closed |
| Reviewer, rounds 2–4 | Fable 5 (non-producer) | 2026-08-03 | NO-GO at round 4 — all CRITICAL/HIGH since closed |
| **Owner** | hello@ordeliya.com | — | **PENDING — §6** |
