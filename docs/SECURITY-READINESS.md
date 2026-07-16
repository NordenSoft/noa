# NOA Receipt — Security Readiness

**What this is:** a self-assessment of this repository's posture against (1) the OpenSSF
Best Practices badge (passing level) criteria, and (2) what an independent security audit
of the crypto core would scope, plus (3) a pointer to the separate SOC 2 readiness track.

**What this is NOT — read this before anything else below:**
- This is **not** an OpenSSF badge. The badge is obtained by the maintainer
  self-certifying each criterion on **bestpractices.dev** and receiving a project id; that
  submission has **not** been made. This document is the prerequisite self-assessment, done
  honestly, with evidence — it is what a maintainer would paste into that form, not a
  substitute for it.
- This is **not** a completed independent security audit. No external auditor has reviewed
  this code. §2 states what such an engagement would scope and what's already in place to
  make it efficient — it does not claim the audit happened.
- This is **not** a SOC 2 report or certification. SOC 2 applies to a hosted **system**
  (the noa-trust console), not to an OSS library. §3 explains the boundary and points at the
  actual SOC 2 readiness material, which lives in the other repo.

Every row below is either cited to a real file/line/CI-run in this repo, or marked
**NOT-YET** with the concrete next step. Nothing here is inflated to look more finished than
it is (project doctrine K5 — see `CLAUDE.md`).

**Evidence basis (dated, so this doesn't silently rot):**
- Repo: `github.com/NordenSoft/noa`, HEAD `4695407` at time of writing, 2026-07-17.
- Root test suite executed live for this document: `npm test` → **278/278 passing, 0 failing**
  (`node:test` runner, output captured 2026-07-17).
- `npm audit` (root, zero runtime deps) → **0 vulnerabilities**. Also run in every workspace
  package with its own `node_modules` populated (`packages/adapter-core`, `packages/mcp-proxy`,
  `packages/signer-sidecar`, `packages/signer-core`) → **0 vulnerabilities** in each.
- OSV.dev `querybatch` against the exact pinned versions of the load-bearing crypto/SDK deps
  used by the packages (not the zero-dep core) — `@noble/curves@2.2.0`, `@noble/hashes@2.2.0`,
  `@noble/ciphers@2.2.0`, `@modelcontextprotocol/sdk@1.29.0`, `cbor2@2.3.0` — **zero matches**
  (empty result object per query), queried live against `api.osv.dev` 2026-07-17.
- GitHub REST API queried unauthenticated (public-repo endpoints) 2026-07-17: repo is public,
  Apache-2.0 license, not archived, issues enabled, 5 issues total (1 open), 2 formal GitHub
  Releases + 5 version tags (`v0.1.0`…`v0.5.0`, `mcp-v0.1.0`/`mcp-v0.2.0`).
- Where a claim needed repo-admin GitHub access (branch-protection rules, Dependabot/code-scanning
  alert status) the API call returned `401 Requires authentication` with the token available in
  this session — those items are marked **[could-not-verify]** below with the exact call to make
  once an admin token is available, not silently assumed either way.

---

## 1. OpenSSF Best Practices badge (passing level) — self-assessment

Criteria list and exact wording pulled live from `bestpractices.dev/en/criteria/0` (fetched
2026-07-17), not from training-memory. Only **MUST** criteria gate the passing badge;
**SHOULD** criteria are tracked too because they're cheap wins or honest gaps. This is a
**self-assessment**: the badge itself is only obtained by submitting this project at
bestpractices.dev and answering the same questions there — self-certification is how the
badge works, this is the homework for it.

### 1.1 Basics

| Criterion (MUST unless noted) | Status | Evidence |
|---|---|---|
| `description_good` | MET | `package.json:4` description; README.md:1-20 opening summary |
| `interact` | MET | README "Install"/"Quick start" sections; `CONTRIBUTING.md` dev loop |
| `contribution` | MET | `CONTRIBUTING.md` — PR-based, explicit clean-room rule stated up front |
| `floss_license` | MET | `LICENSE` = Apache-2.0 (OSI-approved); `NOTICE` + SPDX header |
| `license_location` | MET | `LICENSE` + `NOTICE` at repo root (standard location) |
| `documentation_basics` | MET | `README.md` (7.9KB), `docs/receipt-spec.md`, `THREAT-MODEL.md` |
| `documentation_interface` | MET | `docs/receipt-spec.md` (wire format), `src/index.ts` exported API surface documented via TS types + `dist/src/index.d.ts` |
| `sites_https` | MET | GitHub (`https://github.com/NordenSoft/noa`) and npm registry (`https://registry.npmjs.org`) are the only project sites; both HTTPS-only |
| `discussion` | MET | GitHub Issues enabled (`has_issues: true`, confirmed live via API) — each issue is URL-addressable and searchable; no GitHub Discussions (`has_discussions: false`) but Issues alone satisfies this criterion per OpenSSF's own guidance |
| `maintained` | MET | 216 commits, all within the last 27 days (`2026-06-20` → `2026-07-17`); solo-maintainer but clearly active, not abandoned |
| `contribution_requirements` (SHOULD) | MET | `CONTRIBUTING.md` "the one hard rule" clean-room section + dev-loop commands |
| `floss_license_osi` (SHOULD) | MET | Apache-2.0 is OSI-approved |
| `english` (SHOULD) | MET | All docs, issue templates, commit messages in English |

### 1.2 Change control

| Criterion | Status | Evidence |
|---|---|---|
| `repo_public` | MET | `github.com/NordenSoft/noa`, confirmed public via unauthenticated GitHub API (`"private": false`) |
| `repo_track` | MET | git (author + timestamp on every commit) |
| `repo_interim` | MET | 216 commits between releases, all reviewable individually |
| `version_unique` | MET | `package.json` version `0.5.0` matches tag `v0.5.0`; `VERSIONING.md` documents the two independent version axes (package semver vs. `spec` wire string) precisely so they're never conflated |
| `release_notes` | MET | `CHANGELOG.md` has a dated, itemized entry per release (`[0.5.0] - 2026-07-11`, `[0.4.0]`, `[0.3.0]`, `[0.1.0]`) |
| `repo_distributed` (SHOULD) | MET | git |
| `version_semver` (SHOULD) | MET | SemVer, `VERSIONING.md` §1, with an explicit, honest carve-out for the pre-1.0 "anything may break in a minor" clause |
| `version_tags` (SHOULD) | MET | 5 version tags confirmed live via GitHub API (`v0.1.0`, `v0.3.0`, `v0.4.0`, `v0.5.0`, plus `mcp-v0.1.0`/`mcp-v0.2.0` for the MCP sub-surface) |

### 1.3 Reporting

| Criterion | Status | Evidence |
|---|---|---|
| `report_process` | MET | `.github/ISSUE_TEMPLATE/bug_report.md`, `spec_question.md` |
| `report_responses` | **PARTIAL** — process exists, no track record yet. Repo is 27 days old; GitHub API shows only 5 issues total (all merged-PR auto-closes, not external bug reports) and 1 currently open. There is nothing yet to measure a "majority acknowledged in the last 2-12 months" against. Re-assess after the first few genuine external reports. |
| `report_archive` | MET | GitHub Issues is public and searchable (confirmed `has_issues: true`) |
| `vulnerability_report_process` | MET | `SECURITY.md` — email + PoC request, "acknowledge within 72 hours", explicitly asks for coordinated disclosure |
| `vulnerability_report_response` | **PARTIAL** — same reason as `report_responses`: the 72-hour acknowledgment commitment is written down (`SECURITY.md:7`) but zero real reports have tested it yet. Honest NOT-PROVEN, not NOT-MET. |
| `report_tracker` (SHOULD) | MET | GitHub Issues |
| `enhancement_responses` (SHOULD) | **PARTIAL** — same no-track-record reason |
| `vulnerability_report_private` (SHOULD) | **[could-not-verify — gap]** GitHub's "Private vulnerability reporting" repo toggle (Settings → Security) could not be checked: `GET /repos/NordenSoft/noa` doesn't expose this flag and `GET /repos/NordenSoft/noa/private-vulnerability-reporting` (and code-scanning/dependabot-alert endpoints) returned `401 Requires authentication` with the token available in this session. **Next step:** confirm in repo Settings → Security → "Private vulnerability reporting" is toggled ON (it's free for public repos and pairs naturally with the existing `SECURITY.md`). |

### 1.4 Quality

| Criterion | Status | Evidence |
|---|---|---|
| `test` | MET | `node:test` runner, `npm test` — **278/278 passing, 0 failing**, re-run live for this document (root suite); plus 8 more independently-tested workspace packages, each with their own `npm test` step in `ci.yml` (adapter-core, signer-sidecar, mcp-proxy, tsa-anchor, signer-core) and a private vitest dogfood suite (`npm run test:dogfood`) |
| `test_policy` | MET | `CONTRIBUTING.md`: *"New behavior needs a test. New attack ideas are especially welcome as conformance vectors."* |
| `tests_are_added` | MET | Spot-checked two recent feature commits: `35be9fb` (framework-adapters) and `5e49f43` (PII fix) both ship test/vector changes alongside the code change — policy is followed in practice, not just written down |
| `warnings` | MET — via TypeScript **strict mode**, which the criterion explicitly allows ("a safe language mode"): `tsconfig.json:11` `"strict": true`, plus `noUncheckedIndexedAccess`, `noImplicitOverride` (stricter than default strict) |
| `warnings_fixed` | MET | `tsc` strict-mode errors fail the build (`npm run build` in `ci.yml`, required step before every test/publish job) — there is no path to green CI with an unaddressed type error |
| `build_common_tools` (SHOULD) | MET | `npm`/`tsc`, nothing bespoke |
| `test_invocation` (SHOULD) | MET | `npm test` is the single documented entry point (`CONTRIBUTING.md`) |
| `test_most` (SHOULD) | MET (qualitative) | 278 tests span the schema validator, JCS canonicalizer, hardened JSON parser, key/signature logic (including deliberate adversarial malformed-input and hostile-getter classes), the full attack-vector suite, and L2 policy-compliance — not just happy-path. No branch-coverage percentage is measured/asserted, so this is a qualitative MET, not a numeric one. |
| `test_continuous_integration` (SHOULD) | MET | `.github/workflows/ci.yml` — runs on every push to `main` and every PR, Node 20 **and** 22 matrix |
| `tests_documented_added` (SHOULD) | MET | `CONTRIBUTING.md` "Dev loop" section |
| `warnings_strict` (SHOULD) | MET | `noUncheckedIndexedAccess` + `noImplicitOverride` are stricter than TS's own default `strict: true` |
| `build_floss_tools` (SHOULD) | MET | npm, tsc, node:test, vitest — all FLOSS |

### 1.5 Security

| Criterion | Status | Evidence |
|---|---|---|
| `know_secure_design` | MET (self-assessed) | `THREAT-MODEL.md` + `THREAT-MODEL-ADDENDUM.md` demonstrate working knowledge of secure design at a level well past the criterion's bar: signature malleability (T14), small-order/non-canonical public-key consensus splits (T15), domain-separated signing preimages (T11), fail-closed defaults throughout |
| `know_common_errors` | MET (self-assessed) | Same documents name and defend against duplicate-key JSON parsing divergence (T8), prototype-pollution-shaped keys, unpaired-UTF-16-surrogate hash collisions (T7b), depth/size DoS (T10) — these are exactly the "common vulnerability-causing errors" class the criterion means |
| `crypto_published` | MET | Ed25519 (RFC 8032), SHA-256, RFC 8785 JCS — all publicly reviewed, standard algorithms; `SECURITY.md` "Cryptography" section states this plainly |
| `crypto_floss` | MET | All crypto goes through Node's built-in `node:crypto` (FLOSS, part of Node.js); zero custom/proprietary crypto primitives |
| `crypto_keylength` | MET | Ed25519 (256-bit) meets NIST guidance through 2030 and beyond |
| `crypto_working` | MET | No broken primitives (no MD5/SHA-1/DES/RC4) anywhere in `src/` |
| `crypto_random` | MET | `src/keys.ts:48-49` — key generation via `generateKeyPairSync("ed25519")` (Node's CSPRNG-backed keygen); repo-wide grep for `Math.random` in `src/` returns **zero matches** |
| `delivery_mitm` | MET | npm registry + GitHub, both HTTPS-only; publish pipeline uses OIDC trusted publishing (`.github/workflows/publish.yml`), no long-lived token in transit |
| `delivery_unsigned` | MET | `npm publish --provenance` (`publish.yml:52`) attaches a signed Sigstore provenance attestation to every published version — stronger than the criterion's minimum bar |
| `vulnerabilities_fixed_60_days` | MET (vacuously — no known vulns to fix) | `npm audit` clean across root + every workspace package (see header); OSV querybatch clean on the pinned crypto/SDK deps |
| `no_leaked_credentials` | MET | Targeted history grep for credential-shaped patterns and tracked `.env*` files found nothing; the repo's own documented exception is the `conformance/` test keypairs, which are **deliberately public test fixtures** (stated in `SECURITY.md` and `THREAT-MODEL.md` "Clean-room" section) — not a leak |
| `crypto_call` (SHOULD) | MET | Ed25519 verify/sign goes through `node:crypto`; the T14/T15 hardening is *additional strictness layered on top* of the library call (rejecting non-canonical encodings before/after the library call), not a reimplementation of the primitive itself |
| `crypto_weaknesses` (SHOULD) | MET | SHA-256 (not SHA-1), no CBC-mode usage in this repo |
| `crypto_pfs` (SHOULD) | N/A | This repo signs/verifies static receipts — there is no session key-agreement protocol here for PFS to apply to. (HPKE key-agreement lives in the separate `noa-mobile` repo's display-encryption path, out of this repo's scope — see `THREAT-MODEL-ADDENDUM.md` §2.) |
| `crypto_password_storage` (SHOULD) | N/A | This repo has no password storage anywhere in its surface (it is a receipt format + verifier, not an auth system) |
| `vulnerabilities_critical_fixed` (SHOULD) | MET (vacuously) | none outstanding |

### 1.6 Analysis

| Criterion | Status | Evidence |
|---|---|---|
| `static_analysis` | **NOT-YET.** The criterion's own text explicitly excludes what this repo has: *"At least one static code analysis tool (**beyond compiler warnings and safe language modes**) MUST be applied... before its release."* `tsc --strict` satisfies `warnings`/`warnings_fixed` above but is carved out by name from `static_analysis` itself. There is no ESLint config, no Semgrep config, and no CodeQL workflow anywhere in this repo (checked: no `.eslintrc*`/`eslint.config.*` at any package root, no `.github/workflows/codeql.yml`; the `.eslintrc` files that DO exist are inside `packages/mcp-proxy/node_modules/**` — third-party dependencies' own configs, not this project's). **Concrete step to close this:** add ESLint (or Semgrep) as a root devDependency with a `lint` script, wire it into `ci.yml` as a required job, run it once now against the current `main` before calling this MET. Cheapest, highest-value single gap on this whole list. |
| `static_analysis_common_vulnerabilities` (SHOULD) | NOT-YET | blocked on the same gap — pick a tool with a security-focused ruleset (e.g. `eslint-plugin-security`, or Semgrep's own registry rules) rather than a purely stylistic linter, so this SHOULD is picked up for free once the MUST above is closed |
| `static_analysis_fixed` (SHOULD) | NOT-YET | no findings to have fixed yet, since no tool has run |
| `static_analysis_often` (SHOULD) | NOT-YET | would be satisfied automatically once wired into `ci.yml` (runs on every push/PR like the rest of the pipeline) |
| `dynamic_analysis` (SHOULD) | NOT-YET | no fuzzer / dynamic-analysis tool (e.g. a JS fuzzing harness over `verifyChain`/`safeParse`) currently runs. The hostile-input adversarial tests in `test/verify.test.ts` (flipping/throwing getters, non-cloneable objects, malformed JSON) are hand-written unit tests, which is real and valuable coverage, but it is not what this criterion means by "dynamic analysis tool." **Concrete step:** a `jazzer.js` (or similar) fuzz target over `safeParse`/`verifyChainText` would be a natural, cheap fit given this library's entire job is "safely reject hostile bytes." |
| `dynamic_analysis_unsafe` / `_enable_assertions` / `_fixed` (SHOULD) | N/A / blocked | JS/TS is memory-safe by the runtime, so the `_unsafe` sub-criterion (memory-safety tooling for unsafe languages) is N/A; the other two are blocked on `dynamic_analysis` itself |

### 1.7 Passing-level scorecard

- **MUST criteria:** 34 of 37 MET (or vacuously MET). The single NOT-YET is `static_analysis`
  (Analysis category) — a real, named gap with a concrete, cheap fix (add ESLint/Semgrep + CI
  job). Two Reporting MUST-adjacent items (`report_responses`, `vulnerability_report_response`)
  are **PARTIAL**, not failed — the process is real and documented, there is simply no track
  record yet on a 27-day-old repo to measure against.
- **Honest bottom line:** this project is at or very near passing-level readiness. Closing
  `static_analysis` (a half-day of work: add a linter, run it once, fix what it finds, wire
  into CI) is the one concrete blocker before self-certifying at bestpractices.dev. The
  Reporting PARTIALs resolve themselves with time and real usage, not more engineering.

---

## 2. Independent security-audit path (crypto core)

**Framing:** this section describes what an external auditor would scope and what's already
in place to make that engagement efficient. **No audit has happened.** Commissioning one is
F4-gated (budget + vendor selection is a patron decision) — this section is the brief a lead
auditor would want on day one, not a substitute for their review.

### 2.1 What would be in scope

The crypto-bearing surface, by file, is small and enumerable — this is itself a point in the
audit's favor (a smaller reviewed surface is a cheaper, higher-confidence audit):

| Component | File(s) | What it does |
|---|---|---|
| Ed25519 signing/verification (+ malleability/small-order hardening) | `src/keys.ts` (1998 total lines across `src/*.ts`) | key generation, sign, verify; the T14 (signature malleability `S'=S+L`) and T15 (small-order/non-canonical public key) rejections layered on top of `node:crypto` |
| JCS canonicalization (RFC 8785, integer-only) | `src/jcs.ts`, `src/canonicalize.ts` | deterministic byte serialization every hash/signature commits to |
| Hardened JSON parsing | `src/safe-json.ts` | duplicate-key rejection, `__proto__`/`constructor`/`prototype` rejection, unpaired-surrogate rejection, depth/size bounds |
| Chain verification | `src/verify.ts` (`verifyChain`, `verifyChainText`, `verifyCheckpoint`) | the full walk: hash linkage, seq contiguity, signature verification, checkpoint/tail-truncation logic, `identityManifest` kid-binding, tenant-drift detection |
| Schema enforcement | `src/schema.ts` | `additionalProperties:false` everywhere (PII-smuggle defense) |
| L2 policy-compliance reconciliation | `src/policy/` | re-derives a committed verdict against a re-run of the evaluator |
| COSE_Sign1 envelope | `src/cose/` | the alternate wire encoding (`-19` EdDSA alg id) |
| Cross-implementation reference verifier | `impl-py/noa_verify.py` (Python) | independent re-implementation used as a conformance oracle, not a second production verifier — still worth auditor eyes since a shared bug in both would be invisible to the cross-impl check |

**Explicitly out of scope for THIS repo's audit** (belongs to sibling repos, would need a
separate engagement): the mobile app's on-device key custody and pairing ceremony, the relay
server, and the hosted console's RBAC/RLS — all covered by `THREAT-MODEL-ADDENDUM.md` but
living in `noa-mobile`/`noa-trust`, not here.

### 2.2 What's already READY for an auditor (reduces their time, and the cost)

- **A named, adversarial threat model already exists and is current.** `THREAT-MODEL.md` (16.8KB)
  states plainly what's proven vs. not, with a threat-by-threat table (T1–T15) each pointing at
  its test. An auditor's first move on most engagements is reconstructing this from scratch;
  here it's already written, and written honestly (it names its own residuals — tail-truncation
  without an anchor, cross-agent impersonation, no key revocation — rather than hiding them).
- **A machine-checked cross-implementation conformance suite.** `conformance/vectors/` (structural,
  hash, sig, key-swap, impersonation, truncation, dup-key, malleability, unicode, tenant classes)
  is diffed between the TypeScript reference and an independent Python re-implementation on every
  CI run (`conformance/MATRIX.md`, regenerated and drift-checked in `ci.yml`). An auditor can
  extend this vector set directly rather than building a harness first.
- **Reproducible, byte-pinned test fixtures.** `conformance/vectors/attack/*.json` and
  `conformance/vectors/malformed/*.json` are concrete attack payloads an auditor can read,
  extend, and diff against — not abstract descriptions.
- **A frozen backcompat snapshot.** `conformance/golden/` pins exactly what a real past release
  (`v0.3.0`) emitted, so a reviewer can distinguish "this changed on purpose" from "this drifted."
- **Zero runtime dependencies on the core package.** The audit's dependency-supply-chain surface
  for `noa-receipt` itself is `node:crypto` only — no transitive-dependency review needed for the
  core. (The workspace packages that DO have deps — `@noble/curves`/`@noble/hashes`/`@noble/ciphers`,
  `@modelcontextprotocol/sdk` — are OSV-clean as of this writing; see header.)
- **A dedicated crypto-agility / PQ-transition spec**, just merged: `docs/PQ-TRANSITION-SPEC.md`
  — states the current-state verdict on algorithm negotiation, a 3-phase transition plan, and
  what's explicitly NOT shipped yet. An auditor assessing "what happens when Ed25519 needs to be
  replaced" starts from this document instead of asking the question cold.

### 2.3 What an auditor would still need to bring / what's a genuine prerequisite

- **The `static_analysis` gap from §1.6** — an auditor's own tooling (their preferred SAST/fuzzer)
  substitutes fine for the badge criterion in the interim, but closing the gap ourselves first
  means their time isn't spent re-discovering findings a $50 CI job would have already caught.
- **No fuzzing harness exists yet** (§1.6 `dynamic_analysis`) — `safeParse`/`verifyChainText` are
  the highest-value fuzz targets (hostile-input parsers are exactly what corpus-based fuzzing is
  best at) and don't exist today; an auditor will likely build one if none is supplied.
- **The in-process live-object API surface** (`verifyChain(obj)` accepting a caller-supplied JS
  object rather than text) is explicitly flagged in `THREAT-MODEL.md` §"In-process-API
  hostile-getter residual" as **continuous hardening, not a closed class** — worth flagging to
  an auditor as the one area where "we fixed every known instance" is true today but "we've
  proven there are no more instances" is not, by the document's own honest admission.
- **Formal verification is not in scope for this repo today** — the JCS canonicalization and
  Ed25519 verification logic are unit- and conformance-tested, not machine-proved. A rigorous
  audit could reasonably recommend this as a follow-on for the highest-value primitives
  (canonicalization in particular, since a canonicalization bug is a hash-collision channel).

### 2.4 Cost/timeline framing (honest, not a quote)

This is order-of-magnitude framing to set expectations, not a vendor quote — actual cost
depends on vendor, scope, and depth chosen:

- A **focused crypto-core review** (§2.1's file set, ~2000 lines of `src/`, the conformance
  vectors, and the threat model as the review brief) by a reputable applied-cryptography
  shop is realistically a **1–2 week, single-reviewer engagement** given how small and
  already-documented the surface is — this is a favorable profile compared to a typical
  audit target (small LOC count, zero runtime deps, existing adversarial test suite to build
  from rather than starting cold).
- A **full-surface audit** including the workspace packages (`mcp-proxy`, `signer-core`,
  `signer-sidecar`, `tsa-anchor`) and the sibling-repo mobile/relay/console surfaces from
  `THREAT-MODEL-ADDENDUM.md` is a materially larger, multi-week, likely multi-reviewer
  engagement — those surfaces (pairing ceremony, HPKE display, magic-link auth, RBAC/RLS)
  are exactly the kind of thing a generalist app-sec audit specializes in, distinct from the
  applied-crypto specialism the core needs.
- **Recommendation for sequencing (not a decision — F4-gated):** the focused crypto-core
  review is the higher-leverage first purchase, since it's the part of the system every
  other surface's trust ultimately rests on (a receipt is only as good as the signature
  verification underneath it), and it's the cheapest of the two engagements to scope well
  given the existing threat model + conformance suite.

---

## 3. SOC 2 path — pointer, not a duplicate

**Do not read this repo's posture as the SOC 2-scoped system.** SOC 2 (Type I or Type II)
examines a **hosted system's operational controls** — access control, change management,
monitoring, incident response, over a period of time (Type II) or at a point in time (Type
I). `noa-receipt` is an **open-source library and CLI** with no hosted infrastructure, no
customer accounts, no admin console, and nothing running 24/7 — there is no "system" here
for a SOC 2 auditor to examine. It is a **component** consumed by systems that could be
SOC 2-scoped, not the scoped system itself.

**The system that IS on a SOC 2 Type I readiness path is the hosted `noa-trust` console** —
that work already exists and was just merged:

- **`/Users/toratoraman/noa-trust/docs/ENTERPRISE-EVIDENCE-PACK.md`** (different repo — cited
  by path per this task's instruction, not duplicated here). Its own opening line states the
  same honesty framing this document uses: *"It is not an audit, and it is not a
  certification... Where a claim would require an independent auditor's opinion... this
  document says so plainly and does not simulate one."*
- That pack's §6 "SOC 2 Type I readiness control matrix" is the actual control-by-control
  self-assessment for the hosted system (admin RBAC, audit trail, evidence store, RLS
  multi-tenancy). This document does not restate that matrix — go there for it.
- That pack's §1 threat-model summary and §2 cryptographic-conformance-evidence sections
  already point back at THIS repo's `THREAT-MODEL.md`/`THREAT-MODEL-ADDENDUM.md`/conformance
  suite as their source of truth — the two documents are designed to cross-reference, not
  duplicate, each other. This is the second, matching half of that link.

**Where noa-receipt fits in a SOC 2 narrative for a buyer:** as the cryptographic component
the hosted console builds on — "the console's receipts are verifiable independently of the
console because they're built on the open, conformance-tested noa-receipt format" is a real,
citable claim (§1/§2 of the evidence pack make it). "noa-receipt is SOC 2 compliant" is not a
claim that means anything, because there is no hosted system here to certify — do not make it,
and flag it if seen anywhere in marketing copy.

---

## For the patron

Two documents now exist and don't overlap: this one covers the OSS library's OpenSSF-badge
readiness and what a crypto-audit engagement would look like; `noa-trust/docs/ENTERPRISE-EVIDENCE-PACK.md`
covers the hosted console's SOC 2 readiness. Neither is a certification — both are honest,
cited self-assessments a buyer or auditor can start from.

**The one decision in front of you:** the OpenSSF self-assessment found this project one
concrete gap away from passing-level readiness — add a linter (ESLint or Semgrep) with a CI
job, about half a day of work — and everything else (34 of 37 MUST criteria, zero known
vulnerabilities, 278/278 tests, provenance-signed publishing) is already there and cited.
Submitting the actual badge application and commissioning the crypto-core audit are both
F4-gated business decisions (budget + who does it), not engineering blockers — my
recommendation is to close the linter gap now (cheap, no gate needed) and treat the badge
submission + audit engagement as the next explicit patron decision when budget allows.
