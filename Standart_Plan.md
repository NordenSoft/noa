# NOA Trust — Standart Plan

> **THE SINGLE CANONICAL PLAN.** Additions, removals, status changes, revisions — all happen
> in this file. No new plan file is ever opened. Long analyses may live as **detail files**,
> but this file links to them and authority stays here. Supersedes and replaces
> `NOA-TRUST-MASTER-PLAN.md` and every other plan file — all archived at
> `~/noa-trust/.plan/_archive/` (see §10; index in `_archive/INDEX.md`).
>
> **NO DATES.** We work continuously and announce when finished. This plan contains no
> self-imposed target dates. Ordering is by dependency (§2). The only dates permitted are
> **externally imposed constraints** (§6) — facts set by others, not commitments by us.
>
> Consolidated from 71 files / 26,545 lines across `~/noa-trust/.plan/`, `~/noa-receipt/docs/`,
> `~/noa/`. Backup of everything: `~/.claude/backups/noa-plan-consolidation/20260728-123052`.
> Last consolidation: 2026-07-28 (historical timestamps are facts and stay; targets do not).

---

## 1. CURRENT STATE (measured 2026-07-28)

### noa-receipt (kernel + wire format)
| | |
|---|---|
| Branch | `arp-interop-response-20260727` @ `0874221`, 53 commits ahead of main |
| main | `bfa272b` — untouched |
| Hosted CI | Green, 6 jobs (`30326961204`) |
| PR to main | none opened |
| npm | `noa-receipt` 0.5.0 — unchanged, no publish. Ownership still on the daughter's account (`noatoraman` / hello@ordeliya.com), not the principal's `toratoraman` |
| Also on npm | `noa-mcp-proxy` 0.2.0, `noa-mcp-adapter-core` 0.2.0 (principal's account, OIDC trusted-publisher). `noa-framework-adapters`, `noa-signer-sidecar`, `noa-tsa-anchor` — code exists, **unpublished** |
| Tests | 12/12 suites, 1619 tests, 0 failures. Five verifiers: TS↔PY full PASS, Go 47/47, Rust 38/38+40/40, C# 40/40 |
| Dependabot | open (fix not on default branch) |
| QA convergence | **0 / 2** cross-family clean rounds (last round was same-family and found a CRITICAL → counter reset) |
| IETF | `draft-noa-scitt-ai-agent-receipt-00` filed and active; -01 text written and committed on the branch (`1769b99`), **not filed** |
| e2e | `packages/e2e-demo` (D3 golden demo) exists and is merged |

### noa-trust (enterprise console + site)
| | |
|---|---|
| main | `8f63e2b`, clean, in sync with origin. PRs #2 #3 #5 #6 merged (Core-8 rollout, Stage B hardening, supply-chain, scheduler) |
| PR #7 | `feat(release): bind releases to the exact signed OCI digest` — **OPEN**, CI green, unmerged |
| Production | `6e063b6` live, `/health/ready` 200. **ZERO tenants** — 0 orgs/users/holds/decisions/devices. "Broken in prod" ≠ "customer impacted"; pre-launch breaking-change window is OPEN |
| Prod signing | **fail-closed dead** — approval-signing / audit-anchor env keys not provisioned; no approval surface can produce a real signed record until §2-B3 |
| Migrations | 001→050 in tree; per-tenant HKDF signing live (`lib/console-key-custody.ts`, KARAR-7), RFC 3161 client live (`lib/console-rfc3161.mjs`), SIEM/anchor live |
| Core-8 | packages 1–7 closed; **package 8 open** (§2-B2). `.plan` inner repo pushed to `NordenSoft/noatrust-plan` (private) through 07-23 |
| Site | noatrust.com live: 8 languages, /demo.html, /playground, /proof, /compare, /regulations. No waitlist |

### noa-mobile (phone app)
| | |
|---|---|
| Client | 593/593 tests, tsc clean; approve/deny path attack-tested; signed Android release pipeline works |
| System level | **a shell**: release binary ships empty `RELEASE_RELAY_URL`/`RELEASE_CONSOLE_URL`; phone speaks `/v1/devices|holds|trust` but the console serves `/v1/mobile/*` → 404; pairing is copy-paste JSON and violates spec Red Line 15 |
| Spec | `MOBILE-APP-BUILD-SPEC.md` v6.2 **FROZEN** (survived 8 adversarial rounds to 0 findings) — still authoritative for the protocol, but carries two amendment debts (§2-C3) |
| Store | submission blocked solely on operator inputs (Apple issuer-id + team-id, Play service-account JSON) |

### ~/noa (voice assistant)
Different product. Its `STATUS.md` / `WORLD_CLASS_PLAN.md` are that project's own files and are
**deliberately not merged** into this plan.

---

## 2. WHAT REMAINS — in dependency order

Sequencing rule in force (patron, 07-22, latest dated word): **core system first, mobile last.**
The native app remains the v1 product definition (patron dictate, 07-21) — deferred, not dropped.
Cross-track order: **A (kernel/standards) and B (console) proceed now → C (mobile) → D (market).**
D items that are pure patron sends can fire anytime at his discretion, but the standing dictate
defers marketing until the product is finished and tested.

### TRACK A — kernel + standards (noa-receipt) — ACTIVE

Order within track; each item lists what it blocks.

1. **A1 — Principal decision batch** (§5 group 1). Blocks A2, A4, letters.
2. **A2 — QA convergence to 2/2 cross-family clean rounds**, then land the branch on main
   (or, as fallback for the draft only, cherry-pick docs commit `1769b99` to main).
   Blocks: -01 filing from a stable base · Dependabot closure · any future npm publish.
3. **A3 — Conformance-evidence sweep**: every normative MUST in the -01 delta gets a pointed-to
   mechanical check (TS+Python minimum): surrogate/duplicate/integer-bound rejection,
   no-normalization, five chain axes, Option B headers, `-19`-only. Any MUST without a check:
   add the vector or soften the sentence **before** filing — never file, then backfill. Blocks A4.
4. **A4 — File draft -01** (principal submits, his name). Constraint: comfortably before the
   external IETF 127 cutoff (§6); the filing itself resets expiry ~185 days out. Content is
   fixed: corrections of the filed record + externally-requested canon-params/chain-axes.
   Nothing promissory; 0.2 material stays out (Amendment A1.3).
5. **A5 — `0.1-beta` tag** — evidence-gated, not date-gated: filed -01 + every MUST passing in
   **all five** sibling implementations. Git tag + VERSIONING/CHANGELOG only; no npm event,
   no announcement. Commits us to semantic freeze of 0.1.
6. **A6 — bytes-in migration (P3)** — 452 TS call sites measured; then **P4** delete legacy
   object-ingest paths (no hidden legacy path); then the **9 open class-B exploits**
   (prototype/intrinsic class) which wait on P3. Order vs CI ratchet = decision H-6.
7. **A7 — KMS / key custody (kernel keyring)** — the panel's named "fatal gap". Before scoping:
   read GAP-C + `~/noa-trust/lib/console-key-custody.ts` as prior art and decide **consciously**
   reuse-vs-domain-separated-fork (console solved custody-without-KMS for *its* keys already).
8. **A8 — Chain persistence** (restart-survivable chain continuity — no named competitor ships it).
9. **A9 — RFC 3161 (kernel side)** — evaluate lifting `~/noa-trust/lib/console-rfc3161.mjs`
   (dependency-free DER client, golden-vector-tested) instead of writing a second one.
   `noa-tsa-anchor` package exists unpublished.
10. **A10 — SCITT registration** — genuinely unstarted on both surfaces; gated by the
    A1.3 six-condition threshold and the principal's public-participation decision.
11. **A11 — Interop letters** (all principal-gated sends): CAID reply after its 5 corrections ·
    ARP thread reply **after** the private memo to Hillier (standing sequencing) · standards
    question is stronger sent after A4.
12. **A12 — Carlos / physical-completion track** — DEFERRED by decision; 10-stage plan and
    6 unanswered questions for Carlos exist (`docs/carlos.md` + archived fuller design).
    Until its release gate passes, NOA states physical-completion proof is **not implemented**.
13. **A13 — #48 PII-in-signed-receipt fix** `[UNVERIFIED whether closed]` — raw email +
    free-text into signed bytes was a named **pre-public-beta blocker** (07-16). Verify status;
    if open, it changes signed bytes → golden backcompat + schema migration + QA panel.

### TRACK B — console / enterprise production (noa-trust) — ACTIVE

1. **B1 — PR #7 decision** (signed-OCI release contract) — review + merge under lead release
   authority. Part of the Core-8 release-authorization thread.
2. **B2 — Core-8 package 8 (the last one)**: production freeze → encrypted archive activation →
   base-backup/WAL proof → isolated production-lineage restore (**second** restore still owed) →
   migration 039 governed audit-bridge + external anchor linkage → hosted PG18 gates → exact
   release authorization → push/deploy. Plus the **headless canary** item. (Source: session
   ledger + master plan; both agreed these are the only Core-8 remainders.)
3. **B3 — Production activation chain** (prerequisite for ANY real customer or design partner):
   custody-master provisioning (patron) → prod migration apply (operator) → signing + anchor
   env keys live → F14b artifact flag ON → gate-pairing ceremony ratified → ≥1 HPKE device
   per tenant. Until this closes, every approval surface is theater in prod.
4. **B4 — GAP residuals** (all design docs archived; this list is the living authority):
   - **H-v3 enforcement surface**: admin `layout.tsx` not IP-ACL gated (verified still true) ·
     OIDC/SAML reauth routes unchecked · **Railway proxy-header assumption `[UNVERIFIED]` —
     gates whether the feature works at all in prod** · no config/read UI · compressed IPv6
     not normalized.
   - **Audit-write atomicity** — ONE consolidated item (was tracked three times as AB-C7,
     G-(c), H-(f)): `audit()` post-commit best-effort → transactional/durable.
   - **Chain-id pre-emption/squatting** (P1.5 residual, MEDIUM) — named 07-14, never fixed.
   - **GAP-D scope extension** decision: maker-checker currently trust-root-only; SSO-config
     and key-manifest/credential-mint not covered.
   - **GAP-F↔D coupling** decision: does an ACTIVE break-glass grant bypass maker-checker?
     Deferred three separate times; still the most concrete open trade-off.
   - **GAP-G**: 7 retention policy decisions (§5) + `--apply` cadence + retention-vs-tamper-
     evidence conflict (compliance architecture call).
   - GAP-A/B residuals: read-time "configured" check (OPEN#1) · C5 deep-link UX · C6 wording.
5. **B5 — Hardening leftovers**: SP-8 DB pool `max:3` shared admin+API (operator: Railway
   conn ceiling — production landmine at 4 concurrent) · iteration-4 re-triage against the
   zero-tenant reality · break-glass start/end UI (mutations exist, no page posts them) ·
   HPKE-encrypt decision reason (currently plaintext console-side; the app's red-line test was
   right; decision already taken, work open) · CSP nonce on public routes · per-locale
   `<html lang>` · sitemap gaps · mobile-menu touch targets · **the patron-ordered final deep
   adversarial QA across all streams (07-20 order) — no evidence it ever ran**.
6. **B6 — Console split decision** (`/admin`-in-repo vs separate service) — recommended
   "before enterprise beta"; **cheapest moment is now, at zero tenants**. Principal's call.
7. **B7 — Mobile-web approval slice** (4 items: hold e-mail notification via Resend +
   deep link · inline step-up (kill the 428 dead-end) · phone-layout approval cards ≥44px ·
   real-device iPhone/Android proof). Decided 07-21 as v1 scope under delegation; status under
   the later native-app dictate **needs principal confirmation** (§5). The notification item is
   load-bearing regardless: an approver cannot approve what nothing tells them about.
8. **B8 — #29 K5 honesty fix** `[UNVERIFIED whether closed]` — replace "we cannot forge it"
   with *"we cannot forge your approval and cannot read what you approved"* (gate/console keys
   are ours; the strong claim is phase-2 native-app material). Zero code; cheapest open item.
9. **B9 — Policy-engine evaluation/simulation** — status unconfirmed across all sources;
   verify against code, then plan or close.

### TRACK C — mobile app (frozen spec v6.2) — AFTER core, per standing dictate

0. **C0 — Resume trigger**: principal reconfirms native-app-v1 + names what "core done enough"
   means. No document defines it; that absence is why mobile drifted (§9-1).
1. **C1 — Two cheap principal decisions** (minutes to decide, gate ~48h of work):
   Red Line 15 — waive with sign-off (0h) vs build real local-gate SAS surface (~24h) ·
   PIN posture — ratify salted-SHA256-as-boolean (~2h) vs implement spec Argon2id→KEK (~24h).
2. **C2 — Stream A (critical path ~40h)**: rewrite `PhoneRelayClient` to speak the console's
   `/v1/mobile/*` (logged lead decision: target the live console API, not a private relay).
3. **C3 — Spec amendments** to the frozen v6.2 (documentation debt, do not skip):
   (a) §9 standalone-relay → console-API pivot; (b) Red-Line-15 disposition per C1.
   The BLOKOR-1 console-pairing UI design as written **violates RL15** (console displays the
   SAS) — flagged independently twice; resolve before any real customer pairing.
4. **C4 — Stream B (custody)**: per C1 decision + persist lockout state across restart.
5. **C5 — Stream C (pairing)**: real HTTP pairing transport replacing copy-paste →
   QR/deep-link self-pairing (zero QR exists today).
6. **C6 — Stream D (release/ops)**: release URL/CI injection (empty-endpoint shell fix) ·
   **real-device keychain verification** — all 19 custody tests currently run against an
   in-memory fake; the custody claim has never met a real OS keychain on either platform.
7. **C7 — Store submission** — blocked purely on operator inputs (§5 group 4); then Apple
   review (external, §6).
8. **C8 — Open mobile defects**: C2b sealing TOCTOU (`useApprovalApp.ts:1288-1316`) ·
   gate-key kid-rotation adoption slice · F-002 custody unlock/backup wiring (HIGH-adjacent,
   bites at first real customer) · perf batch (HPKE re-alloc, countdown, unvirtualized inbox,
   1617-line hook).
9. **C9 — Re-verify the D3 golden demo** (5 scenarios) against current code before any
   "end-to-end proven" claim — the package exists and merged, but the full chain has not been
   re-run since the console-API pivot decision.

### TRACK D — market / external (ALL principal-gated sends; deferred by standing dictate)

1. **D1 — Announcement kit**: Part 1 approved 07-11 and **still unposted** (only the principal
   can post — his accounts). Part 2 marketplace-listing text choice (original vs extended;
   recommendation: extended). Never list `noa-framework-adapters` anywhere until published.
2. **D2 — Design partner (F3)**: profile, disqualifiers and two send-ready templates exist.
   Hard prerequisite: B3 (a partner must see real signed records). Sequencing question for the
   principal: original rule was "perfect MCP wedge + 1 partner, THEN portfolio" — the wedge
   arguably is perfected; does partner outreach wait for the whole app or not? (§5)
3. **D3 — Investor brief**: exists, QA'd, **stale** — its "console LIVE" claim predated the
   85-90% audit, and two weeks of shipped work postdate it. Refresh before any send; also
   decide the contact address (currently hello@ordeliya.com — the daughter's npm account
   e-mail).
4. **D4 — Break-me window**: issue #5 open, **zero engagement in 17+ days**. Decide: escalate
   to r/netsec + r/crypto + 3-5 direct researcher e-mails (drafted, never sent) · add a bounty ·
   or accept silence and proceed.
5. **D5 — /regulations legal review**: the source mapping said "lawyer before publish"; the
   page shipped with **no evidence of review**. Close the loop or accept the risk explicitly.
6. **D6 — npm ownership transfer** of `noa-receipt` to the principal's account
   (`npm owner add toratoraman noa-receipt` + `npm owner rm noatoraman noa-receipt`;
   needs one-time access to the daughter's account). Business-continuity item, flagged since
   07-11, still open.
7. **D7 — Hosted tier / F13 S4** (hosted-relay production cutover, Postgres store, "shipped"
   claim change on /compare): strategic fork — free self-hosted vs paid hosted is the revenue
   model's first real test. Requirements sketch exists (archived ops-runbook §f).
8. **D8 — Merge the two competitor universes** — the 07-10 set (Microsoft AGT, Pipelock,
   Asqav, AGLedger, AIR Blackbox) and the 07-21 set (Airlock/HARP, HAP, Humanos, Permission
   Protocol, Stipul, Handshake.AI, Obsigna, ATAP, Paphwey) were never merged into one tracked
   list. Cheap doc task, real blind-spot closure.

---

## 3. DONE — kept only because completion is load-bearing context

- **C-04 closed** (`a14aad5`): `report()` signs **no** determinate negative in any state;
  UNUSED→409, RESERVED→202. First fix was wrong and made the hole cheaper — self-found,
  reversed. The green test that blessed the vuln was inverted (`grant-atomic.test.ts:66`).
- **CI source-gates live** (poison catalog): entry-points generated from `src/index.ts`
  (68 exports, 24 security-sensitive, 21 not yet bytes-in); L0/L5/L6/L7/registry/R7 blocking;
  L1/L2/L3 warn+ratchet; L4 kill-the-check test 10/10. The gates caught the author's own
  errors three times — that is why they exist.
- **Authority↔integrity split shipped**: `--purpose audit|authorize`, unknown value fail-closed.
- **NON-CLAIMS.md** (what a receipt does NOT prove) + threat-model refresh (two claims
  withdrawn) + `docs/MIGRATION-1.0.0.md` + unpublished C-04 advisory.
- **Console enterprise stack shipped and merged** (the GAP design docs are archived history —
  the code is in main): SSO enforcement + federated reauth (mig 018) · per-tenant HKDF signing
  keys + rotation/history tooling (migs 023-026, 037; KARAR-7) · trust-root maker-checker
  (mig 020) · break-glass episodes · retention sweep · IP allow-list (mig 019) · signed audit
  anchor batches + RFC 3161 TSA client + NDJSON SIEM pull (mig 021, extended to 050) ·
  jsonb double-encoding fix across 23 sites (was silently: SSO fail-open, quorum 3→1, holds
  entirely dead) · admin-audit 10-bug fix · Core-8 packages 1-7.
- **Five-implementation parity** held through all of it (TS/Py/Go/Rust/C#).
- **Demo + site live** (demo.html, playground, proof, compare, regulations, 8 locales).
  MCP packages 0.2.0 live under the principal's account with provenance.
- **Mobile client layer** genuinely near-done (593/593; D2 fail-closed verify; substitution
  attacks proven rejected) — the gap is connective tissue, not the client (§2-C).
- **v6.2 app spec frozen** after V3→V4→V5→V6→V6.1→v6.2 (7→5→3→0 findings); the chain's
  directives are archived; v6.2 is the only surviving authority.
- **D3 golden-demo package** built and merged (`packages/e2e-demo`).

---

## 4. DECISIONS — made and binding (one line of reasoning each)

### Kernel / wire format (ADR-0001 is normative; Amendment 1 PROPOSED, §5)
| Decision | Reasoning |
|---|---|
| Wire `noa.receipt/0.1` frozen (30 leaf fields, `additionalProperties:false`) | Interop identity; changes go through 0.2 gate only |
| Seven-state outcome model REJECTED | Existing six-state machine covers it; re-ask carried no new evidence |
| Blockchain REJECTED | tsa-anchor + SCITT superior on every axis for our problem |
| Temporal/durable-execution REJECTED (this scope) | Right instinct, wrong frame for C-04/H-02 class |
| Cedar/OPA/OpenFGA REJECTED for `noa.policy/0.2` | Smallness is deliberate |
| Five independent verifiers retained | The strongest correctness control the project has |
| Rust = independent verifier, not mandatory kernel | Parity value without a rewrite tax |
| Security APIs go bytes-in (`string`\|`Uint8Array`) | Kernel must never walk/serialize caller objects (binding) |
| External policy engines = gate-side input only, bound via `inputsHash` | Kernel stays small and auditable |
| Authority rule: separate authority+claim → separate artifact; same producer+missing content → base-format revision, **not** sidecar | A second envelope adds a signer matrix and no truth |
| Correlation sidecar REJECTED (`MAPPING_PROFILE_ONLY`) | Its central claim is unverifiable by any third party |
| `noa.receipt/0.2` requires ALL SIX conditions (2 external written requests · vectors in ≥2 independent orgs · CAID exchange proves real need · bytes-in landed · KMS landed · legal review) | The draft's reservation paragraph IS the entire 0.2 roadmap until then |
| Non-claim: two differently-constructed digests are never proven equal by signatures | Signing an unfalsifiable assertion launders an assumption into a check |
| Terminal negative outcomes (EXPIRED/DENIED) stay verifiable forever | A signed timeout receipt is proof the action never ran |
| "A determinate 'nothing ran' requires an observer other than the executed party" | The C-04 lesson, generalized |

### Console security architecture
| Decision | Reasoning |
|---|---|
| Per-tenant signing keys: HKDF-derive now, KMS-migratable registry later (Alt-C) | KMS call inside a FOR-UPDATE tx is an architecture change; enum makes KMS a forward rotation. Honest limit: cryptographic separation, NOT custody separation |
| Anchor batches layered + optional RFC 3161 leg; reusing inbound checkpoint-anchor REJECTED | Self-anchoring into the same DB is zero security against the DB owner |
| SIEM = native NDJSON pull; CEF/OCSF-as-primary REJECTED; push/webhook REJECTED for v1 | Any transformation breaks hash recomputation; pull keeps the server stateless |
| Hand-rolled fixed-template RFC 3161 DER; ASN.1 library REJECTED | No supply-chain dependency for a tiny bounded encoder; auditors verify with openssl |
| Anchor key independent of tenant signing keys | Never couple two crypto-core decisions |
| Maker-checker via new default-OFF flag; reuse of `require_two_person_critical` REJECTED | Zero-surprise rollout |
| Deny-by-default; never fetch by resource ID alone; internal admin never silently impersonates | Tenant isolation + liability posture |
| Secrets shown once, never retrievable | Binding invariant |
| step-up rank password<passkey<federated | Policy judgement ("IdP has authority"), not a claimed security fact |
| Audit chain + signed evidence excluded from retention purge | Retention-vs-tamper-evidence conflict is real and undecided — not silently resolved |
| Break-glass = a **record**, not a capability | Bootstrap already covers lockout; the gap was auditability |

### App protocol (v6.2, frozen)
| Decision | Reasoning |
|---|---|
| SAS derived from full JCS transcript, never transmitted, shown by the LOCAL gate (RL15/D10-v2) | A transmitted or console-displayed code cannot authenticate the transcript that carries it |
| Offline root delegates to HSM/KMS manifest key (D16-v2); gate never signs its own manifest | No self-certifying trust roots |
| Gate's atomic CAS is the grant enforcer, reserve-before-dispatch | Wrapper-local flags race; post-execution callbacks are too late |
| Any non-executed outcome without a fresh trusted checkpoint = INCONCLUSIVE (G1/F3) | A compromised gate must not launder an execution behind "cancelled" |
| PIN→Argon2id→KEK; WebAuthn = unlock gate only, assertion ≠ receipt signature | 4-6 digit PIN alone is offline-brutable; challenge-signing is not action-signing |
| Approval unit = the risky action itself, never "this session" | A hijacked mid-session agent abuses a session-level yes |
| Target the live console API, not a private alpha relay (lead decision, logged) | One production path; the standalone relay design is superseded (spec amendment owed, §2-C3) |
| Never price per-approval | Perverse incentive against security; price on agents/approvers/tenant |
| React Native native app (patron mandate), Android-first | Enterprise-grade requirement overrode the PWA-day-1 arbitration |

### Strategy / positioning
| Decision | Reasoning |
|---|---|
| Red lines K1-K6 stand: neutral-standard + hosted revenue · no vaporware · no Brain merger · zero internal traces public · honest language ("tamper-evident", never "tamper-proof") · install-honesty | Each is a trust-brand invariant; K3 pending re-affirmation (§5) |
| Sell **"approval-of-record"**; "verifiable action authority" = vision language only | The honest v1 claim: "approval bound to a biometric-verified person; record server-signed, hash-chained, anchored" — NOT "even NOA cannot forge it" (that is native-app phase-2) |
| "No exact competitor" NEVER appears in external material | An investor disproves it in one call; Humanos sells "close enough" today with named customers |
| Position beneath Okta/Auth0/Entra as the enforcement/evidence layer; never fight "AI security platform" messaging | Bundling is the channel threat, not the product threat |
| Payments: be a compatible layer over AP2/Visa TAP/Mastercard, never a rival rail; do not enter finance first | Humanos + card-network wall |
| Telegram: NO campaigns, messages, bridges, or external actions, ever (07-22 decree — supersedes all earlier Telegram plans) | Own the customer relationship; Telegram was a hunting ground, then not even that |
| Moat = enforcement-point breadth + auditor-accepted evidence format + conformance ecosystem + production history — never the crypto itself | Ed25519/JCS/hash-chains are copyable; head start ≈ months, not a moat |
| MCP wedge first, portfolio second; spec/conformance publication AFTER a design partner | Standard-leverage, not standard-first |
| Prepare-don't-fire for every irreversible reputational action | Drafts always ready; only the principal fires |
| OIDC/Trusted-Publisher npm publishing only | Local token publish breaks the SLSA provenance story |

### Process (project-level)
| Decision | Reasoning |
|---|---|
| Evidence-before-done; fail-before/pass-after for every fix; green CI ≠ convergence | The R7 runner counted crashed exploits as CLOSED — silence and health are different facts |
| No test weakened; a test blessing unsafe behavior gets inverted | Tests measure reality, not comfort |
| No artifact/schema for unimplemented mechanisms | Anti-vaporware, wire-format edition |
| Versioned migrations are never edited in place | Checksum hard-fail; a replayed DB can never catch up |
| Docs are the least trusted source: code+SQL > tests > migrations/git > runbooks > plans | Measured repeatedly; this consolidation found six stale "status" docs (§9) |

---

## 5. THE PRINCIPAL'S OPEN DECISIONS

**Group 1 — kernel/standards batch (blocks Track A):**
| # | Decision |
|---|---|
| H-1 | Accept breaking `1.0.0` (customer commitment) |
| H-2 | Deprecation window length |
| H-3 | Ship `noa-receipt-compat`? (verified external consumers: **0** — lower bound) |
| H-5 | Publish the C-04 security advisory? (disclosure posture) |
| H-6 | CI-ratchet-first or bytes-in-first (lead recommends CI-first) |
| H-7 | Keep five-implementation parity as a product commitment? (if dropped, Rust re-evaluated) |
| — | Ratify/reject **ADR-0001 Amendment 1** (authority rule + sidecar rejection + 0.2 threshold) |
| — | Approve the **-01 filing** (public act under his name) + masthead e-mail (keep toratoraman@gmail.com?) |
| — | Ratify the **0.1-beta definition** (profile-maturity tag, evidence-gated) |
| — | Send/hold each letter: private ARP memo → ARP thread reply · CAID reply (after 5 fixes) · standards question |
| — | scitt@ietf.org filing-week note? Request IETF 127 agenda minutes? |

**Group 2 — cheap unblockers (minutes each, gate real work):**
Red Line 15 waive-vs-build · PIN posture ratify-vs-Argon2id · GAP-D maker-checker default
(recommendation: opt-in) · GAP-F↔D break-glass coupling · marketplace listing text (original
vs extended) · #26 packaging (publish the two builders inside zero-dep `noa-approval-artifacts`
only — ONE new promise, not two; `noa-signer` stays unpublished).

**Group 3 — strategic forks:**
Mobile priority reconfirmation + definition of the resume trigger (§2-C0) · does design-partner
outreach wait for the whole app or follow the MCP wedge (§2-D2) · is the mobile-web approval
slice still v1 scope (§2-B7) · console split now at zero tenants (§2-B6) · hosted tier / F13
S4 go-live (§2-D7) · SCITT / public transparency-log participation (governance + disclosure
of anchor cadence) · privilege separation for trust-root writes (separate DB role — the ONLY
way to *stop* rather than record a DB-credentialed insider) · F11 waitlist table DROP
(irreversible) · #24 delete three dead Railway services (irreversible) · re-affirm K3
(no Brain merger) now that shared plumbing serves Brain-as-first-customer · GAP-G retention
policies (7 items) + sweep cadence · break-me escalation (§2-D4) · OpenSSF timing.

**Group 4 — external inputs only the principal can supply:**
Apple issuer-id + team-id · Play service-account JSON · customer IdP metadata · FCM/APNs
credentials · Resend API key (prod) · custody-master + anchor env keys (B3) · Railway
connection ceiling for SP-8 · TSA vendor choice (freetsa / DigiCert / customer-corporate) ·
one-time access to the daughter's npm account for the ownership transfer (D6).

**Group 5 — confirmations of fact only he can settle:**
Was the legacy global signing key ever destroyed after the per-tenant cutover? (irreversible
step, status unrecorded) · was /regulations ever legally reviewed? (§2-D5) · bundle id
`com.noatrust.approver` + name "NOA Approvals" final before store registration?

---

## 6. EXTERNAL CONSTRAINTS — set by others, not commitments by us

| Fact | Source |
|---|---|
| `draft-...-00` **expires 2026-12-25** (six-month I-D rule); an expired draft is by its own boilerplate inappropriate to cite | IETF datatracker + filed TXT |
| IETF 127 I-D **submission cutoff 2026-11-02 23:59 UTC**; tool closed after that until ~the meeting | IETF important-dates |
| IETF 127 meeting: Nov 14-20, San Francisco; no SCITT session scheduled yet (scheduling absence, not session absence) | IETF |
| Filing -01 resets expiry ~185 days from filing | IETF mechanics |
| SCITT WG core is finishing (RFCs 9942/9943/9995 published; SCRAPI in queue); rechartering poll was 11/6/5 — undecided; neighbors revise actively (ARP -01, VCP -03, delegation-receipts -10) | WG minutes/datatracker |
| Apple App Store review takes 1-3 days once submitted | Apple |
| Hillier's unexplained "15th" — referent unverifiable; treated as robust-under-both-readings | correspondence |

Consequence (dependency, not date): -01 files when the A1→A3 chain closes, with buffer against
the cutoff; the closer it drifts toward the cutoff, the more it becomes archaeology-prevention
instead of participation.

---

## 7. RULES IN FORCE

- Feature branch discipline: no merge/publish/deploy/production-touch without lead+patron
  release authority; `noa-receipt` branch stays put until convergence.
- Dependabot alert stays open until the fix reaches the default branch.
- No security advisory published (H-5 pending).
- No test weakened; tests blessing unsafe behavior get inverted; every fix carries a
  regression test that goes red when only its own predicate is disabled.
- Green CI ≠ convergence; convergence = 2 consecutive cross-family clean adversarial rounds.
- No artifact or schema for unimplemented mechanisms.
- K1-K6 red lines (§4 strategy) + the 17 app-spec Red Lines (spec §1) bind all work.
- K4: no agent trailers / internal traces in public repos; no public git-history rewrite
  (v0.4.0 provenance pins the SHA).
- External sends (announcements, outreach, letters, filings) are **prepare-don't-fire**:
  drafts ready, only the principal fires, from his own accounts.
- NO self-imposed dates anywhere (this plan's charter). Dependency order replaces schedule.
- English everywhere in docs/output (language policy 07-26); verbatim Turkish dictates live
  only in the doctrine changelog.
- This file is the only plan. New work = new line HERE. Detail analyses link from §10.

---

## 8. KNOWN BLIND SPOTS / UNVERIFIED

- **Zero-tenant paradox**: everything "prod-live" has zero production usage; all "verified
  safe" claims are code/test-level. First real tenant is the actual test. (SSO enforcement has
  never met a real IdP; a go-live dry run with a real customer IdP is owed.)
- **Docs lag reality systematically** — six files claimed states the code disproved (§9).
  Trust order: code+SQL > tests > migrations/git > runbooks > plans (including this one).
- Library-level findings **A1-A5 + B4** from the 07-10 audit (tenant enforcement inside
  `verifyChain`, genesis ownership, builder pre-sign validation, L2 TOCTOU snapshot, explicit
  S<L check, paramsHash low-entropy) have **no closure evidence by name** — console-layer RLS
  is a different trust boundary than the standalone library. Needs a source audit.
- #48 PII-in-receipt and #29 K5-honesty fixes: closure unverified (§2-A13, §2-B8).
- Per-tenant signer cutover happened **without the designed feature flag** (grep: flag absent)
  and without a decision-log entry for "KARAR-7" — confirm it was blessed, not momentum.
- Railway proxy-header (XFF/X-Real-IP) behavior `[UNVERIFIED]` — IP allow-list may not work
  at all in prod (§2-B4).
- Mobile custody: 19/19 tests use an in-memory keychain fake; never verified on-device.
- `48bba94` (mobile it2/it3 claims) unverifiable from the noa-trust repo.
- `e2e-demo-golden-path` reports green while six scenarios are **skipped**; MCP SDK hangs
  forever on non-`Error` throw (upstream); L2 lint misses computed access (`x["includes"]`);
  `expectCompileFailure` is dead code; ~25 producer-side exports still read live objects.
- Unverified competitor names — never corroborated: **"Elydora"** (R5's namesake!), "Sello",
  "Loop/secureloop.ai". Do not let them into any external material or tracking list as fact.
  (Also: MS-AGT star/fork counts moved inconsistently between snapshots — nobody analyzed why.)
- The two competitor universes were never merged (§2-D8); current market view is a union of
  two partial snapshots, both stale by a week+.

---

## 9. CONTRADICTIONS FOUND IN CONSOLIDATION — and how each was resolved

1. **Mobile priority** — four rulings in 48h: 07-21 Fable delegation ("web-approval v1, native
   phase-2") → 07-21 patron dictate (native app IS v1, overrides Fable) → 07-21 "shelved,
   finish web first" → 07-22 13:26 Codex reactivation → **07-22 15:58 patron: core first,
   mobile last** (latest dated patron word — wins by precedence). Resolution: native app = v1
   product definition; sequencing = core first; resume trigger undefined → §2-C0/§5. The
   mobile-web slice's status could NOT be fully resolved → explicitly parked as §2-B7/§5.
2. **Competitor research**: 07-10 and 07-21 universes are nearly disjoint; the 07-21 research
   omits Microsoft AGT entirely and understates Humanos. Resolution: the 07-21 Fable
   evaluation is the current *judgment* layer; both lists stand as partial data; merge task
   opened (§2-D8).
3. **GAP-C doc says "not started, awaiting patron"** — code shows it fully live (KARAR-7,
   migrations 023-026/037). Resolution: code wins; doc archived as stale; the un-gated cutover
   and un-logged decision moved to blind spots (§8).
4. **Hardening backlog marks SP-5/SF-002/SP-7 "deferred"** — code shows them done. Resolution:
   code wins; only SP-8 + iteration-4 survive as open (§2-B5).
5. **Master plan FAZ-C headers show #9e/#9g open** — its own done-ledger shows them shipped.
   Resolution: done-ledger wins (same pattern the file itself diagnosed for FAZ-R).
6. **Investor brief claims console "LIVE" (07-14)** — the 07-21 audit measured 85-90% with
   named gaps. Resolution: audit wins; brief marked stale, refresh required before send (§2-D3).
7. **Telegram campaign draft vs 07-22 decree** — decree wins; draft archived; only the
   channel-agnostic *argument* (callback_data not bound to anything) is salvageable.
8. **V3/V4/V6/V6.1 directives** — superseded chain; v6.2 is the sole surviving spec authority.
9. **Master plan "prod-live" vs zero tenants** — both true: code-live, usage-zero. The plan now
   states this explicitly everywhere it matters (§1, §8).
10. **BLOKOR-1 console-SAS design vs spec Red Line 15** — the frozen spec wins (later, and
    names this exact failure mode as a beta blocker); BLOKOR-1 archived with the violation
    flagged; disposition = principal decision C1.
11. **FAZ-APP-IMPLEMENTATION-SPEC** — truncated mid-sentence on disk AND superseded by v6.2 in
    every visible respect; archived; its one salvage (relay-in-receipt-repo location rationale)
    recorded in the archive index.
12. **Relay architecture**: spec §9 standalone relay vs logged lead decision to use the console
    API. Resolution: lead decision wins (it postdates and was code-grounded); formal spec
    amendment owed (§2-C3).
13. **"44 files unrecoverable"** — partly stale: `.plan` has its own private pushed repo
    (`NordenSoft/noatrust-plan`, synced 07-23, 46 files); only `CARLOS.md` and
    `SESSION-ID-LEDGER.md` were untracked there (both in the consolidation backup).
14. **Two Carlos documents** (`.plan/CARLOS.md` fuller design 07-24 vs `docs/carlos.md`
    decision record 07-23). Resolution: consistent in substance (both DEFERRED); decision
    record stays live in docs/, fuller design archived and linked; no conflict to resolve.

---

## 10. DETAIL FILES (authority is in THIS file, never in them)

**Live detail files:**
| File | Content |
|---|---|
| `docs/ADR-0001-trust-kernel-vnext.md` | Normative architecture, 1095 lines |
| `docs/DECISIONS-AND-RATIONALE.md` | The WHY record — per-topic rationale, alternatives rejected, reversals, contested items (from the 40 archived files + this week's decision docs) |
| `docs/ADR-0001-proposed-amendment-2026-07-28-authority-rule.md` | Amendment 1 — awaiting ratification |
| `docs/ASSESSMENT-enterprise-brief-2026-07-28.md` | 23-heading brief dispositioned |
| `docs/2026-07-28-draft-01-timing-and-0.1-beta-decision.md` | -01 analysis (its dates are superseded by this plan's no-dates rule; its dependency logic stands) |
| `docs/interop/*` | ARP memo, two reply drafts, sidecar-rejection review, standards question |
| `docs/carlos.md` | Carlos physical-completion decision record (DEFERRED) |
| `NON-CLAIMS.md` | What we do not prove |
| `docs/advisory-draft-C-04.md` | Unpublished advisory (H-5) |
| `~/noa-trust/.plan/MOBILE-APP-BUILD-SPEC.md` | Frozen v6.2 app protocol (amendments owed: §2-C3) |
| `~/noa-trust/.plan/SESSION-ID-LEDGER.md` | Append-only Codex session ledger (operational) |
| `~/noa-trust/.plan/ANNOUNCEMENT-KIT-DRAFT.md` | Approved, unposted (D1) |
| `~/noa-trust/.plan/DESIGN-PARTNER-OUTREACH-DRAFT.md` | Send-ready templates (D2) |
| `~/noa-trust/.plan/NOA-TRUST-INVESTOR-BRIEF-2026-07-14.md` | STALE — refresh before send (D3) |
| `~/noa-trust/.plan/NOA-TRUST-KIR-BENI-DAVET-TASLAK.md` | Broader break-me channels, unsent (D4) |
| `~/noa-trust/.plan/REGULATION-MAPPING-DRAFT.md` | Internal source for /regulations; legal review open (D5) |

**Everything else** from `.plan/` (39 files + demo mockup) is archived at
`~/noa-trust/.plan/_archive/` with a one-line-per-file index in `_archive/INDEX.md`.
Archived ≠ deleted: full history, rationale and evidence remain readable there; nothing in the
archive is authoritative.

Full pre-consolidation backup: `~/.claude/backups/noa-plan-consolidation/20260728-123052`
(71 files, 26,545 lines — verified intact before any move).
