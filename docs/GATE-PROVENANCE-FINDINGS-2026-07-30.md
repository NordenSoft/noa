# Gate provenance findings — six measured defects and the reason none was caught

| Field | Value |
|---|---|
| **Status** | **OPEN. All lead-verified at source. Nothing fixed — source changes are not authorized.** |
| **Date** | 2026-07-30 |
| **Origin** | Fable 5 advisory review, requested after the owner rejected ADR-0004. Six harnesses at `/tmp/arch-op/`, HEAD `b163e7d`. |
| **Lead disposition** | The findings below were re-verified by the lead against source before being recorded. Attribution: **all six measurements are Fable's**; M3 and the gate-coverage finding are **new to every reviewer in this project.** |

---

## 0. The finding that explains the other five

```console
$ grep -n 'walk("' scripts/lint-security-gates.mjs
275:  walk("src");

$ grep -c "packages/" scripts/lint-security-gates.mjs
0
```

**All nine mechanical gates (L0–L8, plus L8-selftest) inspect `src/` only. Not one file under
`packages/gate/src/` is classified, in the TCB list or the out-of-TCB list.** L4 (control knockout)
*is* cross-package — 12 references to `packages/gate` — so the coverage is not zero, but the nine
lints that carry the security classification are structurally blind to the package that decides
`ALLOW` versus `DENY`.

This is why five adversarial rounds, sixteen fixed CRITICALs, a 31-construct AST evasion matrix and a
gate suite ratcheted to a blocking zero **found none of the six defects below.** Every one of them
lives in `packages/gate/src/`.

**Third instance of one error.** The 2026-07-26 handoff recorded *"six gates reported health while
blind."* Round 5 recorded kimi's selection-effect finding: *"all sixteen CRITICALs were ambient"*
evidences only what reviewers were pointed at. This is the same error at the largest scale yet — the
hardening was real, the measurement was real, and the product's actual decision logic was never in
scope. **Absence of findings where nothing looked is not evidence of soundness.**

**Every row of the forthcoming provenance matrix therefore needs a final column: *which mechanical
gate fires if this regresses?* Most rows will read "none". That column is what turns an inventory into
a gate.**

---

## M3 — CRITICAL, new. A signed human **DENIAL** becomes `HUMAN_APPROVED` with an execution grant.

**Nothing is forged. The signature genuinely covers `DENY`.**

```
engine.ts:448   const daCheck = verifyArtifact(encodeDocument(decisionArtifact), ...)   // read 1
engine.ts:459   const decisionVal = decisionArtifact["decision"];                       // read 2
bytes.ts:18     return ENCODER.encode(JSON.stringify(value));                           // invokes accessors
```

The signature is verified over `JSON.stringify(decisionArtifact)` — which **calls getters**. The
authorization decision is then taken from a **second, live read** of the same caller-owned object. A
two-faced accessor returns the signed `DENY` to read 1 and the attacker's `APPROVE` to read 2.

Fable's measured result:

```
what the human actually signed  : decision=DENY  verdict=BLOCKED
decide() status                 : 200
hold.status                     : APPROVED
hold.reasonCode                 : HUMAN_APPROVED
ExecutionGrant issued           : true
  grant.spec / sig.kid          : noa.execution-grant/0.1 / gate-prod-1
```

The same split exists on the receipt: `:485` verifies the chain over `encodeDocument([deferred,
receipt])`, `:466` reads `receipt.governance.verdict` live.

**Why this outranks every prior finding.** Everything before it let an attacker obtain approval for an
action the human *believed* was something else. **This one inverts an explicit human refusal.** The
human read the request correctly, decided correctly, signed `DENY` — and the gate issued a grant.

**And a false comment on the TCB boundary is why nobody looked.** `bytes.ts:8-13` asserts:

> *"Everything this file serializes is the gate's OWN data … not a round-trip through anything a caller
> can still mutate between two reads."*

**That claim is false at `engine.ts:448` and `:485`.** `decisionArtifact` is caller-supplied. A
docstring asserting the exact safety property that is violated one call away is worse than no
docstring — it retires the question.

**Reachability:** requires an accessor on the artifact, so an in-process client
(`packages/gate/src/index.ts:31`, exported and supported) or an ambient dependency in the gate's realm
— the R5-01 threat model. `[UNVERIFIED: reachability over the HTTP /decision route — Fable could not
construct an accessor through JSON.parse and did not exhaust the search. Treat HTTP reachability as
OPEN, not closed.]`

---

## M1 / M6 — CRITICAL. ENFORCED-mode display integrity is bypassable by an **ordinary remote caller over plain HTTP**.

No forgery, no poisoning, no attacker code in the gate's process.

```
engine.ts:269   const suppliedEnc = input["encryptedDisplay"];
engine.ts:271   encryptedDisplay = suppliedEnc as EncryptedDisplay;
```

Accepted if it is a record whose `spec` string matches, assigned by `as` cast. **These lines sit
outside the RAW/ENFORCED branch, which closes at `:210`.** The pinned projection does run and does
derive a display — and that derived display is then **discarded**, because `display` is only consumed
at `:282`, inside the `else`.

```
HTTP status                      : 201
signed envelope mode             : ENFORCED
signed envelope displayProjection: noa.command.exec.display v1
human will decrypt               : {"Action":"Check disk usage","Command":"/bin/df",...}
gate-derived paramsHash binds    : /bin/rm -rf /srv @ production
```

**Sharper than kimi's version of this finding.** Kimi established that the split exists in ENFORCED.
What it actually is: **the gate signs a Hold Envelope that positively attests a provenance which did
not occur.** `mode: ENFORCED`, `displayProjection` and `actionSchema` are all present and truthful
about the *params* — and all false about the *display*. A relying party reading that envelope
concludes a reviewed renderer produced what the human saw.

**Also caller-chosen: `recipients[]`.** The caller seals to its own kid, and `trust.ts:66`'s
`auditHpkePublicKey` is never a recipient on any path (`engine.ts:282` passes only the approver) — so
**audit decryptability is caller-deletable.**

---

## M2 — CRITICAL/HIGH. The caller's `riskClass` label selects **which human is allowed to approve**.

`engine.ts:171` reads it → `:174` validates set membership only → `:212` stores → `:453` feeds
`verifyArtifact` → `approval-artifacts/src/verify.ts:260` → `requiredApproverRole()` at `:133-138`.

Identical destructive action, approver provisioned `approve-high` only:

```
CRITICAL      decide=422  detail="signer roles [approve-high] lack required approve-critical"
IRREVERSIBLE  decide=422  (same)
HIGH          decide=200  hold=APPROVED  reason=HUMAN_APPROVED  grant=true
LOW           decide=200  hold=APPROVED  reason=HUMAN_APPROVED  grant=true

same paramsHash across all four rows? true
```

The last line matters: **`riskClass` is not in the digest at all today.** ADR-0004 §1 proposed to fix
that — and including it would have made a caller-chosen value *tamper-evident*, not *correct*. **The
attacker in M2 never tampers with anything. They fill in a form.**

Anti-vacuity is intrinsic: the same action is refused at `CRITICAL` and granted at `LOW`, so the gate
is not accepting unconditionally.

---

## M4 — HIGH. Absence is not a trusted fact.

`server.ts:244` is plain `JSON.parse`, so every request body inherits `Object.prototype`. One line
from any dependency in the gate's process:

```
does the request contain encryptedDisplay as an OWN key?  false
recipient the gate sealed to     : ambient-attacker
display the human will decrypt   : {"Action":"List a directory","Command":"/bin/ls",...}
real params executable           : /usr/local/bin/deploy
```

The honest integration sent no such field. **The repository already owns the fix** —
`src/safe-json.ts` and `packages/approval-artifacts/src/inert-core/` — and the gate does not use it.
KURAL 5: extend the existing primitive, do not write a second.

---

## M5 — HIGH. Cross-hold display replay, with no attacker code at all.

A blob the gate itself legitimately sealed for hold A, presented verbatim on hold B. Its four internal
AAD fields — `tenant`, `holdId`, `deferredReceiptHash`, `expiresAt`, bound as AAD by
`signer-core/src/encrypted-display.ts:103-114` — all name hold A. **The gate checks none of them.**

```
blob's embedded holdId : id-00000001   (hold B's id is id-00000005)
hold B paramsHash binds: /bin/rm -rf /srv @ production
human sees on hold B   : {"Command":"/usr/bin/uptime","Env":"dev"}
```

The binding exists and is cryptographically sound. **Nothing verifies it on egress.**

---

## Consequences for the provenance matrix — three columns the owner's item 4 does not name

M3 and M4 are the proof that a field × provenance-class matrix **cannot represent them**.
`decisionArtifact.decision` is provenance class **(C)** — independently observed from an authenticated
external authority, an approver's Ed25519 signature. Its honest matrix entry is **GREEN**, and the
field is exploitable. `encryptedDisplay`'s *absence* has no field to put in a row at all.

> **Provenance is a property of a `(value, read)` pair, not of a field.** A value re-read from a
> mutable object after its authentication has no provenance, whatever its origin.

Required additional columns, before row one:

1. **Parse provenance** — own key or inheritable? Is absence forgeable? Duplicate-key behaviour?
2. **Read count and read source** — how many reads between authentication and consumption, off which
   object? **Any count > 1 against a caller-owned object is a defect by construction.**
3. **Gate coverage** — which mechanical check fires if this regresses? (Expect "none" for nearly every
   row — see §0.)

## Additional fields requiring rows, found by inventory rather than reasoning

| Field | Site | Defect |
|---|---|---|
| `chain` | `engine.ts:176` | `asString(input["chain"]) ?? this.trust.newId()` — the caller picks the receipt-chain identity a relying party uses to reconstruct history |
| `reversible` | `engine.ts:172` | `asBool(rawAction["reversible"], false)` — caller-chosen with a silent default; ADR-0004's tier B keyed its concession on it |
| `ttlMs` | `engine.ts:240-247` | caller picks the approval window within config bounds |
| `idempotencyKey` | `engine.ts:217` | `refHash({mode, action, chain})` — covers neither `display`, nor `encryptedDisplay`, nor `ttlMs`, nor RAW `params`; conflict detection is blind to what the human sees |
| `schemas` | `schemas.ts:22` | `JSON.parse(readFileSync(...))` at boot — unauthenticated, unversioned, pinned in no artifact. Class (B) demands the opposite |
| clock / id source | `config.ts:44`, `trust.ts:50` | injectable; `notBefore`, `expiresAt`, `nonce`, `bootId` all descend from them |
| `encryptedDisplay` internals | `encrypted-display.ts:103-114` | needs **five** rows, not one — the blob's AAD fields are validated by nobody gate-side |
| `recipients[]` | `engine.ts:282` | caller-chosen; the audit key is never a recipient |

`[UNVERIFIED: packages/relay/src/engine.ts (757 lines) — not reviewed. Its caller-controlled-field
surface is unexamined and belongs in the matrix.]`

---

## Reachability, separated rather than blurred

| Defect | Attacker required |
|---|---|
| M1, M2, M5, M6 | **an ordinary authenticated remote caller over plain HTTP.** No forgery, no poisoning, no code in the gate's process |
| M3, M4 | an accessor or an `Object.prototype` write — so the in-process client (exported, supported) or an ambient dependency: the R5-01 threat model |

The first row is the one that matters commercially: four of six defects need nothing but a valid API
credential.
