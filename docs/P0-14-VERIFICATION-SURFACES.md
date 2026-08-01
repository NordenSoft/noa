# P0-14 retired-key verification-surface inventory

Status: enumerated before the third-attempt patch and reconciled after implementation, 2026-08-01.

## Boundary and method

This inventory covers every repository surface found that accepts a keyring, a key-entry map, or a
wrapper that forwards either into a signature verdict. It was derived from:

- every package `exports`/`main`/`bin` entry and `src/index.*` re-export;
- the generated root registry in `conformance/ENTRY-POINTS.md` and
  `test/security/entry-point-registry.ts`;
- definitions and all call sites of `verifyChain`, `verifyChainText`, `verifyCheckpoint`,
  `verifyChainWitnessed`, `coseSign1Verify`, `receiptFromCose`, `verifyReceiptCompliance`,
  `verifyArtifact`, `verifyEvidence`, `verifyApprovalReceipt`, and `verifyOutcomeReceipt`; and
- the Python, Go, Rust, and C# reference verifier entry points.

The export set is mechanically enumerable. A formally complete JavaScript call graph is not: dynamic
imports, consumer callbacks, and external package consumers are not statically enumerable in this
repository. Repository call sites were enumerated textually and each wrapper below is tied to the
decision primitive it reaches. A new keyring-verifying export therefore still requires both the
existing entry-point registry and an update to this inventory/reproduction.

## Independent verification decisions

"Lifecycle" below means `noa.signing-key-lifecycle/0.1`. The required rule is independent of all
artifact timestamps: if the selected lifecycle entry has non-null `retiredAt`, the verdict refuses it
outright. A flat `kid -> publicKey` map remains the legacy shape for genuinely static consumers; it
contains no lifecycle assertion. No verifier can infer retirement from an unlabelled public key, so
the repository must not manufacture a flat map by discarding known lifecycle fields.

| Surface | Export/reachability | Pre-patch measurement | Post-patch disposition |
|---|---|---|---|
| `resolveVerificationKey` | root export; adapter-core re-export | did not exist; packages copied/narrowed keyring parsing | one shared resolver; current/static resolves, lifecycle-retired refuses outright |
| `verifyChain` | root export; adapter-core re-export | backdated retired receipt `VALID` | current/static control accepted; lifecycle-retired receipt `TAMPERED` without reading `receipt.ts` for retirement |
| `verifyCheckpoint` | root export; evidence step 17 | retired checkpoint `ok`; lifecycle unsupported | current/static control `ok`; lifecycle-retired checkpoint returns `retired signing key` without a `checkpoint.ts` comparison |
| `coseSign1Verify` | root export | retired COSE signer accepted under a narrowed historical map | shared lifecycle resolver; current/static accepted, retired refused |
| `receiptFromCose` | root export | retired COSE receipt accepted under a narrowed historical map | same shared rule as `coseSign1Verify` |
| `verifyReceiptCompliance` | root export; adapter-core re-export | flat lookup had no lifecycle decision | shared lifecycle resolver; current/static carrier accepted, retired carrier refused |
| `verifyArtifact` | `noa-approval-artifacts` root export; evidence/gate call sites | compared `revokedAt` with signer/verifier time and accepted older artifacts | any non-null `revokedAt` refused outright; current entry accepted |
| `verifyApprovalReceipt` | adapter-core root export; MCP approval gate/policy-change call sites | flat lookup had no lifecycle decision | shared lifecycle resolver; multiple current keys accepted, retired approver refused |
| `verifyOutcomeReceipt` | MCP proxy source/public package file | cached pre-rotation snapshot or retired-key flat subset accepted | cached frozen handle stays live; retired refused; multi-key static controls accepted; flat historical API removed |
| `verifyEvidence` | `noa-approval-evidence` root export and CLI | checkpoint lifecycle was discarded; manifest receipt keyring dropped revocation | raw lifecycle reaches step 17; retired checkpoint is `INVALID`, not downgraded to `VALID_SEGMENT_ONLY`; manifest receipt lifecycle is preserved |

## Wrappers and compositions (no separate signature decision)

| Surface | Route | Outcome ownership |
|---|---|---|
| `verifyChainText` | direct alias to `verifyChain` | inherits `verifyChain`; independently attack/control probed because it is a public export |
| `verifyChainWitnessed` | forwards its keyring to `verifyChain` | chain half inherits `verifyChain`; witness acceptance has a different trust-set schema |
| root `noa verify` CLI | `src/cli.ts` -> `verifyChain` / `verifyChainWitnessed` | inherits the selected root primitive; CLI exit is probed |
| root `noa --serve` IPC | `src/serve.ts` -> `verifyChain` | same primitive; existing IPC parity covers framing, P0-14 covers the primitive |
| evidence CLI | `packages/evidence/src/cli.ts` -> `verifyEvidence` | inherits `verifyEvidence` |
| e2e evidence composition | `packages/e2e-demo/src/evidence.ts` -> `verifyEvidence` | inherits `verifyEvidence` |
| gate/evidence internal call sites | gate -> `verifyArtifact`/`verifyChain`; evidence steps -> `verifyArtifact`/`verifyChain`/`verifyCheckpoint` | no duplicate cryptographic decision; each primitive above owns lifecycle enforcement |

## Lifecycle narrowing and production surfaces

| Surface | Pre-patch issue | Required outcome |
|---|---|---|
| `createRotatableSigner().historicalKeyring()` | publishes retired public keys with the retirement state removed | remove the downgrade-producing API; the generic static-map verifier contract remains |
| `createRotatableSigner().verificationLifecycle()` | detached snapshots become stale after rotation; uses live `Object.freeze`; first final review also proved live `Map` iteration could forge `retiredAt:null` | a cached in-process handle resolves the latest atomic snapshot; module-load captures harden freezing plus Map construction, lookup, mutation, and iteration against post-load poisoning |
| `asStringKeyring()` | converts structured entries/lifecycle to strings and drops lifecycle fields | throw an explicit narrowing error whenever lifecycle/security fields would be lost |
| `buildReceiptKeyring()` | converts manifest `KeyEntry` values to strings and drops `revokedAt` | return a lifecycle document, preserving retirement for `verifyChain` |
| gate `createAlphaTrust().receiptKeyring` | separate flat receipt map could diverge from `KeyEntry` state | emits a lifecycle document consumed by `verifyChain` |
| e2e `assembleGateTrust().receiptKeyring` | rebuilt a flat receipt map from a manifest that carries revocation | preserves manifest `revokedAt` as lifecycle `retiredAt` |

## Reference implementations and raw-key boundaries

`impl-py/noa_verify.py`, `impl-go/verify.go`, `impl-rust/src/verify.rs`, and
`impl-csharp/src/Verify.cs` are separate flat-map CLI verifiers. They do not contain a lifecycle
narrowing conversion: a lifecycle document does not resolve a receipt kid and is refused. They also
cannot distinguish a caller who manually labels a retired public key as a static current key. This is
the same irreducible legacy-map boundary as the published TypeScript static-map contract, not proof
of key currency. The third-attempt patch does not add the MCP lifecycle schema to those four ports.

`verifyEd25519`, relay `verifyReceiptSignature`, COSE's internal `coseSign1VerifyParsed`, TSA
`verifyStamp`, and witness `verifyCompleteness` do not accept a keyring lifecycle: they accept one raw
public key, a caller-pinned witness trust set, or an already-resolved internal map. They are listed so
that exclusion is explicit. Their callers must resolve lifecycle state before reaching a raw-key
primitive; the public composed surfaces above own that check.

## Historical evidence boundary

Once a key is marked retired, self-dated historical artifacts signed by it are intentionally no
longer accepted by these surfaces. A verifier cannot distinguish genuine old bytes from a new
backdated forgery using a timestamp chosen and signed by the same compromised key. Restoring
historical acceptance requires an independent time witness. `packages/tsa-anchor` exists in source
but is unpublished and is not integrated by this patch.

## Evidence-count correction

Commit `adb4033` claimed that a grep count in `src/verify.ts` moved from 0 to 32. The 0 baseline is
reproducible; 32 is not. At that commit the measured alternatives were 23 matching lines, 31
case-sensitive occurrences, 26 case-insensitive matching lines, and 37 case-insensitive occurrences.
This inventory and the attack/control reproduction replace mention-counting with behavior.
