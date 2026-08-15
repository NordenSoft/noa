# P0-14 retired-key verification-surface inventory

Status: Batch M correction after fifth-review BLOCK, 2026-08-01.

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

**Human-review wrapper classification rule (corrected in Batch L):** a wrapper may say it inherits a verifier's
keyring outcome only when it forwards the received keyring document unchanged. A wrapper that
constructs a keyring, selects a security-weaker shape, or drops lifecycle fields is itself an
independent verification surface and needs its own attack/control outcome. `verifyBundle` was the
missed 13th surface: it accepted `GateTrust`, rebuilt `{ [gateKid]: publicKey }`, and discarded the
retirement state before calling `verifyEvidence`.

This classification rule is **not mechanically enforced whole-program**. `lint-resolver-parity.mjs`
AST-scans production verifier calls for inline or single-alias keyring
literals, including renamed ES imports, literal computed option names, and options-object spreads.
Its same-run synthetic controls prove all four discarded-lifecycle spellings are detected and an
unchanged `trust.receiptKeyring` pass-through is not. The scan is not whole-program dataflow: factory
returns, callbacks, property mutation, dynamic imports/CommonJS destructuring, arbitrary verifier
function reassignment, and ambiguous aliases are not mechanically decidable here. For those, a
reviewer must trace the wrapper's accepted trust type to the exact bytes passed to the verifier and
compare every lifecycle/security field by hand. That human trace—not the syntactic gate—is what must
stop a differently-spelled next surface.

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
| `receiptFromCose` | root export | retired COSE receipt accepted under a narrowed historical map | same shared rule as `coseSign1Verify`, **and since 2026-08-15 applied to the ENVELOPED receipt's own `sig.kid` as well** — a live relay key re-presenting a receipt signed by a retired agent key is refused, which the outer check alone cannot see (`test/cose/cose.test.ts`, "P0-14 (enveloped)") |
| `verifyReceiptCompliance` | root export; adapter-core re-export | flat lookup had no lifecycle decision | shared lifecycle resolver; current/static carrier accepted, retired carrier refused |
| `verifyArtifact` | `noa-approval-artifacts` root export; evidence/gate call sites | retirement accepted signer-backdating; Batch L then regressed a claimed pre-activation artifact by checking only verifier time | any non-null `revokedAt` refused outright; `authorizationTime ?? now` is required for acceptance, while signer-claimed artifact time is reject-only and refuses a pre-`validFrom` contradiction; static entry accepted |
| `verifyApprovalReceipt` | adapter-core root export; MCP approval gate/policy-change call sites | flat lookup had no lifecycle decision | shared lifecycle resolver; multiple current keys accepted, retired approver refused |
| `verifyOutcomeReceipt` | MCP proxy source/public package file | cached pre-rotation snapshot or retired-key flat subset accepted | cached frozen handle stays live; retired refused; multi-key static controls accepted; flat historical API removed |
| `verifyEvidence` | `noa-approval-evidence` root export and CLI | checkpoint lifecycle was discarded; manifest receipt keyring dropped revocation; step 18 let checkpoint `ts` activate its own not-yet-active key; step 1 let signer-chosen manifest time establish expired delegated authority | raw lifecycle reaches step 17; retired checkpoint is `INVALID`; step 18 uses verifier-owned `now` for checkpoint-key activation; step 1 requires verifier-owned `now` inside the root-signed delegation and treats manifest/received times as reject-only; manifest receipt lifecycle is preserved |
| `verifyBundle` | private e2e-demo application wrapper; called by `runApprovedFlow` and `runTimeoutFlow` | wrapper `VALID_FULL_CHAIN` while direct `verifyEvidence` on the same retired lifecycle was `INVALID` | independently constructs a gate-only lifecycle subset: current gate checkpoint `VALID_FULL_CHAIN`; retired gate checkpoint `INVALID` in wrapper and direct verifier; approver checkpoint cannot exceed `VALID_SEGMENT_ONLY` |

## Re-audit of every former "inherits" row

| Surface | Re-audited keyring handling | Corrected classification | Measured outcome |
|---|---|---|---|
| `verifyChainText` | forwards the received `opts` object unchanged to `verifyChain` | pass-through alias; inherits the keyring decision | current lifecycle `VALID`; retired lifecycle `TAMPERED` |
| `verifyChainWitnessed` | creates `verifyOpts`, but assigns the received keyring bytes unchanged | pass-through for chain lifecycle; witness trust-set remains a separate schema | current lifecycle chain `VALID`; retired lifecycle chain `TAMPERED` |
| root `noa verify` CLI | reads keyring text and forwards those bytes through `opts.keyring` or the witnessed positional argument | pass-through CLI composition | current exit `0`; retired exit `2` |
| root `noa --serve` IPC | copies the parsed TLV keyring bytes unchanged into `opts.keyring` | pass-through IPC composition | current `VALID`; retired `TAMPERED` |
| evidence CLI | reads keyring file bytes and forwards them unchanged as `checkpointKeyring` | pass-through CLI composition | current exit `0`; retired exit `2` |
| e2e `verifyBundle` | **pre-fix:** manufactured a flat gate map and lost retirement; **post-fix:** constructs a gate-only lifecycle subset by copying the gate entry intact | independent 13th surface, not inherited; exact AST site, classification, reason, and attack/control proof are machine-pinned | current gate `VALID_FULL_CHAIN`; retired gate `INVALID`; direct `verifyEvidence` also `INVALID`; approver checkpoint only `VALID_SEGMENT_ONLY` |
| gate/evidence internal call sites | pass resolved keyring variables unchanged at verifier call sites; resolver construction is inventoried separately below | compositions, not additional keyring constructors at the call boundary | lifecycle outcomes are owned by the named primitives and resolver proofs |

The former table had seven aggregate rows: five pass-through compositions, one independent narrowing
surface (`verifyBundle`), and one aggregate row for internal call sites. This is a row-by-row source
classification, not a string count. The scanner separately reports seven inline flat-map call sites
in four `examples/` files; those are example calls, not seven reclassified wrappers. Each example map is
built from a locally generated, non-rotating key and no lifecycle-bearing input exists to narrow.
They remain inside the documented static compatibility boundary; they are not classified as
inherited wrappers. Each exception is machine-pinned to the exact file, lexical scope, verifier,
field, forwarding expression, construction expression, and a non-empty reason. The independent
surface additionally requires a resolving proof marker. A new call in the same file or a changed
expression is therefore red; a stale classification is red too.

## Reviewed pass-through wrappers previously omitted from the table

These rows record the wrappers fifth review found absent. “Source trace” is deliberately not called
a behavior measurement: it proves the value is forwarded without a lifecycle-to-flat conversion,
while the named primitive's attack/control owns the retired-key verdict. No wrapper-specific retired
attack was executed for the adapter/proxy rows in this batch.

| Surface | Route and exact keyring handling | Own observed outcome |
|---|---|---|
| public `applyPolicyChange` | `policy-change-guard.mjs` receives `approverKeyring` and passes that same value to `verifyApprovalReceipt` | source trace found no construction or field selection; the primitive's lifecycle-retired control refuses |
| published `createProxyServer` | `create-proxy-server.mjs` closes over the received `approverKeyring` and passes it unchanged to `verifyApprovalReceipt` on ticket consumption | source trace found no lifecycle loss; wrapper-specific retired execution path not run |
| `startHttpProxy` | `http-server.mjs` retains `approverKeyring` inside `proxyConfig` and spreads the unchanged value into each `createProxyServer` session | source trace found no narrowing; verdict remains owned by `createProxyServer` → `verifyApprovalReceipt` |
| proxy CLI configuration | `proxy.mjs` parses the entire keyring JSON document once, stores it as `gateConfig.approverKeyring`, and forwards the same value to stdio or HTTP composition | source trace found no lifecycle-to-flat conversion; no claim that the CLI proves lifecycle currency by itself |
| e2e `runApprovedFlow` | `harness.ts` passes `ctx.trust` unchanged to `verifyBundle` | source trace found no extra transformation; current managed run stopped at `listen EPERM` before a flow verdict, while the direct `verifyBundle` attack/control passed |
| e2e `runTimeoutFlow` | `harness.ts` passes `ctx.trust` unchanged to `verifyBundle` | source trace found no extra transformation; current managed run stopped at `listen EPERM` before a flow verdict, so no wrapper-specific behavior claim is made |
| e2e demo/test callers | `demo.ts` and `e2e.test.ts` call the two harness flows without constructing a keyring | no additional lifecycle transformation found; they are callers, not independent signature decisions |

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

## Claim and count corrections

The Batch L commit statement “7 rows are now classified as narrowing, 3 remain genuine
pass-throughs” is withdrawn. Direct inspection of the former seven-row table yields the five / one /
one classification stated above. The seven entries in `staticConstructedKeyrings` are syntactic
example call sites. Their list length is not a measurement of wrapper behavior.

Commit `adb4033` claimed that a grep count in `src/verify.ts` moved from 0 to 32. The 0 baseline is
reproducible; 32 is not. At that commit the measured alternatives were 23 matching lines, 31
case-sensitive occurrences, 26 case-insensitive matching lines, and 37 case-insensitive occurrences.
This inventory and the attack/control reproduction replace mention-counting with behavior.
