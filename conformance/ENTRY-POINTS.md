# Entry-point registry — GENERATED, DO NOT EDIT

Regenerate with `npm run gen:entry-points`. CI diffs this file; an edit by hand is a merge conflict
waiting to happen and, worse, a list that can drift from the code it claims to describe.

Source: `src/index.ts` value exports, resolved through the TypeScript compiler API.

- total value exports: **68**
- security-sensitive: **24**
- security-sensitive already bytes-in: **3**
- security-sensitive NOT yet bytes-in (ADR §3.1 target): **21**

| Export | Kind | First parameter | Bytes-in | Declared in | Exemption reason |
|---|---|---|---|---|---|
| `ANCHOR_SIG_DOMAIN` | CONSTANT | `—` | n/a | `src/federation/acceptance.ts` |  |
| `AnchorError` | ERROR_CLASS | `—` | n/a | `src/federation/anchor.ts` |  |
| `anchorForChainHead` | PRODUCER | `readonly Receipt[]` | n/a | `src/federation/anchor.ts` | the signer's own data (ADR §3.3) |
| `anchorSigningInput` | UTILITY | `Pick<Anchor, "chain" \| "highestSeq" \| "headHash" \| "ts">` | n/a | `src/federation/acceptance.ts` | pure pre-image construction |
| `assertValidPolicy` | SECURITY_SENSITIVE | `unknown` | NO | `src/policy/validate.ts` |  |
| `buildAnchor` | PRODUCER | `AnchorFrontier` | n/a | `src/federation/anchor.ts` | the signer's own data (ADR §3.3) |
| `buildCheckpoint` | PRODUCER | `Receipt` | n/a | `src/builder.ts` | the signer's own data (ADR §3.3) |
| `BuilderError` | ERROR_CLASS | `—` | n/a | `src/builder.ts` |  |
| `buildReceipt` | PRODUCER | `BuildInput` | n/a | `src/builder.ts` | the signer's own data (ADR §3.3) |
| `buildReceiptAsync` | PRODUCER | `BuildInput` | n/a | `src/builder.ts` | the signer's own data (ADR §3.3) |
| `canonicalize` | UTILITY | `unknown` | n/a | `src/jcs.ts` | pure JCS canonicalization; no verdict |
| `CborError` | ERROR_CLASS | `—` | n/a | `src/cose/cbor.ts` |  |
| `checkpointHashInput` | UTILITY | `Checkpoint` | n/a | `src/canonicalize.ts` | pure pre-image construction |
| `complianceCommit` | PRODUCER | `Policy` | n/a | `src/policy/compliance.ts` | commits the caller's own inputs into a receipt it is building |
| `coseSign1` | PRODUCER | `Buffer<ArrayBufferLike>` | n/a | `src/cose/cose-sign1.ts` | signs the caller's own payload |
| `coseSign1Verify` | SECURITY_SENSITIVE | `Buffer<ArrayBufferLike>` | NO | `src/cose/cose-sign1.ts` |  |
| `decode` | SECURITY_SENSITIVE | `Buffer<ArrayBufferLike>` | NO | `src/cose/cbor.ts` |  |
| `deepFreeze` | UTILITY | `T` | n/a | `src/ingest.ts` | pure structural helper |
| `encArray` | UTILITY | `Buffer<ArrayBufferLike>[]` | n/a | `src/cose/cbor.ts` | CBOR encoder primitive |
| `encBstr` | UTILITY | `Buffer<ArrayBufferLike>` | n/a | `src/cose/cbor.ts` | CBOR encoder primitive |
| `encInt` | UTILITY | `number` | n/a | `src/cose/cbor.ts` | CBOR encoder primitive |
| `encMap` | UTILITY | `[Buffer<ArrayBufferLike>, Buffer<ArrayBufferLike>][]` | n/a | `src/cose/cbor.ts` | CBOR encoder primitive |
| `encTag` | UTILITY | `number` | n/a | `src/cose/cbor.ts` | CBOR encoder primitive |
| `encTstr` | UTILITY | `string` | n/a | `src/cose/cbor.ts` | CBOR encoder primitive |
| `evaluate` | SECURITY_SENSITIVE | `Policy` | NO | `src/policy/eval.ts` |  |
| `frozenSet` | SECURITY_SENSITIVE | `readonly T[]` | NO | `src/inert.ts` |  |
| `frozenTable` | SECURITY_SENSITIVE | `T` | NO | `src/inert.ts` |  |
| `generateKeyPair` | PRODUCER | `string` | n/a | `src/keys.ts` | generates the caller's own key |
| `INERT_ARRAY_PROTOTYPE` | CONSTANT | `—` | n/a | `src/inert.ts` |  |
| `inertViolations` | SECURITY_SENSITIVE | `unknown` | NO | `src/inert.ts` |  |
| `IngestError` | ERROR_CLASS | `—` | n/a | `src/ingest.ts` |  |
| `intrinsics` | SECURITY_SENSITIVE | `—` | n/a | `src/intrinsics.ts` |  |
| `isFrozenSet` | SECURITY_SENSITIVE | `unknown` | NO | `src/inert.ts` |  |
| `isInertArray` | SECURITY_SENSITIVE | `unknown` | NO | `src/inert.ts` |  |
| `isIngestError` | SECURITY_SENSITIVE | `unknown` | NO | `src/ingest.ts` |  |
| `isNFC` | UTILITY | `string` | n/a | `src/nfc.ts` | pure predicate over a string |
| `JcsError` | ERROR_CLASS | `—` | n/a | `src/jcs.ts` |  |
| `makeInertArray` | SECURITY_SENSITIVE | `T[]` | NO | `src/inert.ts` |  |
| `MAX_INGEST_DEPTH` | CONSTANT | `—` | n/a | `src/ingest.ts` |  |
| `MutablePolicyTableError` | ERROR_CLASS | `—` | n/a | `src/inert.ts` |  |
| `nonNfcPaths` | UTILITY | `unknown` | n/a | `src/nfc.ts` | pure predicate |
| `POLICY_SPEC` | CONSTANT | `—` | n/a | `src/policy/dsl.ts` |  |
| `PolicyError` | ERROR_CLASS | `—` | n/a | `src/policy/eval.ts` |  |
| `policyHash` | UTILITY | `Policy` | n/a | `src/policy/dsl.ts` | pure hash of a policy |
| `readSet` | UTILITY | `Policy` | n/a | `src/policy/dsl.ts` | pure projection |
| `readSetHash` | UTILITY | `Policy` | n/a | `src/policy/dsl.ts` | pure hash |
| `RECEIPT_SPEC` | CONSTANT | `—` | n/a | `src/types.ts` |  |
| `receiptFromCose` | SECURITY_SENSITIVE | `Buffer<ArrayBufferLike>` | NO | `src/cose/receipt-cose.ts` |  |
| `receiptHashInput` | UTILITY | `Receipt` | n/a | `src/canonicalize.ts` | pure pre-image construction |
| `receiptToCose` | PRODUCER | `Receipt` | n/a | `src/cose/receipt-cose.ts` | serializes the caller's own receipt |
| `REF_EVAL_VERSION` | CONSTANT | `—` | n/a | `src/policy/eval.ts` |  |
| `SafeJsonError` | ERROR_CLASS | `—` | n/a | `src/safe-json.ts` |  |
| `safeParse` | UTILITY | `string` | n/a | `src/safe-json.ts` | IS the strict parse boundary (src/safe-json.ts); already bytes/text-in |
| `sha256Digest` | UTILITY | `string \| Buffer<ArrayBufferLike>` | n/a | `src/hash.ts` | pure hash |
| `sha256Hex` | UTILITY | `string \| Buffer<ArrayBufferLike>` | n/a | `src/hash.ts` | pure hash |
| `sha256Prefixed` | UTILITY | `string \| Buffer<ArrayBufferLike>` | n/a | `src/hash.ts` | pure hash |
| `signEd25519` | PRODUCER | `string` | n/a | `src/keys.ts` | signs with the caller's own key |
| `snapshotImmutable` | SECURITY_SENSITIVE | `unknown` | NO | `src/ingest.ts` |  |
| `tryIngest` | SECURITY_SENSITIVE | `unknown` | NO | `src/ingest.ts` |  |
| `validatePolicy` | SECURITY_SENSITIVE | `unknown` | NO | `src/policy/validate.ts` |  |
| `validateReceiptShape` | SECURITY_SENSITIVE | `unknown` | NO | `src/schema.ts` |  |
| `verifyChain` | SECURITY_SENSITIVE | `unknown` | NO | `src/verify.ts` |  |
| `verifyChainText` | SECURITY_SENSITIVE | `string` | YES | `src/verify.ts` |  |
| `verifyChainWitnessed` | SECURITY_SENSITIVE | `string \| readonly unknown[]` | NO | `src/federation/verify-witnessed.ts` |  |
| `verifyCheckpoint` | SECURITY_SENSITIVE | `Checkpoint` | NO | `src/verify.ts` |  |
| `verifyCompleteness` | SECURITY_SENSITIVE | `ChainHead` | NO | `src/federation/acceptance.ts` |  |
| `verifyEd25519` | SECURITY_SENSITIVE | `string` | YES | `src/keys.ts` |  |
| `verifyReceiptCompliance` | SECURITY_SENSITIVE | `Receipt` | NO | `src/policy/compliance.ts` |  |

