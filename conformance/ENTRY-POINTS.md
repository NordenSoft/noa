# Entry-point registry — GENERATED, DO NOT EDIT

Regenerate with `npm run gen:entry-points`. CI diffs this file; an edit by hand is a merge conflict
waiting to happen and, worse, a list that can drift from the code it claims to describe.

Source: `src/index.ts` value exports, resolved through the TypeScript compiler API.

- total value exports: **69**
- security-sensitive: **17**
- security-sensitive already bytes-in: **17**
- security-sensitive NOT yet bytes-in (ADR §3.1 target): **0**

| Export | Kind | First parameter | Bytes-in | Declared in | Exemption reason |
|---|---|---|---|---|---|
| `ANCHOR_SIG_DOMAIN` | CONSTANT | `—` | n/a | `src/federation/acceptance.ts` |  |
| `AnchorError` | ERROR_CLASS | `—` | n/a | `src/federation/anchor.ts` |  |
| `anchorForChainHead` | PRODUCER | `readonly Receipt[]` | n/a | `src/federation/anchor.ts` | the signer's own data (ADR §3.3) |
| `anchorSigningInput` | UTILITY | `Pick<Anchor, "chain" \| "highestSeq" \| "headHash" \| "ts">` | n/a | `src/federation/acceptance.ts` | pure pre-image construction |
| `assertValidPolicy` | SECURITY_SENSITIVE | `string \| Uint8Array<ArrayBufferLike>` | YES | `src/policy/validate.ts` |  |
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
| `coseSign1Verify` | SECURITY_SENSITIVE | `Uint8Array<ArrayBufferLike>` | YES | `src/cose/cose-sign1.ts` |  |
| `decode` | SECURITY_SENSITIVE | `Uint8Array<ArrayBufferLike>` | YES | `src/cose/cbor.ts` |  |
| `decodeDocument` | UTILITY | `unknown` | n/a | `src/bytes.ts` | IS the byte boundary (src/bytes.ts); decides whether a value is a document at all |
| `deepFreeze` | UTILITY | `T` | n/a | `src/inert.ts` | pure structural helper |
| `encArray` | UTILITY | `Buffer<ArrayBufferLike>[]` | n/a | `src/cose/cbor.ts` | CBOR encoder primitive |
| `encBstr` | UTILITY | `Buffer<ArrayBufferLike>` | n/a | `src/cose/cbor.ts` | CBOR encoder primitive |
| `encInt` | UTILITY | `number` | n/a | `src/cose/cbor.ts` | CBOR encoder primitive |
| `encMap` | UTILITY | `[Buffer<ArrayBufferLike>, Buffer<ArrayBufferLike>][]` | n/a | `src/cose/cbor.ts` | CBOR encoder primitive |
| `encTag` | UTILITY | `number` | n/a | `src/cose/cbor.ts` | CBOR encoder primitive |
| `encTstr` | UTILITY | `string` | n/a | `src/cose/cbor.ts` | CBOR encoder primitive |
| `evaluate` | SECURITY_SENSITIVE | `string \| Uint8Array<ArrayBufferLike>` | YES | `src/policy/eval.ts` |  |
| `frozenSet` | INERT_CONSTRUCTOR | `readonly T[]` | n/a | `src/inert.ts` | builds THIS package's literal membership table (ADR §5.6); its subject is prototype+mutability, which bytes cannot express |
| `frozenTable` | INERT_CONSTRUCTOR | `T` | n/a | `src/inert.ts` | builds THIS package's literal policy table (ADR §5.6); serializing it would produce a different table, not a safer one |
| `generateKeyPair` | PRODUCER | `string` | n/a | `src/keys.ts` | generates the caller's own key |
| `INERT_ARRAY_PROTOTYPE` | CONSTANT | `—` | n/a | `src/intrinsics.ts` |  |
| `inertViolations` | INERT_CONSTRUCTOR | `unknown` | n/a | `src/inert.ts` | the audit walker BEHIND the policy-table control (test/security/policy-tables-inert.test.ts); reports findings, decides nothing |
| `intrinsics` | SECURITY_SENSITIVE | `—` | n/a | `src/intrinsics.ts` |  |
| `isFrozenSet` | INERT_CONSTRUCTOR | `unknown` | n/a | `src/inert.ts` | pure brand predicate; carries no verdict |
| `isInertArray` | INERT_CONSTRUCTOR | `unknown` | n/a | `src/inert.ts` | pure structural predicate over a prototype identity; carries no verdict |
| `isNFC` | UTILITY | `string` | n/a | `src/nfc.ts` | pure predicate over a string |
| `isUint8Array` | UTILITY | `unknown` | n/a | `src/bytes.ts` | pure predicate over an internal slot |
| `JcsError` | ERROR_CLASS | `—` | n/a | `src/jcs.ts` |  |
| `makeInertArray` | INERT_CONSTRUCTOR | `T[]` | n/a | `src/inert.ts` | re-roots a module-owned array onto the inert prototype (ADR §5.6) |
| `MAX_INPUT_BYTES` | CONSTANT | `—` | n/a | `src/bytes.ts` |  |
| `MutablePolicyTableError` | ERROR_CLASS | `—` | n/a | `src/inert.ts` |  |
| `nonNfcPaths` | UTILITY | `unknown` | n/a | `src/nfc.ts` | pure predicate |
| `parseDocument` | UTILITY | `unknown` | n/a | `src/bytes.ts` | IS the byte boundary (src/bytes.ts); decode-then-strict-parse, the route every document takes |
| `POLICY_SPEC` | CONSTANT | `—` | n/a | `src/policy/dsl.ts` |  |
| `PolicyError` | ERROR_CLASS | `—` | n/a | `src/policy/eval.ts` |  |
| `policyHash` | UTILITY | `Policy` | n/a | `src/policy/dsl.ts` | pure hash of a policy |
| `readSet` | UTILITY | `Policy` | n/a | `src/policy/dsl.ts` | pure projection |
| `readSetHash` | UTILITY | `Policy` | n/a | `src/policy/dsl.ts` | pure hash |
| `RECEIPT_SPEC` | CONSTANT | `—` | n/a | `src/types.ts` |  |
| `receiptFromCose` | SECURITY_SENSITIVE | `Uint8Array<ArrayBufferLike>` | YES | `src/cose/receipt-cose.ts` |  |
| `receiptHashInput` | UTILITY | `Receipt` | n/a | `src/canonicalize.ts` | pure pre-image construction |
| `receiptToCose` | PRODUCER | `Receipt` | n/a | `src/cose/receipt-cose.ts` | serializes the caller's own receipt |
| `REF_EVAL_VERSION` | CONSTANT | `—` | n/a | `src/policy/eval.ts` |  |
| `resolveVerificationKey` | SECURITY_SENSITIVE | `string \| Uint8Array<ArrayBufferLike>` | YES | `src/verification-keyring.ts` |  |
| `SafeJsonError` | ERROR_CLASS | `—` | n/a | `src/safe-json.ts` |  |
| `safeParse` | UTILITY | `string` | n/a | `src/safe-json.ts` | IS the strict parse boundary (src/safe-json.ts); already bytes/text-in |
| `sha256Digest` | UTILITY | `string \| Buffer<ArrayBufferLike>` | n/a | `src/hash.ts` | pure hash |
| `sha256Hex` | UTILITY | `string \| Buffer<ArrayBufferLike>` | n/a | `src/hash.ts` | pure hash |
| `sha256Prefixed` | UTILITY | `string \| Buffer<ArrayBufferLike>` | n/a | `src/hash.ts` | pure hash |
| `signEd25519` | PRODUCER | `string` | n/a | `src/keys.ts` | signs with the caller's own key |
| `SIGNING_KEY_LIFECYCLE_SPEC` | SECURITY_SENSITIVE | `—` | n/a | `src/verification-keyring.ts` |  |
| `validatePolicy` | SECURITY_SENSITIVE | `string \| Uint8Array<ArrayBufferLike>` | YES | `src/policy/validate.ts` |  |
| `validateReceiptShape` | SECURITY_SENSITIVE | `string \| Uint8Array<ArrayBufferLike>` | YES | `src/schema.ts` |  |
| `verifyChain` | SECURITY_SENSITIVE | `string \| Uint8Array<ArrayBufferLike>` | YES | `src/verify.ts` |  |
| `verifyChainText` | SECURITY_SENSITIVE | `string` | YES | `src/verify.ts` |  |
| `verifyChainWitnessed` | SECURITY_SENSITIVE | `string \| Uint8Array<ArrayBufferLike>` | YES | `src/federation/verify-witnessed.ts` |  |
| `verifyCheckpoint` | SECURITY_SENSITIVE | `string \| Uint8Array<ArrayBufferLike>` | YES | `src/verify.ts` |  |
| `verifyCompleteness` | SECURITY_SENSITIVE | `string \| Uint8Array<ArrayBufferLike>` | YES | `src/federation/acceptance.ts` |  |
| `verifyEd25519` | SECURITY_SENSITIVE | `string` | YES | `src/keys.ts` |  |
| `verifyReceiptCompliance` | SECURITY_SENSITIVE | `string \| Uint8Array<ArrayBufferLike>` | YES | `src/policy/compliance.ts` |  |

