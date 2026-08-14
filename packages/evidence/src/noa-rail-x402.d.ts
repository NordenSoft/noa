/**
 * Local ambient types for the untyped `noa-rail-x402` bridge.
 *
 * `noa-rail-x402` ships as plain `.mjs` with JSDoc and no `.d.ts`, so TypeScript cannot see through
 * its `main`. This file declares ONLY the one surface this package consumes — the D7 reconciler and
 * its §6 result envelope — so a signature drift in the shipped module (a renamed field, a new code)
 * surfaces here as a compile error rather than as an `any`. The shape mirrors the JSDoc at
 * `packages/rail-x402/src/settlement-evidence.mjs`; the module header there is the authority.
 */
declare module "noa-rail-x402" {
  /** The bytes-or-string documents + verifier policy the reconciler consumes (S4 layers 4+6). */
  export interface SettlementReconcileInput {
    artifact: Uint8Array | string;
    receiptChain: Uint8Array | string;
    grant: Uint8Array | string;
    keyring: Uint8Array | string;
    holdEnvelope: Uint8Array | string;
    holdResolution?: Uint8Array | string | null;
    chainFacts?: Uint8Array | string | null;
    chainFactsOrigin?: string;
    paramsPreimage?: Uint8Array | string | null;
    expect: { tenant: string; chain: string };
    minConfirmations?: number;
    now?: string;
    freshnessWindowMs?: number;
    expectedAmountMinorUnits?: string;
  }

  /** The §6 result envelope. Every field is always present; the reconciler never throws (R-1). */
  export interface SettlementReconcileResult {
    purpose: string;
    artifactStatus: string;
    linkageStatus: string;
    correlationStatus: string;
    boundsStatus: string;
    chainStatus: string;
    railReceiptStatus: string;
    witnessTrustStatus: string;
    purposeStatus: string;
    observerRelationship: string;
    observerRelationshipSource: string;
    trustPolicyHash: string;
    registrySnapshotHash: string;
    reconciled: Record<string, unknown> | null;
    /** The single machine-readable outcome code (a member of `SETTLEMENT_RESULT_CODES`). */
    code: string;
    reason: string | null;
    warnings: string[];
  }

  export function reconcileSettlementEvidence(input: SettlementReconcileInput): SettlementReconcileResult;
  export const SETTLEMENT_EVIDENCE_SPEC: string;
  export const CHAIN_FACTS_ORIGIN_RELYING_PARTY: string;

  /** The D7 correlation derivation — used by the fixtures generator to mint bound settlement artifacts. */
  export function deriveCorrelationNonce(input: {
    chainId: number;
    tokenAddress: string;
    payerAddress: string;
    dispatchId: string;
    seed: Uint8Array;
  }): { nonce: string; commitment: string };
}
