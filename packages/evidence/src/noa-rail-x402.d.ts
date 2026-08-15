/**
 * Local ambient types for the untyped `noa-rail-x402` bridge.
 *
 * `noa-rail-x402` ships as plain `.mjs` with JSDoc and no `.d.ts`, so TypeScript cannot see through
 * its `main`. This file declares ONLY the one surface this package consumes — the D7 reconciler and
 * its §6 result envelope — so that consumption is typed rather than `any`.
 *
 * ⚠ WHAT THIS DOES AND DOES NOT CATCH, corrected after a reviewer found the earlier claim false. It
 * previously said a renamed field or a new code in the shipped module "surfaces here as a compile
 * error". It does not. This declaration is HAND-WRITTEN and is never checked against the JavaScript
 * module, so implementation drift is invisible to the compiler: if the module renames a field, this
 * file keeps describing the old one and the build stays green. What it does buy is that THIS
 * package's uses are type-checked against the shape written here, and that the shape is stated in one
 * place a reader can diff against the module by hand.
 *
 * `code` is deliberately `string` and not a union of the registered codes: the reconciler owns that
 * registry (`SETTLEMENT_RESULT_CODES`), and duplicating it here would create a second authority that
 * drifts silently. The consequence is that a new or renamed code is NOT exhaustiveness-checked — the
 * `switch` over it in `steps.ts` fails CLOSED on anything it does not recognise, which is where that
 * risk is actually handled.
 *
 * The shape mirrors the JSDoc at `packages/rail-x402/src/settlement-evidence.mjs`; that module header
 * is the authority, and on any disagreement it wins.
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

  /** The §6 warning registry — the CLOSED set of tokens the reconciler may emit. The evidence
   *  verifier maps anything outside it to its own unrecognised-warning line rather than publishing
   *  it, so this export is the single authority and there is no second list to drift. */
  export const SETTLEMENT_WARNINGS: readonly string[];

  /** The D7 correlation derivation — used by the fixtures generator to mint bound settlement artifacts. */
  export function deriveCorrelationNonce(input: {
    chainId: number;
    tokenAddress: string;
    payerAddress: string;
    dispatchId: string;
    seed: Uint8Array;
  }): { nonce: string; commitment: string };
}
