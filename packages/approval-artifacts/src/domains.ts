/**
 * The side-artifact registry (§6 of the Mobile Approval App build spec, v6.2).
 *
 * One row per artifact `spec`: its Ed25519 signing DOMAIN tag (or `null` for the two HPKE-AEAD
 * blobs, which are NOT signed — their integrity comes from the AEAD tag + AAD binding + the hash a
 * signed parent commits to), the schema `$id` filename, and the signer TYPE+ROLE the F15
 * role-enforcement matrix requires. The domain tags are the load-bearing anti-cross-protocol-replay
 * constants; each is distinct from every other and from the receipt/checkpoint tags upstream.
 */

import { frozenTable } from "./inert-core/inert.js";

export type SignerType = "GATE" | "APPROVER" | "AUDIT" | "ROOT";
export type ManifestRole =
  | "hold-signer"
  | "execution-signer"
  | "settlement-observer"
  | "approve-high"
  | "approve-critical"
  | "audit-decrypt"
  | "key-manifest-sign"
  // S5 §3.3 — enrolment authority, granted by the ROOT through `noa.key-delegation/0.1.permissions`
  // and never by the manifest. It is a separate permission from `key-manifest-sign` so a root can
  // revoke the authority to say WHICH ACTION CLASSES REQUIRE SETTLEMENT EVIDENCE without rotating
  // the manifest signer. Stated honestly, because the spec's first draft overstated it: putting both
  // permissions on ONE delegation gives ONE kid and ONE private key both authorities, so this buys
  // VISIBILITY and INDEPENDENT REVOCATION, not custody separation. Custody separation needs a second
  // delegation slot, which the container does not have.
  | "action-class-enrol";

export interface ArtifactMeta {
  spec: string;
  /** Ed25519 signing domain tag (§6), or null for the unsigned HPKE-AEAD blobs. */
  domain: string | null;
  /** schema/<file>.schema.json */
  schemaId: string;
  /** F15: required signer TYPE (null for pairing, which is verified by transcript/kid match, not the manifest). */
  signerType: SignerType | null;
  /** F15: the manifest role the signer key must hold (null where role is not manifest-gated). */
  signerRole: ManifestRole | null;
}

// INERT AT LOAD (review #6, C3 — found by the policy-table walker, not by a reviewer). This is the §6
// authority table: which specs exist, which domain tag each is signed under, and which signer TYPE and
// ROLE each requires. It was a plain mutable object, so
// `ARTIFACTS["noa.decision/0.1"].signerRole = "anything"` rewrote, at runtime, who may sign an
// approval — the same class as review #5's mutable Set and review #6's mutable outcome tables, in a
// third file. `frozenTable` deep-freezes it and refuses anything mutable at construction.
export const ARTIFACTS: Record<string, ArtifactMeta> = frozenTable({
  "noa.hold/0.1": {
    spec: "noa.hold/0.1",
    domain: "NOA-Hold-v0.1-sig",
    schemaId: "noa-hold-0.1.schema.json",
    signerType: "GATE",
    signerRole: "hold-signer",
  },
  "noa.decision/0.1": {
    spec: "noa.decision/0.1",
    domain: "NOA-Decision-v0.1-sig",
    schemaId: "noa-decision-0.1.schema.json",
    signerType: "APPROVER",
    // approve-high | approve-critical is risk-tier dependent (F15) — resolved in verify.ts, not here.
    signerRole: null,
  },
  "noa.key-manifest/0.1": {
    spec: "noa.key-manifest/0.1",
    domain: "NOA-KeyManifest-v0.1-sig",
    schemaId: "noa-key-manifest-0.1.schema.json",
    // The manifest signer is the ROOT-DELEGATED manifest-signing key (D16-v2) — verified against the
    // delegation, not against the manifest's own key list, so signerType/role here are advisory.
    signerType: null,
    signerRole: "key-manifest-sign",
  },
  "noa.key-delegation/0.1": {
    spec: "noa.key-delegation/0.1",
    domain: "NOA-KeyDelegation-v0.1-sig",
    schemaId: "noa-key-delegation-0.1.schema.json",
    signerType: "ROOT",
    signerRole: null,
  },
  "noa.execution-grant/0.1": {
    spec: "noa.execution-grant/0.1",
    domain: "NOA-ExecGrant-v0.1-sig",
    schemaId: "noa-execution-grant-0.1.schema.json",
    signerType: "GATE",
    signerRole: "execution-signer",
  },
  "noa.execution-consumption/0.1": {
    spec: "noa.execution-consumption/0.1",
    domain: "NOA-ExecConsume-v0.1-sig",
    schemaId: "noa-execution-consumption-0.1.schema.json",
    signerType: "GATE",
    signerRole: "execution-signer",
  },
  "noa.execution-uncertainty/0.1": {
    spec: "noa.execution-uncertainty/0.1",
    domain: "NOA-ExecUncertainty-v0.1-sig",
    schemaId: "noa-execution-uncertainty-0.1.schema.json",
    signerType: "GATE",
    signerRole: "execution-signer",
  },
  "noa.hold-resolution/0.1": {
    spec: "noa.hold-resolution/0.1",
    domain: "NOA-HoldResolution-v0.1-sig",
    schemaId: "noa-hold-resolution-0.1.schema.json",
    signerType: "GATE",
    signerRole: "execution-signer",
  },
  "noa.pairing/0.1": {
    spec: "noa.pairing/0.1",
    domain: "NOA-Pairing-v0.1-sig",
    schemaId: "noa-pairing-0.1.schema.json",
    // Pairing is verified by out-of-band SAS / transcript-anchored kid match (§3), not the manifest.
    signerType: null,
    signerRole: null,
  },
  "noa.pairing-confirmation/0.1": {
    spec: "noa.pairing-confirmation/0.1",
    domain: "NOA-PairingConfirm-v0.1-sig",
    schemaId: "noa-pairing-confirmation-0.1.schema.json",
    signerType: "GATE",
    signerRole: null,
  },
  "noa.encrypted-display/0.1": {
    spec: "noa.encrypted-display/0.1",
    domain: null, // HPKE AEAD — NOT Ed25519-signed (§6/§9)
    schemaId: "noa-encrypted-display-0.1.schema.json",
    signerType: null,
    signerRole: null,
  },
  "noa.encrypted-reason/0.1": {
    spec: "noa.encrypted-reason/0.1",
    domain: null, // HPKE AEAD — NOT Ed25519-signed (§6/§12)
    schemaId: "noa-encrypted-reason-0.1.schema.json",
    signerType: null,
    signerRole: null,
  },
  "noa.settlement-evidence/0.1": {
    spec: "noa.settlement-evidence/0.1",
    domain: "NOA-SettlementEvidence-v0.1-sig",
    schemaId: "noa-settlement-evidence-0.1.schema.json",
    signerType: "GATE",
    signerRole: "settlement-observer",
  },
  "noa.action-class-enrolment/0.1": {
    spec: "noa.action-class-enrolment/0.1",
    domain: "NOA-ActionClassEnrolment-v0.1-sig",
    schemaId: "noa-action-class-enrolment-0.1.schema.json",
    // `signerType: null` like `noa.key-manifest/0.1`, and for the same reason: the signer is the
    // ROOT-DELEGATED kid, whose authority comes from the delegation the external tenant root signed —
    // not from the manifest's own typed key list. With the type check skipped, the POSITIVE role
    // check below is the whole control, which is why the permission is its own enum member.
    signerType: null,
    signerRole: "action-class-enrol",
  },
});

/** The signed artifact `spec`s whose domain tags MUST all be distinct (anti-replay). */
export const SIGNED_SPECS: readonly string[] = frozenTable(
  Object.values(ARTIFACTS)
    .filter((m) => m.domain !== null)
    .map((m) => m.spec),
);
