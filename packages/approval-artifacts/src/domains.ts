/**
 * The side-artifact registry (§6 of the Mobile Approval App build spec, v6.2).
 *
 * One row per artifact `spec`: its Ed25519 signing DOMAIN tag (or `null` for the two HPKE-AEAD
 * blobs, which are NOT signed — their integrity comes from the AEAD tag + AAD binding + the hash a
 * signed parent commits to), the schema `$id` filename, and the signer TYPE+ROLE the F15
 * role-enforcement matrix requires. The domain tags are the load-bearing anti-cross-protocol-replay
 * constants; each is distinct from every other and from the receipt/checkpoint tags upstream.
 */

export type SignerType = "GATE" | "APPROVER" | "AUDIT" | "ROOT";
export type ManifestRole =
  | "hold-signer"
  | "execution-signer"
  | "approve-high"
  | "approve-critical"
  | "audit-decrypt"
  | "key-manifest-sign";

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

export const ARTIFACTS: Record<string, ArtifactMeta> = {
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
};

/** The eight signed artifact `spec`s whose domain tags MUST all be distinct (anti-replay). */
export const SIGNED_SPECS = Object.values(ARTIFACTS)
  .filter((m) => m.domain !== null)
  .map((m) => m.spec);
