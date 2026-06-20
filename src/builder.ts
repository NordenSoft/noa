import type { Receipt, ReceiptScope, ReceiptAgent, ReceiptAction, ReceiptGovernance, Checkpoint } from "./types.js";
import { RECEIPT_SPEC } from "./types.js";
import { receiptHashInput, checkpointHashInput } from "./canonicalize.js";
import { sha256Hex } from "./hash.js";
import { signEd25519 } from "./keys.js";
import { signingMessage, RECEIPT_SIG_DOMAIN, CHECKPOINT_SIG_DOMAIN } from "./signing.js";

export interface Signer {
  kid: string;
  /** base64 PKCS8 DER Ed25519 private key */
  privateKey: string;
}

export interface BuildInput {
  id: string;
  ts: string;
  scope: ReceiptScope;
  agent: ReceiptAgent;
  action: ReceiptAction;
  governance: ReceiptGovernance;
}

/**
 * Build the next receipt in a chain: compute seq/prevHash from `prev`, canonicalize, hash,
 * and sign. The hash covers sig.alg + sig.kid (key-swap protection); the signature is over
 * the 32-byte digest whose hex is chain.hash.
 */
export function buildReceipt(input: BuildInput, prev: Receipt | null, signer: Signer): Receipt {
  const seq = prev ? prev.chain.seq + 1 : 0;
  const prevHash = prev ? prev.chain.hash : null;

  const draft: Receipt = {
    spec: RECEIPT_SPEC,
    id: input.id,
    ts: input.ts,
    scope: input.scope,
    agent: input.agent,
    action: input.action,
    governance: input.governance,
    chain: { seq, prevHash, hash: "" },
    sig: { alg: "ed25519", kid: signer.kid, value: "" },
  };

  const hashInput = receiptHashInput(draft);
  draft.chain.hash = "sha256:" + sha256Hex(hashInput);
  draft.sig.value = signEd25519(signer.privateKey, signingMessage(RECEIPT_SIG_DOMAIN, hashInput));
  return draft;
}

/** Build a signed checkpoint asserting the current head of a chain (tail-truncation defense). */
export function buildCheckpoint(head: Receipt, ts: string, signer: Signer): Checkpoint {
  const draft: Checkpoint = {
    spec: "noa.checkpoint/0.1",
    chain: head.scope.chain,
    highestSeq: head.chain.seq,
    headHash: head.chain.hash,
    ts,
    sig: { alg: "ed25519", kid: signer.kid, value: "" },
  };
  const hashInput = checkpointHashInput(draft);
  draft.sig.value = signEd25519(signer.privateKey, signingMessage(CHECKPOINT_SIG_DOMAIN, hashInput));
  return draft;
}
