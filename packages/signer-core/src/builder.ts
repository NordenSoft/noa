import { sha256Hex } from "./hash.js";
import { receiptHashInput } from "./receipt-hash.js";
import { signReceipt, type SignerKey } from "./sign.js";
import { RECEIPT_SPEC } from "./types.js";
import type { Receipt, ReceiptAction, ReceiptAgent, ReceiptGovernance, ReceiptScope } from "./types.js";
import { nonNfcPaths } from "./nfc.js";

/** Same shape as `noa-receipt`'s `BuildInput` (`src/builder.ts`). */
export interface BuildInput {
  id: string;
  ts: string;
  scope: ReceiptScope;
  agent: ReceiptAgent;
  action: ReceiptAction;
  governance: ReceiptGovernance;
}

/**
 * Build the next receipt draft in a chain: compute seq/prevHash from `prev`, canonicalize, and
 * hash — everything `noa-receipt`'s `buildReceipt` does EXCEPT the actual signature, mirroring
 * its internal `buildDraft` helper (`src/builder.ts`). The caller-supplied fields are
 * `structuredClone`d before use, so mutating `input`/`prev` after this call cannot retroactively
 * corrupt the returned draft.
 *
 * NOTE (scope, see README.md): unlike upstream's `buildDraft`, this function does not re-run a
 * ported `validateReceiptShape` — this package intentionally stays a minimal signing core. A
 * caller building production receipts should still validate/verify the result against
 * `noa-receipt`'s own `validateReceiptShape`/`verifyChain` before trusting it.
 */
export function buildReceiptDraft(input: BuildInput, prev: Receipt | null, kid: string): Receipt {
  const cloned = structuredClone({
    id: input.id,
    ts: input.ts,
    scope: input.scope,
    agent: input.agent,
    action: input.action,
    governance: input.governance,
  });

  // NFC ENFORCEMENT AT THE PRODUCER, before anything is hashed or signed. This package is an
  // INDEPENDENT signing implementation, so enforcing it only in noa-receipt's builder left a second
  // door open and the invariant was not universal. Same rule, same failure mode, both producers.
  const nonNfc = nonNfcPaths(cloned);
  if (nonNfc.length > 0) {
    throw new Error(
      `buildReceipt: refusing to sign a payload with non-NFC strings (the profile requires producers to emit Unicode NFC): ${nonNfc.join(", ")}`,
    );
  }

  const seq = prev ? prev.chain.seq + 1 : 0;
  const prevHash = prev ? prev.chain.hash : null;

  const draft: Receipt = {
    spec: RECEIPT_SPEC,
    id: cloned.id,
    ts: cloned.ts,
    scope: cloned.scope,
    agent: cloned.agent,
    action: cloned.action,
    governance: cloned.governance,
    chain: { seq, prevHash, hash: "" },
    sig: { alg: "ed25519", kid, value: "" },
  };

  const hashInput = receiptHashInput(draft);
  draft.chain.hash = "sha256:" + sha256Hex(hashInput);
  return draft;
}

/**
 * Full pipeline: draft + sign, in one call. For the SAME `input`/`prev`/signer key, this
 * produces a BYTE-IDENTICAL `Receipt` to `noa-receipt`'s own `buildReceipt` — the load-bearing
 * claim this package's G2 golden-parity test proves.
 */
export function buildReceipt(input: BuildInput, prev: Receipt | null, signer: SignerKey): Receipt {
  const draft = buildReceiptDraft(input, prev, signer.kid);
  return signReceipt(draft, signer);
}
