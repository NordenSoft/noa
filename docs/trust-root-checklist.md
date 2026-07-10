# Production key management — a practical checklist

Everything a NOA Receipt proves collapses to one sentence: **the keyring (and, if you use one,
the identity manifest) is the root of trust.** Get that wrong and every "VALID" is meaningless.
This is the one-page version of "how do I actually run this in production" — the full reasoning
is in [THREAT-MODEL.md](../THREAT-MODEL.md) and [`docs/receipt-spec.md`](receipt-spec.md) §5–§6;
read those before you rely on any of this.

## 1. Generate a signing key per agent identity

```js
import { generateKeyPair } from "noa-receipt";

const kp = generateKeyPair("agent-prod-key-1"); // kid: any string you'll recognize later
// kp.publicKey  -> base64 SPKI, goes in the keyring
// kp.privateKey -> base64 PKCS8, keep secret
```

One `kid` per key. Give each agent/service its own key rather than sharing one across agents —
a shared key means a keyring compromise or a rogue caller can author receipts for *every* agent
that uses it.

## 2. Never let the private key touch a receipt, a repo, or a log

`kp.privateKey` is a secret, full stop — [`src/keys.ts`](../src/keys.ts) says so at the type
definition. Load it from an env var, a secrets manager, or (for anything that matters) a
KMS/HSM that never exports the raw key material. It is never part of the signed receipt body —
only `sig.kid` (which key signed) and `sig.value` (the signature) are.

## 3. Build the keyring, distribute it out-of-band

```js
import { generateKeyPair } from "noa-receipt";

const kp = generateKeyPair("agent-prod-key-1");
const keyring = { [kp.kid]: kp.publicKey }; // kid -> base64 SPKI public key
```

This object is the trust root every verifier needs (`verifyChain(receipts, { keyring })`). It
must reach verifiers through a channel you trust *independently of the receipts themselves* —
e.g. a signed manifest file you publish and checksum, your own config-management/secrets
pipeline, or plain trust-on-first-use for a low-stakes deployment. Whatever you pick, write it
down: an attacker who can also rewrite your keyring distribution channel owns the whole system.

## 4. Bind `agent.id` to its key with an `identityManifest`

A keyring alone proves *"a trusted key signed this"* — not *which* agent. If more than one key
is ever trusted, any holder of any trusted key can author a fully `VALID` chain that asserts
someone else's `agent.id`. Close that with an `identityManifest`:

```js
import { generateKeyPair, buildReceipt, verifyChain } from "noa-receipt";

const kp = generateKeyPair("agent-prod-key-1");
const signer = { kid: kp.kid, privateKey: kp.privateKey };
const keyring = { [kp.kid]: kp.publicKey };
const identityManifest = { "billing-agent-7": [kp.kid] }; // agent.id -> authorized kid(s)

const receipt = buildReceipt(
  {
    id: "rcpt_0",
    ts: new Date().toISOString(),
    scope: { chain: "checklist:demo" },
    agent: { id: "billing-agent-7", model: "vendor/model-v1", principal: "SERVICE" },
    action: {
      id: "payment.refund",
      canonical: "payment.refund",
      riskClass: "LOW",
      paramsHash: "sha256:" + "0".repeat(64), // never carry raw params — only their hash
      reversible: false,
      rollbackRef: null,
    },
    governance: { mode: "on", verdict: "EXECUTED", ruleId: "low-risk-auto", approval: null, sandboxed: false },
  },
  null, // no previous receipt: this is the genesis of the chain
  signer,
);

const result = verifyChain([receipt], { keyring, identityManifest });
console.log(result.status); // -> "VALID"
// an unauthorized (agent.id, sig.kid) pairing instead -> status: "UNTRUSTED", not "TAMPERED"
```

Skip this only for a single-key keyring, where the ambiguity can't arise. Details:
[receipt-spec.md](receipt-spec.md) §5, step 5b.

## 5. Pin the head with a signed checkpoint

`prevHash` catches an edited *past* record but not a deleted *recent* one — a verifier handed a
truncated prefix still sees `VALID`. A checkpoint closes that:

```js
import { generateKeyPair, buildReceipt, buildCheckpoint, verifyChain } from "noa-receipt";

const kp = generateKeyPair("agent-prod-key-1");
const signer = { kid: kp.kid, privateKey: kp.privateKey }; // the chain's opener key — see step 6
const keyring = { [kp.kid]: kp.publicKey };
const identityManifest = { "billing-agent-7": [kp.kid] };

const latestReceipt = buildReceipt(
  {
    id: "rcpt_0",
    ts: new Date().toISOString(),
    scope: { chain: "checklist:demo" },
    agent: { id: "billing-agent-7", model: "vendor/model-v1", principal: "SERVICE" },
    action: {
      id: "payment.refund",
      canonical: "payment.refund",
      riskClass: "LOW",
      paramsHash: "sha256:" + "0".repeat(64),
      reversible: false,
      rollbackRef: null,
    },
    governance: { mode: "on", verdict: "EXECUTED", ruleId: "low-risk-auto", approval: null, sandboxed: false },
  },
  null, // genesis: this receipt also opens the chain, so `signer` is the opener key here
  signer,
);

const checkpoint = buildCheckpoint(latestReceipt, new Date().toISOString(), signer);
const result = verifyChain([latestReceipt], { keyring, identityManifest, checkpoint });
console.log(result.status, result.tailChecked); // -> "VALID" true
```

Sign checkpoints with the **private key that corresponds to the `kid` which signed the chain's
genesis (`seq == 0`) receipt for that `agent.id`** — colloquially "the opener key", but it is a
*key*, not the `agent.id` string itself. That's the key `verifyChain` checks a checkpoint's
authority against when an `identityManifest` is supplied, and it's what stops a co-trusted key
from re-heading the chain and forging a checkpoint over its own truncated view
(receipt-spec.md §6). Publish/refresh the checkpoint on whatever cadence matches your risk
tolerance; without one, the verifier still runs, but it emits an explicit tail-truncation
warning instead of silently trusting completeness.

## 6. Rotating a key

A `kid` is pinned to `agent.id` **within one chain** the moment the second receipt lands
(`receipt-spec.md` §5 step 4) — a same-chain swap to a different key is rejected as `TAMPERED`
by design, not a bug to work around:

```js
import { generateKeyPair, buildReceipt, verifyChain } from "noa-receipt";

const kp = generateKeyPair("agent-prod-key-1");
const kp2 = generateKeyPair("agent-prod-key-2"); // a second key, wrongly reused mid-chain
const keyring = { [kp.kid]: kp.publicKey, [kp2.kid]: kp2.publicKey };

const buildInputBase = (id) => ({
  id,
  ts: new Date().toISOString(),
  scope: { chain: "checklist:demo" },
  agent: { id: "billing-agent-7", model: "vendor/model-v1", principal: "SERVICE" },
  action: {
    id: "payment.refund",
    canonical: "payment.refund",
    riskClass: "LOW",
    paramsHash: "sha256:" + "0".repeat(64),
    reversible: false,
    rollbackRef: null,
  },
  governance: { mode: "on", verdict: "EXECUTED", ruleId: "low-risk-auto", approval: null, sandboxed: false },
});

const genesis = buildReceipt(buildInputBase("rcpt_0"), null, { kid: kp.kid, privateKey: kp.privateKey });
// same chain, second receipt signed by a different key -> rejected
const second = buildReceipt(buildInputBase("rcpt_1"), genesis, { kid: kp2.kid, privateKey: kp2.privateKey });

const result = verifyChain([genesis, second], { keyring });
console.log(result.status, "|", result.reason);
// -> TAMPERED | key swap for agent "billing-agent-7" (kid agent-prod-key-1 -> agent-prod-key-2)
```

So rotation is a **new chain, not an in-chain edit**: generate a new key pair, start the next
`scope.chain` under the new `kid`, and update the keyring + `identityManifest` to authorize
**both** the retiring and the new `kid` for that `agent.id` (drop the old entry once every
chain signed under it is fully retired and no longer needs re-verification). Redistribute the
updated keyring/manifest through the same out-of-band channel as step 3 — there is no in-band
rotation-attestation yet (an open item tracked in THREAT-MODEL.md, "Cross-agent impersonation").

## 7. What this does *not* give you — read before you rely on it

- **No freshness guarantee.** `ts` is signer-asserted and backdatable; a wholly valid chain can
  be replayed later as if current. Pin an expected chain id/head from a channel you trust *now*.
- **No revocation list.** A leaked private key lets the holder re-sign a fabricated history
  bounded only by a checkpoint someone already holds. Treat key compromise as "rotate + audit
  every chain that key ever signed," not as something the format detects for you.
- **The keyring/manifest are inputs you vouch for**, not something the library derives or
  authenticates on its own — get their distribution wrong and "VALID" stops meaning anything.

Full threat catalogue, including the honest residual gaps: [THREAT-MODEL.md](../THREAT-MODEL.md).
