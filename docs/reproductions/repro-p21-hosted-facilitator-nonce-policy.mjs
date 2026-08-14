/**
 * REPRODUCTION — hosted-facilitator nonce-policy measurement (recorded 2026-08-14) — does a HOSTED x402 facilitator impose an entropy/randomness policy on the
 * EIP-3009 authorization nonce, making a DERIVED correlation value unusable?
 *
 * Method: sign three real EIP-712 TransferWithAuthorization structs from one throwaway key —
 * (A) a DERIVED nonce (our two-stage derivation), (B) a freshly random nonce, (C) a
 * low-entropy/structured nonce (all-zero-ish) — and submit each to the hosted facilitator's
 * /verify. Verification runs the facilitator's own acceptance policy WITHOUT broadcasting.
 *
 * The discriminating comparison: if A and B are refused for the SAME reason as each other and that
 * reason is unrelated to the nonce (e.g. insufficient_funds — the throwaway key holds nothing),
 * the facilitator did not gate on nonce content. If A is refused where B passes the same stage,
 * the derivation is unavailable in this deployment. C is the control: a facilitator that DOES
 * police nonce shape should treat C differently from B.
 *
 * Nothing is broadcast; the key is generated here and funded by nobody.
 */
import { createWalletClient, http, publicActions, hexToBytes } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { baseSepolia } from "viem/chains";
import { randomBytes } from "node:crypto";

const FACILITATOR = "https://x402.org/facilitator";
const NETWORK = "eip155:84532";
const USDC = "0x036CbD53842c5426634e7929541eC2318f3dCF7e";
const PAY_TO = "0x209693Bc6afc0C5328bA36FaF03C514EF312287C";
const AMOUNT = "10000";

const { deriveCorrelationNonce } = await import(
  new URL("../../packages/rail-x402/src/correlation-nonce.mjs", import.meta.url).href
);

// Throwaway key, generated now, never funded, never persisted.
const pk = `0x${randomBytes(32).toString("hex")}`;
const account = privateKeyToAccount(pk);
const client = createWalletClient({ account, chain: baseSepolia, transport: http("https://sepolia.base.org") }).extend(publicActions);

// Read the EIP-712 domain from the token itself (the mainnet-vs-testnet name trap in the research note).
const erc20 = [
  { name: "name", outputs: [{ type: "string" }], inputs: [], stateMutability: "view", type: "function" },
  { name: "version", outputs: [{ type: "string" }], inputs: [], stateMutability: "view", type: "function" },
];
const tokenName = await client.readContract({ address: USDC, abi: erc20, functionName: "name" });
let tokenVersion = "2";
try {
  tokenVersion = await client.readContract({ address: USDC, abi: erc20, functionName: "version" });
} catch { /* some deployments omit version(); the x402 example uses "2" */ }

const now = Math.floor(Date.now() / 1000);
const validAfter = String(now - 60);
const validBefore = String(now + 600);

const derived = deriveCorrelationNonce({
  chainId: 84532,
  tokenAddress: USDC,
  payerAddress: account.address,
  dispatchId: "sha256:" + "a".repeat(64),
  seed: randomBytes(32),
}).nonce;
const random = `0x${randomBytes(32).toString("hex")}`;
const structured = `0x${"00".repeat(28)}deadbeef`;

async function signAndVerify(label, nonce) {
  const authorization = {
    from: account.address,
    to: PAY_TO,
    value: AMOUNT,
    validAfter,
    validBefore,
    nonce,
  };
  const signature = await client.signTypedData({
    domain: { name: tokenName, version: tokenVersion, chainId: 84532, verifyingContract: USDC },
    types: {
      TransferWithAuthorization: [
        { name: "from", type: "address" },
        { name: "to", type: "address" },
        { name: "value", type: "uint256" },
        { name: "validAfter", type: "uint256" },
        { name: "validBefore", type: "uint256" },
        { name: "nonce", type: "bytes32" },
      ],
    },
    primaryType: "TransferWithAuthorization",
    message: {
      from: authorization.from,
      to: authorization.to,
      value: BigInt(AMOUNT),
      validAfter: BigInt(validAfter),
      validBefore: BigInt(validBefore),
      nonce,
    },
  });

  const accepted = {
    scheme: "exact",
    network: NETWORK,
    amount: AMOUNT,
    asset: USDC,
    payTo: PAY_TO,
    maxTimeoutSeconds: 60,
    extra: { name: tokenName, version: tokenVersion },
  };
  const body = {
    x402Version: 2,
    paymentPayload: {
      x402Version: 2,
      resource: { url: "https://example.invalid/p21-measurement", description: "P-2.1 nonce-policy measurement", mimeType: "application/json" },
      accepted,
      payload: { signature, authorization },
    },
    paymentRequirements: accepted,
  };

  const res = await fetch(`${FACILITATOR}/verify`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const text = await res.text();
  let parsed;
  try { parsed = JSON.parse(text); } catch { parsed = { raw: text.slice(0, 300) }; }
  console.log(`\n[${label}] nonce=${nonce}`);
  console.log(`  HTTP ${res.status} :: ${JSON.stringify(parsed)}`);
  return { label, nonce, status: res.status, body: parsed };
}

console.log(`facilitator      : ${FACILITATOR}`);
console.log(`network          : ${NETWORK} (Base Sepolia)`);
console.log(`token            : ${USDC}  name()=${JSON.stringify(tokenName)} version=${JSON.stringify(tokenVersion)}`);
console.log(`payer (throwaway): ${account.address}`);
console.log(`nonce bytes      : derived=${hexToBytes(derived).length} random=${hexToBytes(random).length} structured=${hexToBytes(structured).length}`);

const results = [];
results.push(await signAndVerify("A-DERIVED", derived));
results.push(await signAndVerify("B-RANDOM", random));
results.push(await signAndVerify("C-STRUCTURED-LOW-ENTROPY", structured));

const reason = (r) => r.body?.invalidReason ?? r.body?.error ?? `http-${r.status}`;
console.log("\n════ VERDICT ════");
const [a, b, c] = results;
console.log(`A-DERIVED   reason: ${reason(a)}`);
console.log(`B-RANDOM    reason: ${reason(b)}`);
console.log(`C-LOW-ENTR  reason: ${reason(c)}`);
const sameAB = reason(a) === reason(b);
console.log(`\nA and B treated identically : ${sameAB}`);
console.log(
  sameAB
    ? "=> the hosted facilitator applied NO nonce-content policy: a derived nonce reaches exactly\n" +
      "   the same stage as a freshly random one. The derivation is available in this deployment."
    : "=> DIVERGENCE: the derived nonce was treated differently from a random one. Read the reasons above."
);
console.log(`C treated same as B         : ${reason(c) === reason(b)}  (control: a shape-policing facilitator would differ)`);

// Requires: `npm install viem` next to this script (the repository does not vendor it).
