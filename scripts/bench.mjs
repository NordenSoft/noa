// Micro-benchmark for refEval on the safe (allow) path. Prints p50/p99 so the site/docs can cite a
// measured number instead of an unbacked "sub-millisecond" claim. Run: npm run build && node scripts/bench.mjs
import { evaluate } from "../dist/src/policy/eval.js";

const policy = {
  spec: "noa.policy/0.2", id: "refund-guard-v1", requiredPaths: ["action", "amountMinor"],
  rules: [
    { id: "block-million", when: { op: "ge", path: "amountMinor", value: 100000000 }, then: "DENY" },
    { id: "allow-small-refund", when: { op: "and", clauses: [
      { op: "eq", path: "action", value: "payment.refund" },
      { op: "lt", path: "amountMinor", value: 100000000 }] }, then: "ALLOW" },
  ],
};
const inputs = { action: "payment.refund", amountMinor: 4200 };
const N = 100000, WARM = 5000;
for (let i = 0; i < WARM; i++) evaluate(policy, inputs);
const t = new Array(N);
for (let i = 0; i < N; i++) { const s = process.hrtime.bigint(); evaluate(policy, inputs); t[i] = Number(process.hrtime.bigint() - s) / 1000; } // µs
t.sort((a, b) => a - b);
const p = (q) => t[Math.floor(q * N)].toFixed(2);
console.log(`refEval safe-path over ${N} runs: p50=${p(0.5)}µs  p90=${p(0.9)}µs  p99=${p(0.99)}µs  max=${t[N-1].toFixed(2)}µs`);
