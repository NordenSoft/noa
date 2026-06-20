# Contributing

Thanks for looking. This is **one organ** of NOA — the open governance/receipt layer. The
agent-cognition brain is separate and proprietary; contributions here are about the receipt
format, the verifier, the SDK, and the integrations.

## The one hard rule: clean-room boundary

This repository accepts and emits **only generic action-provenance primitives** — enums,
opaque ids/handles, and hashes. Do **not** add:

- cognition / memory / planning / model-routing logic,
- tenant data, customer data, secrets, or real private keys,
- proprietary policy engines (a policy *decision* enters as a `verdict` enum, never the engine
  that produced it).

PRs that cross this line are declined on principle. See [THREAT-MODEL.md](./THREAT-MODEL.md).

## Dev loop

```bash
npm install
npm test          # build + generate conformance vectors + run the suite (node:test)
npm run build     # type-check + emit dist/
npm run verify -- conformance/vectors/valid-chain.json --keyring conformance/vectors/keyring.json
```

- **Zero runtime dependencies** is a feature — do not add one without a strong, discussed
  reason. Dev-only deps (TypeScript, types) are fine.
- If you touch hashing/canonicalization/schema, **regenerate vectors** (`npm run gen:vectors`)
  and commit them; CI fails on vector drift.
- New behavior needs a test. New attack ideas are especially welcome as conformance vectors.

## Security

Please report vulnerabilities privately — see [SECURITY.md](./SECURITY.md).

## License

By contributing you agree your contributions are licensed under Apache-2.0.
