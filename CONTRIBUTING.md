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

Repository placement is itself a security boundary. A package-level `"private": true` flag only
prevents accidental publication to npm; it does **not** hide files committed to this public GitHub
repository. Hosted-control-plane code, production tenant configuration, customer-specific policy,
commercial risk intelligence, credentials, and operational data belong in the private product
repositories and must never be staged here. Before every release, inspect both `git diff --cached`
and `npm pack --dry-run --json` for boundary violations.

## Dev loop

```bash
npm install
npm test          # build + generate conformance vectors + run the suite (node:test)
npm run build     # type-check + emit dist/
npm run test:dogfood  # private dogfood suite (vitest)
npm run verify -- conformance/vectors/valid-chain.json --keyring conformance/vectors/keyring.json
```

- **Node version:** the published package targets **Node ≥ 20** (`engines`) and has **zero runtime
  dependencies**, so consumers run it on any Node ≥ 20. The *contributor toolchain* is stricter: the
  dogfood suite's `vitest`/`vite` devDependency needs **Node ≥ 20.19** (or ≥ 22.12). This is a
  dev-only requirement — it does not narrow the runtime `engines` the package ships to consumers.
- **Zero runtime dependencies** is a feature — do not add one without a strong, discussed
  reason. Dev-only deps (TypeScript, types, vitest) are fine.
- If you touch hashing/canonicalization/schema, **regenerate vectors** (`npm run gen:vectors`)
  and commit them; CI fails on vector drift.
- New behavior needs a test. New attack ideas are especially welcome as conformance vectors.

## Security

Please report vulnerabilities privately — see [SECURITY.md](./SECURITY.md).

## License

By contributing you agree your contributions are licensed under Apache-2.0.
