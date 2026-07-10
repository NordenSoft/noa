## What changed and why

<!-- One or two sentences. Link an issue if there is one. -->

## Clean-room boundary

<!-- See CONTRIBUTING.md. This repo accepts only generic action-provenance primitives —
     enums, opaque ids/handles, hashes. No cognition/memory/planning/model-routing logic,
     no tenant/customer data or real private keys, no proprietary policy engines. -->

- [ ] This PR does not cross the clean-room boundary (or: N/A, docs-only).

## Test evidence

<!-- `npm test` runs the full build + conformance-vector generation + suite (node:test),
     including the TS <-> Python cross-implementation conformance check. Paste the
     pass/fail summary, not just "tests pass". -->

```
$ npm test
...
```

- [ ] `npm test` passes locally (0 failures).
- [ ] If this touches hashing/canonicalization/schema: vectors regenerated
      (`npm run gen:vectors`) and committed — CI fails on vector drift otherwise.
- [ ] New behavior has a test. New attack ideas are conformance vectors, not just unit tests.

## Conformance / spec impact

<!-- Does this change what a receipt/checkpoint/chain looks like on the wire, what a
     conformant verifier must accept or reject, or the CLI's documented exit codes? -->

- [ ] No spec/conformance impact (internal refactor, docs, tooling).
- [ ] Spec/conformance impact — described above, and `docs/receipt-spec.md` /
      `THREAT-MODEL.md` updated in this PR to match.
