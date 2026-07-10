---
name: Bug report
about: Something in the receipt format, verifier, or SDK doesn't behave as documented
title: ""
labels: bug
assignees: ""
---

## What happened

<!-- One or two sentences: what did you expect, what did you get instead? -->

## Reproduction

<!-- Exact steps, ideally a copy-pasteable command. If you touched hashing, canonicalization,
     schema, or the verifier, a minimal script beats a description. -->

```
npm install noa-receipt
npx --package=noa-receipt noa verify <receipts.json> [--keyring <keyring.json>] [--checkpoint <checkpoint.json>]
# ...or whatever steps actually trigger it
```

## Expected verdict vs. actual verdict

<!-- e.g. "expected VALID, got TAMPERED" or "expected exit code 2, got exit code 3" -->

- Expected:
- Actual:

## A minimal receipt (or chain) that reproduces it

<!-- Paste the smallest receipt/chain/keyring/checkpoint JSON that triggers the issue.
     Strip anything sensitive first — this is a PUBLIC repo, do not paste real keys,
     real agent identifiers, or any tenant/customer data. Synthetic data only. -->

```json
{
  "spec": "noa.receipt/0.1"
}
```

## Environment

- `noa-receipt` version:
- Node version (`node -v`):
- OS:

## Anything else

<!-- Links, screenshots, related issues. -->
