# IPC rehearsal conformance vectors — Stage 0.5

> **LABEL:** These vectors exercise the **PROTOCOL REHEARSAL** of `docs/kernel-wire-protocol.md`
> — NOT a security deliverable, NOT the isolated Go kernel (ADR-0002). They pin the WIRE
> CONTRACT (framing, envelope, error taxonomy, caller-side verification) so the future Go
> kernel can be built against executable expectations. They pin nothing about the receipt
> format (that is `conformance/vectors/` + `golden/`), and they prove nothing about
> in-process integrity of the TypeScript server.

`vectors.json` is EXECUTABLE: `test/serve/ipc-rehearsal.test.ts` runs every vector and fails
if any vector is unknown, unexecuted, or diverges from its pinned `expect`. V-25 deliberately
pins a NON-guarantee (spec §8 N-3): a caller that violates the fresh-nonce contract loses
replay detection — the sharp edge stays measured instead of assumed away.
