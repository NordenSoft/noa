# `SIDE_EFFECT_UNCONFIRMED` — the durable adapter commit protocol

**Status:** specification + executable state machine + adversarial fixtures. The protocol itself is
**not implemented**, deliberately. Nothing in this repository claims exactly-once delivery or
physical completion of a side effect, and this document does not change that.

- Executable state machine: [`packages/adapter-core/src/side-effect-state.mjs`](../packages/adapter-core/src/side-effect-state.mjs)
- Adversarial fixtures: [`packages/adapter-core/test/side-effect-state.test.mjs`](../packages/adapter-core/test/side-effect-state.test.mjs)
- The thrown type for the state today: [`packages/adapter-core/src/tool-outcome-not-recorded.mjs`](../packages/adapter-core/src/tool-outcome-not-recorded.mjs)

---

## 1. The state that had nowhere to go

Between "the tool was dispatched" and "the outcome is durably recorded" there is a window. If the
process dies, the network partitions, or the signer refuses, what happened to the side effect in
that window is **unknown**. It is not "succeeded" and it is not "failed".

Every layer used to round it to one of the two, and both roundings are wrong in the same way — an
indeterminate state reported as determinate:

| rounding | consequence |
|---|---|
| → `EXECUTED` | a signed attestation that something ran which may never have run |
| → `FAILED` | a caller retries a payment that may already have been made |

`SIDE_EFFECT_UNCONFIRMED` is that state, named. It is **terminal** for the adapter (there is nothing
further to observe) and **not safe to retry**. It resolves only through reconciliation against the
remote system of record — never through a timeout, never through an assumption, and never by an
adapter deciding it "probably failed".

## 2. Why the state machine is executable

A named state that nothing computes is decoration. `next(state, event)` is a pure reducer over the
events an adapter can actually **observe**; every scenario is replayed against the rules rather than
argued about in prose. Two properties in the fixture suite are load-bearing and hold over the whole
transition table, not over the cases someone happened to write down:

1. `SIDE_EFFECT_UNCONFIRMED` has exactly two exits, `RECONCILED_COMPLETED` and
   `RECONCILED_NOT_PERFORMED`. Every other event is refused.
2. After `DISPATCH_STARTED`, no event reaches a retry-safe state except a **proof** — the tool
   stating it did nothing, or reconciliation stating it. Absence of a success is never a proof.

An unmodelled `(state, event)` pair raises `IllegalSideEffectTransition` rather than inventing a
state. Guessing is precisely how an indeterminate outcome became a determinate lie.

## 3. Relationship to the §13 evidence layer

The frozen §13 outcome union already carries `UNKNOWN_AFTER_DISPATCH` for this condition at the
**gate** layer, and five independent verifiers agree on that union. It is **not widened** by this
design — widening it is a spec change, not a bug fix. `SIDE_EFFECT_UNCONFIRMED` is the **adapter**
layer's name for the same fact, and `EVIDENCE_OUTCOME_FOR` is the mapping, stated once and asserted
by test.

## 4. What is NOT implemented, and why

A durable commit protocol needs four things this branch cannot supply safely:

1. **An idempotency key the remote honours end to end.** The adapter can generate and persist one;
   only the tool and the remote system can make it mean anything. A key that the remote ignores
   produces a system that *believes* it is exactly-once, which is strictly worse than one that
   knows it is not.
2. **An operation reference the tool echoes back.** Without it, reconciliation has nothing to ask
   about. This is a change to the tool-facing contract of a published package, and it requires
   agreement from callers who are not in this repository.
3. **A durable store with its own fsync / torn-write discipline.** `packages/adapter-core`'s
   file-session store is the closest existing component and it is scoped to chain positions, not to
   in-flight operations.
4. **A reconciliation channel.** Somebody must be able to ask the remote "did operation X happen?"
   and get an authoritative answer. No such channel exists today for the general tool case.

Shipping halves of this would produce the exact failure the design exists to prevent. So the
deliverable is the specification, the executable machine and the fixtures; the protocol is specified
against them and implemented when the contract changes above can be made deliberately.

## 5. Implementation plan (precise, in dependency order)

**Phase 1 — carry the key (additive, no behaviour change).**
`createToolGuard({ idempotencyKeyFor })` produces a key per call, derived from
`(chain, decisionReceipt.id, action.paramsHash)` so it is deterministic across a retry of the SAME
logical call and distinct across different ones. It is recorded in the decision receipt's existing
fields — no receipt-shape change — and passed to the tool only when the caller opts in. *Done when:*
the key is present in the receipt log and byte-identical for a replayed call, proven by a test that
replays one.

**Phase 2 — persist the intent BEFORE dispatch.**
An `InFlightStore` (same fsync + torn-write discipline as `createFileSessionStore`) records
`{ idempotencyKey, decisionReceiptId, action, paramsHash, startedAt }` **before** `fn(args)` is
called, and clears it when the outcome receipt lands. *Done when:* a crash injected between the
write and the dispatch, and between the dispatch and the outcome record, leaves a readable in-flight
record in both cases — proven with a child process killed with SIGKILL, not a mocked failure.

**Phase 3 — recover on start.**
`recoverInFlight(store)` replays every record through the state machine and returns each as
`SIDE_EFFECT_UNCONFIRMED` with the data needed to reconcile. It never resolves a record on its own.
*Done when:* the recovery output for each Phase-2 crash matches the fixture-expected state.

**Phase 4 — reconcile (requires the tool-side contract).**
`reconcile(record, { lookup })` where `lookup(idempotencyKey)` is supplied by the integrator and
returns `COMPLETED | NOT_PERFORMED | UNKNOWN`. `UNKNOWN` leaves the record unconfirmed — that is the
whole discipline. A reconciled result emits the terminal receipt that was lost, chained to the
original decision. *Done when:* a reconciled `COMPLETED` produces an offline-verifiable EXECUTED
receipt bound to the ORIGINAL decision, and a `NOT_PERFORMED` produces a FAILED one, with the
evidence bundle verifying in both cases.

**Phase 5 — expose it.**
`ToolOutcomeNotRecorded` gains `idempotencyKey` and `operationRef`, so a caller holding the error can
drive reconciliation without reaching into the store. Breaking only in the sense that the fields did
not exist.

## 6. Claims this design does NOT make

- **Not exactly-once.** `safeToRetry` means "no evidence of a side effect exists", never "a retry is
  harmless". Exactly-once is a property of the remote honouring an idempotency key end to end, and
  nothing here can assert it on the remote's behalf.
- **Not physical completion.** A reconciled `COMPLETED` is the system of record's claim, faithfully
  recorded. The receipt attests what the system of record said, not what physically happened.
- **Not a durability guarantee for the window itself.** Until Phase 2 ships, a crash between dispatch
  and record leaves nothing on disk to reconcile — the state machine names that state honestly and
  the fixtures pin it; it does not make it recoverable.
