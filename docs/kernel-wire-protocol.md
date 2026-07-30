# Kernel wire protocol — Stage 0.5 PROTOCOL REHEARSAL

> **THE LABEL — READ THIS FIRST.**
> This document specifies a **PROTOCOL REHEARSAL, NOT a security deliverable, and NOT the
> isolated Go kernel** of ADR-0002. The `--serve` implementation that speaks this protocol is
> same-realm TypeScript running behind an ordinary process boundary: everything inside that
> process — the parser, the verifier, the envelope signer, the ephemeral key — is poisonable
> *inside* the process, exactly as ADR-0002 §2–§3 measured. What this rehearsal exercises is the
> **wire contract** (framing, request/response envelope, error taxonomy, caller-side
> verification) so that the Go kernel (ADR-0002 §5, not yet built) can implement it against
> conformance vectors instead of against prose. Any reading of this document as a security
> claim about the TypeScript process is the overclaim this project's NON-CLAIMS.md exists to
> prevent.

Status: Stage 0.5 rehearsal draft of the ADR-0002 §7 Stage-1 spec ("freeze the wire spec").
It becomes a candidate for freezing only after cross-family review; nothing here is frozen.

---

## 1. Transport and framing (T-1)

The protocol runs over any reliable, ordered byte stream. The rehearsal binds it to a child
process's stdin (requests in) and stdout (frames out). stderr is out of band and carries no
protocol data.

```
frame := length:u32be ‖ payload:byte[length]
```

- All integers in this protocol are **unsigned big-endian**.
- `MAX_FRAME = 67 108 864` (64 MiB — chosen to equal the one-shot CLI's existing
  `MAX_FILE_BYTES` input bound, `src/cli.ts:39`). A header whose `length` exceeds `MAX_FRAME`
  is a protocol error (`FRAME_OVERSIZE`), detected **before** any payload byte is read or
  buffered, so an attacker cannot make the server allocate from a header. `length = 0` is
  `FRAME_UNDERSIZE`.
- Frames may arrive split across any number of reads and multiple frames may arrive in one
  read; the receiver MUST reassemble on the length prefix alone (conformance V-04, V-05).
- A partial frame that does not complete within the assembly deadline (§6) is `FRAME_TIMEOUT`.
  EOF in the middle of a frame is `EOF_MID_FRAME`. EOF on a frame boundary is a clean shutdown.

Every payload begins with two fixed bytes:

```
version:u8 = 0x01     (this rehearsal draft; any other value → BAD_VERSION)
type:u8               (0x01 HELLO · 0x02 REQUEST · 0x03 RESPONSE · 0x7F PROTOCOL_ERROR;
                       any other value → BAD_TYPE)
```

## 2. HELLO (server → caller, exactly once, first frame)

```
version:u8=0x01 ‖ type:u8=0x01
‖ proto_id_len:u8 ‖ proto_id:byte[proto_id_len]   -- ASCII "noa-kernel-rehearsal/0"
‖ max_frame:u32be                                  -- the server's MAX_FRAME
‖ pubkey_len:u16be ‖ pubkey:byte[pubkey_len]       -- DER SPKI, Ed25519, the envelope key (§5)
```

The `proto_id` string names the **rehearsal** on the wire, so a captured byte stream can never
be mistaken for (or replayed against) the future kernel protocol, which will carry a different
identifier.

The HELLO is **unsigned and unauthenticated** — there is nothing the caller already trusts
that could sign it. See §5 and §8 for exactly what that costs.

> ⛔ **RESOLVED AND FORBIDDEN GOING FORWARD (2026-07-29, T-7).** This HELLO shape — the server
> announcing its own public key — is **Model F** in `docs/T7-trust-root.md` §3, and it is measured
> broken: substituting the HELLO forges any verdict (N-2, reproduced again in T7 §5, row A1).
> **It MUST NOT be carried into the Go kernel.** The kernel HELLO carries a **key identifier only**,
> never key material, and the caller pins the key out of band and fails closed without one
> (`docs/T7-trust-root.md` §4.1, rules 1–7). This paragraph stands only because Stage 0.5 is a
> frozen rehearsal artefact and rewriting shipped rehearsal evidence would falsify the record.

## 3. REQUEST (caller → server)

```
version:u8=0x01 ‖ type:u8=0x02
‖ request_id:u64be        -- strictly increasing per connection, first value ≥ 1
‖ nonce:byte[32]          -- caller-chosen; the caller's CONTRACT is a fresh,
                          -- cryptographically random 32-byte value per request (§T-4)
‖ op:u8 = 0x01            -- VERIFY_CHAIN, the only operation in this rehearsal
‖ sections:TLV*           -- to end of payload
```

```
TLV := tag:u8 ‖ len:u32be ‖ bytes:byte[len]
tag 0x01  document (the receipts JSON, as bytes)   REQUIRED, exactly once
tag 0x02  keyring bytes                            optional, at most once
tag 0x03  checkpoint bytes                         optional, at most once
tag 0x04  identity-manifest bytes                  optional, at most once
```

**Closed, canonical grammar:** tags MUST appear in strictly ascending order, each at most
once; an unknown tag, a duplicate, a `len` overrunning the payload, a missing document
section, or trailing bytes after the last TLV is `BAD_REQUEST_GRAMMAR`. A `request_id` not
strictly greater than every previous id on the connection is `ID_NOT_MONOTONIC`. Ascending
unique tags make the encoding of a given request **unique**, so `request_digest` (§4) is
well-defined with no re-encoding ambiguity.

**Sections are opaque bytes at this layer.** The transport MUST NOT parse, normalize,
re-encode or otherwise interpret them (T-2). They are handed as bytes to the verification
boundary (`verifyChain(Uint8Array, …)`), whose strict parser is normative for what a document
is. Consequence, pinned by conformance V-19: a document that strict-parse rejects (e.g.
duplicate JSON keys) yields a **signed MALFORMED verdict**, not a protocol error — the
envelope was well-formed; the document is the verdict's business.

## 4. RESPONSE (server → caller)

```
version:u8=0x01 ‖ type:u8=0x03
‖ request_id:u64be         -- echo
‖ nonce:byte[32]           -- echo
‖ request_digest:byte[32]  -- SHA-256 over the ENTIRE request payload bytes as received
                           -- (version byte through last TLV byte)
‖ verdict_len:u32be ‖ verdict:byte[verdict_len]
                           -- UTF-8 JSON, the same VerifyResult object the one-shot CLI prints
‖ sig:byte[64]             -- Ed25519, MUST be the final bytes; trailing bytes → reject
```

### 4.1 Signature preimage and domain separation

```
preimage := UTF8("NOA-KernelRehearsal-v0.1-sig:")
          ‖ request_digest        (32 bytes)
          ‖ request_id:u64be      ( 8 bytes)
          ‖ nonce                 (32 bytes)
          ‖ SHA-256(verdict)      (32 bytes)
sig      := Ed25519-sign(envelope_private_key, preimage)
```

Layout justification, following the discipline of `src/signing.ts`:

- **Domain tag first, colon-terminated**, exactly like `RECEIPT_SIG_DOMAIN` /
  `CHECKPOINT_SIG_DOMAIN`. The tag is distinct from both, so an envelope signature can never
  be replayed as a receipt or checkpoint signature or vice versa; and the tag names the
  **rehearsal** (`KernelRehearsal`), so no rehearsal signature can ever satisfy the future
  kernel's envelope domain, which will be a different tag.
- **Every field after the tag is fixed-width** (32 ‖ 8 ‖ 32 ‖ 32), so the concatenation is
  injective — no length-prefix tricks, no ambiguity between field boundaries.
- **The verdict enters as its SHA-256**, keeping the preimage a fixed 133 bytes regardless of
  verdict size, the same digest-then-sign shape the receipt preimage uses.
- The signed tuple is `(request_digest ‖ verdict ‖ nonce)` per ADR-0002 §6 T-3, **plus
  `request_id`** per T-5, which requires the correlation id *inside* the signed envelope:
  without it, two in-flight requests carrying identical bodies and (contract-violating)
  identical nonces would have interchangeable responses.

### 4.2 Caller verification (normative — all five, in this order)

1. the frame parses as a RESPONSE with the exact fixed-width layout, `sig` is the final
   64 bytes, no trailing bytes;
2. `request_id` equals the id of a request this caller sent and still awaits — the response
   is verified against **the caller's own request record**, never against the response's
   self-description;
3. `nonce` equals that request's nonce;
4. `request_digest` equals the caller's own SHA-256 of the request payload it sent;
5. `sig` verifies under the HELLO public key over the §4.1 preimage.

A response failing ANY check is **discarded as unauthentic**. It is not a verdict, not an
error verdict, not a retry hint — it is transport garbage.

## 5. The envelope key — provenance, and what its compromise means

- The server generates an **ephemeral Ed25519 keypair at process start**
  (`generateKeyPair()`, `src/keys.ts`), announces the public half in HELLO, and holds the
  private half **in ordinary process memory** for the process lifetime. It is never written
  to disk and dies with the process.
- **Compromise of this key = every guarantee of §4 is void for that process lifetime**: the
  holder forges responses that pass all five caller checks.
- **This is trust-on-first-read over the same untrusted pipe.** A transport hostile from the
  first byte substitutes its own HELLO key and forges everything thereafter; the caller
  cannot detect it. Closing that requires provisioning the expected key/binary out of band
  (ADR-0002 T-7) and keeping keys out of process memory (T-9, KMS/HSM by handle). Both
  require operator/infrastructure input that does not exist in this rehearsal. **No key
  management story is invented here; this is where the rehearsal stops.**

## 6. Resource bounds and DoS posture (T-6)

- Per-request byte cap: `MAX_FRAME` bounds the whole request, checked at the header.
- Frame-assembly deadline: a partial frame older than the deadline (default 30 000 ms;
  `--frame-timeout-ms <n>` for tests) is `FRAME_TIMEOUT` → close.
- In-flight bound: the rehearsal server processes requests **sequentially**; in-flight = 1 by
  construction, responses are emitted in request order.
- Wall-clock **compute** deadline: NOT enforceable from inside this rehearsal process — the
  verification call is synchronous TypeScript and cannot preempt itself. In the rehearsal the
  compute deadline belongs to the supervisor (kill the process); in the Go kernel it is
  internal (context deadline). Stated as OPEN in the Stage 0.5 report.
- **DoS is in scope for availability and out of scope for integrity**: there is no code path
  that emits a verdict on timeout, overload or kill. A killed process yields **no verdict —
  never a permissive one**. Every terminal outcome is either a signed RESPONSE or the absence
  of one.

## 7. Error taxonomy (T-1) — structural, never a status string

A protocol error **closes the connection and is never a verdict**. The distinction from a
verdict is **structural**, three ways at once: a different type byte (`0x7F` vs `0x03`), the
absence of any verdict field, and the absence of a signature — a PROTOCOL_ERROR frame is
never signed, so nothing that fails §4.2 can be laundered into "the kernel said no".

```
PROTOCOL_ERROR := version:u8=0x01 ‖ type:u8=0x7F ‖ code:u8
```

| code | name | meaning |
|---|---|---|
| 0x01 | FRAME_OVERSIZE | header length > MAX_FRAME (checked before any payload read) |
| 0x02 | FRAME_UNDERSIZE | header length = 0, or payload shorter than its type's fixed header |
| 0x03 | BAD_VERSION | payload version byte ≠ 0x01 |
| 0x04 | BAD_TYPE | unknown type byte, or a type the server never accepts (HELLO/RESPONSE/PROTOCOL_ERROR sent TO the server) |
| 0x05 | BAD_REQUEST_GRAMMAR | TLV grammar violation, unknown op, missing document, duplicate/unordered tag, trailing bytes |
| 0x06 | ID_NOT_MONOTONIC | request_id ≤ a previous id on this connection (or < 1) |
| 0x07 | FRAME_TIMEOUT | partial frame exceeded the assembly deadline |
| 0x08 | EOF_MID_FRAME | stream ended inside a frame |
| 0x09 | INTERNAL | server defect; deliberately carries no detail |

Emission of the error frame is **best-effort**; the normative signal is *connection close
without a RESPONSE for the affected request*. After any protocol error the server writes
nothing further and exits non-zero (conformance V-21).

## 8. Guarantees and NON-guarantees of this rehearsal, in the same breath

Given a caller that (a) obtained the HELLO public key from an honest, un-substituted process
start, and (b) honors its nonce contract, the rehearsal demonstrates the **mechanics** of:

- **G-1 (T-3 mechanics):** a transport that alters a verdict, a digest, an id or a nonce
  after signing is detected by §4.2 — forging requires the envelope private key.
- **G-2 (T-4 mechanics):** a recorded response replayed against a later request is rejected
  at check 3 (fresh nonce ⇒ mismatch).
- **G-3 (T-5 mechanics):** cross-pairing responses between in-flight requests is rejected at
  checks 2–4, and the id is inside the signed preimage.
- **G-4 (T-1):** no framing/grammar failure ever yields a verdict; every such failure closes
  the connection.
- **G-5 (T-2):** no live object crosses the wire in either direction; documents are bytes
  end-to-end and the transport never interprets them.

**NON-guarantees — each the flip side of the same item:**

- **N-1:** none of G-1…G-5 holds against code inside the server process. Same-realm
  TypeScript can poison the parser, the verifier or the signer **before** signing; the
  envelope then authenticates a corrupted verdict perfectly. That is ADR-0002 §2, unchanged,
  and it is why this is a rehearsal, not a boundary.
- **N-2:** a transport hostile from process start substitutes the HELLO key and defeats G-1,
  G-2, G-3 wholesale (§5). T-7 provisioning is not rehearsed.
- **N-3:** a caller that reuses a nonce forfeits G-2 for the colliding requests — pinned
  deliberately by conformance V-14, which asserts the replay is ACCEPTED under a reused
  nonce, so the sharp edge stays measured instead of assumed away.
- **N-4:** the private key sits in process memory (violates the T-9 target by design, stated).
- **N-5:** availability is not defended beyond §6's bounds; compute preemption is OPEN.
- **N-6:** side channels (T-8): out of scope, as in the ADR.

## 9. Conformance vectors

`conformance/ipc-rehearsal/vectors.json` — executable via
`test/serve/ipc-rehearsal.test.ts`, which runs EVERY vector (an unknown or skipped vector
fails the suite). Vector ↔ threat mapping is carried in each vector's `threat` field.
