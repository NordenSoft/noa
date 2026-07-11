# noa-signer-sidecar

A process-isolated Ed25519 signing oracle for `noa-receipt`. The private key lives ONLY in this
separate process; a caller (e.g. [`noa-mcp-proxy`](../mcp-proxy)) never holds the raw key
material in its own process memory — it talks to this process over a Unix domain socket instead.

## Why

`noa-receipt`'s receipt-signing callsite (`buildReceipt`/`buildReceiptAsync` in the core package)
needs a `{ kid, privateKey }` local `Signer` or a `{ kid, sign }` `RemoteSigner`. Running the
signer IN the same process as the thing deciding ALLOW/DENY means a compromise of that process
(a dependency-confusion attack in the downstream tool it proxies, a memory-dump, a debugger
attached) also exposes the signing key. This package moves the key into its own process, reachable
only over a local, owner-only-permissioned socket.

## Protocol

One JSON line per request, one JSON line per response, one socket connection per operation:

```
{"op":"pubkey"}                     -> {"kid":"...","pub":"...","alg":"ed25519"}
{"op":"sign","message":"<base64>"}  -> {"kid":"...","sig":"<base64>","alg":"ed25519"}
(anything malformed/unknown)        -> {"error":"<reason>"}
```

`message` is the EXACT domain-tagged pre-image `noa-receipt`'s `signingMessage()` produces — this
process never re-derives it, never inspects what it represents, and has zero opinion about
receipts, chains, or policy. It is a generic Ed25519 signing oracle: whoever can reach the socket
decides WHAT gets signed; this process only protects WHERE the key lives.

## Run it yourself

```bash
mkdir -p -m 700 /path/to/private-dir
node src/sidecar.mjs --key-file /path/to/private-dir/key.json --socket /path/to/private-dir/signer.sock
```

Then, from a client (e.g. `noa-mcp-proxy`'s `--signer-socket` flag):

```js
import { createRemoteSigner } from "noa-signer-sidecar/client.mjs";
const signer = await createRemoteSigner({ socketPath: "/path/to/private-dir/signer.sock" });
// signer = { kid, publicKey, sign(message) } -- drop straight into buildReceiptAsync /
// noa-mcp-adapter-core's preCheckAsync / prepareSessionReceiptAsync.
```

## Test

```bash
(cd ../adapter-core && npm install)
npm install
npm test   # node test/smoke.mjs -- a real sidecar child process + the real client, no mocks
```

## Honest limits

- **This is PROCESS isolation, not an HSM.** Root on the same machine — or the same OS user this
  process runs as — can still read `--key-file` directly, attach a debugger to this process, or
  read its memory. What this package removes is the SPECIFIC risk of the private key living in
  the SAME process as a governed proxy forwarding untrusted tool-call traffic; it does not remove
  every risk a hardware security module or a remote KMS would.
- **The sidecar signs whatever bytes it is asked to sign.** It has no receipt schema, no policy
  engine, and no opinion about what a `sign` request represents — the caller (e.g.
  `noa-mcp-proxy`) is solely responsible for deciding WHAT gets signed and WHEN. Anyone who can
  reach the socket and is permitted to connect to it can produce a valid signature under this
  process's key.
- **The socket's parent directory permission is enforced at startup, not continuously.** `sidecar.mjs`
  refuses to start if the socket's containing directory is not mode 0700 at launch time, and the
  socket file itself is `chmod`'d to 0600 after `listen()` — but a directory whose permissions are
  loosened AFTER this process has already started is not re-checked on every request.
- **No TLS/mTLS — this is a local Unix domain socket only,** never intended to be reachable over a
  network. Exposing this socket path over any network-bridging mechanism (a bind-mount into
  another container, an SSH port-forward of a Unix socket, etc.) is outside this package's threat
  model and is the operator's responsibility to avoid.
- **Key rotation is not implemented.** Retiring an old `kid` while keeping receipts signed under it
  verifiable (a multi-key keyring on the verifying side) is a deployment concern this package does
  not automate.
