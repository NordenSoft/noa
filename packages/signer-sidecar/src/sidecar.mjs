#!/usr/bin/env node
/**
 * sidecar.mjs — noa-signer-sidecar's CLI entrypoint: a standalone Ed25519 signing oracle
 * listening on a Unix domain socket. Holds the ONLY copy of the private key in this process; no
 * other process (including noa-mcp-proxy) ever sees the raw key material.
 *
 * Protocol: one JSON line per request, one JSON line per response, ONE socket connection per
 * operation (connect -> write one line -> read one line -> the server closes the connection). A
 * fresh connection per call keeps the wire format trivial (no request-id correlation, no
 * partial-write/partial-read interleaving between concurrent callers) at the cost of one extra
 * connect() per signature -- a local Unix-domain-socket connect is microseconds, not a network
 * round trip, so this trade is free in practice.
 *
 *   {"op":"pubkey"}                     -> {"kid":"...","pub":"...","alg":"ed25519"}
 *   {"op":"sign","message":"<base64>"}  -> {"kid":"...","sig":"<base64>","alg":"ed25519"}
 *   (anything malformed/unknown)        -> {"error":"<reason>"}
 *
 * Flags:
 *   --key-file <path>   required. Persisted signing identity (mode 0600, O_NOFOLLOW-hardened
 *                        load -- see noa-mcp-adapter-core's loadOrCreateKeyFile). Generated on
 *                        first run if the path does not exist yet.
 *   --socket <path>     required. Unix domain socket path. The CONTAINING DIRECTORY must already
 *                        exist with mode 0700 (owner-only) -- this process refuses to start
 *                        otherwise (a signing oracle listening in a world/group-traversable
 *                        directory is a local privilege-boundary mistake, not something to
 *                        silently paper over).
 *
 * See README.md's "Honest limits" section for what process isolation does and does NOT protect
 * against.
 */
import { createServer, connect } from "node:net";
import { statSync, unlinkSync, chmodSync, existsSync } from "node:fs";
import { dirname } from "node:path";
import { loadOrCreateKeyFile, generateKeyPair } from "noa-mcp-adapter-core";
import { signEd25519 } from "noa-receipt";

const MAX_LINE_BYTES = 65536;

function oneLineError(error) {
  const message = error instanceof Error ? error.message : String(error);
  return message
    .replace(/[\r\n\u2028\u2029]/g, " ")
    .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, "?")
    .slice(0, 512);
}

function parseArgs(argv) {
  const opts = { keyFile: null, socket: null };
  for (let i = 0; i < argv.length; i++) {
    const flag = argv[i];
    const value = argv[++i];
    if (flag === "--key-file") opts.keyFile = value;
    else if (flag === "--socket") opts.socket = value;
    else throw new Error(`sidecar.mjs: unknown flag "${flag}"`);
  }
  if (!opts.keyFile) throw new Error("sidecar.mjs: --key-file is required");
  if (!opts.socket) throw new Error("sidecar.mjs: --socket is required");
  return opts;
}

/** Refuses to start if the socket's containing directory is not owner-only (mode 0700 or
 *  stricter) -- mirrors --key-file's own loose-permission refusal, applied to the socket's
 *  parent directory instead of a key file. */
function assertSocketDirIsPrivate(socketPath) {
  const dir = dirname(socketPath);
  let st;
  try {
    st = statSync(dir);
  } catch (err) {
    throw new Error(`sidecar.mjs: --socket directory "${dir}" does not exist (${err.message}). Create it with mode 0700 first.`);
  }
  if (!st.isDirectory()) throw new Error(`sidecar.mjs: --socket directory "${dir}" is not a directory`);
  if ((st.mode & 0o077) !== 0) {
    throw new Error(
      `sidecar.mjs: --socket directory "${dir}" is readable/writable/traversable by group or others ` +
        `(mode 0${(st.mode & 0o777).toString(8)}) -- refusing to listen for signing requests in a ` +
        `non-owner-only directory. chmod 700 it first.`,
    );
  }
}

/** Removes a STALE socket file left behind by an unclean shutdown (process killed with -9, host
 *  crash) so this run can bind cleanly. "Stale" is VERIFIED, not assumed: a quick connect probe
 *  must fail with ECONNREFUSED/ENOENT before the file is unlinked -- if something is actually
 *  LISTENING on it, this refuses to steal the path out from under a live sidecar. */
function clearStaleSocket(socketPath) {
  return new Promise((resolve, reject) => {
    if (!existsSync(socketPath)) return resolve();
    const probe = connect(socketPath);
    probe.once("connect", () => {
      probe.destroy();
      reject(new Error(`sidecar.mjs: --socket "${socketPath}" already has a live listener -- refusing to start a second sidecar on the same path`));
    });
    probe.once("error", (err) => {
      if (err.code === "ECONNREFUSED" || err.code === "ENOENT") {
        try {
          unlinkSync(socketPath);
        } catch (unlinkErr) {
          if (unlinkErr.code !== "ENOENT") return reject(unlinkErr);
        }
        return resolve();
      }
      reject(err);
    });
  });
}

function readOneLine(socket, onLine, onError) {
  let buf = "";
  let done = false;
  socket.setEncoding("utf8");
  socket.on("data", (chunk) => {
    if (done) return;
    buf += chunk;
    if (buf.length > MAX_LINE_BYTES) {
      done = true;
      onError(new Error("request line too long"));
      socket.destroy();
      return;
    }
    const nl = buf.indexOf("\n");
    if (nl !== -1) {
      done = true;
      onLine(buf.slice(0, nl));
    }
  });
  socket.on("error", (err) => {
    if (!done) {
      done = true;
      onError(err);
    }
  });
}

async function main() {
  const opts = parseArgs(process.argv.slice(2));
  assertSocketDirIsPrivate(opts.socket);
  await clearStaleSocket(opts.socket);

  const identity = loadOrCreateKeyFile({
    keyFile: opts.keyFile,
    mintKeyPair: () => generateKeyPair(`noa-signer-sidecar:${new Date().toISOString()}-${process.pid}`),
    callerLabel: "sidecar.mjs",
  });

  const server = createServer((socket) => {
    readOneLine(
      socket,
      (line) => {
        let req;
        try {
          req = JSON.parse(line);
        } catch {
          socket.end(JSON.stringify({ error: "malformed JSON request" }) + "\n");
          return;
        }
        try {
          if (req.op === "pubkey") {
            socket.end(JSON.stringify({ kid: identity.kid, pub: identity.publicKey, alg: "ed25519" }) + "\n");
          } else if (req.op === "sign") {
            if (typeof req.message !== "string") {
              socket.end(JSON.stringify({ error: "sign: `message` must be a base64 string" }) + "\n");
              return;
            }
            const message = Buffer.from(req.message, "base64");
            const sig = signEd25519(identity.privateKey, message);
            socket.end(JSON.stringify({ kid: identity.kid, sig, alg: "ed25519" }) + "\n");
          } else {
            socket.end(JSON.stringify({ error: `unknown op "${req.op}"` }) + "\n");
          }
        } catch (err) {
          // Fail-closed per REQUEST, never per PROCESS: a single malformed/hostile request must
          // never crash the sidecar out from under every other in-flight session -- that would
          // turn one bad request into an outage for every signer this process serves.
          socket.end(JSON.stringify({ error: `internal error: ${err.message}` }) + "\n");
        }
      },
      (err) => {
        console.error(`noa-signer-sidecar: connection error: ${oneLineError(err)}`);
        socket.destroy();
      },
    );
  });

  server.on("error", (err) => {
    console.error(`noa-signer-sidecar: fatal server error: ${oneLineError(err)}`);
    process.exit(1);
  });

  await new Promise((resolve) => server.listen(opts.socket, resolve));
  chmodSync(opts.socket, 0o600);
  console.error(`noa-signer-sidecar: listening on ${opts.socket} (kid=${identity.kid})`);

  const shutdown = () => {
    server.close(() => {
      try {
        unlinkSync(opts.socket);
      } catch {
        // already gone -- fine
      }
      process.exit(0);
    });
  };
  process.on("SIGTERM", shutdown);
  process.on("SIGINT", shutdown);
}

main().catch((err) => {
  console.error(`noa-signer-sidecar: fatal -- ${oneLineError(err)}`);
  process.exit(1);
});
