#!/usr/bin/env node
/**
 * noa-gate — the one-shot grant-signer CLIENT SHIM.
 *
 * Reads ONE JSON line on stdin, opens the grant sidecar's Unix domain socket, writes that line,
 * reads ONE JSON line back, prints it on stdout, exits 0. Holds no key, makes no decision, keeps no
 * state. It exists for exactly one reason: `node:net` has no synchronous mode, and the gate engine's
 * single-use CAS and one-shot report lock are atomic only because nothing suspends inside them
 * (`exec-signer.ts`, "why the transport is synchronous"). A process boundary is the cheapest
 * blocking round trip that does not put an `await` inside those windows.
 *
 * Every failure is fail-closed: a non-zero exit with a one-line reason on stderr, never a partial
 * or invented response on stdout.
 */

import { connect } from "node:net";
import { describeThrown } from "noa-mcp-adapter-core/safe-throw";

const REQUEST_TIMEOUT_MS = 10_000;
const MAX_LINE_BYTES = 256 * 1024;

function socketFromArgv(argv: string[]): string {
  const i = argv.indexOf("--socket");
  const value = i >= 0 && i + 1 < argv.length ? argv[i + 1] : undefined;
  if (!value) throw new Error("grant-signer-call: --socket <path> is required");
  return value;
}

function readStdin(): Promise<string> {
  return new Promise((resolve, reject) => {
    let buf = "";
    process.stdin.setEncoding("utf8");
    process.stdin.on("data", (chunk: string) => {
      buf += chunk;
      if (buf.length > MAX_LINE_BYTES) {
        reject(new Error("grant-signer-call: request exceeds the line bound"));
        process.stdin.destroy();
      }
    });
    process.stdin.on("end", () => resolve(buf));
    process.stdin.on("error", (err) => reject(new Error(describeThrown(err))));
  });
}

function rpc(socketPath: string, line: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const socket = connect(socketPath);
    let buf = "";
    let settled = false;
    const fail = (err: Error): void => {
      if (settled) return;
      settled = true;
      socket.destroy();
      reject(err);
    };
    const timer = setTimeout(() => fail(new Error(`grant-signer-call: timed out after ${REQUEST_TIMEOUT_MS}ms`)), REQUEST_TIMEOUT_MS);
    socket.setEncoding("utf8");
    socket.on("connect", () => socket.end(line.endsWith("\n") ? line : line + "\n"));
    socket.on("data", (chunk: string) => {
      buf += chunk;
      if (buf.length > MAX_LINE_BYTES) {
        clearTimeout(timer);
        fail(new Error("grant-signer-call: response exceeds the line bound"));
        return;
      }
      const nl = buf.indexOf("\n");
      if (nl !== -1 && !settled) {
        clearTimeout(timer);
        settled = true;
        resolve(buf.slice(0, nl));
      }
    });
    socket.on("error", (err) => {
      clearTimeout(timer);
      fail(new Error(`grant-signer-call: ${describeThrown(err)}`));
    });
    socket.on("close", () => {
      clearTimeout(timer);
      if (!settled) fail(new Error("grant-signer-call: connection closed before a response arrived"));
    });
  });
}

async function main(): Promise<void> {
  const socketPath = socketFromArgv(process.argv.slice(2));
  const request = await readStdin();
  if (request.trim() === "") throw new Error("grant-signer-call: empty request on stdin");
  const response = await rpc(socketPath, request.trim());
  process.stdout.write(response + "\n");
}

main().catch((err: unknown) => {
  process.stderr.write(`${describeThrown(err)}\n`);
  process.exit(1);
});
