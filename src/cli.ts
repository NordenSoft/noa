#!/usr/bin/env node
/**
 * `noa verify <receipts.json> [--keyring <keyring.json>] [--checkpoint <cp.json>] [--identity <manifest.json>]`
 *
 * Offline receipt-chain verifier. No network, no NOA cloud. Deterministic exit codes so it
 * drops straight into CI:
 *   0  VALID        (structure + chain + signatures verified against the keyring)
 *   1  UNVERIFIED   (chain ok, but NO keyring supplied so signatures were not authenticated)
 *   2  TAMPERED     (an integrity check failed)
 *   3  MALFORMED    (not a well-formed receipt chain / bad input)
 *   4  USAGE        (bad arguments / unreadable file)
 *   5  UNTRUSTED    (signature ok, but (agent.id, sig.kid) not authorized by the identity manifest)
 *
 * CI rule: treat ANY non-zero exit as failure. Do not special-case "==2".
 *
 * Hostile-input hardened: input is read with a size cap and parsed by the strict safeParse
 * (duplicate-key reject, depth bound, prototype-pollution guard, float reject).
 */

import { readFileSync, statSync } from "node:fs";
import { safeParse } from "./safe-json.js";
import { verifyChain, type VerifyOptions } from "./verify.js";
import type { Keyring, Checkpoint, IdentityManifest } from "./index.js";

const MAX_FILE_BYTES = 64 * 1024 * 1024; // 64 MiB hard cap

const EXIT = {
  VALID: 0,
  UNVERIFIED: 1,
  TAMPERED: 2,
  MALFORMED: 3,
  USAGE: 4,
  UNTRUSTED: 5,
} as const;

function usage(msg?: string): never {
  if (msg) process.stderr.write(`error: ${msg}\n`);
  process.stderr.write(
    "usage: noa verify <receipts.json> [--keyring <keyring.json>] [--checkpoint <checkpoint.json>] [--identity <manifest.json>]\n",
  );
  process.exit(EXIT.USAGE);
}

function readJsonFile(path: string): unknown {
  let size: number;
  try {
    size = statSync(path).size;
  } catch {
    usage(`cannot stat file: ${path}`);
  }
  if (size > MAX_FILE_BYTES) usage(`file too large (>${MAX_FILE_BYTES} bytes): ${path}`);
  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch {
    usage(`cannot read file: ${path}`);
  }
  return safeParse(text, { maxLength: MAX_FILE_BYTES });
}

function main(argv: string[]): number {
  const args = argv.slice(2);
  if (args.length === 0) usage();
  const cmd = args[0];
  if (cmd !== "verify") usage(`unknown command: ${cmd}`);

  let receiptsPath: string | undefined;
  let keyringPath: string | undefined;
  let checkpointPath: string | undefined;
  let identityPath: string | undefined;

  for (let i = 1; i < args.length; i++) {
    const a = args[i]!;
    if (a === "--keyring") {
      const v = args[++i];
      if (v === undefined || v.startsWith("--")) usage("--keyring requires a path");
      keyringPath = v;
    } else if (a === "--checkpoint") {
      const v = args[++i];
      if (v === undefined || v.startsWith("--")) usage("--checkpoint requires a path");
      checkpointPath = v;
    } else if (a === "--identity") {
      const v = args[++i];
      if (v === undefined || v.startsWith("--")) usage("--identity requires a path");
      identityPath = v;
    } else if (a.startsWith("--")) usage(`unknown flag: ${a}`);
    else if (!receiptsPath) receiptsPath = a;
    else usage(`unexpected argument: ${a}`);
  }
  if (!receiptsPath) usage("missing <receipts.json>");

  let receipts: unknown;
  const opts: VerifyOptions = {};
  try {
    receipts = readJsonFile(receiptsPath);
    if (keyringPath) opts.keyring = readJsonFile(keyringPath) as Keyring;
    if (checkpointPath) opts.checkpoint = readJsonFile(checkpointPath) as Checkpoint;
    if (identityPath) opts.identityManifest = readJsonFile(identityPath) as IdentityManifest;
  } catch (e) {
    process.stderr.write(`error: ${(e as Error).message}\n`);
    return EXIT.MALFORMED;
  }

  const result = verifyChain(receipts, opts);
  process.stdout.write(JSON.stringify(result, null, 2) + "\n");

  switch (result.status) {
    case "VALID":
      return EXIT.VALID;
    case "UNVERIFIED":
      return EXIT.UNVERIFIED;
    case "UNTRUSTED":
      return EXIT.UNTRUSTED;
    case "TAMPERED":
      return EXIT.TAMPERED;
    default:
      return EXIT.MALFORMED;
  }
}

process.exit(main(process.argv));
