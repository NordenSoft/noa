#!/usr/bin/env node
/**
 * noa-tsa — RFC 3161 trusted-timestamp sidecar for noa-receipt witness anchors (opt-in).
 *
 *   noa-tsa stamp  --anchors <anchors.json> --tsa-url <url> [--out <path>] [--no-cert-req] [--no-nonce]
 *   noa-tsa verify --anchors <anchors.json> --tsr <tsr.json>
 *
 * `stamp` requests ONE RFC 3161 timestamp per DISTINCT anchor in <anchors.json> (keyed by the
 * anchor's own hash — see anchor-hash.mjs — so two anchors over the same frontier from different
 * witnesses get separate stamps) and writes a {anchorHash -> stamp record} sidecar map; it NEVER
 * modifies <anchors.json>. `verify` structurally checks every anchor against its stamp (verify.mjs)
 * and exits non-zero if ANY anchor is unstamped or mismatched. Hostile-input hardened: input files
 * are read with a size cap and parsed by noa-receipt's own hardened safeParse.
 *
 * Exit codes: 0 OK · 1 MISMATCH (verify: >=1 anchor unstamped/mismatched) · 2 TRANSPORT (stamp: TSA
 * request failed) · 3 MALFORMED (bad JSON/DER input) · 4 USAGE.
 */
import { readSync, writeFileSync, openSync, fstatSync, closeSync, constants as fsConstants } from "node:fs";
import { safeParse } from "noa-receipt";
import { stampAnchor } from "./client.mjs";
import { verifyStamp } from "./verify.mjs";
import { anchorHash } from "./anchor-hash.mjs";

const MAX_FILE_BYTES = 64 * 1024 * 1024;
const EXIT = { OK: 0, MISMATCH: 1, TRANSPORT: 2, MALFORMED: 3, USAGE: 4 };

function usage(msg) {
  if (msg) process.stderr.write(`error: ${msg}\n`);
  process.stderr.write(
    "usage: noa-tsa stamp --anchors <anchors.json> --tsa-url <url> [--out <path>] [--no-cert-req] [--no-nonce]\n" +
      "       noa-tsa verify --anchors <anchors.json> --tsr <tsr.json>\n",
  );
  process.exit(EXIT.USAGE);
}

function readJsonFile(path) {
  const flags = fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0);
  let fd;
  try {
    fd = openSync(path, flags);
  } catch {
    usage(`cannot open file: ${path}`);
  }
  let text;
  try {
    let st;
    try {
      st = fstatSync(fd);
    } catch {
      usage(`cannot inspect file: ${path}`);
    }
    if (!st.isFile()) usage(`not a regular file: ${path}`);
    if (st.size > MAX_FILE_BYTES) usage(`file too large (>${MAX_FILE_BYTES} bytes): ${path}`);
    try {
      const chunks = [];
      const chunk = Buffer.allocUnsafe(64 * 1024);
      let total = 0;
      for (;;) {
        const remaining = MAX_FILE_BYTES + 1 - total;
        const n = readSync(fd, chunk, 0, Math.min(chunk.length, remaining), null);
        if (n === 0) break;
        total += n;
        if (total > MAX_FILE_BYTES) usage(`file too large (>${MAX_FILE_BYTES} bytes): ${path}`);
        chunks.push(Buffer.from(chunk.subarray(0, n)));
      }
      text = Buffer.concat(chunks, total).toString("utf8");
    } catch {
      usage(`cannot read file: ${path}`);
    }
  } finally {
    closeSync(fd);
  }
  try {
    return safeParse(text, { maxLength: MAX_FILE_BYTES });
  } catch (e) {
    // Malformed JSON is EXIT.MALFORMED (3) with a clean one-line message — never an uncaught
    // safeParse throw dumping a raw stack and exiting 1 (which contradicts the header's exit table).
    process.stderr.write(`error: malformed JSON in ${path}: ${e.message}\n`);
    process.exit(EXIT.MALFORMED);
  }
}

function parseFlags(args, spec) {
  const out = {};
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (spec.valued.has(a)) {
      const v = args[++i];
      if (v === undefined || v.startsWith("--")) usage(`${a} requires a value`);
      out[a] = v;
    } else if (spec.flags.has(a)) {
      out[a] = true;
    } else {
      usage(`unknown flag: ${a}`);
    }
  }
  return out;
}

async function cmdStamp(args) {
  const flags = parseFlags(args, { valued: new Set(["--anchors", "--tsa-url", "--out"]), flags: new Set(["--no-cert-req", "--no-nonce"]) });
  if (!flags["--anchors"]) usage("stamp requires --anchors <path>");
  if (!flags["--tsa-url"]) usage("stamp requires --tsa-url <url>");
  const anchors = readJsonFile(flags["--anchors"]);
  if (!Array.isArray(anchors)) usage("--anchors file must contain a JSON array of anchors");
  const out = flags["--out"] ?? `${flags["--anchors"]}.tsr.json`;

  const sidecar = {};
  for (const a of anchors) {
    let key;
    try {
      key = anchorHash(a);
    } catch (e) {
      process.stderr.write(`error: malformed anchor entry: ${e.message}\n`);
      return EXIT.MALFORMED;
    }
    if (sidecar[key]) continue; // distinct-anchor dedup (same witness re-listed twice in the file)
    try {
      sidecar[key] = await stampAnchor(a, {
        tsaUrl: flags["--tsa-url"],
        certReq: !flags["--no-cert-req"],
        includeNonce: !flags["--no-nonce"],
      });
    } catch (e) {
      process.stderr.write(`error: stamping anchor ${key} (kid=${a?.sig?.kid}): ${e.message}\n`);
      return EXIT.TRANSPORT;
    }
  }
  writeFileSync(out, JSON.stringify(sidecar, null, 2) + "\n", "utf8");
  process.stdout.write(`wrote ${Object.keys(sidecar).length} stamp(s) to ${out}\n`);
  return EXIT.OK;
}

function cmdVerify(args) {
  const flags = parseFlags(args, { valued: new Set(["--anchors", "--tsr"]), flags: new Set() });
  if (!flags["--anchors"]) usage("verify requires --anchors <path>");
  if (!flags["--tsr"]) usage("verify requires --tsr <path>");
  const anchors = readJsonFile(flags["--anchors"]);
  const sidecar = readJsonFile(flags["--tsr"]);
  if (!Array.isArray(anchors)) usage("--anchors file must contain a JSON array of anchors");
  if (typeof sidecar !== "object" || sidecar === null || Array.isArray(sidecar)) usage("--tsr file must contain a JSON object (anchorHash -> stamp record)");

  let mismatches = 0;
  let malformed = 0;
  const results = [];
  for (const a of anchors) {
    let key;
    try {
      key = anchorHash(a);
    } catch (e) {
      results.push({ ok: false, code: "MALFORMED", reason: `malformed anchor entry: ${e.message}` });
      mismatches++;
      malformed++;
      continue;
    }
    const record = sidecar[key];
    const res = record ? verifyStamp(a, record) : { ok: false, reason: "no stamp for this anchor in the .tsr file" };
    results.push({ anchorHash: key, chain: a?.chain, highestSeq: a?.highestSeq, ...res });
    if (!res.ok) {
      mismatches++;
      if (res.code === "MALFORMED") malformed++;
    }
  }
  process.stdout.write(JSON.stringify({ results, mismatches }, null, 2) + "\n");
  // A bad-DER/bad-base64 (or malformed anchor) input is EXIT.MALFORMED (3) per the header table —
  // distinct from a well-formed-but-non-matching stamp, which is EXIT.MISMATCH (1).
  if (malformed > 0) return EXIT.MALFORMED;
  return mismatches === 0 ? EXIT.OK : EXIT.MISMATCH;
}

async function main(argv) {
  const args = argv.slice(2);
  if (args.length === 0) usage();
  const cmd = args[0];
  if (cmd === "stamp") return cmdStamp(args.slice(1));
  if (cmd === "verify") return cmdVerify(args.slice(1));
  usage(`unknown command: ${cmd}`);
}

main(process.argv).then((code) => process.exit(code));
