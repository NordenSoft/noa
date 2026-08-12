import { readFileSync, writeFileSync, openSync, fstatSync, fchmodSync, fsyncSync, closeSync, constants as fsConstants } from "node:fs";
import { describeThrown, thrownCode } from "./safe-throw.mjs";

import { intrinsics } from "noa-receipt";

// REDTEAM 2026-08-03 — bulk hardening of the published decision paths. Four CRITICALs came out of
// this package in two days, every one of them a LIVE builtin read that an attacker could replace
// after module load: an approval seat bound by `Array.prototype.includes`, a signature verified over
// bytes from `Buffer.concat`, a policy weakening hidden by `JSON.stringify`, an approval rule made
// invisible by `Array.isArray`. Auditing the remaining ~300 flagged reads one at a time is not a
// control — it is a race against the next person who adds one.
//
// So the builtins are taken from the kernel's module-load capture here too, whether or not each
// individual site is reachable today. Reachability is a property of the surrounding code, and the
// surrounding code changes.
const { jsonParse, jsonStringify, numToString } = intrinsics;

// Captured at MODULE-EVALUATION time, before any caller-supplied value has been read: the effective
// uid this process is allowed to trust a PRIVATE SIGNING KEY from. `null` on a platform with no
// POSIX uid model (Windows), where the ownership test is skipped and DOCUMENTED as skipped rather
// than silently reported as passed — O_NOFOLLOW, the regular-file test and the mode test all still
// apply there. Same shape as config-artifact.mjs's own PROCESS_EUID capture.
const PROCESS_EUID = typeof process.geteuid === "function" ? process.geteuid() : null;


function createPrivateKeyFile(keyFile, record) {
  const flags =
    fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | (fsConstants.O_NOFOLLOW ?? 0);
  let fd;
  try {
    // O_EXCL makes any earlier observation non-authoritative by design: if a pathname appears
    // before this open, creation fails. O_NOFOLLOW also refuses a symlink at the final component.
    // All permission and write operations use this same descriptor, never the checked path.
    fd = openSync(keyFile, flags, 0o600);
    fchmodSync(fd, 0o600);
    writeFileSync(fd, jsonStringify(record, null, 2), "utf8");
    fsyncSync(fd);
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
}

/**
 * loadOrCreateKeyFile — persisted-signing-identity loader shared by every caller in this repo
 * that offers a `--key-file` flag (packages/mcp-proxy's proxy.mjs, packages/signer-sidecar's
 * sidecar.mjs). MOVED here (not duplicated) from proxy.mjs so the CWE-367 symlink/TOCTOU
 * hardening below has exactly ONE implementation across every caller -- a future security fix to
 * this loader lands once, for everyone, instead of silently drifting between hand-copied
 * versions.
 *
 * Loads a persisted `{ kid, privateKey, publicKey }` signing identity from `keyFile`, or mints
 * one via the caller-supplied `mintKeyPair()` and persists it (mode 0600 -- it holds a private
 * key) if the file does not exist yet.
 *
 * SYMLINK / TOCTOU HARDENING (CWE-367): a naive `existsSync` -> `readFileSync`/`writeFileSync`
 * FOLLOWS a symlink sitting at `keyFile` and never checks the existing file's permissions. An
 * attacker with write access to the DIRECTORY holding `keyFile` (but not to wherever the operator
 * actually intends the secret to live) could plant a symlink there -- pointing either at an
 * EXISTING file (get it silently clobbered with new key material + forced to 0600) or at a
 * location that does NOT exist yet (get the newly-generated PRIVATE KEY redirected to an
 * attacker-readable path). Fixed by:
 *   - A single `openSync(keyFile, O_RDONLY | O_NOFOLLOW)` replaces `existsSync` + `readFileSync`
 *     entirely: this is simultaneously the "does something exist here" check AND the read, with
 *     NO separate check-then-open gap for a race to land in. `O_NOFOLLOW` makes the open itself
 *     fail (`ELOOP`) if `keyFile` is a symlink, whether it resolves to an existing target or is
 *     dangling.
 *   - The resulting fd is `fstatSync`'d (not a second `lstatSync`/`statSync` on the PATH, which
 *     would reopen the TOCTOU window) to confirm it's a regular file with no group/other
 *     permission bits set -- a private key file the operator left world/group-readable is
 *     refused, not silently trusted.
 *   - The create path opens exactly once with `O_CREAT|O_EXCL|O_WRONLY|O_NOFOLLOW`, then writes,
 *     permission-pins and fsyncs through that descriptor. No path-based chmod follows the write,
 *     so an attacker cannot swap the pathname between create and permission hardening.
 *
 * @param {{ keyFile: string, mintKeyPair: () => { kid: string, privateKey: string, publicKey: string }, callerLabel?: string }} options
 */
export function loadOrCreateKeyFile({ keyFile, mintKeyPair, callerLabel = "loadOrCreateKeyFile" }) {
  if (!keyFile) throw new Error(`${callerLabel}: \`keyFile\` is required`);
  if (typeof mintKeyPair !== "function") throw new Error(`${callerLabel}: \`mintKeyPair\` is required`);

  // O_NOFOLLOW (POSIX-only; `0` on a platform lacking it, in which case this degrades to a plain
  // read-only open -- no worse than the pre-fix behavior on that platform, but the O_EXCL
  // create-path below stays protective everywhere Node runs, since O_EXCL's symlink refusal is
  // POSIX-universal).
  // O_NONBLOCK so a FIFO planted at `--key-file` cannot HANG this open. Measured 2026-08-12: with a
  // FIFO at the path and no writer, `open(fifo, O_RDONLY)` never returned — the loader was still
  // blocked when a 12-second cap killed it, which is a startup-stall primitive for anyone who can
  // create a file where the key is expected. The regular-file guard below is correct but sits
  // DOWNSTREAM of that block, so it never got to run. With O_NONBLOCK the same case returns in
  // milliseconds and the existing guard fires and refuses. Measured no-op on a regular file.
  const READONLY_NOFOLLOW = fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0) | (fsConstants.O_NONBLOCK ?? 0);

  let fd = null;
  try {
    // The key path can point into a caller-owned mkdtemp directory in tests. The descriptor-level
    // O_NOFOLLOW checks below, exclusive create, and 0600 permissions make that use safe; the
    // generic query does not model those controls across callers.
    // codeql[js/insecure-temporary-file]
    fd = openSync(keyFile, READONLY_NOFOLLOW);
  } catch (err) {
    if (thrownCode(err) === "ELOOP") {
      throw new Error(
        `${callerLabel}: --key-file "${keyFile}" is a symlink -- refusing to follow it (CWE-367 symlink-attack guard). Point --key-file directly at the intended regular file.`,
      );
    }
    if (thrownCode(err) !== "ENOENT") throw err;
    // fall through: genuinely nothing at this path yet -- the create branch below runs.
  }

  if (fd !== null) {
    try {
      const st = fstatSync(fd);
      if (!st.isFile()) {
        throw new Error(`${callerLabel}: --key-file "${keyFile}" is not a regular file -- refusing to load a signing identity from a special file`);
      }
      // OWNER. This loader never had one, and mode alone is NOT an owner test: `0o600 & 0o077` is
      // 0, so a mode-0600 key file planted by a DIFFERENT uid passed every check here and a
      // root-run proxy would adopt it as its SIGNING IDENTITY — the one secret whose entire job is
      // to be unforgeable. Root-owned is accepted for the same reason config-artifact.mjs accepts
      // it: a root-provisioned secret is the operator's own provisioning, not a foreign plant.
      if (PROCESS_EUID !== null && st.uid !== PROCESS_EUID && st.uid !== 0) {
        throw new Error(
          `${callerLabel}: --key-file "${keyFile}" is owned by uid ${numToString(st.uid, 10)}, not by this process (uid ${numToString(PROCESS_EUID, 10)}) or root -- refusing to load a private signing identity from a file this process does not own.`,
        );
      }
      // MASK — DELIBERATELY STRICTER THAN config-artifact.mjs. DO NOT CONSOLIDATE THE TWO LOADERS.
      // This line denies on 0o077: ANY group or other bit, READ included. config-artifact.mjs's own
      // mode test denies on 0o022 — WRITE bits only — and that is correct THERE, because a rule set
      // others can merely read is still a usable rule set. A private key others can read is not a
      // private key. Both loaders were run against ONE 0644 file holding a private key (2026-08-12):
      // this loader REFUSED it, readConfigArtifact ACCEPTED it and readConfigJson handed the
      // privateKey field straight back. So routing --key-file through
      // readConfigJson/readConfigArtifact to "remove the duplication" would silently start accepting
      // world-readable private keys while reading like cleanup. The duplication IS the control.
      // The mirror of this note belongs beside config-artifact.mjs's own 0o022 mask; it is not
      // written there in this change because that file was under concurrent edit, so whoever
      // touches it next should carry the note across.
      if ((st.mode & 0o077) !== 0) {
        throw new Error(
          `${callerLabel}: --key-file "${keyFile}" is readable/writable by group or others (mode 0${(st.mode & 0o777).toString(8)}) -- refusing to load a private key from a loosely-permissioned file. chmod 600 it first.`,
        );
      }
      let raw;
      try {
        raw = jsonParse(readFileSync(fd, "utf8"));
      } catch (err) {
        throw new Error(`${callerLabel}: --key-file "${keyFile}" is not valid JSON (${describeThrown(err)})`);
      }
      if (!raw || typeof raw.kid !== "string" || typeof raw.privateKey !== "string" || typeof raw.publicKey !== "string") {
        throw new Error(`${callerLabel}: --key-file "${keyFile}" is malformed (expected { kid, privateKey, publicKey })`);
      }
      return raw;
    } finally {
      closeSync(fd);
    }
  }

  // First run against this path: mint a stable identity ONCE (not tied to any one call/session --
  // the whole point of a persisted key is that it outlives any one process lifetime) and
  // persist it.
  const kp = mintKeyPair();
  const record = { kid: kp.kid, privateKey: kp.privateKey, publicKey: kp.publicKey };
  createPrivateKeyFile(keyFile, record);
  return record;
}
