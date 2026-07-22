import { readFileSync, writeFileSync, openSync, fstatSync, fchmodSync, fsyncSync, closeSync, constants as fsConstants } from "node:fs";

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
  const READONLY_NOFOLLOW = fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0);

  let fd = null;
  try {
    // The key path can point into a caller-owned mkdtemp directory in tests. The descriptor-level
    // O_NOFOLLOW checks below, exclusive create, and 0600 permissions make that use safe; the
    // generic query does not model those controls across callers.
    // codeql[js/insecure-temporary-file]
    fd = openSync(keyFile, READONLY_NOFOLLOW);
  } catch (err) {
    if (err.code === "ELOOP") {
      throw new Error(
        `${callerLabel}: --key-file "${keyFile}" is a symlink -- refusing to follow it (CWE-367 symlink-attack guard). Point --key-file directly at the intended regular file.`,
      );
    }
    if (err.code !== "ENOENT") throw err;
    // fall through: genuinely nothing at this path yet -- the create branch below runs.
  }

  if (fd !== null) {
    try {
      const st = fstatSync(fd);
      if (!st.isFile()) {
        throw new Error(`${callerLabel}: --key-file "${keyFile}" is not a regular file -- refusing to load a signing identity from a special file`);
      }
      if ((st.mode & 0o077) !== 0) {
        throw new Error(
          `${callerLabel}: --key-file "${keyFile}" is readable/writable by group or others (mode 0${(st.mode & 0o777).toString(8)}) -- refusing to load a private key from a loosely-permissioned file. chmod 600 it first.`,
        );
      }
      let raw;
      try {
        raw = JSON.parse(readFileSync(fd, "utf8"));
      } catch (err) {
        throw new Error(`${callerLabel}: --key-file "${keyFile}" is not valid JSON (${err.message})`);
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
  const CREATE_PRIVATE_NOFOLLOW =
    fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | (fsConstants.O_NOFOLLOW ?? 0);
  let createFd;
  try {
    // O_EXCL makes the earlier ENOENT result non-authoritative by design: if any pathname appears
    // before this open, creation fails. O_NOFOLLOW also refuses a symlink at the final component.
    // All permission and write operations then use this same descriptor, never the checked path.
    // codeql[js/file-system-race]
    createFd = openSync(keyFile, CREATE_PRIVATE_NOFOLLOW, 0o600);
    fchmodSync(createFd, 0o600);
    writeFileSync(createFd, JSON.stringify(record, null, 2), "utf8");
    fsyncSync(createFd);
  } finally {
    if (createFd !== undefined) closeSync(createFd);
  }
  return record;
}
