import { readFileSync, writeFileSync, chmodSync, openSync, fstatSync, closeSync, constants as fsConstants } from "node:fs";

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
 *   - The create-path's `writeFileSync(..., { flag: "wx" })` (`O_CREAT|O_EXCL|O_WRONLY`) is
 *     POSIX-specified to refuse to create THROUGH a symlink at the target path -- dangling or
 *     not -- even if one is planted in the gap between the `openSync` check above and this write:
 *     it fails closed with `EEXIST` instead of silently redirecting the newly-generated private
 *     key.
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
  writeFileSync(keyFile, JSON.stringify(record, null, 2), { mode: 0o600, flag: "wx" });
  // Belt-and-suspenders: writeFileSync's `mode` option only governs the permissions a NEWLY
  // created file gets (subject to umask); an explicit chmod pins it to 0600 regardless.
  chmodSync(keyFile, 0o600);
  return record;
}
