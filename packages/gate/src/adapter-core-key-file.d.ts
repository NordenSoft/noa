/**
 * Types for the ONE member of `noa-mcp-adapter-core`'s main entry point this package imports.
 *
 * `noa-mcp-adapter-core` is `.mjs` and ships `types` only for its subpath exports
 * (`./safe-throw`, `./tool-outcome-not-recorded`, `./side-effect-state`), so a NodeNext TypeScript
 * import of the main entry has no declaration to resolve. The alternative was to hand-copy
 * `key-file.mjs`'s CWE-367 symlink/TOCTOU hardening into this package — which is precisely what that
 * file's own docstring says NOT to do ("MOVED here, not duplicated … so a future security fix lands
 * once, for everyone, instead of silently drifting between hand-copied versions").
 *
 * So: one shared implementation, one narrow declaration. Only `loadOrCreateKeyFile` is declared —
 * anything else this package needs from that module should be added deliberately, not inherited.
 */
declare module "noa-mcp-adapter-core" {
  export function loadOrCreateKeyFile(options: {
    keyFile: string;
    mintKeyPair: () => { kid: string; privateKey: string; publicKey: string };
    callerLabel?: string;
  }): { kid: string; privateKey: string; publicKey: string };
}
