/**
 * NOA Gate — ENFORCED-mode display projections (D22).
 *
 * A projection is a REGISTERED, reviewed, pinned adapter — **never caller-supplied code**. Each is
 * side-effect-free, deterministic, network-less and versioned, and its identity (`{id,version,hash}`)
 * is bound into the signed Hold Envelope. `hash` is a stable sha256 over the adapter's identity
 * descriptor (test-vectored — see test/projection.test.ts), NOT over its runtime output, so a
 * verifier can pin "which reviewed adapter ran" without re-running it.
 *
 * Alpha ships ONE ENFORCED adapter, `noa.command.exec/1` — a shell-command bind (D14: the command
 * string alone is insufficient; the canonical param set is executable real-path + argv + cwd +
 * allowed-env-hash + stdin-hash + tenant + target-env). The gate CANONICALIZES the real params
 * itself and computes `paramsHash`; a caller-supplied `paramsHash` that disagrees is REJECTED
 * (ENFORCED never trusts the caller's hash).
 */

import { canonicalize, sha256Prefixed } from "noa-approval-artifacts";
import type { ProjectionId } from "./types.js";

export interface ProjectionResult {
  ok: true;
  paramsHash: string;
  display: Record<string, unknown>;
  actionSchema: ProjectionId;
  displayProjection: ProjectionId;
}
export interface ProjectionError {
  ok: false;
  error: string;
}

export interface DisplayProjection {
  /** the `action.canonical` this adapter is registered for. */
  canonical: string;
  actionSchema: ProjectionId;
  displayProjection: ProjectionId;
  /** validate + canonicalize the real params, compute paramsHash, derive the display. */
  run(params: unknown): ProjectionResult | ProjectionError;
}

function idHash(descriptor: Record<string, unknown>): string {
  return sha256Prefixed(canonicalize(descriptor));
}

/** The pinned identity of a projection/schema — stable, test-vectored. */
function projectionId(id: string, version: number, kind: string): ProjectionId {
  return { id, version, hash: idHash({ id, version, kind }) };
}

function asString(v: unknown): string | undefined {
  return typeof v === "string" && v.length > 0 ? v : undefined;
}

/** `noa.command.exec/1` — the alpha ENFORCED shell-command adapter (D14 bind). */
const commandExec: DisplayProjection = {
  canonical: "noa.command.exec",
  actionSchema: projectionId("noa.command.exec.schema", 1, "actionSchema"),
  displayProjection: projectionId("noa.command.exec.display", 1, "displayProjection"),
  run(params: unknown) {
    if (typeof params !== "object" || params === null || Array.isArray(params)) {
      return { ok: false, error: "params must be an object" };
    }
    const p = params as Record<string, unknown>;
    const executable = asString(p["executable"]);
    const argv = Array.isArray(p["argv"]) ? (p["argv"] as unknown[]) : undefined;
    const cwd = asString(p["cwd"]);
    const targetEnv = asString(p["targetEnv"]);
    if (!executable || !argv || !argv.every((a) => typeof a === "string") || !cwd || !targetEnv) {
      return { ok: false, error: "command params require { executable, argv:string[], cwd, targetEnv }" };
    }
    // D14 immutable canonical snapshot → paramsHash (JCS-RFC8785, gate-computed).
    const snapshot = {
      executable,
      argv,
      cwd,
      targetEnv,
      allowedEnvHash: asString(p["allowedEnvHash"]) ?? null,
      stdinHash: asString(p["stdinHash"]) ?? null,
    };
    let paramsHash: string;
    try {
      paramsHash = sha256Prefixed(canonicalize(snapshot));
    } catch {
      return { ok: false, error: "params are not JCS-canonicalizable" };
    }
    // Derived display — max 4–5 fields (§12), gate-authored (never caller free text).
    const display: Record<string, unknown> = {
      Action: this.canonical,
      Command: executable,
      Args: (argv as string[]).join(" "),
      Cwd: cwd,
      Env: targetEnv,
    };
    return { ok: true, paramsHash, display, actionSchema: this.actionSchema, displayProjection: this.displayProjection };
  },
};

const REGISTRY = new Map<string, DisplayProjection>([[commandExec.canonical, commandExec]]);

export function getProjection(canonical: string): DisplayProjection | undefined {
  return REGISTRY.get(canonical);
}

export function registerProjection(p: DisplayProjection): void {
  REGISTRY.set(p.canonical, p);
}
