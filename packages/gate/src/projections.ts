/**
 * NOA Gate — ENFORCED-mode display projections (D22).
 *
 * A projection is a REGISTERED, reviewed, pinned adapter — **never caller-supplied code**. Each is
 * side-effect-free, deterministic, network-less and versioned, and its identity (`{id,version,hash}`)
 * is bound into the signed Hold Envelope.
 *
 * ─── WHAT `hash` COMMITS TO — ADR-0006-A PART A, owner-decided 2026-08-03 ────────────────────────
 *
 * `hash` is a sha256 over `{id, version, kind, implementation}`, where `implementation` is the
 * sha256 of the adapter's EMITTED SOURCE TEXT. Change `run()` in any way and the identity changes.
 *
 * HISTORY, KEPT BECAUSE THE CORRECTION IS THE POINT. Until this change `hash` covered `{id, version,
 * kind}` — THREE SELF-DECLARED STRINGS — and nothing about `run()`. An adapter with entirely
 * different behaviour reproduced the shipped identity byte-for-byte, so the signed envelope pinned a
 * NAME, not a renderer. Before THAT, this docstring claimed the opposite ("a verifier can pin which
 * reviewed adapter ran without re-running it") while the code did no such thing — a load-bearing
 * false claim, corrected 2026-07-30 to say so plainly and deferred to ADR-0006. The owner took that
 * decision on 2026-08-03 and this is its implementation.
 *
 * ⚠ WHAT IT STILL DOES NOT DO, STATED WITH THE SAME FORCE THE OLD CAVEAT HAD:
 *
 *   • It is a WITHIN-BUILD commitment. The digest is computed by the same process that runs the
 *     adapter, so it proves the identity TRACKS the artifact — not that any particular artifact is
 *     the reviewed one. An off-box verifier can only compare it against a published expected value;
 *     it cannot recompute it without the build.
 *   • It commits to the EMITTED artifact, not to the TypeScript source. A toolchain change that
 *     alters emit without altering behaviour DOES change the identity. That is the correct semantics
 *     for an artifact commitment and it is the price of the property — `test/projection.test.ts`
 *     names both legitimate causes of drift so a compiler bump is diagnosed, not investigated.
 *   • It says nothing about WHO reviewed the artifact. An authenticated, versioned ProjectionBundle
 *     manifest is still ADR-0006 stage 8 and still not built here.
 *   • It commits to `run()`'s OWN source text only. Behaviour reached through free variables — the
 *     allowlist table, `commandView`, the canonicalizer — is outside the commitment: an edit there
 *     changes behaviour without moving the identity. The identity is a NECESSARY signal for
 *     substitution, never a SUFFICIENT one for equivalence. Whole-bundle commitment is the stage-8
 *     manifest.
 *
 *     ⚠ This bullet exists because the sentence above ("change `run()` in any way and the identity
 *     changes") is true but invites a FALSE converse: *identity unchanged ⇒ behaviour unchanged*.
 *     Concretely — add `"/bin/sh": "LOW"` to `REVIEWED_EXECUTABLES` and the risk floor of every shell
 *     invocation drops while both identities stay byte-identical. Widening the hash to cover the
 *     module text was considered and REFUSED: it is stage-8 shape smuggled in, and it would make
 *     every comment edit an identity event.
 *
 * The registry is sealed at module load (B-3, below), so within one process there is exactly one
 * adapter per canonical and the identity it advertises is the identity of the code that will run.
 *
 * Alpha ships ONE ENFORCED adapter, `noa.command.exec/1` — a shell-command bind (D14: the command
 * string alone is insufficient; the canonical param set is executable real-path + argv + cwd +
 * allowed-env-hash + stdin-hash + tenant + target-env). The gate CANONICALIZES the real params
 * itself and computes `paramsHash`; a caller-supplied `paramsHash` that disagrees is REJECTED
 * (ENFORCED never trusts the caller's hash).
 */

import { canonicalize, sha256Prefixed, parseDocument } from "noa-approval-artifacts";
// R8-08: reached through the ALREADY-PUBLISHED `intrinsics` namespace (src/index.ts:81)
// rather than a new top-level export. Adding one tripped L1 and the C2 registry test —
// correctly: a new name on a published surface is a permanent compatibility commitment,
// and this needs no new name at all.
import { intrinsics } from "noa-receipt";
const { hasOwn, strIncludes } = intrinsics;

/**
 * The captured source-text reader for the implementation-artifact digest (ADR-0006-A part A).
 *
 * Module-load capture, for the same reason every other builtin on a decision path is captured: this
 * function's result becomes the ADAPTER'S IDENTITY, so a replaced `Function.prototype.toString`
 * would let whatever installed it choose what the reviewed adapter is called. `intrinsics` has no
 * entry for it, and adding one is a permanent commitment on a PUBLISHED surface (R8-08) for a need
 * that exists only in this unpublished package — so the capture is local, which is the same
 * discipline at the right scope.
 */
const funcToString = Function.prototype.toString;
import type { ProjectionId, RiskClass } from "./types.js";

export interface ProjectionResult {
  ok: true;
  paramsHash: string;
  display: Record<string, unknown>;
  actionSchema: ProjectionId;
  displayProjection: ProjectionId;
  /**
   * B-1 (owner decision 2026-07-30) — RISK DERIVED INSIDE THE TRUSTED BOUNDARY.
   *
   * The projection is the derivation point that ALREADY EXISTS: it is the only component that has
   * validated and canonicalized the real params, so it is the only one that can classify what the
   * action actually does. A caller hint may RAISE this floor and may never lower it.
   *
   * Before this existed, `engine.ts` took `riskClass` from caller input, validated SET MEMBERSHIP
   * ONLY, and `approval-artifacts/src/verify.ts:133-138` derived the REQUIRED APPROVER ROLE from it —
   * so the caller chose both its own enforcement tier and its own approver. Measured: the identical
   * `rm -rf /srv` was refused at CRITICAL and granted at LOW by an approve-high device.
   */
  derivedRisk: RiskClass;
}
export interface ProjectionError {
  ok: false;
  error: string;
}

/**
 * Shell-exec risk floor, derived from the executable and argv the adapter has already validated.
 *
 * ⚠ REWRITTEN 2026-07-30 after codex adjudication F-3 (HIGH), reproduced by the lead. THE PREVIOUS
 * VERSION VIOLATED A DECISION I HAD WRITTEN MYSELF. `docs/OWNER-DECISION-REGISTER.md:79-80` states
 * that an unmatched action "must classify to the HIGHEST tier and fail closed — otherwise the default
 * is the vulnerability." The previous implementation was a DENYLIST of nine binaries and four flags
 * that returned `HIGH` for everything unmatched, and I documented that as an accepted "lower bound"
 * as though disclosure discharged the requirement. It does not. Measured hole:
 *
 *     executable /usr/bin/python3, argv ["-c", "import shutil; shutil.rmtree('/srv')"], hint LOW
 *     -> status 201, effectiveRisk HIGH  => an approve-high operator could authorize a recursive delete
 *
 * Node, Perl, BusyBox, `find -delete` and any vendor CLI evade a denylist identically. **A denylist
 * cannot fail closed by construction**: its default is "unrecognised, therefore fine".
 *
 * NOW AN ALLOWLIST. Only executables that have been explicitly reviewed carry a floor below the top.
 * Everything else — including every interpreter capable of arbitrary destruction — classifies to
 * `CRITICAL`, so the strongest approver is required and the caller cannot obtain a weaker one.
 *
 * WHAT THIS IS NOT. The allowlist is hard-coded here, so it is trusted CODE rather than authenticated
 * POLICY. A per-tenant authenticated classifier is ADR-0006 and is not built here. What changed is the
 * DIRECTION OF THE DEFAULT, which is the part the register actually requires.
 */
const REVIEWED_EXECUTABLES: Readonly<Record<string, RiskClass>> = Object.freeze(
  Object.assign(Object.create(null) as Record<string, RiskClass>, {
    // The one action this adapter ships for. Reviewed: a deploy driver, not an arbitrary interpreter.
    "/usr/local/bin/deploy": "HIGH" as RiskClass,
  }),
);

function classifyShellCommand(executable: string, argv: readonly string[]): RiskClass {
  // An explicitly destructive flag overrides any allowlist entry — the allowlist grants a floor for a
  // BINARY, never for an arbitrary invocation of it.
  //
  // INDEX WALK, not `for..of`. `for..of` dispatches through `Symbol.iterator`, so on a caller-reachable
  // array the ITERATOR decides which elements the classifier ever sees — a skipping iterator hides
  // `-rf` from this loop while the hash still binds it. This function is only ever called with the
  // render node's own array now, but the discipline is applied uniformly rather than argued per-caller:
  // the whole ADR-0005 defect record is of controls that were safe until one caller changed.
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "-rf" || a === "-fr" || a === "--force" || a === "--no-preserve-root") return "CRITICAL";
  }
  if (hasOwn(REVIEWED_EXECUTABLES, executable)) {
    return REVIEWED_EXECUTABLES[executable]!;
  }
  // FAIL CLOSED. Unreviewed executable ⇒ highest tier. This is the register's requirement and the
  // reason the previous denylist was wrong.
  return "CRITICAL";
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

/**
 * Upper bound on argv length, read ONCE before the capture walk.
 *
 * Not a DoS control — the gate's `maxBodyBytes` (256 KiB) already bounds what can arrive over HTTP.
 * This exists because `getProjection()` is a PUBLIC export (`index.ts`), so `run()` is reachable
 * in-process with a `length` of any value, including one an accessor changes mid-walk. Reading it once
 * into a bounded local is what makes the walk's extent a decision the caller cannot revise. 4096 is far
 * beyond any legitimate deploy invocation and far below anything that could exhaust memory.
 */
const MAX_ARGV = 4096;

const CANON_ENCODER = new TextEncoder();

/**
 * THE RENDER NODE — parse OUR OWN canonical bytes back, so the display and the hash cannot diverge.
 *
 * `paramsHash` is `sha256(canonical)`. Everything the human is shown, and the risk class the approver
 * tier is derived from, comes from `commandView(canonical)`. One immutable input, three outputs. The
 * previous shape read the `argvSnapshot` variable three separate times (hash, `join`, classify), which
 * is safe only while that variable is genuinely ours — and the ArraySpeciesCreate finding is precisely
 * the case where it was not.
 *
 * `parseDocument` is the kernel's strict boundary, reused rather than re-implemented (KURAL 5). Parsing
 * a string we produced ourselves one line earlier cannot fail on hostile input; the `ok:false` arms are
 * kept and returned rather than asserted away, because "this cannot fail" is how the previous
 * `Object.freeze` came to be treated as sufficient.
 *
 * ⚠ THIS NODE SURVIVES ITS OWN KNOCKOUT TODAY, AND THAT IS RECORDED RATHER THAN GLOSSED.
 * Measured (ADR-0005 Slice 2): bypassing this node so the display and the risk class read the
 * PRE-canonical `argvSnapshot` object leaves the suite at 198 pass / 2 fail — IDENTICAL to the tree
 * with it. Zero tests detect its removal, because the capture-once walk above independently closes
 * every split reachable today: once the snapshot is a plain array literal built in one read per index,
 * `join()` and the indices cannot disagree.
 *
 * By this repository's own standard that makes it a STRUCTURAL INVARIANT, not a measured control —
 * `wrapper.ts` deleted two defences on exactly this evidence ("Redundant defences read as prudence and
 * measure as blindness"). The difference from that case, and the reason it is kept: there, the
 * redundant defence made the OTHER control unobservable. Here it does not — knocking out capture-once
 * alone still turns two tests RED with this node in place. So it hides nothing; it removes a class of
 * FUTURE defect (a fourth read of a caller-influenced value added later cannot diverge, because there
 * is no second input to diverge over), which is the same "make it unwritable" argument as the Slice 1
 * signature change.
 *
 * FLAGGED FOR THE ARCHITECT rather than decided here: keeping an unobservable defence is in tension
 * with the anti-redundancy rule, and removing it would be improvising a different design than the one
 * that was settled. The knockout matrix is:
 *     A  restore Array.prototype.slice        -> capture-once + length-drift RED
 *     B  bypass this render node              -> NOTHING red  (survives)
 *     A+B  the true pre-Slice-2 state         -> capture-once + length-drift + species RED
 */
type CommandView =
  | { ok: true; executable: string; argv: readonly string[]; argsJoined: string; cwd: string; targetEnv: string }
  | { ok: false; error: string };

function commandView(canonical: string): CommandView {
  const parsed = parseDocument(CANON_ENCODER.encode(canonical), "canonical params");
  if (!parsed.ok) return { ok: false, error: `canonical params did not re-parse: ${parsed.reason}` };
  const v = parsed.value;
  if (typeof v !== "object" || v === null || Array.isArray(v)) {
    return { ok: false, error: "canonical params are not an object" };
  }
  const o = v as Record<string, unknown>;
  const executable = asString(o["executable"]);
  const cwd = asString(o["cwd"]);
  const targetEnv = asString(o["targetEnv"]);
  const rawArgv = o["argv"];
  if (!executable || !cwd || !targetEnv || !Array.isArray(rawArgv)) {
    return { ok: false, error: "canonical params lost a required field" };
  }
  // Index walk + explicit concatenation rather than `join`. `join` is a method, and the whole finding
  // this node closes was a method — `Hostile.prototype.join` — answering differently from the indices.
  const argv: string[] = [];
  let argsJoined = "";
  for (let i = 0; i < rawArgv.length; i++) {
    const a: unknown = rawArgv[i];
    if (typeof a !== "string") return { ok: false, error: `canonical params: argv[${i}] is not a string` };
    argv[i] = a;
    argsJoined = i === 0 ? a : `${argsJoined} ${a}`;
  }
  Object.freeze(argv);
  return { ok: true, executable, argv, argsJoined, cwd, targetEnv };
}

/**
 * Digest of the adapter's implementation artifact — the byte string the engine will actually run.
 *
 * FAIL CLOSED AT MODULE LOAD, deliberately. If the artifact cannot be measured — a native function,
 * a `bind` wrapper, a Proxy whose `toString` lies — the honest options are to throw or to ship an
 * identity that silently commits to nothing. The second is the defect this whole change exists to
 * remove, so it throws, and it throws at IMPORT time rather than at approval time: a broken
 * environment fails loudly before a human is ever asked to approve anything.
 */
function implementationDigest(implementation: unknown): string {
  if (typeof implementation !== "function") {
    throw new TypeError("projection identity: the implementation must be a function");
  }
  const source: unknown = funcToString.call(implementation);
  if (typeof source !== "string" || source.length === 0 || strIncludes(source, "[native code]")) {
    throw new TypeError(
      "projection identity: the implementation artifact is not measurable (native, bound or proxied " +
        "source text). Refusing to construct an identity that would commit to nothing.",
    );
  }
  return sha256Prefixed(source);
}

/**
 * The pinned identity of a projection/schema — stable, test-vectored, and bound to the artifact.
 *
 * `implementation` is REQUIRED and is the same `run()` for both the schema and the display identity.
 * That is not a shortcut: in this adapter `run()` IS both the validator and the renderer, so it is
 * the artifact for both roles. Giving the schema identity a weaker commitment than the display one
 * would fix a site and leave its neighbour — the pattern that produced a CRITICAL in three
 * consecutive releases of this project.
 */
function projectionId(id: string, version: number, kind: string, implementation: unknown): ProjectionId {
  return { id, version, hash: idHash({ id, version, kind, implementation: implementationDigest(implementation) }) };
}

function asString(v: unknown): string | undefined {
  return typeof v === "string" && v.length > 0 ? v : undefined;
}

/** `noa.command.exec/1` — the alpha ENFORCED shell-command adapter (D14 bind).
 *
 *  ⚠ WRAPPED IN AN IIFE, AND THE REASON IS THE IDENTITY (ADR-0006-A part A). The identity is now
 *  derived FROM `run`, and inside an object literal `run` does not exist yet when the sibling
 *  `projectionId(...)` initializers are evaluated. Defining `run` first and the identities second is
 *  the whole change; the body below is byte-identical and at the same indentation, so a reviewer can
 *  diff it as the whitespace-free change it is. `this` still resolves to the projection at call time
 *  — every caller reaches this function as `projection.run(...)`. */
const commandExec: DisplayProjection = (() => {
  function run(this: DisplayProjection, params: unknown): ProjectionResult | ProjectionError {
    if (typeof params !== "object" || params === null || Array.isArray(params)) {
      return { ok: false, error: "params must be an object" };
    }
    const p = params as Record<string, unknown>;
    const executable = asString(p["executable"]);
    // ─── F-05 (Fable adjudication, HIGH, 2026-07-30): READ ONCE, VALIDATE WITH OUR OWN LOOP ───────
    // This line previously read `p["argv"]` TWICE — once for `Array.isArray`, once for the value
    // actually used — and validated elements via `argv.every(...)`, which dispatches through the
    // CALLER's `every`. Measured consequences: a nested array `[["-rf","/srv"]]` passed the type check
    // by type, rendered as `-rf,/srv` to the human, classified HIGH instead of CRITICAL, and obtained
    // HUMAN_APPROVED plus a grant from an approve-high device; `[{a:1}]` made the human authorize
    // `[object Object]`. The comment below used to claim ".every() above already validated each element
    // is a string, so the copy is scalars only" — that claim was false.
    const rawArgv: unknown = p["argv"];
    const argv = Array.isArray(rawArgv) ? (rawArgv as unknown[]) : undefined;
    const cwd = asString(p["cwd"]);
    const targetEnv = asString(p["targetEnv"]);
    if (!executable || !argv || !cwd || !targetEnv) {
      return { ok: false, error: "command params require { executable, argv:string[], cwd, targetEnv }" };
    }
    // ─── CAPTURE-ONCE (ADR-0005 Slice 2) ─────────────────────────────────────────────────────────
    // What stood here was a VALIDATE-then-COPY pair:
    //
    //     for (let i = 0; i < argv.length; i++) if (typeof argv[i] !== "string") return …;   // read 1
    //     const argvSnapshot = Object.freeze(Array.prototype.slice.call(argv) as string[]);  // read 2
    //
    // TWO defects, both measured on the tree this replaces.
    //
    // (a) TWO READS PER INDEX. The value that was VALIDATED is not the value that was COPIED. A Proxy
    //     or accessor answers the type check with a string and the copy with anything at all.
    //
    // (b) `Array.prototype.slice` DOES NOT PRODUCE OUR ARRAY. It calls ArraySpeciesCreate, which reads
    //     `argv.constructor[Symbol.species]` — CALLER-CONTROLLED — and constructs the "snapshot" with
    //     it. So the frozen copy was an ATTACKER INSTANCE, and `Object.freeze` on an attacker instance
    //     freezes its properties, not its methods. Measured through the PUBLIC `getProjection().run()`:
    //
    //         class Hostile extends Array { join() { return "--help"; } }
    //         argv = ["-rf", "/srv"]; argv.constructor = { [Symbol.species]: Hostile };
    //
    //         display.Args (human reads) : "--help"
    //         paramsHash (gate binds)    : sha256:2234882…  === hash of "-rf /srv"
    //
    //     The human authorized `--help` and the grant bound `rm -rf /srv`. `Object.freeze` was
    //     decorative: the split lands in `join()`, which is a method, not a property.
    //
    // NOW: `length` is read ONCE into a bounded local, then ONE index walk captures and validates in
    // the SAME read into a fresh array literal. No `slice`, no `every`, no `map`, no spread, no
    // `for..of` — every one of those dispatches through something the caller can supply. A hole or a
    // shrinking `length` reads back `undefined` and is refused by the same type test, so length drift
    // needs no separate check.
    const rawLen: unknown = (argv as { length?: unknown }).length;
    if (typeof rawLen !== "number" || !Number.isInteger(rawLen) || rawLen < 0 || rawLen > MAX_ARGV) {
      return { ok: false, error: `command params: argv length must be an integer in [0, ${MAX_ARGV}]` };
    }
    const n: number = rawLen;
    const argvSnapshot: string[] = [];
    for (let i = 0; i < n; i++) {
      const v: unknown = argv[i]; // THE ONE READ of this index. Validated and kept as the same value.
      if (typeof v !== "string") {
        return { ok: false, error: `command params: argv[${i}] is not a string` };
      }
      argvSnapshot[i] = v;
    }
    Object.freeze(argvSnapshot);

    const snapshot = {
      executable,
      argv: argvSnapshot,
      cwd,
      targetEnv,
      allowedEnvHash: asString(p["allowedEnvHash"]) ?? null,
      stdinHash: asString(p["stdinHash"]) ?? null,
    };

    // ─── THE RENDER NODE (ADR-0005 Slice 2) ──────────────────────────────────────────────────────
    // The hash, the display and the risk class are now all derived from ONE immutable value: the JCS
    // canonical form. Previously each read `argvSnapshot` separately, so "they agree" was a property of
    // the snapshot being trustworthy — and (b) above is exactly the case where it was not. Now they
    // cannot disagree BY CONSTRUCTION, because `paramsHash` is a hash OF `canonical` and the display is
    // parsed FROM `canonical`. There is no second input for them to diverge over.
    let canonical: string;
    try {
      canonical = canonicalize(snapshot);
    } catch {
      return { ok: false, error: "params are not JCS-canonicalizable" };
    }
    const paramsHash = sha256Prefixed(canonical);
    const view = commandView(canonical);
    if (!view.ok) return { ok: false, error: view.error };

    // Derived display — max 4–5 fields (§12), gate-authored (never caller free text).
    const display: Record<string, unknown> = {
      Action: this.canonical,
      Command: view.executable,
      Args: view.argsJoined,
      Cwd: view.cwd,
      Env: view.targetEnv,
    };
    return {
      ok: true, paramsHash, display,
      actionSchema: this.actionSchema, displayProjection: this.displayProjection,
      derivedRisk: classifyShellCommand(view.executable, view.argv),
    };
  }
  return {
    canonical: "noa.command.exec",
    actionSchema: projectionId("noa.command.exec.schema", 1, "actionSchema", run),
    displayProjection: projectionId("noa.command.exec.display", 1, "displayProjection", run),
    run,
  };
})();

/**
 * B-3 (owner decision 2026-07-30) — THE TRUSTED PROJECTION REGISTRY IS SEALED AT MODULE LOAD.
 *
 * WHAT WAS HERE. A `new Map(...)` plus an EXPORTED `registerProjection` doing `REGISTRY.set`. No
 * freeze, no already-registered guard, no authentication, and zero callers anywhere in the
 * repository — pure attack surface. One call from any dependency running as the application's uid
 * replaced a REVIEWED display adapter while the signed envelope still advertised the reviewed
 * identity. Measured end-to-end: the human saw a routine deploy, the gate signed a grant for
 * `/bin/rm -rf /` (`docs/GATE-PROVENANCE-FINDINGS-2026-07-30.md`, Fable QA F-1).
 *
 * It also broke this project's OWN TEST SUITE: the regression test that poisons the registry left it
 * poisoned, and every later test could no longer create a hold. A registry any code can overwrite has
 * no isolation — not even from the tests written to prove it needs isolation.
 *
 * WHY A FROZEN NULL-PROTOTYPE OBJECT AND NOT A FROZEN MAP. `Object.freeze` does NOT disable
 * `Map.prototype.set`. This repository already learned that and wrote it down —
 * `packages/approval-artifacts/src/inert-core/inert.ts:131` — and `frozenTable` REFUSES a Map or Set
 * at construction for exactly this reason. Reusing that primitive (KURAL 5) rather than writing a
 * second freezer is what makes the seal load-bearing instead of decorative.
 *
 * SCOPE. Sealing is ADR-0005 (minimal closure of a measured defect). An authenticated, versioned,
 * integrity-pinned ProjectionBundle manifest — the FUTURE extensibility path — is ADR-0006 and is
 * deliberately NOT built here.
 */
/** Freeze a projection and every nested plain object it carries, transitively. Methods are frozen as
 *  values but not traversed into.
 *
 *  ⚠ WHY NOT `frozenTable` FROM inert-core (KURAL 5 — reuse was TRIED FIRST and REFUSED).
 *  `frozenTable` deliberately REJECTS functions: it exists for DATA tables whose every leaf must be a
 *  scalar. A projection's whole purpose is to carry `run()`, so `frozenTable` threw at
 *  `<projection-registry>.noa.command.exec.run`. That refusal is correct and is left intact — the
 *  right conclusion is that a projection is not a frozenTable subject, not that frozenTable should be
 *  loosened. Loosening it would weaken every DATA table in the kernel to seal one registry here. */
function sealProjection<T>(v: T): T {
  if (v === null || (typeof v !== "object" && typeof v !== "function")) return v;
  if (typeof v === "object") {
    for (const k of Object.keys(v as Record<string, unknown>)) {
      sealProjection((v as Record<string, unknown>)[k]);
    }
  }
  return Object.freeze(v);
}

const REGISTRY: Readonly<Record<string, DisplayProjection>> = Object.freeze(
  Object.assign(Object.create(null) as Record<string, DisplayProjection>, {
    [commandExec.canonical]: sealProjection(commandExec),
  }),
);

/**
 * The only accessor. Returns the frozen entry itself — `frozenTable` froze it transitively, so a
 * caller cannot mutate what it receives, and there is no path back to the registry container.
 *
 * NOTE the deliberate absence: there is NO `registerProjection`, and no other export in this module
 * returns or closes over `REGISTRY`. Mechanically checked by the L9-B gate and by
 * `test/provenance-regression.test.ts`.
 */
export function getProjection(canonical: string): DisplayProjection | undefined {
  return hasOwn(REGISTRY, canonical) ? REGISTRY[canonical] : undefined;
}
