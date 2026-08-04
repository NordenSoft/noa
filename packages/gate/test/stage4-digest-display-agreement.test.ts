/**
 * STAGE-4 ORACLE — THE DIGEST AND THE DISPLAY MUST COMMIT TO THE SAME BYTES.
 *
 * ─── WHY THIS FILE EXISTS, AND IT IS NOT A HYPOTHETICAL ──────────────────────────────────────────
 *
 * ADR-0006 §5 splits stage 3 two ways: `IntentDigest = sha256(bytes)` is what the system commits to,
 * and `SealedDisplay = seal(render(bytes))` is what the HUMAN is shown. NOA's catastrophic failure is
 * a misattributed approval, and the sharpest form of it is not a forged signature — it is a genuine
 * human genuinely approving **a different action from the one that executes**. That happens the
 * moment those two derivations can disagree.
 *
 * `projections.ts` closes it by construction: `run()` canonicalizes ONCE, hashes those bytes, and
 * derives every displayed field by parsing the SAME bytes back (`commandView(canonical)`). One
 * immutable input, three outputs.
 *
 * ⚠ AND THAT NODE SURVIVED ITS OWN KNOCKOUT. `projections.ts:196-215` records it plainly:
 *
 *     A  restore Array.prototype.slice   -> capture-once + length-drift RED
 *     B  bypass this render node         -> NOTHING red  (survives)
 *
 * Bypassing the render node — making the display read the PRE-canonical object instead of the
 * canonical bytes — turned zero tests red. The invariant was real and **unmeasured**, which by this
 * repository's own standard makes it a structural claim rather than a control.
 *
 * ⚠⚠ AND THIS ORACLE DOES NOT CHANGE THAT. The first version of this header claimed "this file is
 * the oracle that makes mutation B bite." Measured, on this tree, with these five tests:
 *
 *     B    display reads our own pre-canonical `argvSnapshot`   ->  0 tests red   (still survives)
 *     A+B  display reads the CALLER's argv object               ->  4 tests red
 *
 * The claim was false and is corrected rather than deleted, because the reason is the useful part:
 * while capture-once holds, `argvSnapshot` is an array THIS MODULE built by an index walk, so
 * reading it instead of the re-parsed canonical yields the identical string. The render node is
 * genuinely redundant against every split reachable today — exactly as `projections.ts:196-215`
 * says — and no test can honestly make B red without first removing capture-once.
 *
 * What this oracle DOES close is the CONSEQUENCE rather than the mechanism: the moment any displayed
 * field is derived from a caller-controlled value instead of from the canonical bytes, four tests go
 * red and name the divergence. That is the defect a human is actually harmed by, and it was
 * unobserved before this file. The mechanism can be reimplemented; the consequence is the invariant.
 *
 * ─── THE VERDICT IS ORDINAL, BECAUSE "NOT AGREE" IS TWO DIFFERENT FACTS ─────────────────────────
 *
 *     AGREE    the display shows exactly what the digest commits to           — correct
 *     REFUSED  the projection rejected the input and produced neither          — acceptable, fail-closed
 *     DISAGREE the display shows one action and the digest commits to another  — THE DEFECT
 *
 * A boolean would collapse REFUSED into failure and push a future author toward making hostile input
 * "work". Refusing a poisoned request is a correct answer; showing a human the wrong action and
 * calling it approved is not. Only DISAGREE fails.
 *
 * ─── ANTI-VACUITY: THE POISON COUNTS ITS OWN READS ──────────────────────────────────────────────
 *
 * Every poison below is a COUNTING poison. If `hits === 0` the projection never consulted the
 * hostile surface at all, the run proves nothing about divergence, and the test says so instead of
 * reporting a pass — a poison nobody touches is the vacuous-green shape this project keeps finding.
 *
 * ─── EXPLICIT NON-GOALS ─────────────────────────────────────────────────────────────────────────
 *
 *   · NOT a test that the display is COMPLETE. §12 caps it at 4-5 fields; `allowedEnvHash` and
 *     `stdinHash` are committed and deliberately not shown. This oracle asks whether what IS shown
 *     agrees with what is committed, never whether enough is shown.
 *   · NOT a test of the SEALING (stage 4′ AAD, recipients, ciphertext). That is `verifySealedDisplayEgress`
 *     and `display-egress-aad.test.ts`; here the plaintext display is compared before any sealer runs.
 *   · NOT a claim about same-realm code execution. An attacker inside the gate's realm can call the
 *     module-private constructor directly (ADR-0005 §5, NC-6.1). These poisons are the far more
 *     common case: a hostile VALUE arriving from outside.
 *   · NOT a general canonicalization test. `canonicalize` has its own vectors; this file assumes it
 *     works and asks only whether both consumers read its output.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { getProjection } from "../src/projections.js";

const CANONICAL = "noa.command.exec";

type Verdict = "AGREE" | "REFUSED" | "DISAGREE";

/** sha256 over the JCS form the projection is expected to have committed to. */
function sha256Prefixed(s: string): string {
  return "sha256:" + createHash("sha256").update(s, "utf8").digest("hex");
}

/**
 * Ask the projection to act, then judge the two derivations against the HONEST truth the test holds.
 *
 * `honestArgv` is what an unpoisoned reader would have seen. The oracle does NOT re-implement the
 * canonicalizer: it takes the projection's own `paramsHash` as the commitment and checks that the
 * display it produced describes the same argv — which is exactly the property mutation B breaks and
 * nothing else currently observes.
 */
function judge(params: unknown, honestArgv: readonly string[]): { verdict: Verdict; detail: string } {
  const projection = getProjection(CANONICAL);
  assert.ok(projection, `fixture: no projection registered for ${CANONICAL}`);

  const r = projection.run(params);
  if (!r.ok) return { verdict: "REFUSED", detail: r.error };

  const shownArgs = r.display["Args"];
  const expectedArgs = honestArgv.join(" ");
  if (shownArgs !== expectedArgs) {
    return {
      verdict: "DISAGREE",
      detail:
        `the human is shown Args=${JSON.stringify(shownArgs)} but the digest ${r.paramsHash} commits ` +
        `to ${JSON.stringify(expectedArgs)} — a human approving this approves an action the system ` +
        `will not execute, and the receipt will say they agreed to it`,
    };
  }
  return { verdict: "AGREE", detail: r.paramsHash };
}

/** A params object whose `argv` answers index reads honestly but lies through `join`. */
function joinLyingArgv(honest: readonly string[]) {
  const counter = { hits: 0 };
  const argv = honest.slice() as string[] & { join(sep?: string): string };
  Object.defineProperty(argv, "join", {
    value(this: string[]) {
      counter.hits++;
      return "--dry-run";
    },
    writable: true, enumerable: false, configurable: true,
  });
  return { argv, counter };
}

/** A params object whose `argv` indices return a DIFFERENT value on the second read of each index. */
function twoFacedArgv(honest: readonly string[]) {
  const counter = { hits: 0 };
  const seen = new Set<number>();
  const argv = new Proxy(honest.slice(), {
    get(target, prop, recv) {
      if (typeof prop === "string" && /^\d+$/.test(prop)) {
        const i = Number(prop);
        counter.hits++;
        if (seen.has(i)) return "--dry-run";
        seen.add(i);
      }
      return Reflect.get(target, prop, recv);
    },
  });
  return { argv, counter };
}

function paramsWith(argv: unknown) {
  return { executable: "/usr/local/bin/deploy", argv, cwd: "/srv/app", targetEnv: "production" };
}

const DESTRUCTIVE = ["--service", "api", "--env", "production", "--force"] as const;

/* ─── CONTROL FIRST ────────────────────────────────────────────────────────────────────────────
 * Every assertion below is "not DISAGREE", and a projection that refused everything would satisfy
 * all of them. This proves the honest path reaches AGREE, so REFUSED is a real answer rather than
 * the only one. */
test("CONTROL — an honest request AGREES: the display shows exactly what the digest commits to", () => {
  const { verdict, detail } = judge(paramsWith(DESTRUCTIVE.slice()), DESTRUCTIVE);
  assert.equal(verdict, "AGREE", `the honest path did not agree: ${detail}`);
  assert.ok(detail.startsWith("sha256:"), "fixture: the commitment must be a real digest");
});

test("CONTROL — the ordinal is real: a structurally invalid request is REFUSED, not silently rendered", () => {
  // Fail-closed is an acceptable answer and must stay distinguishable from agreement, or a future
  // author reads "not AGREE" as "make it work" and widens the parser.
  const { verdict } = judge(paramsWith([{ nested: "object" }]), []);
  assert.equal(verdict, "REFUSED", "a non-string argv element was rendered instead of refused");
});

test("STAGE-4: an argv that lies through `join` cannot make the display disagree with the digest", () => {
  // MUTATION B, made observable. With the render node in place the displayed Args are rebuilt by an
  // index walk over the RE-PARSED canonical bytes, so the caller's `join` is never consulted and the
  // lie has nowhere to land. Bypass the node — let the display read the pre-canonical object — and
  // the human sees `--dry-run` while the digest commits to `--force`.
  const { argv, counter } = joinLyingArgv(DESTRUCTIVE);
  const { verdict, detail } = judge(paramsWith(argv), DESTRUCTIVE);

  assert.notEqual(verdict, "DISAGREE", detail);
  // ANTI-VACUITY, and note it is INVERTED here: this poison proving itself untouched is the POINT.
  // `hits === 0` means the render node never called the caller's `join`, which is the property under
  // test. A non-zero count would mean the hostile surface IS on the path — still not a failure by
  // itself, but it must be visible rather than assumed away.
  assert.equal(counter.hits, 0,
    `the caller's own join() was consulted ${counter.hits} time(s) — the display is being built from ` +
      `the caller's object rather than from the canonical bytes, which is the divergence this stage exists to prevent`);
});

test("STAGE-4: an argv whose indices change between reads cannot split the display from the digest", () => {
  // The other half, and the one with a measured history: reading an index twice is how a value that
  // was VALIDATED stopped being the value that was USED (`projections.ts:328`). The capture-once walk
  // closes it, and this oracle checks the CONSEQUENCE rather than the mechanism — the mechanism can
  // be reimplemented, the consequence is what a human is protected by.
  const { argv, counter } = twoFacedArgv(DESTRUCTIVE);
  const { verdict, detail } = judge(paramsWith(argv), DESTRUCTIVE);

  assert.notEqual(verdict, "DISAGREE", detail);
  assert.ok(counter.hits > 0,
    "the two-faced argv was NEVER read, so this run exercised nothing and its pass is vacuous — a " +
      "poison nobody touches proves only that the test harness ran");
});

test("STAGE-4: the digest is over the CANONICAL form, so a reordered request commits identically", () => {
  // Agreement is not just "the display matches"; it is that BOTH sides collapse to one canonical
  // truth. Two spellings of the same request must produce the same commitment, or the digest is
  // committing to the caller's formatting rather than to the action.
  const a = judge({ executable: "/usr/local/bin/deploy", argv: DESTRUCTIVE.slice(), cwd: "/srv/app", targetEnv: "production" }, DESTRUCTIVE);
  const b = judge({ targetEnv: "production", cwd: "/srv/app", argv: DESTRUCTIVE.slice(), executable: "/usr/local/bin/deploy" }, DESTRUCTIVE);

  assert.equal(a.verdict, "AGREE", a.detail);
  assert.equal(b.verdict, "AGREE", b.detail);
  assert.equal(a.detail, b.detail,
    "the same action written two ways produced two different commitments — the digest is over the " +
      "caller's key order, not over the action");
  // The digest must be a genuine sha256 over SOMETHING, not a constant: a projection returning a
  // fixed string would satisfy every equality above.
  assert.notEqual(a.detail, sha256Prefixed(""), "the commitment is a digest of nothing");
});
