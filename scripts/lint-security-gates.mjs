#!/usr/bin/env node
/**
 * L1–L7 — THE SOURCE-LEVEL SECURITY GATES (ADR §8.2).
 *
 * WHY SOURCE-LEVEL. H-03 proved the runtime controls reported health while measuring nothing: the
 * poison harness self-check exercised only `POISONS[0]`; the `verifyChain` entry probe supplied a
 * non-array, took the early rejection, fired its hostile getter ZERO times, and passed; three
 * iterator poisons targeted `%IteratorPrototype%` rather than the prototype that actually owns
 * `next` (`poisonActuallyBit:false`). A runtime catalogue asserts "these ~70 poisons do not flip
 * these fixtures" and is falsified by poison 71. A source lint asserts "no decision-path module
 * CONTAINS a construct that could dispatch through a mutable slot" — a property of the code,
 * checkable exhaustively, that fails closed on constructs nobody has thought of yet.
 *
 * ── THE RATCHET, AND WHY IT IS NOT A WEAKENED GATE ────────────────────────────────────────────
 * Several of these cannot block against the CURRENT tree, because the code they govern has not
 * been migrated yet (bytes-in is ADR Phase 1; the closed primitive set and null-prototype tables
 * are Phase 3). There are exactly two honest ways to ship a gate in that situation:
 *
 *   (a) weaken the rule until today's code passes — and then it passes forever, measuring nothing.
 *       That is the blind-gate pathology, reborn as a lint.
 *   (b) keep the rule at FULL STRENGTH and ratchet its ENFORCEMENT: report at full strength today,
 *       block the moment the count reaches zero, and never let the count rise again.
 *
 * This is (b). `mode: "warn"` never softens a check — it only decides whether findings exit
 * non-zero. Every warn-mode lint additionally carries a `budget`: the measured count of existing
 * violations. Exceeding the budget FAILS EVEN IN WARN MODE, so the number can only go down. When a
 * budget reaches 0 the lint is flipped to `mode: "block"` and the budget deleted.
 *
 * Run:  node scripts/lint-security-gates.mjs [--json]
 */
import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const rel = (p) => path.relative(ROOT, p);

/**
 * The trusted computing base (ADR §5.8). L2/L3 apply here and only here — a lint that shouted about
 * every file in the repository would be ignored within a week.
 */
/**
 * EXPLICITLY OUT of the TCB, each with the reason. This list is not decoration: together with TCB
 * it must account for EVERY file under `src/`, and the reconciliation below fails if it does not.
 *
 * Without that, L2 and L3 have a trivial bypass — move a decision path into a new file and the
 * lints simply stop seeing it. A hardcoded subject list that nothing reconciles is the poison
 * matrix again, wearing a different hat: correct on the day it was written, silent thereafter.
 */
const OUT_OF_TCB = {
  "src/index.ts": "re-export surface only; no decision logic (its exports are gated by L1)",
  "src/types.ts": "type declarations and one spec constant",
  "src/builder.ts": "PRODUCER — the signer's own data, trusted by definition (ADR §3.3)",
  "src/cli.ts": "calls the boundary; takes no verdict of its own",
  "src/pii.ts": "advisory helper, not on any verdict path",
};

const TCB = [
  "src/verify.ts",
  // THE BYTES-IN BOUNDARY (ADR §3, P3). Both are decision paths by construction: `bytes.ts` decides
  // whether a value is a document at all, and `opts.ts` decides whether a caller-owned object may be
  // read. They are in the TCB from their first commit rather than after someone notices.
  "src/bytes.ts",
  "src/opts.ts",
  // THE FORMAT SCANNERS (ADR §5.5, added 2026-07-28). A decision path by construction: these
  // functions decide whether a hash, a timestamp or a params-hash is well-formed, and those verdicts
  // gate a witness quorum and a receipt's structural validity. They exist BECAUSE the regex engine
  // could not stay on this path (c02_regexp_witness), so linting them is not optional.
  //
  // The entry it replaces was `src/ingest.ts`, deleted by bytes-in — and the comment that used to sit
  // here is worth preserving in substance: exempting `ingest.ts` was this file author's own first
  // instance of the bypass L0 now blocks. It declared SECURITY_SENSITIVE exports, so it was in the
  // TCB by derivation; deleting it later was the fix, not a reason to stop linting it meanwhile.
  "src/scan.ts",
  "src/schema.ts",
  "src/keys.ts",
  "src/safe-json.ts",
  "src/jcs.ts",
  "src/nfc.ts",
  "src/hash.ts",
  "src/signing.ts",
  "src/canonicalize.ts",
  "src/inert.ts",
  "src/intrinsics.ts",
  "src/policy/dsl.ts",
  "src/policy/eval.ts",
  "src/policy/validate.ts",
  "src/policy/compliance.ts",
  "src/cose/cbor.ts",
  "src/cose/cose-sign1.ts",
  "src/cose/receipt-cose.ts",
  "src/federation/anchor.ts",
  "src/federation/acceptance.ts",
  "src/federation/verify-witnessed.ts",
];

const read = (p) => fs.readFileSync(path.join(ROOT, p), "utf8");
const lines = (p) => read(p).split("\n");

/**
 * Blank out comments and string/template literals so a lint never fires on prose — SINGLE PASS,
 * left to right, because sequential regex replaces get this wrong in both directions.
 *
 * THE BUG THIS REPLACES (adversarial review, 2026-07-28). The first version ran five independent
 * `.replace()` passes: block comments, then line comments, then strings. A string containing comment
 * syntax therefore ATE THE REST OF THE LINE:
 *
 *     const DOCS = "https://example.com/spec"; const ok = TRUSTED.includes(kid);
 *                       ^^ the // inside the string opened a "line comment"
 *
 * Everything after it — including a genuine `.includes(` on a TCB decision path — was blanked, and
 * L2 and L3 saw nothing. A URL in a string literal is ordinary TypeScript, not an exotic construct,
 * so the gate's premise ("a property of the code, checkable exhaustively") was simply false. The
 * same ordering bug let `const OPEN = "/*";` swallow a block.
 *
 * My own self-test missed it because every case I wrote put the string and the call in DIFFERENT
 * positions. A stripper is a tokenizer; testing it with regex-shaped cases tests the same
 * assumption twice.
 *
 * A single left-to-right scan cannot have this class of bug: whichever construct OPENS first wins,
 * which is exactly what the language does. Newlines are preserved so line numbers stay true.
 */
function strip(src) {
  let out = "";
  let i = 0;
  const n = src.length;
  const keep = (ch) => (ch === "\n" ? "\n" : " ");
  while (i < n) {
    const c = src[i];
    const c2 = src[i + 1];
    if (c === "/" && c2 === "/") {
      while (i < n && src[i] !== "\n") { out += " "; i++; }
      continue;
    }
    if (c === "/" && c2 === "*") {
      out += "  "; i += 2;
      while (i < n && !(src[i] === "*" && src[i + 1] === "/")) { out += keep(src[i]); i++; }
      if (i < n) { out += "  "; i += 2; }
      continue;
    }
    if (c === '"' || c === "'" || c === "`") {
      const quote = c;
      out += quote; i++;
      while (i < n) {
        if (src[i] === "\\") { out += "  "; i += 2; continue; }
        if (src[i] === quote) { out += quote; i++; break; }
        out += keep(src[i]); i++;
      }
      continue;
    }
    out += c; i++;
  }
  return out;
}

const findings = [];
const add = (lint, file, line, msg) => findings.push({ lint, file, line, msg });

// ── L1 — BOUNDARY ────────────────────────────────────────────────────────────────────────────────
// Delegates entirely to the GENERATED registry. Two distinct failures: the registry is stale
// (someone changed the exports without regenerating), and a security-sensitive export is not
// bytes-in. Only the first can block today; the second is the migration's own scoreboard.
function L1() {
  const generated = execFileSync(process.execPath, [path.join(ROOT, "scripts", "gen-entry-point-registry.mjs")], {
    cwd: ROOT,
    encoding: "utf8",
    maxBuffer: 32 * 1024 * 1024,
  });
  const checkedIn = fs.existsSync(path.join(ROOT, "conformance/ENTRY-POINTS.md")) ? read("conformance/ENTRY-POINTS.md") : "";
  if (generated !== checkedIn) {
    add("L1", "conformance/ENTRY-POINTS.md", 0,
      "the checked-in entry-point registry does not match src/index.ts. Run `npm run gen:entry-points` and commit the diff. " +
      "A new security entry point must never appear without a human reading the change.");
  }
  const m = /security-sensitive NOT yet bytes-in \(ADR §3.1 target\): \*\*(\d+)\*\*/.exec(generated);
  const notBytesIn = m ? Number(m[1]) : -1;
  for (const row of generated.split("\n")) {
    const cells = /^\| `([^`]+)` \| SECURITY_SENSITIVE \| `(.+?)` \| NO \|/.exec(row);
    if (cells) add("L1", "src/index.ts", 0, `security-sensitive export \`${cells[1]}\` takes \`${cells[2]}\`, not string|Uint8Array (ADR §3.1)`);
  }
  return notBytesIn;
}

// ── L2 — PRIMITIVE ALLOWLIST ─────────────────────────────────────────────────────────────────────
// The rule is ADR §5.5's, at full strength: on a decision path, membership is a direct property
// probe on a null-prototype table, iteration is an index loop, comparison is `===`. Every construct
// below dispatches through a slot an attacker with code execution can replace — and C-02 was
// reproduced through four of them.
const L2_CONSTRUCTS = [
  { re: /\.includes\s*\(/, what: ".includes(", why: "dispatches through Array/String.prototype.includes (C-02, c02_includes425)" },
  { re: /\.has\s*\(/, what: ".has(", why: "dispatches through Set/Map.prototype.has (C-02, c02_sethas_verdict)" },
  { re: /\.some\s*\(|\.every\s*\(|\.find\s*\(|\.findIndex\s*\(|\.filter\s*\(/, what: "array HOF", why: "dispatches through Array.prototype and an iterator" },
  { re: /\bfor\s*\(\s*(?:const|let|var)\s+.*\s+of\s+/, what: "for…of", why: "dispatches through %ArrayIteratorPrototype%.next" },
  { re: /\/(?![/*])(?:[^/\\\n[]|\\.|\[(?:[^\]\\\n]|\\.)*\])+\/[gimsuy]*\s*[.;,)\]]/, what: "regex literal", why: "RegExp.prototype.test performs a dynamic lookup of exec on the receiver (C-02(f), c02_regexp_witness)" },
];
function L2() {
  let n = 0;
  for (const f of TCB) {
    if (!fs.existsSync(path.join(ROOT, f))) continue;
    strip(read(f)).split("\n").forEach((line, i) => {
      for (const c of L2_CONSTRUCTS) {
        if (c.re.test(line)) { add("L2", f, i + 1, `${c.what} on a TCB decision path — ${c.why}`); n++; }
      }
    });
  }
  return n;
}

// ── L3 — NO MUTABLE POLICY STATE ─────────────────────────────────────────────────────────────────
// H-04's root cause was the ENFORCEMENT MECHANISM, not the rule: the runtime walker
// (test/security/policy-tables-inert.test.ts:29) reaches only exported non-function values, so
// module-private tables, closures and symbol-keyed sets were invisible to it by construction. A
// source lint reads the declarations directly and has no such blind spot — which is the clearest
// case in the ADR where the mechanism was the defect.
/**
 * TCB RECONCILIATION — every file under `src/` is either in the TCB (and linted) or explicitly
 * exempted (with a reason). A new file that is neither is a decision path nobody classified, and it
 * defaults to being a FINDING rather than to being invisible.
 */
/**
 * TCB MEMBERSHIP IS NOT A FREE CHOICE (adversarial review, 2026-07-28).
 *
 * `reconcileTCB` requires every `src/**.ts` to be CLASSIFIED. It did not require it to be classified
 * CORRECTLY — so L2 and L3 had a one-line escape that was strictly easier than fixing anything: move
 * `src/verify.ts` (the home of the C-01 `structuredClone` sink and the C-02 `includes` sink) from
 * TCB into OUT_OF_TCB with a prose reason. Measured: 15 violations vanish, L0 stays 0, exit stays 0.
 * And because budgets ratchet DOWNWARD, committing the lower count then makes the gate actively
 * BLOCK putting the file back.
 *
 * A file whose exports are security-sensitive is in the TCB by definition, and `conformance/
 * ENTRY-POINTS.md` already computes that set from `src/index.ts` through the compiler. So membership
 * is DERIVED from the same generated source L1 uses, and an exemption for a file that declares a
 * security-sensitive export is rejected — the two gates can no longer disagree about what is
 * security-critical.
 */
function tcbMembershipFromExports() {
  const registry = fs.existsSync(path.join(ROOT, "conformance/ENTRY-POINTS.md")) ? read("conformance/ENTRY-POINTS.md") : "";
  const required = new Set();
  for (const row of registry.split("\n")) {
    const m = /^\| `[^`]+` \| SECURITY_SENSITIVE \|[^|]*\|[^|]*\| `([^`]+)` \|/.exec(row);
    if (m) required.add(m[1]);
  }
  let n = 0;
  for (const f of required) {
    if (f in OUT_OF_TCB) {
      add("L0", f, 0,
        `exempted from the TCB while declaring a SECURITY_SENSITIVE export (per conformance/ENTRY-POINTS.md). ` +
        `TCB membership is derived, not chosen — exempting a file is not a way to satisfy L2/L3.`);
      n++;
    } else if (!TCB.includes(f)) {
      add("L0", f, 0, "declares a SECURITY_SENSITIVE export but is not in the TCB list — L2/L3 would not lint it.");
      n++;
    }
  }
  return n;
}

function reconcileTCB() {
  const seen = new Set();
  const walk = (dir) => {
    for (const e of fs.readdirSync(path.join(ROOT, dir), { withFileTypes: true })) {
      const rp = `${dir}/${e.name}`;
      if (e.isDirectory()) walk(rp);
      else if (e.name.endsWith(".ts") && !e.name.endsWith(".d.ts")) seen.add(rp);
    }
  };
  walk("src");
  let n = tcbMembershipFromExports();
  for (const f of seen) {
    if (!TCB.includes(f) && !(f in OUT_OF_TCB)) {
      add("L0", f, 0,
        "file under src/ is in neither the TCB list nor OUT_OF_TCB — an unclassified module is a " +
        "decision path L2/L3 cannot see. Classify it in scripts/lint-security-gates.mjs.");
      n++;
    }
  }
  for (const f of [...TCB, ...Object.keys(OUT_OF_TCB)]) {
    if (!seen.has(f)) {
      add("L0", f, 0, "classified in the TCB/OUT_OF_TCB lists but no longer exists — the list is describing code that is gone.");
      n++;
    }
  }
  return n;
}

function L3() {
  let n = 0;
  for (const f of TCB) {
    if (!fs.existsSync(path.join(ROOT, f))) continue;
    const src = strip(read(f));
    src.split("\n").forEach((line, i) => {
      const decl = /^\s*(?:export\s+)?const\s+([A-Za-z_$][\w$]*)\s*(?::[^=]+)?=\s*(\{|\[|new\s+(?:Set|Map)\b)/.exec(line);
      if (!decl) return;
      const name = decl[1];
      // Module-level only: an indented declaration is inside a function and is not shared state.
      if (/^\s/.test(line)) return;
      const window = src.split("\n").slice(i, i + 30).join("\n");
      const frozen = /Object\.freeze|deepFreeze|frozenSet|frozenTable|Object\.create\(null\)/.test(window);
      if (!frozen) { add("L3", f, i + 1, `module-level table \`${name}\` is not built frozen and null-prototype at construction (ADR §5.6)`); n++; }
    });
  }
  return n;
}

// ── L8 — THE DISPATCH-SURFACE ENUMERATOR (added 2026-07-29, round-2, closes R3-10) ─────────────────
// R3-10 was FALSE-GREEN: the runtime poison suite reported 81/81 and this gate exited 0 while nine
// live-lookup forgeries were reproducible, because the enumeration was INCOMPLETE. L2 derives
// `includes/has/HOFs/for…of/regex`; it never derived the OTHER dispatch surfaces an attacker reaches —
// a spread (`[...x]` → `%StringIteratorPrototype%`/`%ArrayIteratorPrototype%.next`), an `instanceof`
// (`Symbol.hasInstance`), a live builtin-static read (`Object.keys(`, `Buffer.from(`, `Array.isArray(`),
// and a live rewrite/decode prototype method (`.toString`, `.equals`, `.export`, `.normalize`,
// `.charCodeAt`, `.codePointAt`, `.isWellFormed`, `.subarray`). Every one of R3-03..R3-09 lived in that
// blind spot. L8 + L2 together DERIVE the full construct set across the TCB, so a NEW live lookup on a
// decision path — the exact defect each of the last three rounds shipped one call deeper — turns a gate
// RED instead of passing silently.
//
// SCOPE, stated so it cannot be quietly narrowed (constraint C-8): every TCB file EXCEPT
// `src/intrinsics.ts`. That module is the capture mechanism itself — its whole job is to read each
// builtin ONCE at load and re-export it as a plain function — so linting it for "no live global read"
// is linting the linter. The exclusion is named here, not hidden, and it is the ONLY file exempt.
// Only INDENTED lines are inspected: a construct at column 0 is a module-load-time capture / frozen-
// table construction (the SAFE pattern L3 already blesses), whereas a live lookup on a decision path is
// always inside a function body. This is a detection rule, not a scan-root narrowing — every TCB file is
// still read in full.
/**
 * ── ROUND-3 EXTENSION (2026-07-29): WHAT THE ENUMERATION STILL MISSED, MEASURED ─────────────────
 *
 * L8 shipped at BLOCK/0 and was FALSE-GREEN within one round, for the same reason L2 was: the
 * enumeration was incomplete, so `0` meant "no instance of the four constructs I happen to list",
 * not "no live lookup". Measured against the tree it was passing, it MISSED all four of that round's
 * findings:
 *
 *   MISSED  cryptoVerify(null, message, key, sigBytes)  — a LIVE BUILTIN ESM IMPORT BINDING. It is
 *           not a `Buffer.x(` static and not a `.y(` method, so it matched nothing — while being the
 *           signature verdict itself, repointable with `crypto.verify = …; syncBuiltinESMExports()`.
 *   MISSED  BigInt(yBytes[i])                           — a BARE GLOBAL call. Absent from the static
 *           alternation, which only listed dotted builtins.
 *   MISSED  pol.rules.forEach(...)                      — a HOF. L2 carries HOFs at a WARN budget, so
 *           a silent-skip `forEach` on a verdict path was an in-budget scoreboard entry, not a block.
 *   MISSED  key.asymmetricKeyType                       — a PROPERTY READ. Every rule required a call.
 *
 * Its regexes were also evadable by spelling: `globalThis.Buffer.from(`, `Buffer["from"]`,
 * `Buffer?.from`, and a detached `const f = Buffer.from` all reach the same slot and matched none of
 * the four rules. Each of those is now its own construct, so the evasion is a finding rather than a
 * gap. Nothing was removed and no budget was raised: the four original constructs are unchanged
 * below and every addition is a strictly larger subject set at the same BLOCK/0 enforcement.
 */
const BUILTIN_GLOBALS = "Object|Array|Buffer|Number|String|JSON|Reflect|Math|Date|Set|Map|WeakSet|WeakMap|Symbol|BigInt|Promise|Proxy|Function|globalThis";
const L8_CONSTRUCTS = [
  { re: /\[\s*\.\.\./, what: "array/iterable spread", why: "`[...x]` dispatches through %String/ArrayIteratorPrototype%.next (R3-04/R3-08)" },
  { re: /\binstanceof\b/, what: "instanceof", why: "performs a dynamic Get(C, Symbol.hasInstance) — use a captured brand check (collectionBrand)" },
  { re: /\b(?:Object|Array|Buffer|Number|String|JSON|Reflect|Math|Date|Set|Map|WeakSet|WeakMap|Symbol)\.\w+\s*\(/, what: "live builtin-static call", why: "a live read of a mutable global (e.g. Object.keys/Buffer.from/Array.isArray) — route through src/intrinsics.ts (R3-04)" },
  { re: /\.(?:toString|equals|export|normalize|charCodeAt|codePointAt|isWellFormed|subarray)\s*\(/, what: "live prototype-method call", why: "a rewrite/decode method looked up on a value (toString/equals/export/normalize/…) — route through src/intrinsics.ts (R3-03/R3-07/R3-09)" },
  // ── ADDED 2026-07-29 (round-3). Each closes one MISS measured above. ────────────────────────────
  {
    re: /(?<![.\w$])(?:BigInt|Number|String|Boolean|parseInt|parseFloat|isNaN|isFinite|encodeURIComponent|decodeURIComponent|encodeURI|decodeURI)\s*\(/,
    what: "bare-global call",
    why: "an UNDOTTED global (BigInt/Number/parseInt/…) is a writable property of globalThis — `globalThis.BigInt = () => 0n` collapsed the y<q AND S<L canonicality gates in verifyEd25519 (T18). Route through src/intrinsics.ts (toBigInt/toNumber/…)",
  },
  {
    re: /\.(?:forEach|map|filter|reduce|reduceRight|some|every|find|findIndex|findLast|findLastIndex|flatMap|flat|sort|reverse)\s*\(/,
    what: "array HOF",
    why: "a higher-order method looked up on a value. `Array.prototype.forEach = () => undefined` VISITS NOTHING, so a validator silently accepts what it never inspected — measured DENY/policy-invalid -> ALLOW (T19). L2 carries these at a WARN budget; on this gate they BLOCK. Use an index walk or a captured wrapper (arrayEvery/arrayMap/…)",
  },
  {
    re: new RegExp(`(?<![.\\w$])(?:${BUILTIN_GLOBALS})\\s*\\[\\s*["'\`]`),
    what: "computed builtin member",
    why: "`Buffer[\"from\"]` reaches the same mutable slot as `Buffer.from` while matching no dotted rule — a spelling evasion, not a different operation",
  },
  {
    re: new RegExp(`(?<![.\\w$])(?:${BUILTIN_GLOBALS})\\s*\\?\\.`),
    what: "optional-chained builtin",
    why: "`Buffer?.from(...)` is the same live read with an existence check in front of it — same evasion class as the computed member",
  },
  {
    re: /(?<![.\w$])globalThis\b/,
    what: "globalThis reference",
    why: "`globalThis.Buffer.from(` is the longhand spelling of every rule above; reaching the global object explicitly on a decision path has no legitimate use here",
  },
  {
    re: new RegExp(`(?:const|let|var)\\s+[\\w$]+\\s*=\\s*(?:${BUILTIN_GLOBALS})\\s*\\.\\s*[\\w$]+\\s*(?:;|,|\\)|$)`),
    what: "detached builtin binding",
    why: "`const f = Buffer.from` inside a function body takes the read at CALL time, so the capture is worthless — a load-time capture belongs in src/intrinsics.ts, at module top level, which this rule (indented lines only) deliberately still permits there",
  },
  {
    re: /(?<![.\w$])new\s+(?:Set|Map|WeakSet|WeakMap|Date|RegExp|Proxy|Function|Array|Object)\s*(?:<[^>]*>)?\s*\(/,
    what: "live global constructor",
    why: "`new Set()` READS globalThis.Set at call time; a substituted class is then handed to the captured Set.prototype.* wrappers. That fails closed rather than permissively, but it is still a live read of a mutable global on a decision path — use newSet()/newMap() from src/intrinsics.ts",
  },
  {
    re: /\.(?:asymmetricKeyType|asymmetricKeyDetails|symmetricKeySize)\b/,
    what: "live KeyObject accessor read",
    why: "`key.asymmetricKeyType` is an ACCESSOR on AsymmetricKeyObject.prototype (measured: configurable, get is a function), NOT a data property — one defineProperty makes the Ed25519 CURVE PIN bless an Ed448 key (T18). Read it through asymmetricKeyType() in src/intrinsics.ts",
  },
  {
    re: /\.(?:buffer|byteOffset|byteLength)\b/,
    what: "live typed-array accessor read",
    why: "`.buffer`/`.byteOffset`/`.byteLength` are configurable ACCESSORS on %TypedArray%.prototype — the bytes the decoder is handed are chosen by them. Use taBuffer/taByteOffset/taByteLength (and byteLength() for `.length`, which is the same accessor)",
  },
];

/**
 * A LIVE BUILTIN ESM IMPORT BINDING — the T17 miss, and the one construct that is a property of the
 * FILE rather than of a line, so it is checked separately and over EVERY line (an import sits at
 * column 0, which the indented-line rule below deliberately skips).
 *
 * `import { verify } from "node:crypto"` is not a snapshot: an ESM namespace binding for a builtin is
 * REPOINTED by `node:module`'s `syncBuiltinESMExports()` after the importing module has been
 * evaluated. `src/keys.ts` carried a comment explaining exactly this about `createPublicKey` — three
 * lines above four sibling bindings from the same statement that were left live, one of which was the
 * signature verdict. So the rule is structural and admits no per-binding argument: `src/intrinsics.ts`
 * is the only TCB file that may import a builtin, because it is the only one that copies the value
 * into a `const` at load and never reads the binding again.
 */
/**
 * COMMENT-ONLY stripper. `strip` above blanks comments AND string CONTENTS, which is right for every
 * other rule and exactly wrong for this one: the thing being detected IS a string literal (the module
 * specifier `"node:crypto"`), so a stripped-source scan would see `"           "` and measure nothing.
 * Scanning the RAW source instead is not the answer either — it fires on any COMMENT that mentions
 * `from "node:crypto"`, and this file's own comments discuss that import at length. A false positive
 * is how a gate earns the right to be ignored.
 *
 * So: blank comments, keep strings. String literals are still CONSUMED properly (left to right,
 * whichever construct opens first wins) so a `//` inside a string cannot open a comment — that
 * ordering bug is documented on `strip` and is not repeated here.
 */
function stripComments(src) {
  let out = "";
  let i = 0;
  const n = src.length;
  while (i < n) {
    const c = src[i];
    const c2 = src[i + 1];
    if (c === "/" && c2 === "/") { while (i < n && src[i] !== "\n") { out += " "; i++; } continue; }
    if (c === "/" && c2 === "*") {
      out += "  "; i += 2;
      while (i < n && !(src[i] === "*" && src[i + 1] === "/")) { out += src[i] === "\n" ? "\n" : " "; i++; }
      if (i < n) { out += "  "; i += 2; }
      continue;
    }
    if (c === '"' || c === "'" || c === "`") {
      const q = c;
      out += q; i++;
      while (i < n) {
        if (src[i] === "\\") { out += src[i] + (src[i + 1] ?? ""); i += 2; continue; }
        if (src[i] === q) { out += q; i++; break; }
        out += src[i]; i++;
      }
      continue;
    }
    out += c; i++;
  }
  return out;
}

/**
 * `\s` matches a NEWLINE, so this one expression covers both spellings — the ordinary
 * `} from "node:crypto";` and the specifier split across lines (`from\n  "node:crypto"`), which a
 * per-line scan misses by construction. The first version of this rule had a separate whole-file
 * "fallback" for the split case; it was DEAD — its two conditions were mutually exclusive — which is
 * the same defect class as a lint that reads 0 because it matches nothing.
 */
const ESM_BUILTIN_IMPORT = /\bfrom\s*["']node:/g;
/** Type-only imports are erased by tsc and have no runtime binding to repoint. */
const TYPE_ONLY_IMPORT = /(?:^|\n)\s*import\s+type\b[^;]*?$/;

/**
 * ONE function, called by BOTH `L8` and its self-test. That is deliberate and it was not the first
 * shape: the self-test originally re-implemented the scan, so knocking out the comment-stripping
 * INSIDE L8 left the self-test green — a self-test that exercises a copy of the code proves the copy
 * works. Sharing the path means any defanging of the real scan is observed.
 *
 * Returns one `{ line }` per live builtin ESM import binding found in `raw`.
 */
function esmImportFindings(raw) {
  const out = [];
  const noComments = stripComments(raw);
  ESM_BUILTIN_IMPORT.lastIndex = 0;
  for (let m = ESM_BUILTIN_IMPORT.exec(noComments); m !== null; m = ESM_BUILTIN_IMPORT.exec(noComments)) {
    const before = noComments.slice(0, m.index);
    // The statement may span lines, so the type-only exemption is tested against the text back to the
    // previous `;` rather than against one line.
    if (TYPE_ONLY_IMPORT.test(before.slice(before.lastIndexOf(";") + 1))) continue;
    out.push({ line: before.split("\n").length });
  }
  return out;
}

function L8() {
  let n = 0;
  for (const f of TCB) {
    if (f === "src/intrinsics.ts") continue; // the capture module — see the scope note above
    if (!fs.existsSync(path.join(ROOT, f))) continue;
    const raw = read(f);
    // The scan lives in `esmImportFindings` and is shared with the self-test — see there for why the
    // self-test must not re-implement it, and for why the source is comment-stripped but NOT
    // string-stripped (the subject IS a string literal).
    for (const hit of esmImportFindings(raw)) {
      add("L8", f, hit.line,
        "LIVE BUILTIN ESM IMPORT BINDING on a TCB decision path — an ESM binding for a node: builtin is " +
        "repointable by syncBuiltinESMExports() AFTER this module is evaluated (T17: `crypto.verify = () => true` " +
        "made a garbage signature VALID under an honest keyring). Only src/intrinsics.ts may import a builtin; " +
        "it snapshots the value into a const at load. Import the captured wrapper instead.");
      n++;
    }
    strip(raw).split("\n").forEach((line, i) => {
      if (!/^\s/.test(line)) return; // module-top-level = load-time capture / table construction (L3's territory)
      for (const c of L8_CONSTRUCTS) {
        if (c.re.test(line)) { add("L8", f, i + 1, `${c.what} on a TCB decision path — ${c.why}`); n++; }
      }
    });
  }
  return n;
}

// ── L5 — VERDICTS PINNED ─────────────────────────────────────────────────────────────────────────
// H-03: the poison suite compared AGGREGATE accept/reject counts, so a poison that flipped one
// fixture from VALID to TAMPERED and another from TAMPERED to VALID netted to zero and passed. A
// verdict must be pinned by exact value, and the CLEAN verdict must be pinned too — otherwise a
// control that rejects everything scores perfectly.
function L5() {
  // `.mjs`/`.js` were invisible here while L6 accepted them — the inconsistency WAS the bypass:
  // renaming counts.test.ts to counts.test.mjs turned this control off.
  const suites = fs.existsSync(path.join(ROOT, "test/security"))
    ? fs.readdirSync(path.join(ROOT, "test/security")).filter((f) => /\.test\.(ts|mts|mjs|js)$/.test(f))
    : [];
  let n = 0;
  for (const f of suites) {
    const p = `test/security/${f}`;
    // Comments and string literals are stripped FIRST. A gate that fires on prose is a gate people
    // learn to ignore, and an ignored gate is the blind gate with extra steps.
    const src = strip(read(p));
    const usesCounts = /\b(accepted|rejected|passCount|failCount|okCount)\s*(\+\+|\+=|=\s*\d)/.test(src);
    // The old predicate was `/clean/i.test(src) && /assert\.(equal|...)/.test(src)` — ANY identifier
    // containing "clean" anywhere plus ANY equality assert anywhere. A variable named `cleanup` and
    // an `assert.equal(1, 1)` satisfied a blocking gate. It now requires the two to be on the SAME
    // assertion, which is what "pin the clean verdict by exact value" actually means.
    const pinsClean = /assert\.(equal|deepEqual|strictEqual)\([^;]*\bclean/i.test(src);
    if (usesCounts && !pinsClean) {
      add("L5", p, 0, "compares aggregate counts without pinning the CLEAN verdict by exact value — offsetting flips net to zero (H-03)");
      n++;
    }
  }
  return n;
}

// ── L6 — CASES EXECUTE ───────────────────────────────────────────────────────────────────────────
// "Absence of findings and absence of checking are the same value in code and opposite facts in
// reality." A declared case must assert that it RAN: a hostile getter must assert it fired ≥1 time,
// and a self-check must iterate the whole catalogue rather than element [0].
function L6() {
  let n = 0;
  const dir = path.join(ROOT, "test/security");
  if (!fs.existsSync(dir)) return 0;
  for (const f of fs.readdirSync(dir).filter((x) => /\.test\.[tm]?[jt]s$/.test(x))) {
    const p = `test/security/${f}`;
    // COMMENTS AND STRINGS ARE STRIPPED FIRST. L5 already did this and said why; L6 read the raw
    // file, so a blocking gate was SATISFIED BY PROSE — one comment line mentioning `fired++`
    // silenced it with no code change. That is strictly worse than firing on prose.
    const src = strip(read(p));
    // The RULE is "a self-check must exercise the WHOLE catalogue". The H-03 defect was a self-check
    // that touched element [0] and nothing else. Referencing [0] is fine — as a worked example
    // alongside a whole-catalogue assertion. It is a finding only when the whole-catalogue
    // assertion is ABSENT, which is the rule stated exactly, not softened.
    // Keyed to the SHAPE, not to the identifier `POISONS` — renaming the catalogue turned this off.
    const catalogue = /\b([A-Z][A-Z0-9_]*)\s*(?::[^=]+)?=\s*\[/.exec(src)?.[1];
    const touchesZero = catalogue ? new RegExp(`\\b${catalogue}\\[0\\]`).test(src) : /\w+\[0\]!?\.apply\(/.test(src);
    const iteratesAll = catalogue
      ? new RegExp(`for\\s*\\(\\s*const\\s+\\w+\\s+of\\s+${catalogue}\\s*\\)`).test(src)
      : false;
    // The evidence must be an ASSERTION, not a sentence: searched in stripped source.
    const assertsBite = /assert\.(ok|equal|deepEqual|strictEqual)\(/.test(src) && /(bite|bites|actually|patched|inert)/i.test(src);
    if (touchesZero && !(iteratesAll && assertsBite)) {
      add("L6", p, 0, "the poison self-check does not exercise the whole catalogue and assert each poison BITES — the H-03 defect verbatim");
      n++;
    }
    const declaresGetter = /get\s*\(\s*\)\s*\{/.test(src) || /defineProperty\([^)]*get[:\s]/.test(src);
    // Must be real code in stripped source — a counter INCREMENT or an assertion ON the counter.
    const countsFires = /(fired|invocations|reads|calls|hits|touched)\s*(\+\+|\+=)/.test(src)
      || /assert\.(ok|equal|deepEqual|strictEqual)\([^;]*\b(fired|invocations|reads|calls|hits|touched)\b/.test(src);
    if (declaresGetter && !countsFires) {
      add("L6", p, 0, "declares a hostile accessor but never asserts it FIRED — the verifyChain entry probe passed while firing zero times (H-03)");
      n++;
    }
  }
  return n;
}

// ── L7 — CORPUS PARITY ───────────────────────────────────────────────────────────────────────────
// The five implementations are the strongest control the project has, and their value is realised
// only if they all run the SAME corpus on every change. The matrix must be generated and diffed,
// never hand-maintained.
function L7() {
  let n = 0;
  const impls = ["impl-py", "impl-go", "impl-rust", "impl-csharp"];
  for (const i of impls) {
    if (!fs.existsSync(path.join(ROOT, i))) { add("L7", i, 0, `implementation \`${i}\` is missing — the five-verifier parity claim rests on it`); n++; }
  }
  if (!fs.existsSync(path.join(ROOT, "conformance/MATRIX.md"))) { add("L7", "conformance/MATRIX.md", 0, "the conformance matrix is absent"); n++; }
  const ci = fs.existsSync(path.join(ROOT, ".github/workflows/ci.yml")) ? read(".github/workflows/ci.yml") : "";
  // Detect the MECHANISM, not one spelling of it: CI runs the matrix inline as
  // `node scripts/conformance-matrix.mjs --write && git diff --exit-code`, which is the same gate
  // as the `check:matrix` script. A lint that demanded one particular spelling would be a false
  // positive, and a false positive is how a gate earns the right to be ignored.
  const matrixGated = /check:matrix/.test(ci) || (/conformance-matrix\.mjs\s+--write/.test(ci) && /git diff --exit-code/.test(ci));
  if (ci && !matrixGated) { add("L7", ".github/workflows/ci.yml", 0, "CI does not diff-gate the generated conformance matrix"); n++; }
  // The five-verifier corpus must actually be RUN, not merely present in the tree.
  for (const [impl, marker] of [["impl-go", /impl-go\/conformance/], ["impl-rust", /impl-rust\/conformance/], ["impl-csharp", /impl-csharp\/conformance/], ["impl-py", /impl-py\/conformance/]]) {
    if (ci && !marker.test(ci)) { add("L7", ".github/workflows/ci.yml", 0, `CI never runs the ${impl} verifier against the corpus — a verifier that is not run is not a verifier`); n++; }
  }
  // The entry-point registry (L1) and the R7 exploit corpus must be gated in CI too, or they are
  // developer conveniences rather than controls.
  if (ci && !/lint:security-gates/.test(ci)) { add("L7", ".github/workflows/ci.yml", 0, "CI does not run the L1-L7 security gates"); n++; }
  if (ci && !/test:r7-exploits/.test(ci)) { add("L7", ".github/workflows/ci.yml", 0, "CI does not run the pinned R7 exploit corpus"); n++; }
  if (ci && !/lint:dispatch-surfaces/.test(ci)) { add("L7", ".github/workflows/ci.yml", 0, "CI does not run the dispatch-surface enumeration"); n++; }
  return n;
}

/**
 * THE LINT TABLE. `mode` is enforcement, never strength. `budget` is the measured violation count
 * at the moment the lint landed; exceeding it fails even in warn mode, so the number only falls.
 */
const LINTS = [
  // L0 runs FIRST and BLOCKS unconditionally. It is deliberately not part of any budget: if an
  // unclassified file could be absorbed by L3's allowance, then fixing one mutable table would buy
  // the right to hide one whole decision module, and the scoreboard would net to zero while the
  // blind spot grew. Coverage of the subject list is a precondition for every other lint's number
  // meaning anything, so it cannot itself be traded against them.
  { id: "L0", name: "TCB coverage (every src/ file is classified)", run: reconcileTCB, mode: "block" },
  // FLIPPED warn(21) -> BLOCK on 2026-07-28, and the budget is DELETED rather than set to 0, per the
  // rule at the top of this file: "when a budget reaches 0 the lint is flipped to mode:'block' and
  // the budget deleted". Measured 0 — every security-sensitive export now takes string|Uint8Array.
  //
  // Two things went into that number and both belong in the record. Twelve of the twenty-one were
  // migrated code the DETECTOR could not see: the bytes-in pattern predated TypeScript 5.7 making
  // `Uint8Array` generic, so `Uint8Array<ArrayBufferLike>` matched nothing (fixed, with a two-way
  // self-test, in gen-entry-point-registry.mjs). Six were `src/inert.ts` exports that had never been
  // CLASSIFIED and were SECURITY_SENSITIVE by the fail-closed default; they are now
  // INERT_CONSTRUCTOR, with the reasoning and the counter-argument written out at the exemption and
  // a mechanical constraint that voids it if the control earning it is deleted. Three were the
  // deleted ingest exports. No budget anywhere was raised and no scan root was narrowed.
  { id: "L1", name: "boundary (generated entry-point registry)", run: L1, mode: "block" },
  // BUDGET RATCHETED 64 → 35 on 2026-07-28 (measured). Budgets move DOWNWARD only, and this one moved
  // because the four C-02 sinks and the C-02(f) regex path left the decision path: membership is now
  // `arrayIncludes`/`membership()`, presence is `hasOwn`, and every format decision is a hand-written
  // character walk in `src/scan.ts`. It stays in WARN mode because 35 is not 0 — the residue is
  // mostly `for…of` over `safeParse` output and array HOFs in non-verdict positions, and claiming
  // "blocking" for a gate the code does not yet satisfy is the failure mode this table exists to
  // prevent. The earlier note here recorded a RAISE 63 → 64 when `src/ingest.ts` moved into the TCB;
  // that file no longer exists, and `src/scan.ts` took its place in the subject set.
  // Budget RATCHETED 35 -> 33 -> 29 on 2026-07-29. 35->33: `src/jcs.ts` lost two `for…of` loops
  // when its key walk and code-point walk became index loops. 33->29: `src/verify.ts` lost four more
  // when the chain-partition, seq-map, hash/signature and distinct-agent walks became index loops —
  // those were not style changes, they closed a substituting-iterator forgery. The ratchet only ever
  // moves down: lowering it locks the gain in so a later change cannot quietly spend it.
  // Budget RATCHETED 29 -> 17 on 2026-07-29 (round-2). The drop is the substituting-iterator closure of
  // R3-04/R3-05/R3-06/R3-08: `for…of` over parsed arrays became index walks and the policy `and/or/in`
  // quantifiers (`.some`/`.every`) became captured wrappers in `src/nfc.ts`, `src/schema.ts`,
  // `src/policy/eval.ts` and `src/federation/verify-witnessed.ts`. The ratchet only ever moves down.
  // Budget RATCHETED 17 -> 11 on 2026-07-29 (round-3, measured). The drop is the T19 closure: the
  // three protected/unprotected COSE header walks in `src/cose/cose-sign1.ts`, the `clauses`/`rules`
  // walks in `src/policy/validate.ts` and `src/policy/dsl.ts`, and the identity-manifest `.every` in
  // `src/verify.ts` became index walks and captured wrappers. The ratchet only ever moves down;
  // lowering it locks the gain in so a later change cannot quietly spend it.
  { id: "L2", name: "primitive allowlist on TCB decision paths", run: L2, mode: "warn", budget: 11,
    ratchet: "blocks when the decision path stops calling includes/has/HOFs/for-of/regex (ADR §5.5, P3)." },
  // FLIPPED warn(10) -> BLOCK on 2026-07-28, budget deleted. Measured 0: every module-level table in
  // the TCB is now built frozen and null-rooted at construction. The last three were CHECKPOINT_KEYS
  // (verify.ts), MUTATORS (inert.ts) and INVALID_HEAD (verify-witnessed.ts) — a shared sentinel any
  // caller could have rewritten for every other caller.
  { id: "L3", name: "no mutable policy state (module-level tables)", run: L3, mode: "block" },
  { id: "L4", name: "mutation-observable (control knockout)", run: () => 0, mode: "external",
    ratchet: "run by `npm run lint:knockout` — a separate process because each control must be knocked out and the suite re-run." },
  { id: "L5", name: "verdicts pinned by exact value", run: L5, mode: "block" },
  { id: "L6", name: "declared cases actually execute", run: L6, mode: "block" },
  { id: "L7", name: "corpus parity across five implementations", run: L7, mode: "block" },
  // ADDED 2026-07-29 (round-2). Enters at BLOCK/0: R3-03..R3-09 were all closed at the source in this
  // pass (spread/instanceof/live-static/live-proto counts across the TCB = 0, measured), so per the
  // rule at the top of this file a zero-count gate ships blocking with no budget — any regression is a
  // hard failure, never an in-budget warning.
  // EXTENDED 2026-07-29 (round-3) with the four construct classes it was MEASURED to miss —
  // bare-global calls, array HOFs, live builtin ESM import bindings and live accessor reads — plus the
  // four spelling evasions of its own original rules (globalThis./["x"]/?./detached binding). Stays at
  // BLOCK with no budget: measured 0 across the TCB after the fixes in this pass. `--selftest` proves
  // every rule still BITES, because a rule that has never been observed to fail is not a rule.
  // Runs BEFORE L8 in the table so a defanged rule is reported before its count of 0 is printed.
  { id: "L8-selftest", name: "every L8 construct is observed to bite (positive + negative sample)", run: L8SelfTest, mode: "block" },
  { id: "L8", name: "dispatch-surface enumeration (spread/instanceof/live-static/live-proto/bare-global/HOF/esm-binding/accessor)", run: L8, mode: "block" },
];

/**
 * ── L8 SELF-TEST: EVERY RULE MUST BE OBSERVED TO BITE ──────────────────────────────────────────────
 *
 * L8 reads 0 after this pass, and 0 is exactly what it read on the day it MISSED four reproducible
 * forgeries. A count of zero is evidence only if the instrument is known to respond, so each
 * construct carries a POSITIVE sample it must match and a NEGATIVE sample it must not — the negative
 * half matters as much, because a rule that fires on the captured wrapper (`toBigInt(x)`,
 * `arrayEvery(a, f)`) trains everyone to route around the gate.
 *
 * This is the same rule L6 enforces on the poison suite, applied to the lint itself: "absence of
 * findings and absence of checking are the same value in code and opposite facts in reality." It runs
 * on EVERY invocation, not behind a flag, so the gate cannot be silently defanged by a regex edit.
 */
const L8_SELFTEST = [
  // [ construct `what`, MUST match, MUST NOT match ]
  ["array/iterable spread",        "  const a = [...parsed];",                      "  const a = arraySlice(parsed);"],
  ["instanceof",                   "  if (v instanceof Set) return null;",          "  if (collectionBrand(v) !== null) return null;"],
  ["live builtin-static call",     "  const b = Buffer.from(s, 'base64');",         "  const b = bufferFrom(s, 'base64');"],
  ["live prototype-method call",   "  return der.toString('base64');",              "  return bufToString(der, 'base64');"],
  ["bare-global call",             "  y = (y << 8n) | BigInt(yBytes[i]);",          "  y = (y << 8n) | toBigInt(yBytes[i]);"],
  ["array HOF",                    "  pol.rules.forEach((r, i) => check(r, i));",   "  for (let i = 0; i < pol.rules.length; i++) check(pol.rules[i], i);"],
  ["computed builtin member",      "  const f = Buffer[\"from\"];",                  "  const f = bufferFrom;"],
  ["optional-chained builtin",     "  const b = Buffer?.from(s);",                  "  const b = bufferFrom(s);"],
  ["globalThis reference",         "  const b = globalThis.Buffer.from(s);",        "  const b = bufferFrom(s);"],
  ["detached builtin binding",     "  const from = Buffer.from;",                   "  const from = bufferFrom;"],
  ["live global constructor",      "  const seen = new Set();",                     "  const seen = newSet();"],
  ["live KeyObject accessor read", "  if (key.asymmetricKeyType !== 'ed25519') {",  "  if (asymmetricKeyType(key) !== 'ed25519') {"],
  ["live typed-array accessor read", "  return from(bytes.buffer, bytes.byteOffset);", "  return from(taBuffer(bytes), taByteOffset(bytes));"],
];
function L8SelfTest() {
  let n = 0;
  for (const [what, positive, negative] of L8_SELFTEST) {
    const c = L8_CONSTRUCTS.find((x) => x.what === what);
    if (!c) {
      add("L8-selftest", "scripts/lint-security-gates.mjs", 0, `construct "${what}" has a self-test but no rule — the rule was deleted or renamed and its coverage vanished with it`);
      n++;
      continue;
    }
    if (!c.re.test(strip(positive))) {
      add("L8-selftest", "scripts/lint-security-gates.mjs", 0, `construct "${what}" does NOT match its own known-positive sample \`${positive.trim()}\` — the rule reads 0 because it measures nothing`);
      n++;
    }
    if (c.re.test(strip(negative))) {
      add("L8-selftest", "scripts/lint-security-gates.mjs", 0, `construct "${what}" fires on the CAPTURED form \`${negative.trim()}\` — a rule that flags the fix teaches everyone to route around the gate`);
      n++;
    }
  }
  // Every construct must be covered. A rule added without a self-test is a rule nobody has seen bite.
  for (const c of L8_CONSTRUCTS) {
    if (!L8_SELFTEST.some(([what]) => what === c.what)) {
      add("L8-selftest", "scripts/lint-security-gates.mjs", 0, `construct "${c.what}" has NO self-test — it has never been observed to bite`);
      n++;
    }
  }
  // The ESM-import rule is not in L8_CONSTRUCTS (it is a whole-FILE check over comment-stripped
  // source), so it is asserted here — including the two defects the first version of it shipped with:
  // a COMMENT mentioning the specifier fired it, and a specifier SPLIT ACROSS LINES was invisible to
  // both the per-line scan and the "fallback" that was supposed to catch it (that fallback's two
  // conditions were mutually exclusive, i.e. it was dead code pretending to be coverage).
  const esmCase = (label, src, shouldFire) => {
    // THE SAME FUNCTION L8 CALLS — see `esmImportFindings`.
    const fired = esmImportFindings(src).length > 0;
    if (fired !== shouldFire) {
      add("L8-selftest", "scripts/lint-security-gates.mjs", 0,
        `the live-builtin-ESM-import rule ${fired ? "FIRED" : "did NOT fire"} on the "${label}" sample, expected the opposite — ${JSON.stringify(src)}`);
      n++;
    }
  };
  esmCase("ordinary live builtin import", 'import { verify as cryptoVerify } from "node:crypto";', true);
  esmCase("multi-line live builtin import", 'import {\n  sign,\n  verify,\n} from "node:crypto";', true);
  esmCase("specifier split across lines", 'import { verify } from\n  "node:crypto";', true);
  esmCase("captured-wrapper import", 'import { ed25519Verify } from "./intrinsics.js";', false);
  esmCase("type-only import (erased by tsc, no runtime binding)", 'import type { KeyObject } from "node:crypto";', false);
  esmCase("a COMMENT discussing the import", '// e.g. `import { verify } from "node:crypto"` is repointable\nconst x = 1;', false);
  esmCase("a BLOCK COMMENT discussing the import", '/* import { verify } from "node:crypto" */\nconst x = 1;', false);
  return n;
}

let exitCode = 0;
const summary = [];
for (const lint of LINTS) {
  if (lint.mode === "external") { summary.push({ ...lint, count: null }); continue; }
  const before = findings.length;
  let count;
  try {
    count = lint.run();
  } catch (e) {
    add(lint.id, "-", 0, `LINT ITSELF FAILED: ${e.message} — a gate that cannot run is a gate that reports nothing`);
    exitCode = 1;
    count = -1;
  }
  const raised = findings.length - before;
  const n = typeof count === "number" && count >= 0 ? count : raised;
  summary.push({ ...lint, count: n, raised });

  if (lint.mode === "block" && raised > 0) exitCode = 1;
  if (lint.mode === "warn" && typeof lint.budget === "number" && n > lint.budget) {
    add(lint.id, "-", 0, `BUDGET EXCEEDED: ${n} violations against a budget of ${lint.budget}. A warn-mode lint still blocks on REGRESSION — the count may only fall.`);
    exitCode = 1;
  }
}

// L1's registry-staleness finding blocks regardless of L1's warn mode: it is not a migration
// scoreboard, it is "someone changed the public surface and nothing looked at it".
if (findings.some((f) => f.lint === "L1" && f.file === "conformance/ENTRY-POINTS.md")) exitCode = 1;

if (process.argv.includes("--json")) {
  console.log(JSON.stringify({ summary: summary.map((s) => ({ id: s.id, mode: s.mode, count: s.count, budget: s.budget ?? null })), findings }, null, 2));
  process.exit(exitCode);
}

console.log("L1–L7 security gates\n");
for (const s of summary) {
  const state = s.mode === "external" ? "EXTERNAL" : s.mode === "block" ? "BLOCKING" : `warn (budget ${s.budget})`;
  const count = s.count === null ? "—" : String(s.count);
  console.log(`  ${s.id}  ${String(state).padEnd(18)} ${count.padStart(4)}  ${s.name}`);
  if (s.ratchet) console.log(`      ratchet: ${s.ratchet}`);
}

const blocking = findings.filter((f) => {
  const l = LINTS.find((x) => x.id === f.lint);
  return l?.mode === "block" || f.msg.startsWith("BUDGET EXCEEDED") || f.msg.startsWith("LINT ITSELF FAILED") || f.file === "conformance/ENTRY-POINTS.md";
});
if (blocking.length) {
  console.error(`\n${blocking.length} BLOCKING finding(s):`);
  for (const f of blocking) console.error(`  ${f.lint}  ${f.file}${f.line ? ":" + f.line : ""}  ${f.msg}`);
}
const warned = findings.length - blocking.length;
if (warned) console.log(`\n${warned} warn-mode finding(s) within budget — the migration scoreboard, not a failure. Use --json for the full list.`);

process.exit(exitCode);
