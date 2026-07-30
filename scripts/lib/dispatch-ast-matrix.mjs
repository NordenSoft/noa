/**
 * THE EVASION MATRIX — one executable POSITIVE sample per construct the gate must flag, and one
 * NEGATIVE (captured) sample it must not.
 *
 * The negative half matters as much as the positive half: a rule that fires on the FIX
 * (`bufferFrom(s)`, `arrayIncludes(a, k)`) teaches everyone to route around the gate, and a gate
 * people route around measures nothing. Both halves run on EVERY invocation of the gate, not behind
 * a flag, so the analyser cannot be silently defanged.
 *
 * Every entry marked EVASION is a spelling that the previous LINE-BASED L8 was MEASURED to miss.
 */
export const EVASION_MATRIX = [
  // ── the spellings that defeated the regex gate ──────────────────────────────────────────────────
  {
    id: "multiline-member", rule: "live-builtin-member", evasion: true,
    why: "a per-line scan sees `return Buffer` on one line and `.from(s)` on the next, and matches neither",
    positive: `export function f(s: string) {\n  return Buffer\n    .from(s, "base64");\n}\n`,
    negative: `import { bufferFrom } from "./intrinsics.js";\nexport function f(s: string) {\n  return bufferFrom(s, "base64");\n}\n`,
  },
  {
    id: "computed-member-dispatch", rule: "computed-dispatch", evasion: true,
    why: '`allowed["includes"](k)` is a method dispatch containing no `.`',
    positive: `export function f(allowed: string[], k: string) {\n  return allowed["includes"](k);\n}\n`,
    negative: `import { arrayIncludes } from "./intrinsics.js";\nexport function f(allowed: string[], k: string) {\n  return arrayIncludes(allowed, k);\n}\n`,
  },
  {
    id: "optional-chain-builtin", rule: "live-builtin-member", evasion: true,
    why: "`Buffer?.from` reaches the same mutable slot with an existence check in front of it",
    positive: `export function f(s: string) {\n  return Buffer?.from(s);\n}\n`,
    negative: `import { bufferFrom } from "./intrinsics.js";\nexport function f(s: string) {\n  return bufferFrom(s);\n}\n`,
  },
  {
    id: "globalThis-prefixed", rule: "live-builtin-member", evasion: true,
    why: "`globalThis.Buffer.from` is the longhand spelling of every dotted rule",
    positive: `export function f(s: string) {\n  return globalThis.Buffer.from(s);\n}\n`,
    negative: `import { bufferFrom } from "./intrinsics.js";\nexport function f(s: string) {\n  return bufferFrom(s);\n}\n`,
  },
  {
    id: "spread-call-argument", rule: "spread", evasion: true,
    why: "`f(...[a,b])` spreads in an ARGUMENT position — the old rule only matched `[...` in an array literal",
    positive: `declare function g(x: number, y: number): number;\nexport function f(a: number, b: number) {\n  return g(...[a, b] as [number, number]);\n}\n`,
    negative: `declare function g(x: number, y: number): number;\nexport function f(a: number, b: number) {\n  return g(a, b);\n}\n`,
  },
  {
    id: "array-destructuring", rule: "array-destructuring", evasion: true,
    why: "`const [k0] = Object.keys(o)` invokes the value's ITERATOR with no `for…of` and no `...` present",
    positive: `import { objectKeys } from "./intrinsics.js";\nexport function f(o: object) {\n  const [k0] = objectKeys(o);\n  return k0;\n}\n`,
    negative: `import { objectKeys } from "./intrinsics.js";\nexport function f(o: object) {\n  const keys = objectKeys(o);\n  return keys[0];\n}\n`,
  },
  {
    id: "dotted-dotted-hasOwnProperty", rule: "live-builtin-member", evasion: true,
    why: "`Object.prototype.hasOwnProperty.call(a,k)` has no call directly after `Object.<name>` — MEASURED live in src/opts.ts:163, which L8 reported as clean",
    positive: `export function f(a: object, k: string) {\n  return Object.prototype.hasOwnProperty.call(a, k);\n}\n`,
    negative: `import { hasOwn } from "./intrinsics.js";\nexport function f(a: object, k: string) {\n  return hasOwn(a, k);\n}\n`,
  },
  {
    id: "dotted-dotted-includes", rule: "live-builtin-member", evasion: true,
    why: "`Array.prototype.includes.call(a,k)` reaches the C-02 slot by the same shape",
    positive: `export function f(a: string[], k: string) {\n  return Array.prototype.includes.call(a, k);\n}\n`,
    negative: `import { arrayIncludes } from "./intrinsics.js";\nexport function f(a: string[], k: string) {\n  return arrayIncludes(a, k);\n}\n`,
  },
  {
    id: "detached-binding", rule: "live-builtin-member", evasion: true,
    why: "`const f = Buffer.from; f(x)` splits the read from the call across two statements",
    positive: `export function f(x: string) {\n  const from = Buffer.from;\n  return from(x);\n}\n`,
    negative: `import { bufferFrom } from "./intrinsics.js";\nexport function f(x: string) {\n  const from = bufferFrom;\n  return from(x);\n}\n`,
  },
  {
    id: "dynamic-import", rule: "dynamic-import", evasion: true,
    why: "`await import(\"node:crypto\")` resolves the builtin at CALL time — no import STATEMENT exists to match",
    positive: `export async function f() {\n  const c = await import("node:crypto");\n  return c.verify;\n}\n`,
    negative: `import { ed25519Verify } from "./intrinsics.js";\nexport async function f() {\n  return ed25519Verify;\n}\n`,
  },
  {
    id: "process-getBuiltinModule", rule: "live-builtin-member", evasion: true,
    why: "`process.getBuiltinModule(\"node:crypto\").verify` reaches a builtin with no import and no dotted-builtin call",
    positive: `export function f() {\n  return process.getBuiltinModule("node:crypto").verify;\n}\n`,
    negative: `import { ed25519Verify } from "./intrinsics.js";\nexport function f() {\n  return ed25519Verify;\n}\n`,
  },
  {
    id: "bare-builtin-specifier", rule: "builtin-import", evasion: true,
    why: 'the old rule required the `node:` prefix, so `import { verify } from "crypto"` — identical semantics — matched nothing',
    positive: `import { verify } from "crypto";\nexport const v = verify;\n`,
    negative: `import { ed25519Verify } from "./intrinsics.js";\nexport const v = ed25519Verify;\n`,
  },
  {
    id: "slice-rewrite-class", rule: "value-dispatch", evasion: true,
    why: "round one's rewrite class: `.slice(` was in NO rule at all, and the array it manufactures is rooted on the live Array.prototype",
    positive: `export function f(a: string[]) {\n  return a.slice(0);\n}\n`,
    negative: `import { arraySlice } from "./intrinsics.js";\nexport function f(a: string[]) {\n  return arraySlice(a, 0);\n}\n`,
  },
  {
    id: "split-rewrite-class", rule: "value-dispatch", evasion: true,
    why: "`.split(` is the same rewrite class on the string side, and was equally unruled",
    positive: `export function f(s: string) {\n  return s.split(":");\n}\n`,
    negative: `import { strSplit } from "./intrinsics.js";\nexport function f(s: string) {\n  return strSplit(s, ":");\n}\n`,
  },
  {
    id: "parameter-default-constructor", rule: "live-constructor", evasion: true,
    why: "a parameter DEFAULT starts at column 0 on an exported declaration, so L8's indented-lines-only rule skipped it — MEASURED: this is how src/inert.ts kept a live WeakSet on the policy-table audit path",
    positive: `export function f(seen: WeakSet<object> = new WeakSet()) {\n  return seen;\n}\n`,
    negative: `import { newWeakSet } from "./intrinsics.js";\nexport function f(seen: WeakSet<object> = newWeakSet()) {\n  return seen;\n}\n`,
  },

  // ── the constructs the regex gate DID carry: they must still bite ────────────────────────────────
  {
    id: "for-of", rule: "for-of", evasion: false,
    why: "the iterator dispatch this whole round is about",
    positive: `import { objectKeys } from "./intrinsics.js";\nexport function f(o: object) {\n  for (const k of objectKeys(o)) { if (k === "x") return true; }\n  return false;\n}\n`,
    negative: `import { objectKeys } from "./intrinsics.js";\nexport function f(o: object) {\n  const keys = objectKeys(o);\n  for (let i = 0; i < keys.length; i++) { if (keys[i] === "x") return true; }\n  return false;\n}\n`,
  },
  {
    id: "array-spread-literal", rule: "spread", evasion: false,
    why: "`[...x]` dispatches through %ArrayIteratorPrototype%.next",
    positive: `export function f(parsed: string[]) {\n  const a = [...parsed];\n  return a;\n}\n`,
    negative: `import { arraySlice } from "./intrinsics.js";\nexport function f(parsed: string[]) {\n  const a = arraySlice(parsed);\n  return a;\n}\n`,
  },
  {
    id: "instanceof", rule: "instanceof", evasion: false,
    why: "performs a dynamic Get(C, Symbol.hasInstance)",
    positive: `export function f(v: unknown) {\n  if (v instanceof Set) return null;\n  return v;\n}\n`,
    negative: `import { collectionBrand } from "./intrinsics.js";\nexport function f(v: unknown) {\n  if (collectionBrand(v) !== null) return null;\n  return v;\n}\n`,
  },
  {
    id: "live-builtin-static-call", rule: "live-builtin-member", evasion: false,
    why: "a live read of a mutable global",
    positive: `export function f(s: string) {\n  const b = Buffer.from(s, "base64");\n  return b;\n}\n`,
    negative: `import { bufferFrom } from "./intrinsics.js";\nexport function f(s: string) {\n  const b = bufferFrom(s, "base64");\n  return b;\n}\n`,
  },
  {
    id: "live-prototype-method", rule: "value-dispatch", evasion: false,
    why: "a rewrite/decode method looked up on a value",
    positive: `export function f(der: Buffer) {\n  return der.toString("base64");\n}\n`,
    negative: `import { bufToString } from "./intrinsics.js";\nexport function f(der: Buffer) {\n  return bufToString(der, "base64");\n}\n`,
  },
  {
    id: "bare-global-call", rule: "bare-global-call", evasion: false,
    why: "an UNDOTTED global is a writable property of globalThis (T18)",
    positive: `export function f(b: number) {\n  return BigInt(b);\n}\n`,
    negative: `import { toBigInt } from "./intrinsics.js";\nexport function f(b: number) {\n  return toBigInt(b);\n}\n`,
  },
  {
    id: "array-hof", rule: "value-dispatch", evasion: false,
    why: "`Array.prototype.forEach = () => undefined` VISITS NOTHING, so a validator accepts what it never inspected (T19)",
    positive: `export function f(rules: unknown[], check: (r: unknown, i: number) => void) {\n  rules.forEach((r, i) => check(r, i));\n}\n`,
    negative: `export function f(rules: unknown[], check: (r: unknown, i: number) => void) {\n  for (let i = 0; i < rules.length; i++) check(rules[i], i);\n}\n`,
  },
  {
    id: "node-prefixed-import", rule: "builtin-import", evasion: false,
    why: "an ESM binding for a node builtin is repointable by syncBuiltinESMExports() (T17)",
    positive: `import { verify as cryptoVerify } from "node:crypto";\nexport const v = cryptoVerify;\n`,
    negative: `import { ed25519Verify } from "./intrinsics.js";\nexport const v = ed25519Verify;\n`,
  },
  {
    id: "live-global-constructor", rule: "live-constructor", evasion: false,
    why: "`new Set()` READS globalThis.Set at call time",
    positive: `export function f() {\n  const seen = new Set<string>();\n  return seen;\n}\n`,
    negative: `import { newSet } from "./intrinsics.js";\nexport function f() {\n  const seen = newSet<string>();\n  return seen;\n}\n`,
  },
  {
    id: "keyobject-accessor-read", rule: "accessor-read", evasion: false,
    why: "`asymmetricKeyType` is a configurable ACCESSOR — one defineProperty makes the curve pin bless an Ed448 key (T18)",
    positive: `export function f(key: { asymmetricKeyType?: string }) {\n  return key.asymmetricKeyType === "ed25519";\n}\n`,
    negative: `import { asymmetricKeyType } from "./intrinsics.js";\nexport function f(key: never) {\n  return asymmetricKeyType(key) === "ed25519";\n}\n`,
  },
  {
    id: "typed-array-accessor-read", rule: "accessor-read", evasion: false,
    why: "`.buffer`/`.byteOffset` are configurable accessors on %TypedArray%.prototype",
    positive: `export function f(bytes: Uint8Array) {\n  return bytes.byteOffset + bytes.byteLength;\n}\n`,
    negative: `import { taByteOffset, taByteLength } from "./intrinsics.js";\nexport function f(bytes: Uint8Array) {\n  return taByteOffset(bytes) + taByteLength(bytes);\n}\n`,
  },
  {
    id: "regex-literal", rule: "regex-literal", evasion: false,
    why: "RegExp.prototype.test performs a dynamic lookup of exec on the receiver (C-02(f))",
    positive: `export function f(s: string) {\n  return /^[0-9a-f]+$/.test(s);\n}\n`,
    negative: `import { isHexLower } from "./scan.js";\nexport function f(s: string) {\n  return isHexLower(s);\n}\n`,
  },

  // ── FALSE-POSITIVE guards: prose and type-only imports must never fire ───────────────────────────
  {
    id: "comment-discussing-import", rule: null, evasion: false,
    why: "a COMMENT mentioning the specifier fired the old text-based rule; an AST has no comment statements at all",
    positive: null,
    negative: `// e.g. \`import { verify } from "node:crypto"\` is repointable\n/* import { verify } from "crypto" */\nexport const x = 1;\n`,
  },
  {
    id: "type-only-import", rule: null, evasion: false,
    why: "erased by tsc — there is no runtime binding to repoint",
    positive: null,
    negative: `import type { KeyObject } from "node:crypto";\nexport type K = KeyObject;\n`,
  },
  {
    id: "load-time-capture", rule: null, evasion: false,
    why: "a module-top-level capture IS the mechanism — flagging it would flag the fix",
    positive: null,
    negative: `const _includes = Array.prototype.includes;\nconst _apply = Reflect.apply;\nexport const includes = (a: unknown[], v: unknown) => _apply(_includes, a, [v]);\n`,
  },
  {
    id: "local-shadowing-a-builtin-name", rule: null, evasion: false,
    why: "a LOCAL named `Buffer` is not the global — only symbol resolution can tell the difference, and a text scan flags it wrongly",
    positive: null,
    negative: `export function f(Buffer: { from: (s: string) => string }, s: string) {\n  return Buffer.from(s);\n}\n`,
  },
];
