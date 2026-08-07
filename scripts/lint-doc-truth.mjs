#!/usr/bin/env node
/**
 * lint-doc-truth — the README is a claim surface, so it is gated like one.
 *
 * WHY THIS EXISTS, precisely. On 2026-08-06 the root README said `noa-receipt` **0.6.0** while the
 * registry served **0.6.2**, and it stated a total test count that had been counted by hand on one
 * afternoon. Neither was a lie when it was written; both became false while every test, lint and CI
 * job stayed green — because nothing in this repository read the README. A project whose entire
 * product is "a claim you can check mechanically" cannot have a front page that only a human ever
 * checks. This is that check.
 *
 * WHAT IT VERIFIES, and each rule exists because the class it catches has actually occurred here:
 *
 *   1  VERSION LITERAL — any version number the README states next to a published package name must
 *      equal `npm view <pkg> version`. Self-updating shields.io badges state no literal at all and
 *      are therefore the recommended form; a literal that is currently CORRECT still earns advice,
 *      because it is a fact with a decay date.
 *   2  PUBLICATION CLAIM — every package the README presents as being on npm (badge or
 *      npmjs.com/package/<name> link) must actually resolve on the registry. Six manifests in
 *      `packages/` are non-private and unpublished; presenting one of them as installable is the
 *      same false-claim class pointing the other way.
 *   3  TEST COUNT — a hardcoded "N tests" is banned outright. There is no cheap machine source for
 *      it (the suites take minutes across nine packages), so the honest options are "derive it" or
 *      "do not state it", and this repository states it in CI instead. A number nobody can re-derive
 *      in under three minutes does not belong on the front page.
 *   4  RELATIVE LINKS — every relative link resolves to a file or directory that exists. A 404 in
 *      the README of a trust project is a small thing that looks exactly like a big thing.
 *   5  DERIVED COUNTS — "N attack vectors" / "N malformed vectors" / "N verifiers" are re-derived
 *      from the filesystem on every run. The README once carried `14` attack vectors for weeks after
 *      two were added; that is the whole reason these are counted rather than typed.
 *   6  RUNNABLE QUICKSTART — every ```bash block inside the `## 60-second quickstart` section is
 *      concatenated IN ORDER and executed in a fresh temp directory under `set -euo pipefail`. That
 *      is precisely what a reader does when they paste the blocks into one terminal, which is why
 *      the blocks are concatenated rather than run in isolation: `cd` in block 1 must still be in
 *      effect for block 3, exactly as it is for the human.
 *   7  npx FOOTGUN — the CLI binary is named `noa`, but the npm package named `noa` belongs to an
 *      unrelated third party (an MVC library, maintainer `jsz1`). `npx noa verify …` therefore
 *      downloads and runs a stranger's package. The README said exactly that for months. Banned.
 *   8  LICENSE PARITY — a license badge must name the license in the root manifest.
 *
 * WHAT IT DELIBERATELY DOES NOT DO. It does not judge prose, tone, structure or completeness, and it
 * does not require the README to make any particular claim. A rule that fires on a claim the README
 * does not make would be a content mandate, not a truth gate. The consequence is stated plainly so
 * nobody mistakes it for coverage: DELETING a claim always satisfies this gate. It stops false
 * statements, never missing ones — except for the quickstart, where an empty or gutted section is an
 * explicit failure (rule 6's anti-vacuity floor), because "the runnable proof ran" and "there was
 * nothing to run" must never share an exit code.
 *
 * ANTI-VACUITY. `--selftest` runs fixtures in BOTH directions against injected facts — no network,
 * no filesystem, no shell. Every finding carries a `[rule-id]` tag and every must-FAIL fixture
 * declares WHICH rule it is there to prove, so the selftest asserts the triggered rule set is
 * EXACTLY that one. Without this, a fixture can pass for a reason unrelated to the rule it was
 * written for — measured here: `9 attack vectors and 8 malformed vectors` was written to isolate the
 * malformed counter and was actually caught by the attack counter, so deleting the malformed rule
 * outright would have left the suite green. The must-PASS half is the other important one:
 * `noa.receipt/0.1` is a spec id
 * and not a package version, `ADR-0002` is not a version, `0.2.0 (breaking)` in a changelog note is
 * not a package version claim, and the sentence WARNING about `npx noa` must not itself trip the
 * `npx noa` ban. A lazy implementation passes the must-fail half and silently blocks every honest
 * README; that failure looks identical to a working gate until someone switches it off (KURAL 29).
 * CI runs `--selftest` BEFORE it judges the real README: a check that could not run and a check that
 * passed must never share an exit code.
 *
 *   node scripts/lint-doc-truth.mjs             # judge the real README (network + shell)
 *   node scripts/lint-doc-truth.mjs --selftest  # hermetic fixtures, both directions
 *
 * Exit: 0 clean · 1 findings · 2 the gate could not run (selftest failure, registry unreachable).
 */

import { execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, readdirSync, readFileSync, writeFileSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

/** The repository root, derived from this file's own location — one expression, no second copy. */
const ROOT = fileURLToPath(new URL("..", import.meta.url));

/* ── the judging core: pure, fact-injected, no I/O ────────────────────────────────────────────── */

const NUMBER_WORDS = new Map([
  ["zero", 0], ["one", 1], ["two", 2], ["three", 3], ["four", 4], ["five", 5],
  ["six", 6], ["seven", 7], ["eight", 8], ["nine", 9], ["ten", 10],
]);

/** Escape a package name for use inside a RegExp (names contain `-`, which is inert, but not `.`). */
function rx(literal) {
  return literal.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * Every finding is tagged with the rule that produced it. The tag is not decoration: `--selftest`
 * asserts that a must-FAIL fixture trips EXACTLY the rule it was written for, which is the only way
 * to know a fixture still protects the code it was written to protect.
 */
function finding(rule, message) {
  return `[${rule}] ${message}`;
}

/** Quote a matched fragment without its markdown emphasis, so `**15**` reads as `15` in the report. */
function plain(fragment) {
  return fragment.replace(/\*/g, "").trim();
}

/**
 * Fenced-code spans, so link/version scanning can be told "this is prose" vs "this is code".
 * Returns an array of [start, end) offsets covering every ``` fenced block.
 */
function fencedRanges(md) {
  const ranges = [];
  const fence = /^```[^\n]*\n[\s\S]*?^```/gm;
  for (const m of md.matchAll(fence)) ranges.push([m.index, m.index + m[0].length]);
  return ranges;
}

function inRanges(ranges, index) {
  return ranges.some(([a, b]) => index >= a && index < b);
}

/**
 * Extract the ```bash blocks of the quickstart section.
 * The section is located by ONE expression (`## 60-second quickstart`) and ends at the next `## `.
 */
export function quickstartBlocks(md) {
  const start = md.search(/^## 60-second quickstart\s*$/m);
  if (start === -1) return null;
  const rest = md.slice(start + 1);
  const nextHeading = rest.search(/^## /m);
  const section = nextHeading === -1 ? rest : rest.slice(0, nextHeading);
  const blocks = [];
  for (const m of section.matchAll(/^```bash\n([\s\S]*?)^```/gm)) blocks.push(m[1]);
  return blocks;
}

/**
 * Judge a README against injected facts.
 *
 * @param {string} md            README text
 * @param {{
 *   registry: Record<string, string|null>,   // package -> published version, or null when 404
 *   vectors: {attack: number, malformed: number},
 *   implementations: number,
 *   license: string,
 *   fileExists: (relPath: string) => boolean,
 *   runQuickstart: (script: string) => {code: number, output: string},
 * }} facts
 * @returns {{ok: boolean, errors: string[], advice: string[]}}
 */
export function lintDocTruth(md, facts) {
  const errors = [];
  const advice = [];
  const code = fencedRanges(md);

  /* 2 — publication claims. Collected first: they define which names rule 1 must know about. */
  const claimedPublished = new Set();
  for (const m of md.matchAll(/(?:img\.shields\.io\/npm\/v\/|npmjs\.com\/package\/)([@a-z0-9._/-]+?)(?=[?)\s"']|$)/gi)) {
    claimedPublished.add(m[1]);
  }
  for (const name of claimedPublished) {
    // Defensive only. In a real run this branch is unreachable: `candidatePackages()` finds the
    // claims with the SAME expression used here, so every claimed name already carries a registry
    // fact. It fires for injected facts, and it exists so a future divergence between those two
    // expressions surfaces as a loud finding instead of a silent `undefined !== null` pass.
    if (!(name in facts.registry)) {
      errors.push(finding(
        "publication-claim",
        `the README presents \`${name}\` as an npm package, but the gate was given no registry fact ` +
          `for it. Add it to the candidate set or remove the badge/link.`,
      ));
    } else if (facts.registry[name] === null) {
      errors.push(finding(
        "publication-claim",
        `the README presents \`${name}\` as published on npm (badge or package link), but the ` +
          `registry returns 404. Several packages in this repo are non-private and unpublished; ` +
          `presenting one as installable is a false claim in the other direction.`,
      ));
    }
  }

  /* 1 — version literals stated next to a published package name. */
  for (const [name, published] of Object.entries(facts.registry)) {
    const pattern = new RegExp("`?" + rx(name) + "`?\\s*(?:@|\\s)\\s*v?(\\d+\\.\\d+\\.\\d+)", "g");
    for (const m of md.matchAll(pattern)) {
      const stated = m[1];
      if (published === null) {
        errors.push(finding(
          "version-literal",
          `the README states version ${stated} for \`${name}\`, which is not on the registry at all.`,
        ));
      } else if (stated !== published) {
        errors.push(finding(
          "version-literal",
          `the README states \`${name}\` ${stated}; the registry serves ${published}. This is the ` +
            `exact drift this gate was built for — use the self-updating badge ` +
            `(https://img.shields.io/npm/v/${name}) instead of a literal.`,
        ));
      } else {
        advice.push(
          `\`${name}\` ${stated} is currently correct, but it is a hardcoded literal with a decay ` +
            `date. The shields.io badge states the same fact and never goes stale.`,
        );
      }
    }
  }

  /* 3 — hardcoded test counts. */
  for (const m of md.matchAll(/\b(\d[\d,]*)\s+(tests?|test cases?|assertions?|specs?)\b/gi)) {
    if (inRanges(code, m.index)) continue; // sample output inside a fence is a transcript, not a claim
    errors.push(finding(
      "test-count",
      `"${m[0]}" is a hardcoded test count. There is no source a reader can re-derive in seconds, ` +
        `and this repository has already shipped a stale one. State it in CI, not here.`,
    ));
  }
  for (const m of md.matchAll(/\b(\d+)\s*\/\s*(\d+)\s+(pass|passing|green|tests)\b/gi)) {
    if (inRanges(code, m.index)) continue;
    errors.push(finding("test-count", `"${m[0]}" is a hardcoded pass count, same class as a test count.`));
  }

  /* 4 — relative links resolve. */
  for (const m of md.matchAll(/!?\[[^\]]*\]\(\s*([^)\s]+?)(?:\s+"[^"]*")?\s*\)/g)) {
    const target = m[1];
    if (/^(https?:|mailto:|tel:|#)/i.test(target)) continue;
    const clean = decodeURI(target.replace(/[?#].*$/, ""));
    if (clean === "") continue;
    if (!facts.fileExists(clean)) {
      errors.push(finding(
        "relative-link",
        `relative link \`${target}\` does not resolve to a file or directory in this repo.`,
      ));
    }
  }

  /* 5 — counts derived from the repository, never typed. */
  const countRules = [
    ["count-attack-vectors", /(\d+)\*{0,2}\s+attack vectors/gi, facts.vectors.attack, "attack vectors in conformance/vectors/attack"],
    ["count-malformed-vectors", /(\d+)\*{0,2}\s+malformed vectors/gi, facts.vectors.malformed, "malformed vectors in conformance/vectors/malformed"],
  ];
  for (const [rule, pattern, actual, what] of countRules) {
    for (const m of md.matchAll(pattern)) {
      if (Number(m[1]) !== actual) {
        errors.push(finding(rule, `the README says "${plain(m[0])}"; the repository has ${actual} ${what}.`));
      }
    }
  }
  const implPattern =
    /\b(zero|one|two|three|four|five|six|seven|eight|nine|ten|\d+)\*{0,2}\s+(?:independent\s+)?(?:verifier\s+)?(?:implementations|verifiers)\b/gi;
  for (const m of md.matchAll(implPattern)) {
    const word = m[1].toLowerCase();
    const stated = NUMBER_WORDS.has(word) ? NUMBER_WORDS.get(word) : Number(word);
    if (stated !== facts.implementations) {
      errors.push(finding(
        "count-implementations",
        `the README says "${plain(m[0])}"; the repository has ${facts.implementations} verifier ` +
          `implementations (the TypeScript reference plus every impl-* directory).`,
      ));
    }
  }

  /* 7 — the npx footgun. `npx noa <cmd>` runs a third party's package, not ours. */
  for (const m of md.matchAll(/npx\s+(?:--yes\s+|-y\s+)?noa(?![-\w])\s+[a-z]/gi)) {
    errors.push(finding(
      "npx-footgun",
      `"${m[0].trim()}…" tells a reader to run \`npx noa\`, which resolves the npm package named ` +
        `\`noa\` — an unrelated third-party library, not this project. Use ` +
        `\`npx --package noa-receipt noa …\` or the local \`./node_modules/.bin/noa\`.`,
    ));
  }

  /* 8 — license badge parity with the root manifest. */
  for (const m of md.matchAll(/img\.shields\.io\/badge\/license-([^/?\s)]+?)-(?:blue|green|brightgreen|lightgrey|informational|orange)(?:\.svg)?/gi)) {
    const stated = m[1].replace(/--/g, "-").replace(/_/g, " ");
    if (stated !== facts.license) {
      errors.push(finding(
        "license-parity",
        `the license badge says "${stated}"; package.json says "${facts.license}".`,
      ));
    }
  }

  /* 6 — the quickstart actually runs. */
  const blocks = quickstartBlocks(md);
  if (blocks === null) {
    errors.push(finding(
      "quickstart",
      "there is no `## 60-second quickstart` section. That heading is the ONE expression this gate " +
        "uses to find the runnable blocks; renaming it silently disables rule 6.",
    ));
  } else if (blocks.length < 3) {
    errors.push(finding(
      "quickstart",
      `the quickstart section has ${blocks.length} runnable \`\`\`bash block(s); at least 3 are ` +
        `required (install, produce a signed receipt, verify it). A gutted quickstart would ` +
        `otherwise pass this gate by having nothing to prove.`,
    ));
  } else {
    const script = blocks.join("\n");
    if (!/npm install noa-receipt/.test(script)) {
      errors.push(finding(
        "quickstart",
        "the quickstart never runs `npm install noa-receipt`, so it does not exercise the PUBLISHED " +
          "package a stranger actually gets. That is the only thing this section is worth proving.",
      ));
    }
    if (!/noa verify/.test(script)) {
      errors.push(finding("quickstart", "the quickstart never verifies anything (`noa verify` does not appear)."));
    }
    // Executed only when nothing else is wrong: a README with a stale version claim has already
    // failed, and spending 30s of registry install time to say so twice helps nobody.
    if (errors.length === 0) {
      const result = facts.runQuickstart("set -euo pipefail\n\n" + script + "\n");
      if (result.code !== 0) {
        errors.push(finding(
          "quickstart",
          `the quickstart blocks failed with exit code ${result.code} when executed in order in a ` +
            `clean directory. Output tail:\n${indent(tail(result.output, 30))}`,
        ));
      }
    }
  }

  return { ok: errors.length === 0, errors, advice };
}

function tail(text, lines) {
  return text.split("\n").slice(-lines).join("\n");
}

function indent(text) {
  return text.split("\n").map((l) => "      | " + l).join("\n");
}

/* ── fixtures ─────────────────────────────────────────────────────────────────────────────────── */

/** Facts the fixtures are judged against. Fixed, hermetic — no network, no filesystem, no shell. */
const FIXTURE_FACTS = {
  registry: { "noa-receipt": "0.6.2", "noa-mcp-proxy": "0.3.2", "noa-not-published": null },
  vectors: { attack: 16, malformed: 9 },
  implementations: 5,
  license: "Apache-2.0",
  fileExists: (p) => ["NON-CLAIMS.md", "docs/receipt-spec.md", "src/", "LICENSE"].includes(p),
  runQuickstart: () => ({ code: 0, output: "(fixture runner: not executed)" }),
};

/** A quickstart section that satisfies rule 6's structural floor, appended to fixtures that need it. */
const OK_QUICKSTART = `
## 60-second quickstart

\`\`\`bash
npm install noa-receipt
\`\`\`

\`\`\`bash
node -e 'console.log(1)'
\`\`\`

\`\`\`bash
./node_modules/.bin/noa verify chain.json --keyring keyring.json
\`\`\`
`;

/**
 * [markdown, expected rule id, why]. The expected rule is asserted EXACTLY: a fixture that trips two
 * rules proves nothing about either, because deleting one of them leaves the suite green.
 */
const MUST_FAIL = [
  [`\`noa-receipt\` 0.6.0 is published.${OK_QUICKSTART}`, "version-literal", "the live specimen: a version literal one patch behind the registry"],
  [`Install noa-receipt@0.6.1 today.${OK_QUICKSTART}`, "version-literal", "the @ form of the same drift"],
  [`Try noa-mcp-proxy v0.3.1.${OK_QUICKSTART}`, "version-literal", "a v-prefixed literal for the second package"],
  [`Install \`noa-not-published\` 0.1.0.${OK_QUICKSTART}`, "version-literal", "a version for a package that is not on the registry"],
  [`[![npm](https://img.shields.io/npm/v/noa-not-published)](LICENSE)${OK_QUICKSTART}`, "publication-claim", "a badge for an unpublished package"],
  [`See [npm](https://www.npmjs.com/package/noa-not-published).${OK_QUICKSTART}`, "publication-claim", "an npm link for an unpublished package"],
  [`**1891 tests green** across nine suites.${OK_QUICKSTART}`, "test-count", "the live specimen: a hardcoded test count"],
  [`We run 1,891 tests on every push.${OK_QUICKSTART}`, "test-count", "the same count with a thousands separator"],
  [`kernel 534/534 pass.${OK_QUICKSTART}`, "test-count", "a hardcoded pass ratio, same class"],
  [`Read [the spec](docs/nope.md).${OK_QUICKSTART}`, "relative-link", "a relative link to a file that does not exist"],
  [`![diagram](docs/missing.png)${OK_QUICKSTART}`, "relative-link", "an IMAGE with a dead relative target — same rule, different syntax"],
  [`The suite has 15 attack vectors.${OK_QUICKSTART}`, "count-attack-vectors", "a vector count one below the filesystem"],
  [
    `The suite has 16 attack vectors and 8 malformed vectors.${OK_QUICKSTART}`,
    "count-malformed-vectors",
    "ISOLATES the malformed counter — the attack figure here is deliberately CORRECT, because the " +
      "first version of this fixture said `9 attack vectors` and was caught by the attack rule instead",
  ],
  [`Four independent implementations agree.${OK_QUICKSTART}`, "count-implementations", "an implementation count as a WORD, one too low"],
  [`There are 6 verifiers.${OK_QUICKSTART}`, "count-implementations", "the same count as a digit, one too high"],
  [`Run \`npx noa verify receipts.json\` to check a chain.${OK_QUICKSTART}`, "npx-footgun", "the live specimen: npx resolving a stranger's package"],
  [`Run npx --yes noa verify receipts.json.${OK_QUICKSTART}`, "npx-footgun", "the --yes form, which is worse: it skips the install prompt"],
  [`[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)${OK_QUICKSTART}`, "license-parity", "a license badge contradicting package.json"],
  ["# No quickstart here at all", "quickstart", "rule 6 renamed or deleted — the section must exist"],
  [
    `## 60-second quickstart\n\n\`\`\`bash\nnpm install noa-receipt\n\`\`\`\n`,
    "quickstart",
    "a gutted quickstart: one block is below the anti-vacuity floor",
  ],
  [
    `## 60-second quickstart\n\n\`\`\`bash\ntrue\n\`\`\`\n\n\`\`\`bash\ntrue\n\`\`\`\n\n\`\`\`bash\ntrue\n\`\`\`\n`,
    "quickstart",
    "three blocks that never install the published package or verify anything",
  ],
];

const MUST_PASS = [
  [
    `The wire format is \`noa.receipt/0.1\` and it is frozen. Install \`noa-receipt\` from npm.${OK_QUICKSTART}`,
    "SPEC ID next to the package name: `noa.receipt/0.1` is not a package version and must not be read as one",
  ],
  [
    `[![npm](https://img.shields.io/npm/v/noa-receipt?label=noa-receipt)](https://www.npmjs.com/package/noa-receipt)${OK_QUICKSTART}`,
    "the recommended form: a self-updating badge states the version and no literal appears",
  ],
  [
    `\`noa-receipt\` 0.6.2 is the published kernel.${OK_QUICKSTART}`,
    "a literal that is CURRENTLY TRUE passes (with advice) — the gate checks truth, not style",
  ],
  [
    `⚠️ 0.2.0 (breaking): COSE alg-id \`-8\` became \`-19\` (RFC 9864).${OK_QUICKSTART}`,
    "a historical version in a changelog note, not adjacent to a package name",
  ],
  [
    `The isolated kernel is specified in ADR-0002 and NOT built. See RFC 8032 and Ed25519.${OK_QUICKSTART}`,
    "document ids and algorithm names carry digits and are not versions",
  ],
  [
    `Do not run \`npx noa\` — the npm package named \`noa\` is a stranger's.${OK_QUICKSTART}`,
    "THE WARNING ABOUT THE FOOTGUN MUST NOT TRIP THE FOOTGUN RULE — a substring ban would kill it",
  ],
  [
    `Use \`npx --package noa-receipt noa verify chain.json\` when nothing is installed.${OK_QUICKSTART}`,
    "the correct npx incantation names the package and must stay legal",
  ],
  [
    `Or run \`./node_modules/.bin/noa verify chain.json\` directly.${OK_QUICKSTART}`,
    "the local binary path is not an npx invocation",
  ],
  [
    `16 attack vectors and 9 malformed vectors, all rejected.${OK_QUICKSTART}`,
    "counts that match the filesystem",
  ],
  [
    `**five** independent verifier implementations, and Five verifiers agree.${OK_QUICKSTART}`,
    "bold markers and capitalisation must not defeat the number-word comparison",
  ],
  [
    `Python is ground truth for the Go, Rust and C# verifiers below.${OK_QUICKSTART}`,
    "a SUBSET named by language carries no count word — measured: the first draft said 'the three " +
      "verifiers below' and the gate correctly refused it as an ambiguous total claim",
  ],
  [
    `Test counts are deliberately not printed here; CI is the live count.${OK_QUICKSTART}`,
    "the word 'tests' with no number in front is prose, not a claim",
  ],
  [
    `Exit codes: 0 VALID, 1 UNVERIFIED, 2 TAMPERED, 3 MALFORMED.${OK_QUICKSTART}`,
    "small integers next to words are not counts of anything this gate measures",
  ],
  [
    `Read [NON-CLAIMS](NON-CLAIMS.md#nc-61) and [the spec](docs/receipt-spec.md "title").${OK_QUICKSTART}`,
    "a fragment and a link title must be stripped before the existence check",
  ],
  [
    `[home](https://noatrust.com) · [mail](mailto:x@y.z) · [top](#what-we-do-not-claim)${OK_QUICKSTART}`,
    "absolute, mailto and anchor-only links are out of scope, not broken links",
  ],
  [
    `[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)${OK_QUICKSTART}`,
    "shields escapes a hyphen as `--`; un-escaping it must yield exactly Apache-2.0",
  ],
  [
    "```\n$ npm test\n1891 tests passed\n```\n" + OK_QUICKSTART,
    "a TRANSCRIPT inside a fence is sample output, not a claim the README is making",
  ],
];

function selftest() {
  let failed = 0;
  const show = (s) => JSON.stringify(s.split("\n")[0].slice(0, 52));

  console.log("must-FAIL fixtures (each has to be rejected by EXACTLY the rule it was written for):");
  for (const [md, expectedRule, why] of MUST_FAIL) {
    const { ok, errors } = lintDocTruth(md, FIXTURE_FACTS);
    const rules = [...new Set(errors.map((e) => e.match(/^\[([a-z-]+)\]/)?.[1] ?? "untagged"))];
    if (ok) {
      failed++;
      console.log(`  ✖ ESCAPED  ${show(md).padEnd(56)} ${why}`);
    } else if (rules.length !== 1 || rules[0] !== expectedRule) {
      failed++;
      console.log(`  ✖ WRONG RULE ${show(md).padEnd(54)} expected [${expectedRule}], got [${rules.join("][")}]`);
      console.log(`               ${why}`);
    } else {
      console.log(`  ✔ ${`[${expectedRule}]`.padEnd(24)} ${show(md).padEnd(56)} ${why}`);
    }
  }

  console.log("\nmust-PASS fixtures (the gate has to stay quiet on each of these):");
  for (const [md, why] of MUST_PASS) {
    const { ok, errors } = lintDocTruth(md, FIXTURE_FACTS);
    if (!ok) {
      failed++;
      console.log(`  ✖ BLOCKED  ${show(md).padEnd(56)} ${why}`);
      for (const e of errors) console.log(`               ${e.split("\n")[0]}`);
    } else {
      console.log(`  ✔ passed   ${show(md).padEnd(56)} ${why}`);
    }
  }

  if (failed > 0) {
    console.log(`\nSELFTEST FAILED — ${failed} fixture(s) behaved wrongly. The gate is NOT trustworthy`);
    console.log("and renders no verdict on the real README. A check that could not run and a check");
    console.log("that passed must never share an exit code.");
    process.exit(2);
  }
  console.log(`\nSELFTEST PASSED — ${MUST_FAIL.length} rejected, ${MUST_PASS.length} accepted.`);
}

/* ── real facts ───────────────────────────────────────────────────────────────────────────────── */

/** `npm view <pkg> version`. Returns the version, or null for a genuine 404. Throws on anything else. */
function registryVersion(name) {
  try {
    return execFileSync("npm", ["view", name, "version"], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
      timeout: 60_000,
    }).trim();
  } catch (err) {
    const text = String(err.stderr ?? "") + String(err.stdout ?? "") + String(err.message ?? "");
    if (/E404|is not in this registry/.test(text)) return null;
    // Anything else — offline, proxy, rate limit — is the gate failing to RUN, never a pass.
    const e = new Error(`cannot reach the npm registry for \`${name}\`: ${tail(text.trim(), 3)}`);
    e.setupFailure = true;
    throw e;
  }
}

/** Package names this README could possibly be making a registry claim about. */
function candidatePackages(md) {
  const names = new Set();
  const root = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8"));
  names.add(root.name);
  for (const dir of readdirSync(join(ROOT, "packages"), { withFileTypes: true })) {
    if (!dir.isDirectory()) continue;
    const manifest = join(ROOT, "packages", dir.name, "package.json");
    if (!existsSync(manifest)) continue;
    const pkg = JSON.parse(readFileSync(manifest, "utf8"));
    if (pkg.private !== true && pkg.name) names.add(pkg.name);
  }
  for (const m of md.matchAll(/(?:img\.shields\.io\/npm\/v\/|npmjs\.com\/package\/)([@a-z0-9._/-]+?)(?=[?)\s"']|$)/gi)) {
    names.add(m[1]);
  }
  // Only names the README actually mentions cost a network round trip.
  return [...names].filter((n) => md.includes(n));
}

function countJson(dir) {
  return readdirSync(join(ROOT, dir)).filter((f) => f.endsWith(".json")).length;
}

/** The TypeScript reference in `src/` plus every `impl-*` directory. Derived, never hand-listed. */
function countImplementations() {
  if (!existsSync(join(ROOT, "src"))) {
    const e = new Error("src/ is missing — the TypeScript reference is one of the counted implementations");
    e.setupFailure = true;
    throw e;
  }
  const impls = readdirSync(ROOT, { withFileTypes: true }).filter(
    (d) => d.isDirectory() && /^impl-/.test(d.name),
  );
  return impls.length + 1;
}

/**
 * Run the quickstart exactly as a reader would: one shell, one fresh directory, blocks in order.
 * `npm_config_*` keeps the install quiet and out of the developer's real project.
 */
function runQuickstart(script) {
  const dir = mkdtempSync(join(tmpdir(), "noa-doc-truth-"));
  const path = join(dir, "quickstart.sh");
  writeFileSync(path, script, { mode: 0o700 });
  // The transcript is printed even on success, on purpose: a gate that says "the quickstart ran"
  // with nothing to show cannot be told apart from a gate that skipped it. This one shows its work.
  console.log(`  running the quickstart in ${dir} …`);
  try {
    const output = execFileSync("bash", [path], {
      cwd: dir,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
      timeout: 150_000,
      env: { ...process.env, npm_config_fund: "false", npm_config_audit: "false", CI: "1" },
    });
    console.log(indent(output.trimEnd()));
    return { code: 0, output };
  } catch (err) {
    return {
      code: typeof err.status === "number" ? err.status : 1,
      output: String(err.stdout ?? "") + String(err.stderr ?? "") + String(err.message ?? ""),
    };
  }
}

function gatherFacts(md) {
  const registry = {};
  for (const name of candidatePackages(md)) registry[name] = registryVersion(name);
  return {
    registry,
    vectors: {
      attack: countJson("conformance/vectors/attack"),
      malformed: countJson("conformance/vectors/malformed"),
    },
    implementations: countImplementations(),
    license: JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8")).license,
    fileExists: (rel) => {
      const target = join(ROOT, rel);
      try {
        statSync(target);
        return true;
      } catch {
        return false;
      }
    },
    runQuickstart,
  };
}

/* ── entry ────────────────────────────────────────────────────────────────────────────────────── */

const argv = process.argv.slice(2);

if (argv.includes("--selftest")) {
  selftest();
  process.exit(0);
}

const readmePath = join(ROOT, "README.md");
const md = readFileSync(readmePath, "utf8");

let facts;
try {
  facts = gatherFacts(md);
} catch (err) {
  console.error(`GATE COULD NOT RUN: ${err.message}`);
  console.error("This is not a pass. Exiting 2 so nothing downstream reads it as one.");
  process.exit(2);
}

console.log("README.md, judged against:");
for (const [name, v] of Object.entries(facts.registry)) {
  console.log(`  registry  ${name.padEnd(24)} ${v === null ? "(not published)" : v}`);
}
console.log(`  repo      attack vectors           ${facts.vectors.attack}`);
console.log(`  repo      malformed vectors        ${facts.vectors.malformed}`);
console.log(`  repo      verifier implementations ${facts.implementations}`);
console.log(`  manifest  license                  ${facts.license}`);
console.log("  shell     quickstart blocks executed in a fresh temp directory\n");

const { ok, errors, advice } = lintDocTruth(md, facts);

for (const a of advice) console.log(`  advice: ${a}`);

if (ok) {
  console.log("\nOK — every checked claim in README.md matches the repository and the registry,");
  console.log("and the quickstart ran green end to end.");
  process.exit(0);
}

console.log("");
for (const e of errors) console.log(`  ✖ ${e}`);
console.log(
  "\nREADME.md states something this repository does not support. Fix the README (or fix the thing\n" +
    "it describes) — every rule above is re-derived on each run, so nothing here needs updating by\n" +
    "hand when the underlying fact changes.",
);
process.exit(1);
