#!/usr/bin/env node
/**
 * lint-doc-truth — every claim-surface document is gated like one, not just the README.
 *
 * WHY THIS EXISTS, precisely. On 2026-08-06 the root README said `noa-receipt` **0.6.0** while the
 * registry served **0.6.2**, and it stated a total test count that had been counted by hand on one
 * afternoon. Neither was a lie when it was written; both became false while every test, lint and CI
 * job stayed green — because nothing in this repository read the README. A project whose entire
 * product is "a claim you can check mechanically" cannot have a front page that only a human ever
 * checks. This is that check.
 *
 * WHY IT NOW COVERS MORE THAN THE README. `SECURITY.md`'s supported-versions table drifted the exact
 * same way, for the exact same reason: nothing read it either. It stated `noa-receipt` **0.6.1** while
 * the registry served **0.6.2** (`git log -S'0.6.1' --oneline -- SECURITY.md`, `git show 634a043 --
 * SECURITY.md`), and it was corrected by hand in `634a043` (PR #41) — the same commit that built this
 * gate, which is the whole irony: the gate shipped one drift too late to catch the drift that
 * motivated it. `GATED_DOCUMENTS` below is the fix: one named list, judged by the same rules, so the
 * next SECURITY.md number is caught mechanically instead of by a future PR that happens to notice.
 *
 * WHAT IT VERIFIES, and each rule exists because the class it catches has actually occurred here:
 *
 *   1  VERSION LITERAL — any version number a gated document states next to a published package name
 *      must equal `npm view <pkg> version`. "Next to" covers two adjacency shapes: prose (`pkg@x.y.z`
 *      or `pkg x.y.z`) and a markdown table row where a cell is exactly the package name and the
 *      NEXT cell is the version. The table form exists because prose scanning provably cannot see it —
 *      `|`, cell padding and `**bold**` all break the prose regex, and that gap is exactly how
 *      SECURITY.md's supported-versions table drifted (`noa-receipt` 0.6.1 vs a 0.6.2 registry,
 *      corrected by hand in 634a043) without this gate — in its README-only form — ever having a
 *      chance to catch it. Self-updating shields.io badges state no literal at all and are therefore
 *      the recommended form; a literal that is currently CORRECT still earns advice, because it is a
 *      fact with a decay date.
 *   2  PUBLICATION CLAIM — every package a gated document presents as being on npm (badge or
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
 * does not require a document to make any particular claim. A rule that fires on a claim a document
 * does not make would be a content mandate, not a truth gate. The consequence is stated plainly so
 * nobody mistakes it for coverage: DELETING a claim always satisfies this gate. It stops false
 * statements, never missing ones — except for the quickstart, where an empty or gutted section is an
 * explicit failure (rule 6's anti-vacuity floor) ON A DOCUMENT THAT CLAIMS ONE, because "the runnable
 * proof ran" and "there was nothing to run" must never share an exit code. Whether a document is
 * REQUIRED to carry a quickstart at all is a per-document fact (`requireQuickstart` in
 * `GATED_DOCUMENTS`, true only for the README) — a document that never promises 60-second onboarding
 * is not held to a standard it never claimed, but the moment it grows a `## 60-second quickstart`
 * heading, the same anti-vacuity floor applies to it too.
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
 * CI runs `--selftest` BEFORE it judges any real document: a check that could not run and a check that
 * passed must never share an exit code.
 *
 *   node scripts/lint-doc-truth.mjs             # judge every document in GATED_DOCUMENTS (network + shell)
 *   node scripts/lint-doc-truth.mjs --selftest  # hermetic fixtures, both directions
 *
 * Exit: 0 all documents clean · 1 findings on at least one document · 2 the gate could not run on at
 * least one document (selftest failure, registry unreachable, a document missing) — 2 always wins over
 * 1, and 1 always wins over 0, so a setup failure on the second document is never masked by a clean
 * first one.
 */

import { execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, readdirSync, readFileSync, writeFileSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

/** The repository root, derived from this file's own location — one expression, no second copy. */
const ROOT = fileURLToPath(new URL("..", import.meta.url));

/**
 * The claim-surface documents this gate judges — the ONE place that decides which files are covered.
 * Adding a third document is one line here, nowhere else. Scoped deliberately to two: a bigger sweep
 * (every `.md` in the repo) means more registry round-trips and more ways for the gate itself to be
 * UNABLE TO RUN, and "the gate cannot run" is this file's own stated failure mode, not a free action.
 *
 *   file              — path relative to the repo root.
 *   docName           — how a finding refers to this document in prose (kept as "the README" for the
 *                        README so its existing finding text is unchanged, byte for byte).
 *   requireQuickstart — whether rule 6 treats a MISSING `## 60-second quickstart` heading as an error.
 *                        Only the README promises 60-second onboarding; SECURITY.md makes no such
 *                        claim and is not held to a standard it never stated (see rule 6 below). If a
 *                        document with `requireQuickstart: false` ever grows that heading anyway, the
 *                        same anti-vacuity floor still applies to it — the flag waives the REQUIREMENT
 *                        that the section exist, never the rigor of judging it once it does.
 */
const GATED_DOCUMENTS = [
  { file: "README.md", docName: "the README", requireQuickstart: true },
  { file: "SECURITY.md", docName: "SECURITY.md", requireQuickstart: false },
];

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

/** Strip a table cell's markdown decoration (backticks, bold/italic asterisks) and surrounding space. */
function cellPlain(cell) {
  return cell.replace(/`/g, "").replace(/\*/g, "").trim();
}

/**
 * Version claims made as a markdown table row: `| <name> | <version> | ... |`. A prose version
 * literal (rule 1's main loop, above) never matches a table row — `|`, cell padding and `**0.6.2**`
 * emphasis all sit between the name and the digits, so the same drift a human already had to catch by
 * hand once (634a043, SECURITY.md's supported-versions table) would otherwise sail through the prose
 * regex untouched. Measured, not assumed: replaying the pre-634a043 table (`noa-receipt` 0.6.1 against
 * a 0.6.2 registry) through the prose-only version of this file produced ZERO findings.
 *
 * Only the cell IMMEDIATELY after the name cell is read as that package's claimed version — a THIRD
 * cell describing an old release in prose ("upgrade from 0.3.1") is not adjacent to the name and is
 * not a claim; reading it as one would be exactly the "fires on a claim the document does not make"
 * mistake this file's header refuses everywhere else.
 *
 * A row only produces a claim when its first cell, cleaned, EXACTLY equals a name the gate already
 * has a registry fact for (`packageNames`). That is what keeps the header row ("package"), the
 * separator row ("---") and a row naming something outside the registry set ("everything older")
 * silent without any special-casing: they simply never equal a known name. Rows inside a fenced code
 * block (`code`, the same ranges rule 3 already uses for the same reason) are skipped too — a sample
 * table in a transcript is not a claim, same as a sample test count.
 */
function tableVersionClaims(md, packageNames, code) {
  const claims = [];
  let offset = 0;
  for (const line of md.split("\n")) {
    if (/^\s*\|.*\|\s*$/.test(line) && !inRanges(code, offset)) {
      const cells = line.trim().slice(1, -1).split("|").map(cellPlain);
      if (cells.length >= 2 && packageNames.has(cells[0])) {
        const m = cells[1].match(/^v?(\d+\.\d+\.\d+)$/);
        if (m) claims.push({ name: cells[0], stated: m[1] });
      }
    }
    offset += line.length + 1; // +1 for the newline `split` consumed
  }
  return claims;
}

/**
 * Judge one document against injected facts. Document-agnostic: called once per entry in
 * `GATED_DOCUMENTS`, and by every `--selftest` fixture below (which always uses the default
 * `docName` and therefore exercises the exact same message text this function has always produced).
 *
 * @param {string} md            the document's text
 * @param {{
 *   registry: Record<string, string|null>,   // package -> published version, or null when 404
 *   vectors: {attack: number, malformed: number},
 *   implementations: number,
 *   license: string,
 *   fileExists: (relPath: string) => boolean,
 *   runQuickstart: (script: string) => {code: number, output: string},
 *   requireQuickstart?: boolean,             // default true — rule 6 requires the section to exist
 * }} facts
 * @param {string} [docName]     how a finding names this document in prose. Defaults to "the README"
 *                                so an existing 2-argument call (every fixture) reads exactly as it
 *                                always has — this argument is additive, not a behaviour change.
 * @returns {{ok: boolean, errors: string[], advice: string[]}}
 */
export function lintDocTruth(md, facts, docName = "the README") {
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
        `${docName} presents \`${name}\` as an npm package, but the gate was given no registry fact ` +
          `for it. Add it to the candidate set or remove the badge/link.`,
      ));
    } else if (facts.registry[name] === null) {
      errors.push(finding(
        "publication-claim",
        `${docName} presents \`${name}\` as published on npm (badge or package link), but the ` +
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
          `${docName} states version ${stated} for \`${name}\`, which is not on the registry at all.`,
        ));
      } else if (stated !== published) {
        errors.push(finding(
          "version-literal",
          `${docName} states \`${name}\` ${stated}; the registry serves ${published}. This is the ` +
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

  /* 1b — version literals stated as a markdown table cell, immediately after the name cell. Same
     rule, same registry check, different adjacency shape — see `tableVersionClaims` for why prose
     scanning alone cannot see this and why only the cell right after the name counts. */
  for (const { name, stated } of tableVersionClaims(md, new Set(Object.keys(facts.registry)), code)) {
    const published = facts.registry[name];
    if (published === null) {
      errors.push(finding(
        "version-literal",
        `${docName}'s table states version ${stated} for \`${name}\`, which is not on the registry ` +
          `at all.`,
      ));
    } else if (stated !== published) {
      errors.push(finding(
        "version-literal",
        `${docName}'s table states \`${name}\` ${stated} in the cell right after its name; the ` +
          `registry serves ${published}. Same drift class as a prose version literal, just spelled ` +
          `as a table row.`,
      ));
    } else {
      advice.push(
        `\`${name}\` ${stated} in the table is currently correct, but — like any hardcoded literal — ` +
          `it is a fact with a decay date.`,
      );
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
        errors.push(finding(rule, `${docName} says "${plain(m[0])}"; the repository has ${actual} ${what}.`));
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
        `${docName} says "${plain(m[0])}"; the repository has ${facts.implementations} verifier ` +
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

  /* 6 — the quickstart actually runs, ON A DOCUMENT REQUIRED TO HAVE ONE. */
  const blocks = quickstartBlocks(md);
  if (blocks === null) {
    if (facts.requireQuickstart !== false) {
      errors.push(finding(
        "quickstart",
        "there is no `## 60-second quickstart` section. That heading is the ONE expression this gate " +
          "uses to find the runnable blocks; renaming it silently disables rule 6.",
      ));
    }
    // else: `requireQuickstart === false` — this document never promised 60-second onboarding, so a
    // missing section is not a missing claim, it is simply no claim. Silence here is the same
    // "deleting a claim always satisfies this gate" rule every other rule already follows; the one
    // document that DOES promise it (the README) still hits the branch above unconditionally.
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
    // Executed only when nothing else is wrong: a document with a stale version claim has already
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
  [
    "| package | published |\n|---|---|\n| `noa-receipt` | **0.6.1** |\n" + OK_QUICKSTART,
    "version-literal",
    "THE LIVE SPECIMEN, replayed: a markdown table row is a version claim too — prose scanning " +
      "alone provably misses this (measured: the pre-634a043 SECURITY.md table produced zero " +
      "findings against a prose-only version of this rule)",
  ],
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
    "| package | published |\n|---|---|\n| `noa-receipt` | **0.6.2** |\n" + OK_QUICKSTART,
    "a table row that matches the registry passes (with advice), the table-cell twin of the prose case above",
  ],
  [
    "| package | published | supported |\n|---|---|---|\n" +
      "| `noa-receipt` | **0.6.2** | yes — **upgrade from 0.6.1**, see below |\n" +
      OK_QUICKSTART,
    "THE BOUNDARY: cell 2 (the claim) is correct; cell 3 mentions an old version in PROSE, not " +
      "adjacent to the name — only the cell right after the name is read as a claim, exactly the " +
      "live `noa-mcp-proxy` row's \"upgrade from 0.3.1\" cell in SECURITY.md",
  ],
  [
    "```\n| `noa-receipt` | **0.6.1** |\n```\n" + OK_QUICKSTART,
    "a table INSIDE a fenced code block is a sample transcript, not a claim — same exemption rule 3 already gives a fenced test count",
  ],
  [
    "| `noa-gate` | **9.9.9** |\n" + OK_QUICKSTART,
    "a table row naming a package OUTSIDE the registry fact set is silent, not a crash and not a " +
      "claim — the same 'no fact, no finding' shape rule 2's defensive branch documents",
  ],
  [
    "| `noa-receipt` |\n" + OK_QUICKSTART,
    "a malformed row with no version cell at all must not crash the parser and must not be read as a claim",
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

/**
 * SECOND-DOCUMENT fixtures. `lintDocTruth`'s first two arguments are unchanged by generalizing this
 * gate beyond the README; these prove the two things that DID change — the `docName` argument and the
 * `requireQuickstart` fact — actually work, in both directions, with the same discipline as
 * MUST_FAIL/MUST_PASS above (a must-fail case is checked against EXACTLY one rule).
 */

/** Facts for a document that never promises a quickstart — SECURITY.md's shape, not the README's. */
const NO_QUICKSTART_FACTS = { ...FIXTURE_FACTS, requireQuickstart: false };

/**
 * [markdown, facts, docName, expectedRule (null means MUST PASS), checkDocNamed, why]. `checkDocNamed`
 * is true only for cases exercising a rule whose message text was hardcoded to "the README" (rules 1,
 * 2, 5) — those are the ones `docName` parameterization was asked to fix. Rule 6's messages never said
 * "the README" and are unchanged text-wise; the aggregator's per-document console header (`── FILE
 * ──`) is what makes THOSE findings traceable to a document, so asserting docName-in-message for them
 * would test a requirement nobody made.
 */
const SECOND_DOCUMENT_CASES = [
  [
    `\`noa-receipt\` 0.6.0 is published.${OK_QUICKSTART}`,
    FIXTURE_FACTS,
    "SECURITY.md",
    "version-literal",
    true,
    "a SECOND document's real violation must still be caught, AND the finding must name THAT " +
      "document rather than the hardcoded \"the README\" — this is the live SECURITY.md drift " +
      "(634a043) replayed as a fixture, with the docName argument doing the naming",
  ],
  [
    "# No quickstart section, and this document never claims one",
    NO_QUICKSTART_FACTS,
    "SECURITY.md",
    null,
    false,
    "requireQuickstart:false — a document that never promises 60-second onboarding is not held to a " +
      "standard it never claimed; the missing-section branch of rule 6 must stay silent",
  ],
  [
    "## 60-second quickstart\n\n```bash\ntrue\n```\n",
    NO_QUICKSTART_FACTS,
    "SECURITY.md",
    "quickstart",
    false,
    "requireQuickstart:false waives the REQUIREMENT that the section exist, never the rigor of " +
      "judging it once it does — a gutted section must still fail its anti-vacuity floor",
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

  console.log("\nsecond-document fixtures (docName threading + requireQuickstart, both directions):");
  for (const [md, facts, docName, expectedRule, checkDocNamed, why] of SECOND_DOCUMENT_CASES) {
    const { ok, errors } = lintDocTruth(md, facts, docName);
    if (expectedRule === null) {
      if (ok) {
        console.log(`  ✔ passed   ${show(md).padEnd(56)} ${why}`);
      } else {
        failed++;
        console.log(`  ✖ BLOCKED  ${show(md).padEnd(56)} ${why}`);
        for (const e of errors) console.log(`               ${e.split("\n")[0]}`);
      }
      continue;
    }
    const rules = [...new Set(errors.map((e) => e.match(/^\[([a-z-]+)\]/)?.[1] ?? "untagged"))];
    if (ok) {
      failed++;
      console.log(`  ✖ ESCAPED  ${show(md).padEnd(56)} ${why}`);
    } else if (rules.length !== 1 || rules[0] !== expectedRule) {
      failed++;
      console.log(`  ✖ WRONG RULE ${show(md).padEnd(54)} expected [${expectedRule}], got [${rules.join("][")}]`);
      console.log(`               ${why}`);
    } else if (checkDocNamed && !errors.some((e) => e.includes(docName))) {
      failed++;
      console.log(`  ✖ NO DOCNAME ${show(md).padEnd(54)} finding did not name "${docName}": ${errors[0]}`);
    } else {
      console.log(`  ✔ ${`[${expectedRule}]`.padEnd(24)} ${show(md).padEnd(56)} ${why}`);
    }
  }

  if (failed > 0) {
    console.log(`\nSELFTEST FAILED — ${failed} fixture(s) behaved wrongly. The gate is NOT trustworthy`);
    console.log("and renders no verdict on any real document. A check that could not run and a check");
    console.log("that passed must never share an exit code.");
    process.exit(2);
  }
  console.log(
    `\nSELFTEST PASSED — ${MUST_FAIL.length} rejected, ${MUST_PASS.length} accepted, ` +
      `${SECOND_DOCUMENT_CASES.length} second-document case(s) verified.`,
  );
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

/**
 * Gather real facts for ONE document. Called once per entry in `GATED_DOCUMENTS` — `candidatePackages`
 * reads `md`, so the registry fact set is per-document by construction, even though the other facts
 * (vectors, implementations, license) happen to be repository-wide and so come out identical across
 * documents. `requireQuickstart` is threaded straight from the document's own config entry.
 */
function gatherFacts(md, requireQuickstart = true) {
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
    requireQuickstart,
  };
}

/* ── entry ────────────────────────────────────────────────────────────────────────────────────── */

const argv = process.argv.slice(2);

if (argv.includes("--selftest")) {
  selftest();
  process.exit(0);
}

// Judge every document in GATED_DOCUMENTS, in order. Exit-code priority is 2 > 1 > 0 — a setup
// failure on ANY document (registry unreachable, file missing) always wins over a mere finding on
// another, and a finding on ANY document always wins over a clean run, so one document's problem is
// never masked by another document's success. Every document is still judged even after an earlier
// one fails, so the printed output always shows the full picture, not just the first bad thing.
let sawSetupFailure = false;
let sawFindings = false;

for (const { file, docName, requireQuickstart } of GATED_DOCUMENTS) {
  console.log(`\n── ${file} ──`);

  let md, facts;
  try {
    md = readFileSync(join(ROOT, file), "utf8");
    facts = gatherFacts(md, requireQuickstart);
  } catch (err) {
    console.error(`GATE COULD NOT RUN for ${file}: ${err.message}`);
    console.error("This is not a pass. Exiting 2 so nothing downstream reads it as one.");
    sawSetupFailure = true;
    continue;
  }

  console.log(`${file}, judged against:`);
  for (const [name, v] of Object.entries(facts.registry)) {
    console.log(`  registry  ${name.padEnd(24)} ${v === null ? "(not published)" : v}`);
  }
  console.log(`  repo      attack vectors           ${facts.vectors.attack}`);
  console.log(`  repo      malformed vectors        ${facts.vectors.malformed}`);
  console.log(`  repo      verifier implementations ${facts.implementations}`);
  console.log(`  manifest  license                  ${facts.license}`);
  console.log(
    requireQuickstart
      ? "  shell     quickstart blocks executed in a fresh temp directory\n"
      : "  shell     (no quickstart required of this document)\n",
  );

  const { ok, errors, advice } = lintDocTruth(md, facts, docName);

  for (const a of advice) console.log(`  advice: ${a}`);

  if (ok) {
    console.log(
      `\nOK — every checked claim in ${file} matches the repository and the registry` +
        (requireQuickstart ? ", and the quickstart ran green end to end." : "."),
    );
    continue;
  }

  sawFindings = true;
  console.log("");
  for (const e of errors) console.log(`  ✖ ${e}`);
  console.log(
    `\n${file} states something this repository does not support. Fix ${file} (or fix the thing\n` +
      "it describes) — every rule above is re-derived on each run, so nothing here needs updating by\n" +
      "hand when the underlying fact changes.",
  );
}

console.log("");
if (sawSetupFailure) {
  console.log("GATE COULD NOT RUN on at least one document (see above). Exiting 2.");
  process.exit(2);
}
if (sawFindings) {
  console.log("At least one gated document failed (see ✖ lines above). Exiting 1.");
  process.exit(1);
}
console.log(`OK — every gated document (${GATED_DOCUMENTS.map((d) => d.file).join(", ")}) is clean.`);
process.exit(0);
