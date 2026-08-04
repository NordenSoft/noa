#!/usr/bin/env node
/**
 * lint-pr-title — the PR title is now a commit title on `main`, so it is gated like one.
 *
 * WHY THIS EXISTS, precisely. On 2026-08-04 a commit titled `test` landed on `main` and cannot be
 * removed, because `main` is protected against force-pushes and the history is signed. The repo's
 * `squash_merge_commit_title` was `COMMIT_OR_PR_TITLE`, which means *a single-commit PR takes the
 * COMMIT's title*. The setting is now `PR_TITLE`, so every squash on `main` inherits the PR title
 * verbatim — which moves the whole risk onto a field nothing was checking. This checks it.
 *
 * WHAT IT DELIBERATELY DOES NOT DO. It does not require a Conventional-Commits type. Measured over
 * the last 40 commits, 18 titles carry no type — including recent, GOOD ones like
 * "ADR-0007: a phone can join a real relay — device-pairing enrolment, end to end". A type gate
 * would reject those and force worse titles, and a gate that blocks legitimate work is a gate a
 * human switches off — after which there is no gate at all (KURAL 29). A missing type is reported
 * as ADVICE and exits 0.
 *
 * WHAT IT BLOCKS is the narrow class that actually produced the incident: a title that carries no
 * information. Placeholders, GitHub's auto-generated single-file-edit title, and lengths outside
 * what a commit subject can hold.
 *
 * ANTI-VACUITY. `--selftest` runs fixtures in BOTH directions — titles that MUST fail and titles
 * that MUST pass. The must-pass set is the important half: "test the verifier against hostile
 * input" is a legitimate title that a substring check would wrongly kill, so the placeholder test
 * is exact-match on the whole title, never a substring. CI runs `--selftest` BEFORE it judges a
 * real title; if the fixtures do not behave, the gate exits non-zero without rendering a verdict.
 * A check that cannot run and a check that passed must never share an exit code.
 *
 *   node scripts/lint-pr-title.mjs --title "<pr title>"
 *   node scripts/lint-pr-title.mjs --selftest
 */

const MIN_LEN = 12;
const MAX_LEN = 120;

/**
 * Titles that carry no information. Compared against the title with surrounding whitespace and
 * trailing punctuation removed, lower-cased — so `Test`, `test.` and `  test  ` are all caught,
 * while `test the verifier against hostile input` is NOT (this is an exact-match set, by design).
 */
const PLACEHOLDERS = new Set([
  "test", "tests", "testing", "wip", "work in progress", "temp", "tmp", "fix", "fixes", "fixed",
  "update", "updates", "updated", "change", "changes", "changed", "misc", "stuff", "things",
  "asdf", "foo", "bar", "baz", "qux", "x", "y", "z", "a", "untitled", "no title", "new pr",
  "draft", "todo", "cleanup", "clean up", "refactor", "patch", "commit", "init", "initial commit",
  "minor", "minor fix", "small fix", "quick fix", "final", "final fix", "done", "ok", "hotfix",
]);

/** GitHub's own auto-generated title when a file is edited through the web UI. */
const GITHUB_AUTO_TITLE = /^(create|update|delete|add|rename)\s+\S+\.\w{1,8}$/i;

/** A bare reference with no prose: "#22", "PR 22", "issue #22". */
const BARE_REFERENCE = /^(pr\s*)?#?\d+$|^(issue|pr|ticket)\s*#?\d+$/i;

/** Conventional-Commits shape. Advisory only — never a failure. */
const CONVENTIONAL = /^[a-z]+(\([a-z0-9,._/ -]+\))?!?: .+/;

/** Normalise for the placeholder comparison: trim, drop trailing punctuation, lower-case. */
function normalise(title) {
  return title.trim().replace(/[.!?…\s]+$/u, "").trim().toLowerCase();
}

/**
 * Judge one title.
 * @returns {{ok: boolean, errors: string[], advice: string[]}}
 */
export function lintTitle(rawTitle) {
  const errors = [];
  const advice = [];
  const title = typeof rawTitle === "string" ? rawTitle : "";
  const trimmed = title.trim();
  const norm = normalise(title);

  if (trimmed.length === 0) {
    errors.push("the title is empty");
    return { ok: false, errors, advice };
  }

  if (PLACEHOLDERS.has(norm)) {
    errors.push(
      `"${trimmed}" is a placeholder, not a title. This is the exact failure that put a commit ` +
        `titled \`test\` on \`main\` permanently — \`main\` is protected and signed, so it could ` +
        `not be removed afterwards.`,
    );
  }

  if (GITHUB_AUTO_TITLE.test(trimmed)) {
    errors.push(
      `"${trimmed}" is GitHub's auto-generated title for a web-UI file edit. It names the file ` +
        `that changed, which the diff already says, and not what changed or why.`,
    );
  }

  if (BARE_REFERENCE.test(trimmed)) {
    errors.push(`"${trimmed}" is a bare reference with no prose.`);
  }

  if (trimmed.length < MIN_LEN) {
    errors.push(`the title is ${trimmed.length} characters; a commit subject needs at least ${MIN_LEN}.`);
  }

  if (trimmed.length > MAX_LEN) {
    errors.push(
      `the title is ${trimmed.length} characters; ${MAX_LEN} is the ceiling. It becomes a commit ` +
        `subject on \`main\`, and git tooling and GitHub both truncate beyond that.`,
    );
  }

  if (/[.]$/.test(trimmed) && !/\.\.\.$/.test(trimmed)) {
    errors.push("the title ends in a period; a commit subject does not.");
  }

  if (/\n/.test(title)) {
    errors.push("the title contains a newline.");
  }

  if (errors.length === 0 && !CONVENTIONAL.test(trimmed)) {
    advice.push(
      "no Conventional-Commits type prefix (feat:, fix:, docs:, chore:, …). Not required — 18 of " +
        "the last 40 titles in this repo carry none, including good ones — but it helps release " +
        "tooling derive the version bump.",
    );
  }

  return { ok: errors.length === 0, errors, advice };
}

/* ── fixtures ─────────────────────────────────────────────────────────────────────────────── */

/** Titles the gate MUST reject. Includes the mutations a careless author actually produces. */
const MUST_FAIL = [
  ["test", "the title that caused the incident"],
  ["Test", "same word, capitalised — case must not be an escape"],
  ["test.", "trailing period — punctuation must not be an escape"],
  // ── on isolating fixtures, learned by getting it wrong twice in a row ──────────────────────
  // `test.` above is caught TWICE (placeholder AND trailing-period), so it cannot tell you whether
  // normalise()'s punctuation-stripping still works. The obvious repair — `test!`, where the
  // period rule does not apply — is ALSO caught twice, because "test!" is 5 characters and trips
  // the length floor. Both fixtures pass for a reason that has nothing to do with the code they
  // were written to protect, and a mutation run proved it: deleting the strip from normalise()
  // left the whole suite green.
  //
  // A fixture isolates a rule only when EVERY OTHER rule stays silent on it. That needs a
  // placeholder that is long enough to clear the floor and ends in punctuation the period rule
  // ignores. Delete the strip in normalise() and this one line — alone — goes red.
  ["work in progress!", "isolates normalise(): 17 chars clears the floor, '!' dodges the period rule"],
  ["Initial commit...", "the same isolation via ellipsis, with case folding stacked on top"],
  ["   test   ", "surrounding whitespace must not be an escape"],
  ["WIP", "placeholder"],
  ["work in progress", "multi-word placeholder"],
  ["fix", "a type with no subject is still a placeholder"],
  ["Update README.md", "GitHub's auto-generated web-UI title"],
  ["Create docs/new.md", "same generator, different verb"],
  ["#22", "bare reference"],
  ["issue #22", "bare reference with a word in front"],
  ["short", "below the length floor"],
  ["", "empty"],
  ["   ", "whitespace only"],
  ["docs: this is a fine title.", "a good title ruined by a trailing period"],
  [`feat: ${"x".repeat(130)}`, "past the length ceiling"],
  ["docs: two\nlines", "a newline in a commit subject"],
];

/**
 * Titles the gate MUST accept. This half is the one that matters: a lazy implementation using
 * substring matching would kill every one of the first three, and nobody would notice for months
 * because a gate that over-blocks looks identical to a gate that works — until someone disables it.
 */
const MUST_PASS = [
  ["test the verifier against hostile input", "contains 'test' but is a real title"],
  ["fix the override that protected nothing", "starts with 'fix' as a verb, not a placeholder"],
  ["docs: update the supported-versions table", "contains 'update' mid-title"],
  ["ADR-0007: a phone can join a real relay — device-pairing enrolment, end to end", "a real recent title with no Conventional type"],
  ["fix(mcp-proxy)!: the hono override was decoration", "Conventional with a scope and a breaking marker"],
  ["P1-12 ruled no-change, and four files that misstated the project", "a real recent squash title"],
  ["Round-8 closure: the last three P1 items", "a real recent squash title"],
  ["exactly12chs", "precisely at the length floor"],
  [`feat: ${"x".repeat(113)}`, "precisely at the length ceiling"],
  ["docs: a title ending in an ellipsis…", "an ellipsis is not a full stop"],
];

function selftest() {
  let failed = 0;
  console.log("must-FAIL fixtures (the gate has to reject each of these):");
  for (const [title, why] of MUST_FAIL) {
    const { ok } = lintTitle(title);
    const shown = JSON.stringify(title.length > 46 ? title.slice(0, 43) + "..." : title);
    if (ok) {
      failed++;
      console.log(`  ✖ ESCAPED  ${shown.padEnd(50)} ${why}`);
    } else {
      console.log(`  ✔ rejected ${shown.padEnd(50)} ${why}`);
    }
  }
  console.log("\nmust-PASS fixtures (the gate has to stay quiet on each of these):");
  for (const [title, why] of MUST_PASS) {
    const { ok, errors } = lintTitle(title);
    const shown = JSON.stringify(title.length > 46 ? title.slice(0, 43) + "..." : title);
    if (!ok) {
      failed++;
      console.log(`  ✖ BLOCKED  ${shown.padEnd(50)} ${why}`);
      for (const e of errors) console.log(`               ${e}`);
    } else {
      console.log(`  ✔ passed   ${shown.padEnd(50)} ${why}`);
    }
  }
  if (failed > 0) {
    console.log(`\nSELFTEST FAILED — ${failed} fixture(s) behaved wrongly. The gate is NOT trustworthy`);
    console.log("and renders no verdict on the real title. A check that could not run and a check");
    console.log("that passed must never share an exit code.");
    process.exit(2);
  }
  console.log(`\nSELFTEST PASSED — ${MUST_FAIL.length} rejected, ${MUST_PASS.length} accepted.`);
}

/* ── entry ────────────────────────────────────────────────────────────────────────────────── */

const argv = process.argv.slice(2);

if (argv.includes("--selftest")) {
  selftest();
  process.exit(0);
}

const at = argv.indexOf("--title");
if (at === -1 || at === argv.length - 1) {
  console.error("usage: lint-pr-title.mjs --title \"<pr title>\"  |  --selftest");
  process.exit(2);
}

const title = argv[at + 1];
const { ok, errors, advice } = lintTitle(title);

console.log(`PR title: ${JSON.stringify(title)}\n`);

for (const a of advice) console.log(`  advice: ${a}`);

if (ok) {
  console.log("\nOK — this title can become a commit subject on `main`.");
  process.exit(0);
}

for (const e of errors) console.log(`  ✖ ${e}`);
console.log(
  "\nThe repository squashes with `squash_merge_commit_title: PR_TITLE`, so this exact string " +
    "becomes\nthe commit subject on `main` — which is protected and signed, and therefore permanent.\n" +
    "Edit the PR title and this check re-runs by itself.",
);
process.exit(1);
