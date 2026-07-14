/**
 * NOA Gate — load the shipped §6 JSON schemas from `noa-approval-artifacts`.
 *
 * The gate VERIFIES a phone-signed Decision Artifact (D18: the gate re-verifies the human decision
 * before issuing a grant), which requires the frozen schema set as the structural layer of
 * `verifyArtifact`. We REUSE the shipped schemas (KURAL 5 — never re-author the frozen shapes);
 * `noa-approval-artifacts` exports them under `./schema/*` and the `ARTIFACTS` registry maps each
 * spec → its schema filename.
 */

import { createRequire } from "node:module";
import { readFileSync } from "node:fs";
import { ARTIFACTS } from "noa-approval-artifacts";

const require = createRequire(import.meta.url);

/** spec -> parsed schema object (the enforced structural validator for `verifyArtifact`). */
export function loadSchemas(): Record<string, unknown> {
  const schemas: Record<string, unknown> = {};
  for (const meta of Object.values(ARTIFACTS)) {
    const p = require.resolve(`noa-approval-artifacts/schema/${meta.schemaId}`);
    schemas[meta.spec] = JSON.parse(readFileSync(p, "utf8"));
  }
  return schemas;
}
