import assert from "node:assert/strict";
import test from "node:test";
import { parseBearer } from "../src/auth.js";

test("parseBearer accepts a gate credential separated by HTTP whitespace", () => {
  assert.deepEqual(parseBearer("Bearer\tnoa_gateagent_abc123"), { secret: "noa_gateagent_abc123" });
  assert.deepEqual(parseBearer("bearer noa_gateagent_abc123"), { secret: "noa_gateagent_abc123" });
});

test("parseBearer rejects missing, wrong-prefix, and whitespace-bearing credentials", () => {
  assert.equal(parseBearer(undefined), null);
  assert.equal(parseBearer("Basic noa_gateagent_abc123"), null);
  assert.equal(parseBearer("Bearer noa_gateagent_abc 123"), null);
  assert.equal(parseBearer("Bearer noa_gateagent_abc\r\nInjected: yes"), null);
  assert.equal(parseBearer("Bearer noa_gateagent_abcé"), null);
  assert.equal(parseBearer(`Bearer ${" ".repeat(100_000)}`), null);
});
