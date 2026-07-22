import assert from "node:assert/strict";
import test from "node:test";
import { parseBearer } from "../src/auth.js";

test("parseBearer accepts agent and device credentials separated by HTTP whitespace", () => {
  assert.deepEqual(parseBearer("Bearer noa_agent_abc123"), { scheme: "agent", secret: "noa_agent_abc123" });
  assert.deepEqual(parseBearer("Bearer\tnoa_device_abc123"), { scheme: "device", secret: "noa_device_abc123" });
  assert.deepEqual(parseBearer("bearer noa_agent_abc123"), { scheme: "agent", secret: "noa_agent_abc123" });
});

test("parseBearer rejects missing, unknown, and whitespace-bearing credentials", () => {
  assert.equal(parseBearer(undefined), null);
  assert.equal(parseBearer("Basic noa_agent_abc123"), null);
  assert.equal(parseBearer("Bearer noa_unknown_abc123"), null);
  assert.equal(parseBearer("Bearer noa_agent_abc 123"), null);
  assert.equal(parseBearer("Bearer noa_agent_abc\r\nInjected: yes"), null);
  assert.equal(parseBearer("Bearer noa_agent_abcé"), null);
  assert.equal(parseBearer(`Bearer ${" ".repeat(100_000)}`), null);
});
