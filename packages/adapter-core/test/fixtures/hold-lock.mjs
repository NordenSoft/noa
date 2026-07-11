#!/usr/bin/env node
// Test fixture only: holds a createFileSessionStore lock open until killed, so
// test/file-session-store.test.mjs can exercise real cross-process lock contention and
// stale-lock (dead-pid) recovery — a single Node process can't tell its own live pid apart
// from a "different, now-dead" one, so this needs a real child process.
import { createFileSessionStore } from "../../src/file-session-store.mjs";

const dir = process.argv[2];
if (!dir) {
  console.error("hold-lock.mjs: missing <dir> argument");
  process.exit(2);
}
createFileSessionStore(dir);
console.log("LOCKED");
setInterval(() => {}, 1_000_000); // block until the parent test kills this process
