#!/usr/bin/env node
/**
 * Child-process harness for key-file.mjs's OPEN path. Two things about that path cannot be measured
 * in-process, and both need a separate process:
 *
 *   node load-key-file.mjs <keyFile>
 *       Plain load. A FIFO planted at <keyFile> BLOCKS the whole process inside open() before the
 *       O_NONBLOCK fix, and a synchronous block cannot be timed out by the test runner (a blocked
 *       thread never reaches its own timer). The parent times this process on the wall clock and
 *       kills it, so "it hung" is a measurement rather than a hang.
 *
 *   node load-key-file.mjs <keyFile> --euid <n>
 *       Pretends this process's effective uid is <n> BEFORE key-file.mjs is imported, so the
 *       module's load-time PROCESS_EUID capture sees <n>. The owner guard then compares a REAL
 *       file's REAL st.uid against a uid that is not it. This machine has a single uid and chown
 *       needs root, so the MISMATCH is manufactured from the process side instead of the file side
 *       — the branch under test (`st.uid !== PROCESS_EUID && st.uid !== 0`) is the same one either
 *       way, and it is only ever reached with a genuinely-stat'ed st.uid.
 *
 * Prints `LOADED <kid>` and exits 0, or `REFUSED <reason>` and exits 3.
 */
import { generateKeyPair } from "noa-receipt";
import { describeThrown } from "../../src/safe-throw.mjs";

const [keyFile, flag, flagValue] = process.argv.slice(2);
if (flag === "--euid") {
  const pretend = Number(flagValue);
  process.geteuid = () => pretend;
}

const { loadOrCreateKeyFile } = await import("../../src/key-file.mjs");

try {
  const kp = loadOrCreateKeyFile({ keyFile, mintKeyPair: () => generateKeyPair("load-key-file-fixture"), callerLabel: "fixture" });
  process.stdout.write(`LOADED ${kp.kid}\n`);
  process.exit(0);
} catch (err) {
  process.stdout.write(`REFUSED ${describeThrown(err)}\n`);
  process.exit(3);
}
