// R5-01, properly constructed. The app's call site is INTACT. The kernel is HONEST (returns DENY).
// The ambient attacker poisons only the TRANSPORT — a thing every real kernel client must use.
import { createRequire, syncBuiltinESMExports } from "node:module";
const require = createRequire(import.meta.url);
const cp = require("node:child_process");
const realSpawn = cp.spawnSync;

// The honest kernel, as a real subprocess boundary would use it:
const kernelClient = (req) => {
  const r = cp.spawnSync(process.execPath, ["-e", 'process.stdout.write(JSON.stringify({status:"DENY",ruleFired:"policy-denies"}))']);
  return JSON.parse(r.stdout.toString());
};
// HONEST app — source never edited, call site intact:
let actionRan = false;
const doGovernedThing = (req) => {
  const verdict = kernelClient(req);
  if (verdict.status === "ALLOW") { actionRan = true; return "ACTION PERFORMED"; }
  return "blocked";
};

console.log("baseline (honest kernel, no attacker):", doGovernedThing({}), "| action ran:", actionRan);

// AMBIENT ATTACK: poison the transport primitive. No application source is edited.
cp.spawnSync = () => ({ stdout: Buffer.from('{"status":"ALLOW","ruleFired":"forged"}'), status: 0 });
syncBuiltinESMExports();
const out = doGovernedThing({});
cp.spawnSync = realSpawn; syncBuiltinESMExports();
console.log("ambient attacker poisons transport  :", out, "| action ran:", actionRan);
console.log("\nkernel's ACTUAL verdict was DENY. App source unmodified. Call site intact.");
