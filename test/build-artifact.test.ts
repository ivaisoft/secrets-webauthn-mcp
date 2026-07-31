// Regression test for a real published-package bug: 2.1.1 shipped dist/index.js
// without the executable bit (tsc doesn't set it, and npm's own packing didn't
// either), so `npx @ivaisoft/bws-webauthn-mcp` failed with "command not found"
// for every consumer despite tsc/selfcheck/every other test passing clean.
// `npm run build` now chmods it explicitly; this locks that in. Requires a
// prior `npm run build` (true in both local verification and CI, which always
// builds before testing) — this only checks the artifact, it doesn't build it.
import { statSync } from "node:fs";
import assert from "node:assert/strict";

let passed = 0, failed = 0;
function test(name: string, fn: () => void) {
  try { fn(); console.log("ok  -", name); passed++; }
  catch (e) { failed++; console.error("FAIL -", name, "\n   ", e instanceof Error ? e.message : e); }
}

test("dist/index.js (the published bin) is executable after a build", () => {
  const mode = statSync("dist/index.js").mode;
  const executableByOwner = (mode & 0o100) !== 0;
  assert.ok(executableByOwner, `dist/index.js mode ${(mode & 0o777).toString(8)} is missing the owner-execute bit — npx would fail with "command not found"`);
});

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
