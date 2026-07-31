// Security-behaviour test for the run_with_secret tool. No framework: bws is a
// fake, HOME is a throwaway sandbox, the child is a real `node -e` process so
// we can observe what env/argv it actually received, and the Gate is a tiny
// real implementation of the same request-key semantics as gate.ts (not just
// an always-succeeds stub) — so the two-call "not yet approved -> approve out
// of band -> identical call proceeds" flow is exercised as it works in
// production, without real WebAuthn hardware.
//
// Locks the invariants:
//   1. a not-yet-approved call returns instructions (with the approval URL)
//      instead of running anything — works with any MCP client (ADR 0006)
//   2. after out-of-band approval, the identical call proceeds; the secret
//      reaches the child as an env var (default = Bitwarden key name)
//   3. env_overrides renames it; the default name is then NOT set
//   4. the vault token (BWS_ACCESS_TOKEN) is stripped from the child env
//   5. the secret is never passed via argv, and the wrapper doesn't leak it when
//      the child stays quiet
//   6. duplicate / invalid env var names are refused
//   7. the audit log records argv0 but never the secret value
import { mkdtempSync, mkdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import assert from "node:assert/strict";

const SANDBOX = mkdtempSync(join(tmpdir(), "bws-webauthn-run-test-"));
process.env.HOME = SANDBOX;
const CFG = join(SANDBOX, ".config", "bws-webauthn-mcp");
mkdirSync(CFG, { recursive: true });
process.env.BWS_ACCESS_TOKEN = "VAULT-TOKEN-SENTINEL"; // must NOT reach the child

const { registerTools } = await import("../src/tools.js");
const { RunWithSecretArgsSchema } = await import("../src/schemas.js");
const { requestKey } = await import("../src/request-key.js");

const NODE = process.execPath;
const SECRET = "RUN-SECRET-DO-NOT-LEAK-xyz789";

let events: string[] = [];
let secretMap: Record<string, { key: string; value: string }> = {};
const handlers: Record<string, (a: unknown) => Promise<any>> = {};
const fakeMcp = {
  server: {},
  registerTool: (name: string, _cfg: unknown, handler: (a: any) => Promise<any>) => {
    handlers[name] = handler;
  },
} as any;

// A real (not stubbed) implementation of the Gate's request-key semantics —
// checks/consumes exactly like gate.ts's checkApproval, minus the HTTP/WebAuthn
// plumbing. `preApprove` simulates a human having approved out of band.
function makeFakeGate() {
  const approved = new Set<string>();
  return {
    origin: "http://localhost:9",
    port: 9,
    checkApproval(key: string): boolean {
      events.push("checkApproval");
      if (approved.has(key)) {
        approved.delete(key);
        return true;
      }
      return false;
    },
    preApprove(key: string) {
      approved.add(key);
    },
  };
}
const fakeGate = makeFakeGate();

const fakeBws = {
  getSecret: async (id: string) => {
    events.push("getSecret:" + id);
    const s = secretMap[id];
    if (!s) throw new Error("no such secret " + id);
    return s;
  },
  // Mirrors secretMap's key names — real listSecrets() never returns a value,
  // so the fake doesn't either (id -> key only), matching the ADR 0005 contract.
  listSecrets: async () => Object.entries(secretMap).map(([id, s]) => ({ id, key: s.key })),
} as any;

registerTools({ mcp: fakeMcp, gate: fakeGate, bws: fakeBws, timeoutMs: 1000 });
const run = (raw: unknown) => handlers["run_with_secret"]!(RunWithSecretArgsSchema.parse(raw));
const keyFor = (raw: unknown) => requestKey("run_with_secret", RunWithSecretArgsSchema.parse(raw));
const textOf = (r: any) => r.content[0].text as string;
const echo = (js: string) => [NODE, "-e", `process.stdout.write(${js})`];
/** Most tests only care about the post-approval path — approve then run in one step. */
const runApproved = (raw: unknown) => {
  fakeGate.preApprove(keyFor(raw));
  return run(raw);
};

let passed = 0, failed = 0;
async function test(name: string, fn: () => Promise<void>) {
  events = [];
  try { await fn(); console.log("ok  -", name); passed++; }
  catch (e) { failed++; console.error("FAIL -", name, "\n   ", e instanceof Error ? e.message : e); }
}

await test("first call (not yet approved) returns instructions + URL, never spawns", async () => {
  secretMap = { s1: { key: "API_KEY", value: SECRET } };
  const args = { argv: echo("process.env.API_KEY ?? 'UNSET'"), secret_ids: ["s1"] };
  const r = await run(args);
  assert.equal(r.isError, true);
  assert.match(textOf(r), /physical approval required/i);
  assert.ok(textOf(r).includes(fakeGate.origin));
  assert.ok(textOf(r).includes(keyFor(args)));
  assert.equal(events.includes("getSecret:s1"), false, "must not fetch the secret before approval");
  assert.ok(!textOf(r).includes(SECRET));
  assert.equal(r.structuredContent.status, "approval_required");
  assert.equal(typeof r.structuredContent.approve_url, "string");
});

await test("formatting: the real Bitwarden key name is shown, and an ambiguous arg is quoted", async () => {
  secretMap = { s1: { key: "MY_SECRET_KEY", value: SECRET } };
  const args = { argv: ["printf", "%s", "hello world"], secret_ids: ["s1"] };
  const r = await run(args);
  assert.ok(textOf(r).includes("(MY_SECRET_KEY)"), "must show the real Bitwarden key name, not a placeholder");
  assert.ok(
    textOf(r).includes("printf %s 'hello world'"),
    "an argument containing a space must be quoted, matching the real argv boundaries",
  );
  assert.ok(!textOf(r).includes("<its Bitwarden key name>"), "no placeholder once listSecrets resolves the name");
});

await test("formatting: a secret_id not found via list_secrets falls back honestly, not to a fake name", async () => {
  secretMap = {}; // "s1" is unknown to listSecrets (and to getSecret — but approval never gets that far)
  const args = { argv: ["echo", "hi"], secret_ids: ["s1"] };
  const r = await run(args);
  assert.ok(textOf(r).includes("(not found via list_secrets)"));
  assert.ok(textOf(r).includes("<its Bitwarden key name>"));
});

await test("approval is single-use: repeating the same call again is not yet approved", async () => {
  secretMap = { s1: { key: "API_KEY", value: SECRET } };
  const args = { argv: echo("'x'"), secret_ids: ["s1"] };
  fakeGate.preApprove(keyFor(args));
  await run(args); // consumes the approval
  const r2 = await run(args); // same args again, nothing pre-approved this time
  assert.equal(r2.isError, true);
  assert.match(textOf(r2), /physical approval required/i);
});

await test("after approval: inject under the Bitwarden key name; child receives the value", async () => {
  secretMap = { s1: { key: "API_KEY", value: SECRET } };
  const args = { argv: echo("process.env.API_KEY ?? 'UNSET'"), secret_ids: ["s1"] };
  const r = await runApproved(args);
  assert.equal(r.isError, undefined);
  assert.match(textOf(r), /\[exit 0\]/);
  assert.ok(textOf(r).includes(SECRET), "child must receive the secret under its key name");
  assert.deepEqual(events, ["checkApproval", "getSecret:s1"], "Approval check must precede the secret fetch/spawn");
  assert.equal(r.structuredContent.status, "ok");
  assert.equal(r.structuredContent.exit_code, 0);
});

await test("env_overrides renames the var; default name is unset", async () => {
  secretMap = { s1: { key: "API_KEY", value: SECRET } };
  const r = await runApproved({
    argv: echo("'C='+(process.env.CUSTOM_TOKEN ?? 'UNSET')+' A='+(process.env.API_KEY ?? 'UNSET')"),
    secret_ids: ["s1"],
    env_overrides: { s1: "CUSTOM_TOKEN" },
  });
  assert.ok(textOf(r).includes(`C=${SECRET}`), "secret must be under the override name");
  assert.ok(textOf(r).includes("A=UNSET"), "the default key name must not also be set");
});

await test("vault token is stripped from the child env", async () => {
  secretMap = { s1: { key: "API_KEY", value: SECRET } };
  const r = await runApproved({ argv: echo("'TOK='+(process.env.BWS_ACCESS_TOKEN ?? 'UNSET')"), secret_ids: ["s1"] });
  assert.match(textOf(r), /TOK=UNSET/, "BWS_ACCESS_TOKEN must not reach the child");
  assert.ok(!textOf(r).includes("VAULT-TOKEN-SENTINEL"));
});

await test("secret is never in argv, and not leaked when the child is quiet", async () => {
  secretMap = { s1: { key: "API_KEY", value: SECRET } };
  const r = await runApproved({ argv: echo("'ARGV:'+process.argv.slice(2).join(',')+';OUT:done'"), secret_ids: ["s1"] });
  assert.match(textOf(r), /OUT:done/);
  assert.ok(!textOf(r).includes(SECRET), "secret must never appear in argv nor be leaked by the wrapper");
});

await test("duplicate resolved env var name is refused", async () => {
  secretMap = { a: { key: "SAME", value: "v1" }, b: { key: "SAME", value: "v2" } };
  const r = await runApproved({ argv: echo("'x'"), secret_ids: ["a", "b"] });
  assert.equal(r.isError, true);
  assert.match(textOf(r), /same env var name/i);
});

await test("invalid env var name is refused", async () => {
  secretMap = { s1: { key: "bad name!", value: SECRET } };
  const r = await runApproved({ argv: echo("'x'"), secret_ids: ["s1"] });
  assert.equal(r.isError, true);
  assert.match(textOf(r), /invalid/i);
  assert.ok(!textOf(r).includes(SECRET));
});

await test("audit records the tool + argv0 but never the secret", async () => {
  secretMap = { s1: { key: "API_KEY", value: SECRET } };
  await runApproved({ argv: echo("'x'"), secret_ids: ["s1"] });
  const audit = readFileSync(join(CFG, "audit.log"), "utf8");
  assert.ok(audit.includes('"run_with_secret"'), "audit must record the tool");
  assert.ok(!audit.includes(SECRET), "audit log must never contain the secret value");
});

console.log(`\n${passed} passed, ${failed} failed`);
rmSync(SANDBOX, { recursive: true, force: true });
process.exit(failed ? 1 : 0);
