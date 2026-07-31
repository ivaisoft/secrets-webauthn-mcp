// Security-behaviour test for the run_with_secret tool. No framework: the gate +
// bws are fakes, HOME is a throwaway sandbox, and the child is a real `node -e`
// process so we can observe what env/argv it actually received.
//
// Locks the invariants:
//   1. the secret reaches the child as an env var (default = Bitwarden key name)
//   2. env_overrides renames it; the default name is then NOT set
//   3. the vault token (BWS_ACCESS_TOKEN) is stripped from the child env
//   4. the secret is never passed via argv, and the wrapper doesn't leak it when
//      the child stays quiet
//   5. Approval happens before the secret is fetched / the child is spawned
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
const fakeGate = { requireApproval: async () => { events.push("approval"); } } as any;
const fakeBws = {
  getSecret: async (id: string) => {
    events.push("getSecret:" + id);
    const s = secretMap[id];
    if (!s) throw new Error("no such secret " + id);
    return s;
  },
  listSecrets: async () => [],
} as any;

registerTools({ mcp: fakeMcp, gate: fakeGate, bws: fakeBws, timeoutMs: 1000 });
const run = (raw: unknown) => handlers["run_with_secret"]!(RunWithSecretArgsSchema.parse(raw));
const textOf = (r: any) => r.content[0].text as string;
const echo = (js: string) => [NODE, "-e", `process.stdout.write(${js})`];

let passed = 0, failed = 0;
async function test(name: string, fn: () => Promise<void>) {
  events = [];
  try { await fn(); console.log("ok  -", name); passed++; }
  catch (e) { failed++; console.error("FAIL -", name, "\n   ", e instanceof Error ? e.message : e); }
}

await test("inject under the Bitwarden key name; child receives the value", async () => {
  secretMap = { s1: { key: "API_KEY", value: SECRET } };
  const r = await run({ argv: echo("process.env.API_KEY ?? 'UNSET'"), secret_ids: ["s1"] });
  assert.equal(r.isError, undefined);
  assert.match(textOf(r), /\[exit 0\]/);
  assert.ok(textOf(r).includes(SECRET), "child must receive the secret under its key name");
  assert.deepEqual(events, ["approval", "getSecret:s1"], "Approval must precede the secret fetch/spawn");
});

await test("env_overrides renames the var; default name is unset", async () => {
  secretMap = { s1: { key: "API_KEY", value: SECRET } };
  const r = await run({
    argv: echo("'C='+(process.env.CUSTOM_TOKEN ?? 'UNSET')+' A='+(process.env.API_KEY ?? 'UNSET')"),
    secret_ids: ["s1"],
    env_overrides: { s1: "CUSTOM_TOKEN" },
  });
  assert.ok(textOf(r).includes(`C=${SECRET}`), "secret must be under the override name");
  assert.ok(textOf(r).includes("A=UNSET"), "the default key name must not also be set");
});

await test("vault token is stripped from the child env", async () => {
  secretMap = { s1: { key: "API_KEY", value: SECRET } };
  const r = await run({ argv: echo("'TOK='+(process.env.BWS_ACCESS_TOKEN ?? 'UNSET')"), secret_ids: ["s1"] });
  assert.match(textOf(r), /TOK=UNSET/, "BWS_ACCESS_TOKEN must not reach the child");
  assert.ok(!textOf(r).includes("VAULT-TOKEN-SENTINEL"));
});

await test("secret is never in argv, and not leaked when the child is quiet", async () => {
  secretMap = { s1: { key: "API_KEY", value: SECRET } };
  const r = await run({ argv: echo("'ARGV:'+process.argv.slice(2).join(',')+';OUT:done'"), secret_ids: ["s1"] });
  assert.match(textOf(r), /OUT:done/);
  assert.ok(!textOf(r).includes(SECRET), "secret must never appear in argv nor be leaked by the wrapper");
});

await test("duplicate resolved env var name is refused", async () => {
  secretMap = { a: { key: "SAME", value: "v1" }, b: { key: "SAME", value: "v2" } };
  const r = await run({ argv: echo("'x'"), secret_ids: ["a", "b"] });
  assert.equal(r.isError, true);
  assert.match(textOf(r), /same env var name/i);
});

await test("invalid env var name is refused", async () => {
  secretMap = { s1: { key: "bad name!", value: SECRET } };
  const r = await run({ argv: echo("'x'"), secret_ids: ["s1"] });
  assert.equal(r.isError, true);
  assert.match(textOf(r), /invalid/i);
  assert.ok(!textOf(r).includes(SECRET));
});

await test("audit records the tool + argv0 but never the secret", async () => {
  secretMap = { s1: { key: "API_KEY", value: SECRET } };
  await run({ argv: echo("'x'"), secret_ids: ["s1"] });
  const audit = readFileSync(join(CFG, "audit.log"), "utf8");
  assert.ok(audit.includes('"run_with_secret"'), "audit must record the tool");
  assert.ok(!audit.includes(SECRET), "audit log must never contain the secret value");
});

console.log(`\n${passed} passed, ${failed} failed`);
rmSync(SANDBOX, { recursive: true, force: true });
process.exit(failed ? 1 : 0);
