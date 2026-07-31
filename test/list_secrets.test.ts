// Security-behaviour test for the list_secrets tool. No framework, no network:
// bws is a fake whose listSecrets() deliberately returns EXTRA fields (value,
// projectId, note) beyond {id, key} — exactly what the real Bitwarden API can
// include in secret objects (the user confirmed `bws secret list` shows value
// inline) — to prove the tool itself never forwards more than {id, key}, even
// if a future SDK version or a differently-shaped BwsGateway starts including
// more. Also locks that this tool, unlike http_request/run_with_secret, never
// touches the Gate: it's metadata-only discovery, not secret use.
import assert from "node:assert/strict";

const { registerTools } = await import("../src/tools.js");

const handlers: Record<string, (a: unknown) => Promise<any>> = {};
const fakeMcp = {
  server: {},
  registerTool: (name: string, _cfg: unknown, handler: (a: any) => Promise<any>) => {
    handlers[name] = handler;
  },
} as any;

let approvals = 0;
const fakeGate = { checkApproval: () => { approvals++; return true; } } as any;

// Deliberately shaped like the REAL bws API response the user showed, which
// includes value/projectId/note/dates — listSecrets() itself is expected to
// strip these before they ever reach tools.ts, but this test doesn't trust
// that boundary either: it asserts the TOOL's own output, end to end.
const SECRET_VALUE = "LIST-SECRETS-MUST-NEVER-LEAK-THIS";
const fakeBws = {
  getSecret: async () => { throw new Error("list_secrets must not call getSecret"); },
  listSecrets: async () => [
    {
      id: "00000000-0000-0000-0000-000000000001",
      key: "EXAMPLE_USERNAME",
      value: SECRET_VALUE,
      projectId: "00000000-0000-0000-0000-0000000000aa",
      note: "some note",
    },
    { id: "s2", key: "OTHER_KEY", value: "also-secret" },
  ],
} as any;

registerTools({ mcp: fakeMcp, gate: fakeGate, bws: fakeBws, timeoutMs: 1000 });
const listSecrets = handlers["list_secrets"]!;

let passed = 0, failed = 0;
async function test(name: string, fn: () => Promise<void>) {
  try { await fn(); console.log("ok  -", name); passed++; }
  catch (e) { failed++; console.error("FAIL -", name, "\n   ", e instanceof Error ? e.message : e); }
}

await test("returns only {id, key} — value/projectId/note never leak even when the source has them", async () => {
  const before = approvals;
  const result = await listSecrets({});
  const text = result.content[0].text as string;
  const parsed = JSON.parse(text);
  assert.deepEqual(parsed, [
    { id: "00000000-0000-0000-0000-000000000001", key: "EXAMPLE_USERNAME" },
    { id: "s2", key: "OTHER_KEY" },
  ]);
  assert.ok(!text.includes(SECRET_VALUE), "the secret value must never appear in list_secrets output");
  assert.ok(!text.includes("also-secret"));
  assert.ok(!text.includes("projectId"), "only id/key fields — no incidental extra metadata");
  assert.equal(approvals, before, "list_secrets must never require a Gate Approval");
});

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
