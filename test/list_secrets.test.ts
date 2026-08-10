// Security-behaviour test for the list_secrets tool. No framework, no network:
// the Bitwarden Store is a fake whose listSecrets() deliberately returns EXTRA
// fields (value, projectId, note) beyond {id, key} — exactly what the real
// Bitwarden API can include in secret objects (the user confirmed `bws secret
// list` shows value inline) — to prove the tool itself never forwards more than
// {id, key}, even if a future SDK version or a differently-shaped Store starts
// including more. Also locks that this tool, unlike http_request/run_with_secret,
// never touches the Gate: it's metadata-only discovery, not secret use.
//
// The registry is the REAL createStoreRegistry, not a stub, so this also covers
// the two properties that only exist once there is more than one Store: ids come
// back as full Secret References, and a Store that cannot enumerate (the AWS
// ones, ADR 0010) contributes nothing instead of erroring.
import assert from "node:assert/strict";

const { registerTools } = await import("../src/tools.js");
const { createStoreRegistry } = await import("../src/store.js");

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
const fakeBwsStore = {
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

// No listSecrets at all — the shape the SSM / Secrets Manager Stores really have.
const fakeSsmStore = {
  getSecret: async () => { throw new Error("list_secrets must not call getSecret"); },
} as any;

const stores = createStoreRegistry({ bws: fakeBwsStore, ssm: fakeSsmStore });
registerTools({ mcp: fakeMcp, gate: fakeGate, stores, timeoutMs: 1000 });
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
    { id: "bws:00000000-0000-0000-0000-000000000001", key: "EXAMPLE_USERNAME" },
    { id: "bws:s2", key: "OTHER_KEY" },
  ]);
  assert.ok(!text.includes(SECRET_VALUE), "the secret value must never appear in list_secrets output");
  assert.ok(!text.includes("also-secret"));
  assert.ok(!text.includes("projectId"), "only id/key fields — no incidental extra metadata");
  assert.equal(approvals, before, "list_secrets must never require a Gate Approval");
});

await test("ids come back as full Secret References, ready to paste into secret_refs", async () => {
  const parsed = JSON.parse((await listSecrets({})).content[0].text as string);
  assert.ok(
    parsed.every((s: { id: string }) => s.id.startsWith("bws:")),
    "a bare id would be rejected by the tools, so listing must return the prefixed form",
  );
});

await test("a Store that cannot enumerate contributes nothing, and does not error", async () => {
  const parsed = JSON.parse((await listSecrets({})).content[0].text as string);
  assert.equal(
    parsed.some((s: { id: string }) => s.id.startsWith("ssm:")),
    false,
    "the AWS Stores deliberately do not enumerate (ADR 0010)",
  );
});

await test("AWS-only: an empty result explains itself instead of returning a bare []", async () => {
  // The configuration a user hits the moment they wire up AWS without Bitwarden.
  // "[]" is the correct answer forever here (ADR 0010), not a transient empty
  // state, and it is indistinguishable from a broken server at the call site.
  const awsOnly = createStoreRegistry({ ssm: fakeSsmStore, secretsmanager: fakeSsmStore });
  const localHandlers: Record<string, (a: unknown) => Promise<any>> = {};
  registerTools({
    mcp: { server: {}, registerTool: (n: string, _c: unknown, h: any) => { localHandlers[n] = h; } } as any,
    gate: fakeGate,
    stores: awsOnly,
    timeoutMs: 1000,
  });
  const text = (await localHandlers["list_secrets"]!({})).content[0].text as string;

  assert.notEqual(text.trim(), "[]", "a bare [] reads as a broken server");
  assert.match(text, /ssm, secretsmanager/, "must name the Stores that are configured");
  assert.match(text, /not configured/i, "must say Bitwarden is absent");
  assert.match(text, /ssm:\/prod\/app\/STRIPE_KEY/, "must show how to address AWS secrets without listing");
  assert.match(
    text,
    /says nothing about whether the AWS credential works/i,
    "must not let an empty list be read as evidence about the AWS credential",
  );
  assert.match(
    text,
    /SSM_PATH_PREFIX/,
    "must say how to turn Parameter Store listing on, since that is the actionable fix",
  );
  assert.match(
    text,
    /resource-level IAM form/,
    "must distinguish Secrets Manager, which cannot be made to list at all",
  );
});

await test("SSM listing, when a prefix is configured, returns ssm: references", async () => {
  // createSsmStore's GetParametersByPath call itself needs the AWS SDK and is
  // not exercised here; this locks the contract the registry depends on — that
  // a listing Store's ids come back namespaced and pasteable into secret_refs.
  const withPrefix = createStoreRegistry({
    ssm: {
      getSecret: async () => { throw new Error("list must not fetch values"); },
      listSecrets: async () => [
        { id: "/ombrello/prod/DB_PASSWORD", key: "DB_PASSWORD" },
        { id: "/ombrello/prod/STRIPE_KEY", key: "STRIPE_KEY" },
      ],
    } as any,
    secretsmanager: fakeSsmStore,
  });
  assert.deepEqual(withPrefix.enumerable, ["ssm"], "only the Store that implements listing counts");

  const localHandlers: Record<string, (a: unknown) => Promise<any>> = {};
  registerTools({
    mcp: { server: {}, registerTool: (n: string, _c: unknown, h: any) => { localHandlers[n] = h; } } as any,
    gate: fakeGate,
    stores: withPrefix,
    timeoutMs: 1000,
  });
  const parsed = JSON.parse((await localHandlers["list_secrets"]!({})).content[0].text as string);
  assert.deepEqual(parsed, [
    { id: "ssm:/ombrello/prod/DB_PASSWORD", key: "DB_PASSWORD" },
    { id: "ssm:/ombrello/prod/STRIPE_KEY", key: "STRIPE_KEY" },
  ]);
});

await test("Bitwarden configured but empty points at org/project, not at the AWS Stores", async () => {
  const emptyBws = createStoreRegistry({
    bws: { getSecret: async () => { throw new Error("no"); }, listSecrets: async () => [] } as any,
    ssm: fakeSsmStore,
  });
  const localHandlers: Record<string, (a: unknown) => Promise<any>> = {};
  registerTools({
    mcp: { server: {}, registerTool: (n: string, _c: unknown, h: any) => { localHandlers[n] = h; } } as any,
    gate: fakeGate,
    stores: emptyBws,
    timeoutMs: 1000,
  });
  const text = (await localHandlers["list_secrets"]!({})).content[0].text as string;
  assert.match(text, /BWS_ORGANIZATION_ID/, "an empty Bitwarden is a different diagnosis entirely");
});

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
