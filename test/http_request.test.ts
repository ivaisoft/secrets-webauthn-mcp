// Security-behaviour test for the http_request tool. No framework, no network:
// fetch is mocked, the gate + bws are fakes, and HOME is redirected to a throwaway
// sandbox so we never read or write the real ~/.config/bws-webauthn-mcp.
//
// Locks the three invariants the adversarial review cared about:
//   1. allowlist denies BEFORE any Approval or fetch (no touch, no request on deny)
//   2. on allow: Approval happens before fetch, the secret is injected into the
//      header, and the secret value never appears in the returned text
//   3. a 3xx / opaqueredirect is refused (never followed) so the injected secret
//      can't be forwarded to an off-allowlist host
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import assert from "node:assert/strict";

// --- sandbox HOME before importing anything that resolves paths.ts ---
const SANDBOX = mkdtempSync(join(tmpdir(), "bws-webauthn-test-"));
process.env.HOME = SANDBOX;
const CFG = join(SANDBOX, ".config", "bws-webauthn-mcp");
mkdirSync(CFG, { recursive: true });
const writeAllowlist = (obj: Record<string, string[]>) =>
  writeFileSync(join(CFG, "allowlist.json"), JSON.stringify(obj));
writeAllowlist({ "sec-1": ["api.allowed.com"] });

// Import AFTER HOME is set so STATE_DIR points into the sandbox.
const { registerTools } = await import("../src/tools.js");
const { HttpRequestArgsSchema } = await import("../src/schemas.js");

const SECRET = "SECRET-VALUE-DO-NOT-LEAK-abc123";

// --- fakes ---
let events: string[] = [];
const handlers: Record<string, (a: unknown) => Promise<any>> = {};
const fakeMcp = {
  server: {},
  registerTool: (name: string, _cfg: unknown, handler: (a: any) => Promise<any>) => {
    handlers[name] = handler;
  },
} as any;
const fakeGate = { requireApproval: async () => { events.push("approval"); } } as any;
const fakeBws = {
  getSecret: async (id: string) => { events.push("getSecret:" + id); return { key: "API_KEY", value: SECRET }; },
  listSecrets: async () => [],
} as any;

registerTools({ mcp: fakeMcp, gate: fakeGate, bws: fakeBws, timeoutMs: 1000 });
const http = handlers["http_request"]!;

let fetchCalls: { url: string; init: any }[] = [];
function mockFetch(resp: { status?: number; type?: string; text?: string }) {
  fetchCalls = [];
  (globalThis as any).fetch = async (url: string, init: any) => {
    fetchCalls.push({ url, init });
    events.push("fetch");
    return { status: resp.status ?? 200, type: resp.type ?? "basic", text: async () => resp.text ?? "" };
  };
}
const call = (raw: unknown) => http(HttpRequestArgsSchema.parse(raw));
const textOf = (r: any) => r.content[0].text as string;

// --- runner ---
let passed = 0, failed = 0;
async function test(name: string, fn: () => Promise<void>) {
  events = [];
  try { await fn(); console.log("ok  -", name); passed++; }
  catch (e) { failed++; console.error("FAIL -", name, "\n   ", e instanceof Error ? e.message : e); }
}

await test("deny: unknown secret → no Approval, no fetch, audited unverified", async () => {
  mockFetch({});
  const r = await call({ url: "https://api.allowed.com/x", secret_ids: ["sec-unknown"] });
  assert.equal(r.isError, true);
  assert.match(textOf(r), /allowlist/i);
  assert.equal(events.includes("approval"), false, "must not request Approval on deny");
  assert.equal(fetchCalls.length, 0, "must not fetch on deny");
});

await test("deny: host not allowed for this secret → no Approval, no fetch", async () => {
  mockFetch({});
  const r = await call({ url: "https://evil.com/x", secret_ids: ["sec-1"] });
  assert.equal(r.isError, true);
  assert.equal(events.includes("approval"), false);
  assert.equal(fetchCalls.length, 0);
});

await test("allow: Approval BEFORE fetch, secret injected into header, value not returned", async () => {
  mockFetch({ status: 200, text: "RESPONSE_BODY" });
  const r = await call({ url: "https://api.allowed.com/x", secret_ids: ["sec-1"] });
  assert.equal(r.isError, undefined);
  assert.equal(textOf(r), "HTTP 200\n\nRESPONSE_BODY");
  assert.deepEqual(events, ["approval", "getSecret:sec-1", "fetch"], "Approval + fetch must be ordered");
  assert.equal(fetchCalls[0]!.init.headers["Authorization"], `Bearer ${SECRET}`, "secret must be injected");
  assert.equal(fetchCalls[0]!.init.redirect, "manual", "must disable redirect following");
  assert.ok(!textOf(r).includes(SECRET), "secret value must never appear in the tool output");
});

await test("redirect: 3xx refused, body withheld, no leak", async () => {
  mockFetch({ status: 302, text: "SHOULD_NOT_BE_RETURNED" });
  const r = await call({ url: "https://api.allowed.com/x", secret_ids: ["sec-1"] });
  assert.equal(r.isError, true);
  assert.match(textOf(r), /refusing to follow a redirect/i);
  assert.ok(!textOf(r).includes("SHOULD_NOT_BE_RETURNED"), "redirect body must not be returned");
  assert.ok(!textOf(r).includes(SECRET));
});

await test("redirect: opaqueredirect also refused", async () => {
  mockFetch({ status: 0, type: "opaqueredirect", text: "" });
  const r = await call({ url: "https://api.allowed.com/x", secret_ids: ["sec-1"] });
  assert.equal(r.isError, true);
  assert.match(textOf(r), /refusing to follow a redirect/i);
});

await test("multi-secret without a header array is rejected before any Approval", async () => {
  writeAllowlist({ "sec-1": ["api.allowed.com"], "sec-2": ["api.allowed.com"] });
  mockFetch({});
  const r = await call({ url: "https://api.allowed.com/x", secret_ids: ["sec-1", "sec-2"] });
  assert.equal(r.isError, true);
  assert.match(textOf(r), /header/i);
  assert.match(textOf(r), /array/i);
  assert.equal(events.includes("approval"), false, "must reject ambiguous header mapping before touch");
  assert.equal(fetchCalls.length, 0);
  writeAllowlist({ "sec-1": ["api.allowed.com"] });
});

console.log(`\n${passed} passed, ${failed} failed`);
rmSync(SANDBOX, { recursive: true, force: true });
process.exit(failed ? 1 : 0);
