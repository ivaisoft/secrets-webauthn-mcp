// Security-behaviour test for the http_request tool. No framework, no network:
// fetch is mocked, bws is a fake, HOME is redirected to a throwaway sandbox so
// we never read or write the real ~/.config/secrets-webauthn-mcp, and the Gate is a
// tiny real implementation of the same request-key semantics as gate.ts (not a
// stub) — so the two-call "not yet approved -> approve out of band -> identical
// call proceeds" flow is exercised exactly as it works in production, without
// real WebAuthn hardware.
//
// Locks:
//   1. allowlist denies BEFORE any Approval check or fetch (no touch, no request)
//   2. the FIRST call for a not-yet-approved request returns instructions
//      (with the approval URL) instead of fetching — this is the whole point
//      of the redesign: it works with any MCP client, not just ones that
//      support elicitation (see ADR 0006)
//   3. the SECOND, identical call — after out-of-band approval — proceeds:
//      the secret is injected into the header, value never in the output
//   4. a 3xx / opaqueredirect is refused (never followed) so the injected secret
//      can't be forwarded to an off-allowlist host
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import assert from "node:assert/strict";

// --- sandbox HOME before importing anything that resolves paths.ts ---
const SANDBOX = mkdtempSync(join(tmpdir(), "bws-webauthn-test-"));
process.env.HOME = SANDBOX;
const CFG = join(SANDBOX, ".config", "secrets-webauthn-mcp");
mkdirSync(CFG, { recursive: true });
const writeAllowlist = (obj: Record<string, string[]>) =>
  writeFileSync(join(CFG, "allowlist.json"), JSON.stringify(obj));
writeAllowlist({ "bws:sec-1": ["api.allowed.com"] });

// Import AFTER HOME is set so STATE_DIR points into the sandbox.
const { registerTools } = await import("../src/tools.js");
const { createStoreRegistry } = await import("../src/store.js");
const { HttpRequestArgsSchema } = await import("../src/schemas.js");
const { requestKey } = await import("../src/request-key.js");

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

const fakeBwsStore = {
  getSecret: async (id: string) => { events.push("getSecret:" + id); return { key: "API_KEY", value: SECRET }; },
  listSecrets: async () => [],
} as any;

// The REAL registry, so allowlist keys and reference routing are exercised together.
const stores = createStoreRegistry({ bws: fakeBwsStore });
registerTools({ mcp: fakeMcp, gate: fakeGate, stores, timeoutMs: 1000 });
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
const keyFor = (raw: unknown) => requestKey("http_request", HttpRequestArgsSchema.parse(raw));
const textOf = (r: any) => r.content[0].text as string;

// --- runner ---
let passed = 0, failed = 0;
async function test(name: string, fn: () => Promise<void>) {
  events = [];
  try { await fn(); console.log("ok  -", name); passed++; }
  catch (e) { failed++; console.error("FAIL -", name, "\n   ", e instanceof Error ? e.message : e); }
}

await test("deny: unknown secret → no Approval check, no fetch, audited unverified", async () => {
  mockFetch({});
  const r = await call({ url: "https://api.allowed.com/x", secret_refs: ["bws:sec-unknown"] });
  assert.equal(r.isError, true);
  assert.match(textOf(r), /allowlist/i);
  assert.equal(events.includes("checkApproval"), false, "must not even check Approval on deny");
  assert.equal(fetchCalls.length, 0, "must not fetch on deny");
});

await test("deny: host not allowed for this secret → no Approval check, no fetch", async () => {
  mockFetch({});
  const r = await call({ url: "https://evil.com/x", secret_refs: ["bws:sec-1"] });
  assert.equal(r.isError, true);
  assert.equal(events.includes("checkApproval"), false);
  assert.equal(fetchCalls.length, 0);
});

await test("first call (not yet approved) returns instructions + URL, never fetches", async () => {
  mockFetch({});
  const args = { url: "https://api.allowed.com/x", secret_refs: ["bws:sec-1"] };
  const r = await call(args);
  assert.equal(r.isError, true);
  assert.match(textOf(r), /physical approval required/i);
  assert.ok(textOf(r).includes(fakeGate.origin), "must include the approval URL's origin");
  assert.ok(textOf(r).includes(keyFor(args)), "must include this exact request's key in the URL");
  assert.equal(fetchCalls.length, 0, "must not fetch before approval");
  assert.ok(!textOf(r).includes(SECRET));
  // structuredContent lets a client detect this programmatically, not just from prose.
  assert.equal(r.structuredContent.status, "approval_required");
  assert.equal(typeof r.structuredContent.approve_url, "string");
  assert.ok((r.structuredContent.approve_url as string).includes(keyFor(args)));
});

await test("second, identical call after out-of-band approval: fetch happens, secret injected, value never returned", async () => {
  const args = { url: "https://api.allowed.com/x", secret_refs: ["bws:sec-1"] };
  fakeGate.preApprove(keyFor(args));
  mockFetch({ status: 200, text: "RESPONSE_BODY" });
  const r = await call(args);
  assert.equal(r.isError, undefined);
  assert.equal(textOf(r), "HTTP 200\n\nRESPONSE_BODY");
  assert.deepEqual(events, ["checkApproval", "getSecret:sec-1", "fetch"], "Approval check + fetch must be ordered");
  assert.equal(fetchCalls[0]!.init.headers["Authorization"], `Bearer ${SECRET}`, "secret must be injected");
  assert.equal(fetchCalls[0]!.init.redirect, "manual", "must disable redirect following");
  assert.ok(!textOf(r).includes(SECRET), "secret value must never appear in the tool output");
  assert.equal(r.structuredContent.status, "ok");
  assert.equal(r.structuredContent.http_status, 200);
  assert.equal(r.structuredContent.body, "RESPONSE_BODY");
});

await test("approval is single-use: a third call with the same args is not yet approved again", async () => {
  const args = { url: "https://api.allowed.com/x", secret_refs: ["bws:sec-1"] };
  mockFetch({});
  const r = await call(args); // no fresh preApprove — the prior one was consumed
  assert.equal(r.isError, true);
  assert.match(textOf(r), /physical approval required/i);
  assert.equal(fetchCalls.length, 0);
});

await test("redirect: 3xx refused, body withheld, no leak", async () => {
  const args = { url: "https://api.allowed.com/redir", secret_refs: ["bws:sec-1"] };
  fakeGate.preApprove(keyFor(args));
  mockFetch({ status: 302, text: "SHOULD_NOT_BE_RETURNED" });
  const r = await call(args);
  assert.equal(r.isError, true);
  assert.match(textOf(r), /refusing to follow a redirect/i);
  assert.ok(!textOf(r).includes("SHOULD_NOT_BE_RETURNED"), "redirect body must not be returned");
  assert.ok(!textOf(r).includes(SECRET));
});

await test("redirect: opaqueredirect also refused", async () => {
  const args = { url: "https://api.allowed.com/redir2", secret_refs: ["bws:sec-1"] };
  fakeGate.preApprove(keyFor(args));
  mockFetch({ status: 0, type: "opaqueredirect", text: "" });
  const r = await call(args);
  assert.equal(r.isError, true);
  assert.match(textOf(r), /refusing to follow a redirect/i);
});

await test("multi-secret without a header array is rejected before any Approval check", async () => {
  writeAllowlist({ "bws:sec-1": ["api.allowed.com"], "bws:sec-2": ["api.allowed.com"] });
  mockFetch({});
  const r = await call({ url: "https://api.allowed.com/x", secret_refs: ["bws:sec-1", "bws:sec-2"] });
  assert.equal(r.isError, true);
  assert.match(textOf(r), /header/i);
  assert.match(textOf(r), /array/i);
  assert.equal(events.includes("checkApproval"), false, "must reject ambiguous header mapping before touch");
  assert.equal(fetchCalls.length, 0);
  writeAllowlist({ "bws:sec-1": ["api.allowed.com"] });
});

console.log(`\n${passed} passed, ${failed} failed`);
rmSync(SANDBOX, { recursive: true, force: true });
process.exit(failed ? 1 : 0);
