// End-to-end test of the optional Streamable HTTP transport (src/http-serve.ts,
// opt-in via `serve --http`), driven with the SDK's real client transport against
// a real running http.Server — no mocked MCP internals, only gate/bws/fetch are
// faked so this never touches the real vault or a physical authenticator.
//
// Locks:
//   1. DNS-rebinding guard: a foreign Origin is refused (403) before reaching the
//      MCP transport at all — a plain fetch, not the MCP client, proves this.
//   2. a real MCP client can initialize, list tools, and call one over HTTP.
//   3. the tool call still goes through the Gate (Approval before the fetch).
//   4. session termination (client.close() -> DELETE) invalidates the session id.
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import assert from "node:assert/strict";
import type { AddressInfo } from "node:net";

// Sandbox HOME *before* importing anything that resolves paths.ts (checkHostAllowed
// in tools.ts reads the real ~/.config/secrets-webauthn-mcp/allowlist.json otherwise —
// which, on this machine, holds the user's real secrets, not our test fixture).
const SANDBOX = mkdtempSync(join(tmpdir(), "bws-webauthn-http-test-"));
process.env.HOME = SANDBOX;
const CFG = join(SANDBOX, ".config", "secrets-webauthn-mcp");
mkdirSync(CFG, { recursive: true });
writeFileSync(join(CFG, "allowlist.json"), JSON.stringify({ "bws:s1": ["example.test"] }));

const { Client } = await import("@modelcontextprotocol/sdk/client/index.js");
const { StreamableHTTPClientTransport } = await import("@modelcontextprotocol/sdk/client/streamableHttp.js");
const { createHttpApp } = await import("../src/http-serve.js");
const { requestKey } = await import("../src/request-key.js");
const { HttpRequestArgsSchema } = await import("../src/schemas.js");
const { createStoreRegistry } = await import("../src/store.js");
type StoreRegistry = import("../src/store.js").StoreRegistry;
type Gate = import("../src/gate.js").Gate;

const SECRET = "HTTP-TRANSPORT-SECRET-DO-NOT-LEAK";
let approvalChecks = 0;
const approvedKeys = new Set<string>();
const fakeGate: Gate = {
  origin: "http://localhost:0",
  port: 0,
  checkApproval: (key: string) => {
    approvalChecks++;
    if (approvedKeys.has(key)) {
      approvedKeys.delete(key);
      return true;
    }
    return false;
  },
  close: () => {},
};
const stores: StoreRegistry = createStoreRegistry({
  bws: {
    getSecret: async (_id: string) => ({ key: "API_KEY", value: SECRET }),
    listSecrets: async () => [{ id: "s1", key: "API_KEY" }],
  },
});

// The port is only known after listen(0, ...) resolves, but createHttpApp needs
// allowedHostPorts up front — pass a mutable array by reference and fill it in
// once the port is known; the server's request handler reads the same array on
// every request, so this is not a race (no requests arrive before the test body
// below runs, and listen()'s callback has already fired by then).
const allowedHostPorts: string[] = [];
const httpServer = createHttpApp({ gate: fakeGate, stores, timeoutMs: 1000, allowedHostPorts });

let passed = 0, failed = 0;
async function test(name: string, fn: () => Promise<void>) {
  try { await fn(); console.log("ok  -", name); passed++; }
  catch (e) { failed++; console.error("FAIL -", name, "\n   ", e instanceof Error ? e.message : e); }
}

await new Promise<void>((resolve) => httpServer.listen(0, "127.0.0.1", () => resolve()));
const port = (httpServer.address() as AddressInfo).port;
allowedHostPorts.push(`127.0.0.1:${port}`, `localhost:${port}`);
const base = `http://127.0.0.1:${port}`;

await test("DNS-rebinding guard: foreign Origin is refused before reaching MCP", async () => {
  const res = await fetch(`${base}/mcp`, {
    method: "POST",
    headers: { "content-type": "application/json", origin: "http://evil.example.com" },
    body: JSON.stringify({ jsonrpc: "2.0", method: "initialize", id: 1, params: {} }),
  });
  assert.equal(res.status, 403);
});

let client: Client | undefined;
let clientTransport: StreamableHTTPClientTransport | undefined;

await test("real MCP client can initialize over HTTP and list all three tools", async () => {
  clientTransport = new StreamableHTTPClientTransport(new URL(`${base}/mcp`));
  client = new Client({ name: "test-client", version: "1.0.0" });
  await client.connect(clientTransport);
  const { tools } = await client.listTools();
  const names = tools.map((t) => t.name).sort();
  assert.deepEqual(names, ["http_request", "list_secrets", "run_with_secret"]);
  assert.ok(clientTransport.sessionId, "a session id must have been issued");
});

await test("tool call over HTTP: not-yet-approved first, then proceeds after out-of-band approval", async () => {
  // The MCP client transport ALSO uses global fetch to talk to our own server
  // (to send this very tool call as a JSON-RPC POST) — only intercept the
  // TOOL's outbound request (to example.test), and pass everything else
  // (including the client's own traffic to 127.0.0.1) through untouched.
  const originalFetch = globalThis.fetch;
  let sawAuthHeader = "";
  (globalThis as unknown as { fetch: typeof fetch }).fetch = (async (url: unknown, init: any) => {
    if (String(url).includes("example.test")) {
      sawAuthHeader = init.headers["Authorization"];
      return { status: 200, type: "basic", text: async () => "OK" } as Response;
    }
    return originalFetch(url as string, init);
  }) as typeof fetch;
  try {
    const callArgs = { url: "http://example.test/x", secret_refs: ["bws:s1"] };
    const before = approvalChecks;

    const first = await client!.callTool({ name: "http_request", arguments: callArgs });
    assert.equal(approvalChecks, before + 1, "the Gate must be checked for a tool call made over HTTP");
    const firstText = (first.content as { type: string; text: string }[])[0]!.text;
    assert.equal(first.isError, true, "must not proceed before approval — this works with ANY MCP client");
    assert.match(firstText, /physical approval required/i);
    // The declared outputSchema is enforced by the real SDK over the real wire —
    // this is the one test that would fail if structuredContent didn't match it.
    assert.equal(first.structuredContent?.status, "approval_required");
    assert.equal(typeof first.structuredContent?.approve_url, "string");

    // Simulate a human having approved this exact request out of band.
    approvedKeys.add(requestKey("http_request", HttpRequestArgsSchema.parse(callArgs)));

    const second = await client!.callTool({ name: "http_request", arguments: callArgs });
    assert.equal(second.isError, undefined, "the identical call must proceed once approved");
    assert.equal(sawAuthHeader, `Bearer ${SECRET}`);
    const secondText = (second.content as { type: string; text: string }[])[0]!.text;
    assert.ok(!secondText.includes(SECRET), "the secret must never appear in the tool result");
    assert.equal(second.structuredContent?.status, "ok");
    assert.equal(second.structuredContent?.http_status, 200);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

await test("session termination invalidates the session id", async () => {
  const sid = clientTransport!.sessionId!;
  await clientTransport!.terminateSession();
  const res = await fetch(`${base}/mcp`, {
    method: "GET",
    headers: { "mcp-session-id": sid, accept: "text/event-stream" },
  });
  assert.equal(res.status, 400, "a terminated session id must no longer be accepted");
});

console.log(`\n${passed} passed, ${failed} failed`);
httpServer.close();
rmSync(SANDBOX, { recursive: true, force: true });
process.exit(failed ? 1 : 0);
