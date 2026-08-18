// Regression test for the failure that reached a user as, in full, "Couldn't run
// the request: Connection closed".
//
// The Bitwarden Store used to exchange its access token while the server was
// starting. Any failure there — a malformed token, a rotated one, an offline
// machine, a platform with no native prebuilt — killed the process with one line
// on stderr and exit 1. An MCP client shows none of that; it reports only that
// the connection closed, which is indistinguishable from a crash, a bad path, or
// a wrong command, and says nothing about Bitwarden.
//
// So the lock here is startup, not Bitwarden: a Store whose credential cannot be
// used must not prevent the server from speaking MCP, and must surface as an
// error on the call that needed it.
//
// Deliberately offline. The token is malformed rather than merely wrong, which
// the SDK rejects by parsing it — no network, so this behaves the same on a
// developer's machine and on a runner with no route to Bitwarden.
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import assert from "node:assert/strict";

const { Client } = await import("@modelcontextprotocol/sdk/client/index.js");
const { StdioClientTransport } = await import("@modelcontextprotocol/sdk/client/stdio.js");

const SANDBOX = mkdtempSync(join(tmpdir(), "secrets-mcp-bws-"));
const BAD_TOKEN = "0.11111111-2222-3333-4444-555555555555.MALFORMED-ON-PURPOSE";

let passed = 0, failed = 0;
function check(name: string, fn: () => void) {
  try { fn(); console.log("ok  -", name); passed++; }
  catch (e) { failed++; console.error("FAIL -", name, "\n   ", e instanceof Error ? e.message : e); }
}

const transport = new StdioClientTransport({
  command: process.execPath,
  args: ["dist/index.js", "serve"],
  env: {
    PATH: process.env.PATH ?? "",
    HOME: SANDBOX,
    BWS_ACCESS_TOKEN: BAD_TOKEN,
    BWS_ORGANIZATION_ID: "00000000-0000-0000-0000-000000000000",
    AWS_REGION: "us-east-1",
    AWS_ACCESS_KEY_ID: "AKIAEXAMPLEDUMMYKEY",
    AWS_SECRET_ACCESS_KEY: "dummy-secret-never-used-by-this-test",
  },
  stderr: "pipe",
});

const client = new Client({ name: "bws-deferred-test", version: "0.0.0" });

let connectError: unknown;
try {
  await client.connect(transport);
} catch (e) {
  connectError = e;
}

check("a server with an unusable Bitwarden credential still completes the handshake", () => {
  assert.equal(connectError, undefined, `connect failed: ${String(connectError)}`);
});

if (connectError === undefined) {
  const tools = await client.listTools();
  check("its tools are advertised as normal", () => {
    assert.deepEqual(tools.tools.map((t) => t.name).sort(), [
      "http_request", "list_secrets", "run_with_secret",
    ]);
  });

  // list_secrets is the reachable probe: it is the one tool that touches a Store
  // without a physical Approval first, so it is where a deferred sign-in is
  // actually attempted.
  const listed = await client.callTool({ name: "list_secrets", arguments: {} });
  const text = (listed.content as { type: string; text: string }[])[0]!.text;

  check("the Bitwarden failure is reported, named, and actionable", () => {
    assert.match(text, /Stores that failed to list: bws \(/, "named as a per-Store failure");
    assert.match(text, /BWS_ACCESS_TOKEN/, "says which variable to fix");
  });

  check("the failure is isolated: the AWS Stores are unaffected", () => {
    assert.match(text, /ssm/, "the other Stores are still configured and reported");
    assert.doesNotMatch(text, /^Error/, "one broken Store does not fail the whole tool");
  });

  check("the access token never appears in what the agent is told", () => {
    assert.ok(!text.includes(BAD_TOKEN), "token must not be echoed");
    assert.ok(!text.includes("MALFORMED-ON-PURPOSE"), "nor any part of it");
  });

  // Retrying must re-attempt rather than replay a cached rejection — a rotated
  // token has to be able to start working without restarting the server.
  const again = await client.callTool({ name: "list_secrets", arguments: {} });
  check("a second call re-attempts instead of replaying a cached failure", () => {
    const second = (again.content as { type: string; text: string }[])[0]!.text;
    assert.match(second, /Stores that failed to list: bws \(/);
  });

  await client.close();
}

rmSync(SANDBOX, { recursive: true, force: true });
console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
