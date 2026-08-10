// End-to-end smoke test over the REAL stdio transport, against the REAL built
// artifact (dist/index.js) — the thing that actually gets published and that an
// MCP client actually spawns.
//
// Every other suite imports src/ modules and injects fakes, which is right for
// behaviour but blind to the failure that matters most to a user: the server
// not coming up at all. A module that throws at import, a stray write to
// stdout, a bin without its executable bit, a tool that never registers — all
// of those pass `tsc` and every unit test, and all of them look identical from
// the client: the connection just closes.
//
// Deliberately needs no credentials and no network. AWS static keys are dummies
// that are never used: resolveAwsAuth only builds clients, and list_secrets with
// no SSM_PATH_PREFIX returns its explanation without calling AWS. The AWS-only
// configuration is itself part of the assertion — it proves the server starts
// without the Bitwarden native binding, which is a platform-specific prebuilt.
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import assert from "node:assert/strict";

const { Client } = await import("@modelcontextprotocol/sdk/client/index.js");
const { StdioClientTransport } = await import("@modelcontextprotocol/sdk/client/stdio.js");

const SANDBOX = mkdtempSync(join(tmpdir(), "secrets-mcp-smoke-"));

let passed = 0, failed = 0;
function check(name: string, fn: () => void) {
  try { fn(); console.log("ok  -", name); passed++; }
  catch (e) { failed++; console.error("FAIL -", name, "\n   ", e instanceof Error ? e.message : e); }
}

const transport = new StdioClientTransport({
  command: process.execPath,
  args: ["dist/index.js", "serve"],
  // Explicit and minimal: no BWS_* at all, so this fails loudly if the server
  // ever regains a hard dependency on Bitwarden.
  env: {
    PATH: process.env.PATH ?? "",
    HOME: SANDBOX,
    AWS_REGION: "us-east-1",
    AWS_ACCESS_KEY_ID: "AKIAEXAMPLEDUMMYKEY",
    AWS_SECRET_ACCESS_KEY: "dummy-secret-never-used-by-this-test",
  },
  stderr: "pipe",
});

const client = new Client({ name: "smoke-test", version: "0.0.0" });

let connectError: unknown;
try {
  await client.connect(transport);
} catch (e) {
  connectError = e;
}

check("an AWS-only server starts and completes the MCP handshake over stdio", () => {
  assert.equal(connectError, undefined, `connect failed: ${String(connectError)}`);
});

if (connectError === undefined) {
  const tools = await client.listTools();
  const names = tools.tools.map((t) => t.name).sort();

  check("all three tools are advertised", () => {
    assert.deepEqual(names, ["http_request", "list_secrets", "run_with_secret"]);
  });

  check("the gated tools declare an input schema a client can render", () => {
    for (const name of ["http_request", "run_with_secret"]) {
      const tool = tools.tools.find((t) => t.name === name)!;
      const props = (tool.inputSchema as { properties?: Record<string, unknown> }).properties ?? {};
      assert.ok("secret_refs" in props, `${name} must expose secret_refs`);
    }
  });

  const listed = await client.callTool({ name: "list_secrets", arguments: {} });
  check("list_secrets answers over the wire without touching AWS", () => {
    const text = (listed.content as { type: string; text: string }[])[0]!.text;
    assert.match(text, /No listable secrets/, "AWS-only with no prefix has nothing to list");
    assert.match(text, /ssm, secretsmanager/, "and says which Stores are configured");
  });

  // The Gate, end to end, with no hardware: a first call must come back asking
  // for approval rather than running anything.
  const gated = await client.callTool({
    name: "run_with_secret",
    arguments: { argv: ["echo", "hi"], secret_refs: ["ssm:/smoke/test/NOPE"] },
  });
  check("an unapproved call returns approval_required with a URL, and runs nothing", () => {
    const structured = gated.structuredContent as { status?: string; approve_url?: string };
    assert.equal(structured.status, "approval_required");
    assert.match(String(structured.approve_url), /^http:\/\/localhost:\d+\/approve\?rid=[0-9a-f]{64}$/);
  });

  // An unprefixed id is a caller bug: the server must say so rather than
  // spending a physical touch discovering it.
  const malformed = await client.callTool({
    name: "run_with_secret",
    arguments: { argv: ["echo", "hi"], secret_refs: ["no-store-prefix"] },
  });
  check("an unprefixed secret_ref is rejected with an actionable message", () => {
    const structured = malformed.structuredContent as { status?: string; reason?: string };
    assert.equal(structured.status, "error");
    assert.match(String(structured.reason), /no store prefix/i);
  });

  await client.close();
}

rmSync(SANDBOX, { recursive: true, force: true });
console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
