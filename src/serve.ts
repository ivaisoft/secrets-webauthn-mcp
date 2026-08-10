// Serve mode: the MCP stdio server. Connects every configured Store, starts the
// localhost Gate, exposes exactly the three tools. Does NOT serve any /register
// endpoint.
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { loadServeEnv } from "./config.js";
import { connectStores } from "./connect-stores.js";
import { startGate } from "./gate.js";
import { registerTools } from "./tools.js";
import { VERSION } from "./version.js";

export async function runServe(): Promise<void> {
  const env = loadServeEnv();
  // stdout carries the MCP protocol — every human-facing line goes to stderr.
  const log = (line: string): void => void process.stderr.write(`${line}\n`);

  const gate = await startGate({
    reuseMaxMs: env.SECRETS_REUSE_MAX_MS,
    reuseMaxUses: env.SECRETS_REUSE_MAX_USES,
  });
  const stores = await connectStores(env, log);

  const mcp = new McpServer({ name: "secrets-webauthn-mcp", version: VERSION });
  registerTools({ mcp, gate, stores, timeoutMs: env.SECRETS_GATE_TIMEOUT_MS });

  await mcp.connect(new StdioServerTransport());
  log(
    `secrets-webauthn-mcp ready — Stores: ${stores.configured.join(", ")} — ` +
      `Approvals served on ${gate.origin}`,
  );
}
