// Serve mode: the MCP stdio server. Logs into Bitwarden, starts the localhost
// Gate, exposes exactly the two tools. Does NOT serve any /register endpoint.
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { connectBws } from "./bws.js";
import { loadServeEnv } from "./config.js";
import { startGate } from "./gate.js";
import { registerTools } from "./tools.js";

export async function runServe(): Promise<void> {
  const env = loadServeEnv();
  const gate = await startGate();
  const bws = await connectBws(env);

  const mcp = new McpServer({ name: "bws-webauthn-mcp", version: "2.0.0" });
  registerTools({ mcp, gate, bws, timeoutMs: env.BWS_GATE_TIMEOUT_MS });

  await mcp.connect(new StdioServerTransport());
  process.stderr.write(`bws-webauthn-mcp ready — Approvals served on ${gate.origin}\n`);
}
