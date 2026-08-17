// Optional Streamable HTTP transport for the MCP *session* itself (opt-in via
// `serve --http`; stdio remains the default). This lets more than one local MCP
// client share a single running server. Bound to 127.0.0.1 only, and every
// request's Origin/Host is checked before it reaches the transport — without
// that check, a malicious web page open in your browser could use DNS-rebinding
// to talk to this port and trigger Approval prompts (classic rebinding attack:
// fetch() from a page carries the page's Origin even when it targets 127.0.0.1).
// The Gate (WebAuthn) still runs on its own separate ephemeral localhost port
// exactly as in stdio mode — this file only changes how the MCP *protocol*
// connection is carried, never who can approve a secret.
import { randomUUID } from "node:crypto";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";
import { loadServeEnv } from "./config.js";
import { connectStores } from "./connect-stores.js";
import { startGate, type Gate } from "./gate.js";
import { isAllowedRequest } from "./http-guard.js";
import { readJsonBody, sendJson } from "./http-util.js";
import type { StoreRegistry } from "./store.js";
import { registerTools } from "./tools.js";
import { VERSION } from "./version.js";

export interface HttpAppContext {
  gate: Gate;
  stores: StoreRegistry;
  timeoutMs: number;
  waitForApprovalMs?: number;
  allowedHostPorts: readonly string[];
}

/** Build the request handler (gate/stores injected so it's testable without a real
 *  Store or hardware authenticator — see test/http_transport.test.ts). Not yet listening. */
export function createHttpApp(ctx: HttpAppContext): Server {
  const { gate, stores, timeoutMs, waitForApprovalMs, allowedHostPorts } = ctx;

  // One McpServer + one transport per MCP session, exactly as the SDK's own
  // reference server does — required so `elicitInput` (used by every tool call
  // via the Gate) has a live stream to send the request down and await the
  // client's response on.
  const transports = new Map<string, StreamableHTTPServerTransport>();

  async function handleMcp(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const sessionId = req.headers["mcp-session-id"];
    const sid = typeof sessionId === "string" ? sessionId : undefined;

    if (req.method === "POST") {
      const existing = sid ? transports.get(sid) : undefined;
      if (existing) {
        const body = await readJsonBody(req);
        await existing.handleRequest(req, res, body);
        return;
      }
      const body = await readJsonBody(req);
      if (sid === undefined && isInitializeRequest(body)) {
        const mcp = new McpServer({ name: "secrets-webauthn-mcp", version: VERSION });
        registerTools({ mcp, gate, stores, timeoutMs, waitForApprovalMs });
        const transport: StreamableHTTPServerTransport = new StreamableHTTPServerTransport({
          sessionIdGenerator: () => randomUUID(),
          onsessioninitialized: (newSid: string) => {
            transports.set(newSid, transport);
          },
        });
        transport.onclose = () => {
          if (transport.sessionId) transports.delete(transport.sessionId);
        };
        await mcp.connect(transport);
        await transport.handleRequest(req, res, body);
        return;
      }
      sendJson(res, 400, {
        jsonrpc: "2.0",
        error: { code: -32000, message: "Bad Request: no valid session ID and not an initialize request" },
        id: null,
      });
      return;
    }

    // GET (SSE stream) and DELETE (session termination) both require an existing session.
    const transport = sid ? transports.get(sid) : undefined;
    if (!transport) {
      sendJson(res, 400, { jsonrpc: "2.0", error: { code: -32000, message: "Invalid or missing session ID" }, id: null });
      return;
    }
    await transport.handleRequest(req, res);
  }

  return createServer((req, res) => {
    if (!isAllowedRequest(req.headers.host, req.headers.origin, allowedHostPorts)) {
      sendJson(res, 403, { error: "forbidden: unrecognized Host or Origin" });
      return;
    }
    if (new URL(req.url ?? "/", "http://localhost").pathname !== "/mcp") {
      sendJson(res, 404, { error: "not found" });
      return;
    }
    handleMcp(req, res).catch(() => {
      if (!res.headersSent) sendJson(res, 500, { error: "internal error" });
    });
  });
}

export async function runServeHttp(port: number): Promise<void> {
  const env = loadServeEnv();
  const log = (line: string): void => void process.stderr.write(`${line}\n`);

  const gate = await startGate({
    reuseMaxMs: env.SECRETS_REUSE_MAX_MS,
    reuseMaxUses: env.SECRETS_REUSE_MAX_USES,
  });
  const stores = await connectStores(env, log);
  const allowedHostPorts = [`127.0.0.1:${port}`, `localhost:${port}`];

  const httpServer = createHttpApp({
    gate,
    stores,
    timeoutMs: env.SECRETS_GATE_TIMEOUT_MS,
    waitForApprovalMs: env.SECRETS_WAIT_FOR_APPROVAL_MS,
    allowedHostPorts,
  });

  await new Promise<void>((resolve, reject) => {
    httpServer.once("error", reject);
    httpServer.listen(port, "127.0.0.1", () => resolve());
  });

  log(
    `secrets-webauthn-mcp (http) ready on http://127.0.0.1:${port}/mcp — ` +
      `Stores: ${stores.configured.join(", ")} — Approvals: open ${gate.origin} once and leave it open`,
  );
}
