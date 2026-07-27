// The two tools. Both require a fresh Approval (no cache). Secret values are
// fetched only AFTER a verified Approval, injected into a header or a child env,
// and never returned to the agent, placed in argv, or written to any log.
import { spawn } from "node:child_process";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { appendAudit } from "./audit.js";
import { checkHostAllowed, loadAllowlist } from "./allowlist.js";
import type { BwsGateway, SecretHandle } from "./bws.js";
import { resolveEnvName } from "./envname.js";
import type { Gate } from "./gate.js";
import {
  EnvNameSchema,
  HttpRequestArgsSchema,
  RunWithSecretArgsSchema,
  type HttpRequestArgs,
  type RunWithSecretArgs,
} from "./schemas.js";

interface ToolContext {
  mcp: McpServer;
  gate: Gate;
  bws: BwsGateway;
  timeoutMs: number;
}

type ToolResult = {
  content: { type: "text"; text: string }[];
  isError?: boolean;
};

const ok = (text: string): ToolResult => ({ content: [{ type: "text", text }] });
const fail = (text: string): ToolResult => ({ content: [{ type: "text", text }], isError: true });

/** Header names must be unambiguous: one string only when there is exactly one secret. */
function resolveHeaderNames(header: string | string[], count: number): string[] {
  if (Array.isArray(header)) {
    if (header.length !== count) {
      throw new Error(`header array length ${header.length} must match secret_ids length ${count}`);
    }
    return header;
  }
  if (count > 1) {
    throw new Error("multiple secret_ids require a `header` array (one header name per secret)");
  }
  return [header];
}

/** A single scheme string applies to every secret; an array must match. */
function resolveSchemes(scheme: string | string[], count: number): string[] {
  if (Array.isArray(scheme)) {
    if (scheme.length !== count) {
      throw new Error(`scheme array length ${scheme.length} must match secret_ids length ${count}`);
    }
    return scheme;
  }
  return Array.from({ length: count }, () => scheme);
}

export function registerTools(ctx: ToolContext): void {
  const { mcp, gate, bws, timeoutMs } = ctx;
  const mcpLow = mcp.server;

  mcp.registerTool(
    "http_request",
    {
      title: "Call an HTTP endpoint with a Bitwarden secret injected (you never see the value)",
      description:
        "Make an HTTP request with one or more Bitwarden secrets injected into request headers. " +
        "The secret value is never revealed — only the response is returned. Each requested secret's " +
        "target host must be in its allowlist, and every call requires a fresh physical WebAuthn Approval.",
      inputSchema: HttpRequestArgsSchema,
    },
    async (args: HttpRequestArgs): Promise<ToolResult> => {
      let host: string;
      try {
        host = new URL(args.url).host;
      } catch {
        return fail("invalid url");
      }

      // Allowlist is enforced BEFORE any secret is touched.
      const check = checkHostAllowed(loadAllowlist(), args.secret_ids, host);
      if (!check.ok) {
        appendAudit({ tool: "http_request", secret_ids: args.secret_ids, host, verified: false });
        return fail(`Blocked by allowlist: ${check.reason}`);
      }

      let headerNames: string[];
      let schemes: string[];
      try {
        headerNames = resolveHeaderNames(args.header, args.secret_ids.length);
        schemes = resolveSchemes(args.scheme, args.secret_ids.length);
      } catch (e) {
        return fail(e instanceof Error ? e.message : String(e));
      }

      const message =
        `http_request wants to use secret(s) [${args.secret_ids.join(", ")}] ` +
        `to call host "${host}" (${args.method} ${args.url}).`;
      await gate.requireApproval(mcpLow, message, timeoutMs);

      const handles = await Promise.all(args.secret_ids.map((id) => bws.getSecret(id)));
      const headers: Record<string, string> = {};
      for (let i = 0; i < handles.length; i++) {
        headers[headerNames[i]!] = `${schemes[i]!}${handles[i]!.value}`;
      }

      // redirect:"manual" — a 3xx to an off-allowlist host would otherwise cause
      // Node/undici to re-send our injected secret header to that unvetted host
      // (only Authorization is stripped cross-origin; custom headers are forwarded).
      // The allowlist is checked against args.url only, so we must never follow.
      const response = await fetch(args.url, {
        method: args.method,
        headers,
        redirect: "manual",
        ...(args.body !== undefined ? { body: args.body } : {}),
      });
      if (response.type === "opaqueredirect" || (response.status >= 300 && response.status < 400)) {
        appendAudit({ tool: "http_request", secret_ids: args.secret_ids, host, verified: true });
        return fail(
          `Refusing to follow a redirect from ${host}: following it could forward the ` +
            `injected secret to a host outside the allowlist. Re-issue http_request against ` +
            `the final URL if that host is allowlisted for these secrets.`,
        );
      }
      const text = await response.text();
      appendAudit({ tool: "http_request", secret_ids: args.secret_ids, host, verified: true });
      return ok(`HTTP ${response.status}\n\n${text}`);
    },
  );

  mcp.registerTool(
    "run_with_secret",
    {
      title: "Run a command with a Bitwarden secret injected as an environment variable",
      description:
        "Spawn a command (argv array, NO shell) with one or more Bitwarden secrets injected as " +
        "environment variables. Default env var name is the secret's Bitwarden key name; override per " +
        "secret with env_overrides. The secret never appears in argv or logs. Returns the child's " +
        "stdout, stderr, and exit code. Every run requires a fresh physical WebAuthn Approval.",
      inputSchema: RunWithSecretArgsSchema,
    },
    async (args: RunWithSecretArgs): Promise<ToolResult> => {
      const argv0 = args.argv[0]!;
      // Show the human EXACTLY what each secret is injected as (SPEC: the Gate prompt
      // shows argv + injected env-var names + secret ids). Secrets are not fetched
      // before approval, so a default (no override) is shown as its Bitwarden key name.
      const envDisplay = args.secret_ids
        .map((id) => {
          const override = args.env_overrides?.[id];
          return override ? `${id} → $${override}` : `${id} → $<its Bitwarden key name>`;
        })
        .join(", ");
      const message =
        `run_with_secret wants to inject secret(s) as env vars [${envDisplay}] ` +
        `and run (no shell): ${args.argv.join(" ")}`;
      await gate.requireApproval(mcpLow, message, timeoutMs);

      const handles: SecretHandle[] = await Promise.all(
        args.secret_ids.map((id) => bws.getSecret(id)),
      );

      // Child env: inherit PATH etc. but strip the vault token so it can never leak downstream.
      const childEnv: Record<string, string> = {};
      for (const [k, v] of Object.entries(process.env)) {
        if (v !== undefined && k !== "BWS_ACCESS_TOKEN") childEnv[k] = v;
      }

      const used = new Set<string>();
      for (let i = 0; i < handles.length; i++) {
        const secretId = args.secret_ids[i]!;
        const envName = resolveEnvName({
          secretId,
          keyName: handles[i]!.key,
          overrides: args.env_overrides,
        });
        if (!EnvNameSchema.safeParse(envName).success) {
          return fail(
            `env var name "${envName}" for secret ${secretId} is invalid; pass env_overrides to set a valid name`,
          );
        }
        if (used.has(envName)) {
          return fail(`two secrets resolve to the same env var name "${envName}"`);
        }
        used.add(envName);
        childEnv[envName] = handles[i]!.value;
      }

      const result = await new Promise<{ stdout: string; stderr: string; code: number | null }>(
        (resolve, reject) => {
          const child = spawn(argv0, args.argv.slice(1), { env: childEnv, shell: false });
          let stdout = "";
          let stderr = "";
          child.stdout.on("data", (d: Buffer) => (stdout += d.toString()));
          child.stderr.on("data", (d: Buffer) => (stderr += d.toString()));
          child.on("error", (err) => reject(err));
          child.on("close", (code) => resolve({ stdout, stderr, code }));
        },
      ).catch((err: unknown) => {
        // Report only the argv0 and error code — never the env we built.
        const code = err && typeof err === "object" && "code" in err ? String(err.code) : "spawn error";
        return { stdout: "", stderr: `failed to run "${argv0}": ${code}`, code: 127 as number | null };
      });

      appendAudit({ tool: "run_with_secret", secret_ids: args.secret_ids, argv0, verified: true });
      return ok(`[exit ${result.code ?? "null"}]\n\n--- stdout ---\n${result.stdout}\n--- stderr ---\n${result.stderr}`);
    },
  );
}
