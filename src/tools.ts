// The two gated tools. Both require a fresh Approval (no cache). Secret values
// are fetched only AFTER a verified Approval, injected into a header or a
// child env, and never returned to the agent, placed in argv, or written to
// any log. Both declare an outputSchema (ADR 0007) so a client can detect
// `structuredContent.status === "approval_required"` and act on `approve_url`
// programmatically, instead of only having free text to parse.
//
// Secrets are addressed by Secret Reference (`<store>:<id>[#subkey]`), so one
// Approval can authorize a set spanning several Stores — and the human at the
// Gate reads which Store each value is about to come out of.
import { spawn } from "node:child_process";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { appendAudit } from "./audit.js";
import { checkHostAllowed, loadAllowlist } from "./allowlist.js";
import { resolveEnvName } from "./envname.js";
import type { Gate } from "./gate.js";
import { requestKey } from "./request-key.js";
import { lastPathSegment, parseSecretRefs, type SecretRef } from "./secret-ref.js";
import { formatArgv } from "./shell-format.js";
import type { SecretHandle, StoreRegistry } from "./store.js";
import {
  EnvNameSchema,
  HttpRequestArgsSchema,
  HttpRequestOutputSchema,
  RunWithSecretArgsSchema,
  RunWithSecretOutputSchema,
  STORE_CREDENTIAL_ENV_VARS,
  type HttpRequestArgs,
  type RunWithSecretArgs,
} from "./schemas.js";

interface ToolContext {
  mcp: McpServer;
  gate: Gate;
  stores: StoreRegistry;
  timeoutMs: number;
}

type ToolResult = {
  content: { type: "text"; text: string }[];
  structuredContent: Record<string, unknown>;
  isError?: boolean;
};

/** The prose is identical for both tools; only `message` (what will happen)
 *  and `url` (this exact request's Approval link) differ per call. */
function approvalRequired(message: string, url: string): ToolResult {
  return {
    content: [
      {
        type: "text",
        text:
          `Physical approval required.\n\n${message}\n\n` +
          `Open this URL and approve with Touch ID / passkey, then re-run this exact tool call:\n${url}`,
      },
    ],
    structuredContent: { status: "approval_required", approve_url: url },
    isError: true,
  };
}

function errorResult(reason: string): ToolResult {
  return {
    content: [{ type: "text", text: reason }],
    structuredContent: { status: "error", reason },
    isError: true,
  };
}

function httpOk(httpStatus: number, body: string): ToolResult {
  return {
    content: [{ type: "text", text: `HTTP ${httpStatus}\n\n${body}` }],
    structuredContent: { status: "ok", http_status: httpStatus, body },
  };
}

function runOk(exitCode: number | null, stdout: string, stderr: string): ToolResult {
  return {
    content: [
      { type: "text", text: `[exit ${exitCode ?? "null"}]\n\n--- stdout ---\n${stdout}\n--- stderr ---\n${stderr}` },
    ],
    structuredContent: { status: "ok", exit_code: exitCode, stdout, stderr },
  };
}

/** Header names must be unambiguous: one string only when there is exactly one secret. */
function resolveHeaderNames(header: string | string[], count: number): string[] {
  if (Array.isArray(header)) {
    if (header.length !== count) {
      throw new Error(`header array length ${header.length} must match secret_refs length ${count}`);
    }
    return header;
  }
  if (count > 1) {
    throw new Error("multiple secret_refs require a `header` array (one header name per secret)");
  }
  return [header];
}

/** A single scheme string applies to every secret; an array must match. */
function resolveSchemes(scheme: string | string[], count: number): string[] {
  if (Array.isArray(scheme)) {
    if (scheme.length !== count) {
      throw new Error(`scheme array length ${scheme.length} must match secret_refs length ${count}`);
    }
    return scheme;
  }
  return Array.from({ length: count }, () => scheme);
}

const errorMessage = (e: unknown): string => (e instanceof Error ? e.message : String(e));

export function registerTools(ctx: ToolContext): void {
  const { mcp, gate, stores, timeoutMs } = ctx;

  mcp.registerTool(
    "list_secrets",
    {
      title: "List secret references and names (no values, no Approval required)",
      description:
        "List every secret reference and key name this server can enumerate. Never returns a " +
        "value — this is discovery metadata only, so unlike http_request/run_with_secret it does " +
        "NOT require a physical WebAuthn Approval. Only Bitwarden is enumerable: AWS SSM " +
        "Parameter Store and Secrets Manager references are self-describing names you already " +
        "know (e.g. ssm:/prod/app/STRIPE_KEY), and listing them would need an account-wide IAM " +
        "grant. Use a returned reference with http_request or run_with_secret.",
      inputSchema: {},
    },
    async () => {
      const secrets = await stores.list();
      // Explicit map, not a bare stringify of whatever the registry returns:
      // this tool's contract is {id, key} only, enforced here too — not just
      // trusted from the interface — so a future Store that adds fields (or a
      // bug in one) can't silently widen what this tool exposes.
      const safe = secrets.map((s) => ({ id: s.id, key: s.key }));
      return { content: [{ type: "text" as const, text: JSON.stringify(safe, null, 2) }] };
    },
  );

  mcp.registerTool(
    "http_request",
    {
      title: "Call an HTTP endpoint with a secret injected (you never see the value)",
      description:
        "Make an HTTP request with one or more secrets injected into request headers. Secrets are " +
        "addressed as <store>:<id>[#subkey] — e.g. bws:9f3c-…, ssm:/prod/app/STRIPE_KEY, " +
        "secretsmanager:prod/db#password. The secret value is never revealed — only the response " +
        "is returned. Each requested secret's target host must be in its allowlist, and every call " +
        "requires a fresh physical WebAuthn Approval.",
      inputSchema: HttpRequestArgsSchema,
      outputSchema: HttpRequestOutputSchema,
    },
    async (args: HttpRequestArgs): Promise<ToolResult> => {
      // A malformed reference is a caller bug: reject before Approval rather
      // than spending a physical touch to discover a typo.
      let refs: SecretRef[];
      try {
        refs = parseSecretRefs(args.secret_refs);
      } catch (e) {
        return errorResult(errorMessage(e));
      }
      const raws = refs.map((r) => r.raw);

      let host: string;
      try {
        host = new URL(args.url).host;
      } catch {
        return errorResult("invalid url");
      }

      // Allowlist is enforced BEFORE any secret is touched.
      const check = checkHostAllowed(loadAllowlist(), raws, host);
      if (!check.ok) {
        appendAudit({ tool: "http_request", secret_refs: raws, host, verified: false });
        return errorResult(`Blocked by allowlist: ${check.reason}`);
      }

      let headerNames: string[];
      let schemes: string[];
      try {
        headerNames = resolveHeaderNames(args.header, refs.length);
        schemes = resolveSchemes(args.scheme, refs.length);
      } catch (e) {
        return errorResult(errorMessage(e));
      }

      const message =
        `http_request wants to use secret(s) [${raws.join(", ")}] ` +
        `to call host "${host}" (${args.method} ${args.url}).`;
      const key = requestKey("http_request", args);
      if (!gate.checkApproval(key, message, timeoutMs)) {
        appendAudit({ tool: "http_request", secret_refs: raws, host, verified: false });
        return approvalRequired(message, `${gate.origin}/approve?rid=${key}`);
      }

      let handles: SecretHandle[];
      try {
        handles = await Promise.all(refs.map((ref) => stores.get(ref)));
      } catch (e) {
        appendAudit({ tool: "http_request", secret_refs: raws, host, verified: true });
        return errorResult(errorMessage(e));
      }

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
        appendAudit({ tool: "http_request", secret_refs: raws, host, verified: true });
        return errorResult(
          `Refusing to follow a redirect from ${host}: following it could forward the ` +
            `injected secret to a host outside the allowlist. Re-issue http_request against ` +
            `the final URL if that host is allowlisted for these secrets.`,
        );
      }
      const text = await response.text();
      appendAudit({ tool: "http_request", secret_refs: raws, host, verified: true });
      return httpOk(response.status, text);
    },
  );

  mcp.registerTool(
    "run_with_secret",
    {
      title: "Run a command with a secret injected as an environment variable",
      description:
        "Spawn a command (argv array, NO shell) with one or more secrets injected as environment " +
        "variables. Secrets are addressed as <store>:<id>[#subkey] — e.g. bws:9f3c-…, " +
        "ssm:/prod/app/STRIPE_KEY, secretsmanager:prod/db#password. Default env var name is the " +
        "subkey, the Bitwarden key name, or the last path segment; override per secret with " +
        "env_overrides. The secret never appears in argv or logs. Returns the child's stdout, " +
        "stderr, and exit code. Every run requires a fresh physical WebAuthn Approval.",
      inputSchema: RunWithSecretArgsSchema,
      outputSchema: RunWithSecretOutputSchema,
    },
    async (args: RunWithSecretArgs): Promise<ToolResult> => {
      const argv0 = args.argv[0]!;

      let refs: SecretRef[];
      try {
        refs = parseSecretRefs(args.secret_refs);
      } catch (e) {
        return errorResult(errorMessage(e));
      }
      const raws = refs.map((r) => r.raw);

      // env_overrides is validated by zod as Record<string, EnvNameSchema> alone —
      // zod can't cross-check its keys against the sibling secret_refs array. Without
      // this, a typo'd key is silently a no-op: not shown in the Approval message,
      // not applied, no error. Caught here, before Approval, since it's a caller
      // bug, not something worth spending a physical touch to discover.
      if (args.env_overrides) {
        const unknown = Object.keys(args.env_overrides).filter((ref) => !raws.includes(ref));
        if (unknown.length > 0) {
          return errorResult(
            `env_overrides references secret_ref(s) not in secret_refs: ${unknown.join(", ")}`,
          );
        }
      }

      // Show the human EXACTLY what each secret is injected as, including its real
      // name — via the registry's ungated {id,key} listing (ADR 0005). This never
      // fetches a value, so it's safe to call before Approval. Only Bitwarden
      // enumerates (ADR 0010); for AWS the reference already IS the name, so the
      // default env var name is derived from it rather than looked up.
      const known = await stores.list().catch(() => []);
      const keyByRef = new Map(known.map((s) => [s.id, s.key]));
      const envDisplay = refs
        .map((ref) => {
          const storeKeyName = keyByRef.get(ref.raw) ?? (ref.store === "bws" ? undefined : lastPathSegment(ref.id));
          const label =
            ref.store === "bws" && !keyByRef.has(ref.raw)
              ? `${ref.raw} (not found via list_secrets)`
              : keyByRef.has(ref.raw)
                ? `${ref.raw} (${keyByRef.get(ref.raw)})`
                : ref.raw;
          const envName =
            args.env_overrides?.[ref.raw] ?? ref.subkey ?? storeKeyName ?? "<its Bitwarden key name>";
          return `${label} → $${envName}`;
        })
        .join(", ");
      const message =
        `run_with_secret wants to run (no shell):\n  ${formatArgv(args.argv)}\n` +
        `Injecting as env vars: ${envDisplay}`;
      const key = requestKey("run_with_secret", args);
      if (!gate.checkApproval(key, message, timeoutMs)) {
        appendAudit({ tool: "run_with_secret", secret_refs: raws, argv0, verified: false });
        return approvalRequired(message, `${gate.origin}/approve?rid=${key}`);
      }

      let handles: SecretHandle[];
      try {
        handles = await Promise.all(refs.map((ref) => stores.get(ref)));
      } catch (e) {
        appendAudit({ tool: "run_with_secret", secret_refs: raws, argv0, verified: true });
        return errorResult(errorMessage(e));
      }

      // Child env: inherit PATH etc. but strip every Store credential, so the
      // child can never reach a Store directly and skip the Gate. Missing one
      // here would hand an arbitrary command the keys to a whole Store.
      const stripped = new Set<string>(STORE_CREDENTIAL_ENV_VARS);
      const childEnv: Record<string, string> = {};
      for (const [k, v] of Object.entries(process.env)) {
        if (v !== undefined && !stripped.has(k)) childEnv[k] = v;
      }

      const used = new Set<string>();
      for (let i = 0; i < handles.length; i++) {
        const ref = refs[i]!;
        // handles[i].key is already the subkey when the reference selected one,
        // so this covers both cases without a second branch.
        const envName = resolveEnvName({
          ref: ref.raw,
          keyName: handles[i]!.key,
          overrides: args.env_overrides,
        });
        if (!EnvNameSchema.safeParse(envName).success) {
          return errorResult(
            `env var name "${envName}" for secret ${ref.raw} is invalid; pass env_overrides to set a valid name`,
          );
        }
        if (used.has(envName)) {
          return errorResult(`two secrets resolve to the same env var name "${envName}"`);
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

      appendAudit({ tool: "run_with_secret", secret_refs: raws, argv0, verified: true });
      return runOk(result.code, result.stdout, result.stderr);
    },
  );
}
