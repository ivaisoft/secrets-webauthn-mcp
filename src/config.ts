// Typed parse of the process environment. Fails loudly with a readable message
// so a misconfigured launch never limps along with `undefined` secrets.
import { RegisterEnvSchema, ServeEnvSchema, type RegisterEnv, type ServeEnv } from "./schemas.js";

function formatIssue(err: unknown): string {
  if (err && typeof err === "object" && "issues" in err) {
    const issues = (err as { issues: { path: (string | number)[]; message: string }[] }).issues;
    return issues.map((i) => `${i.path.join(".") || "(env)"}: ${i.message}`).join("; ");
  }
  return String(err);
}

export function loadServeEnv(): ServeEnv {
  const parsed = ServeEnvSchema.safeParse(process.env);
  if (!parsed.success) throw new Error(`Invalid environment: ${formatIssue(parsed.error)}`);
  return parsed.data;
}

export function loadRegisterEnv(): RegisterEnv {
  const parsed = RegisterEnvSchema.safeParse(process.env);
  if (!parsed.success) throw new Error(`Invalid environment: ${formatIssue(parsed.error)}`);
  return parsed.data;
}
