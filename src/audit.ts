// Append-only JSONL audit trail. Records that a use was attempted/approved and
// against what — NEVER the secret value. Secret References are recorded as
// written, so the trail says which Store each value came out of.
import { appendFileSync, mkdirSync } from "node:fs";
import { AUDIT_FILE, STATE_DIR } from "./paths.js";

export interface AuditEntry {
  tool: "http_request" | "run_with_secret";
  secret_refs: string[];
  host?: string; // http_request
  argv0?: string; // run_with_secret
  verified: boolean;
}

export function appendAudit(entry: AuditEntry): void {
  mkdirSync(STATE_DIR, { recursive: true });
  const line = JSON.stringify({ ts: new Date().toISOString(), ...entry }) + "\n";
  appendFileSync(AUDIT_FILE, line, { mode: 0o600 });
}
