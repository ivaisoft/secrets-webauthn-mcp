// Per-secret host allowlist for the safe (http_request) path. A host is allowed
// only if it appears in the allowed set of EVERY requested secret. Unknown
// secrets (no entry) deny. This is enforced BEFORE any secret is touched.
import { existsSync, readFileSync } from "node:fs";
import { ALLOWLIST_FILE } from "./paths.js";
import { AllowlistSchema, type Allowlist } from "./schemas.js";

/** Read + validate the allowlist. Returns {} (deny-all) when the file is absent. */
export function loadAllowlist(): Allowlist {
  if (!existsSync(ALLOWLIST_FILE)) return {};
  const raw: unknown = JSON.parse(readFileSync(ALLOWLIST_FILE, "utf8"));
  return AllowlistSchema.parse(raw);
}

export interface HostCheckResult {
  ok: boolean;
  reason?: string;
}

/**
 * Pure allowlist decision: `host` must be listed for every one of `secretIds`.
 * - allow: host is in every secret's list.
 * - deny:  host is listed for some secrets but not this one.
 * - unknown: a secret has no allowlist entry at all — treated as deny.
 */
export function checkHostAllowed(
  allowlist: Allowlist,
  secretIds: readonly string[],
  host: string,
): HostCheckResult {
  for (const id of secretIds) {
    const hosts = allowlist[id];
    if (hosts === undefined) {
      return { ok: false, reason: `no allowlist entry for secret ${id}` };
    }
    if (!hosts.includes(host)) {
      return { ok: false, reason: `host ${host} not allowed for secret ${id}` };
    }
  }
  return { ok: true };
}
