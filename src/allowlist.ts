// Per-secret host allowlist for the safe (http_request) path. A host is allowed
// only if it appears in the allowed set of EVERY requested secret. Unknown
// secrets (no entry) deny. This is enforced BEFORE any secret is touched.
//
// Keys are Secret References exactly as written in a tool call — `bws:9f3c-…`,
// `ssm:/prod/app/STRIPE_KEY` — so an entry grants hosts to one secret in one
// Store, never to a bare id that two Stores might both claim.
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { ALLOWLIST_FILE, STATE_DIR } from "./paths.js";
import { AllowlistSchema, type Allowlist } from "./schemas.js";

/** Read + validate the allowlist. Returns {} (deny-all) when the file is absent. */
export function loadAllowlist(): Allowlist {
  if (!existsSync(ALLOWLIST_FILE)) return {};
  const raw: unknown = JSON.parse(readFileSync(ALLOWLIST_FILE, "utf8"));
  return AllowlistSchema.parse(raw);
}

/**
 * Add one host to one Secret Reference's allowed set, and return the result.
 *
 * Only ever called after a WebAuthn assertion has been verified (gate.ts): this
 * widens what the agent may do, so it is a decision the human makes with the
 * sensor, exactly like using a secret — never a side effect of approving a use.
 *
 * Written via a temp file + rename so a crash mid-write cannot leave a
 * truncated allowlist, which would silently deny every secret rather than fail
 * loudly.
 */
export function addAllowedHost(ref: string, host: string): Allowlist {
  const current = loadAllowlist();
  const hosts = current[ref] ?? [];
  const next: Allowlist = hosts.includes(host)
    ? current
    : { ...current, [ref]: [...hosts, host] };

  mkdirSync(STATE_DIR, { recursive: true });
  const tmp = `${ALLOWLIST_FILE}.tmp`;
  writeFileSync(tmp, `${JSON.stringify(next, null, 2)}\n`, { mode: 0o600 });
  renameSync(tmp, ALLOWLIST_FILE);
  return next;
}

export interface HostCheckResult {
  ok: boolean;
  reason?: string;
  /** The reference that denied, when one did — so the caller can offer to grant
   *  this host for exactly that reference rather than guessing which to widen. */
  ref?: string;
}

/**
 * Pure allowlist decision: `host` must be listed for every one of `secretRefs`.
 * - allow: host is in every secret's list.
 * - deny:  host is listed for some secrets but not this one.
 * - unknown: a secret has no allowlist entry at all — treated as deny.
 */
export function checkHostAllowed(
  allowlist: Allowlist,
  secretRefs: readonly string[],
  host: string,
): HostCheckResult {
  for (const ref of secretRefs) {
    const hosts = allowlist[ref];
    if (hosts === undefined) {
      return { ok: false, reason: `no allowlist entry for secret ${ref}`, ref };
    }
    if (!hosts.includes(host)) {
      return { ok: false, reason: `host ${host} not allowed for secret ${ref}`, ref };
    }
  }
  return { ok: true };
}
