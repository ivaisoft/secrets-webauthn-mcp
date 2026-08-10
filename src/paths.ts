// Filesystem locations for the on-disk state. No secret material is ever
// written here — only public keys, counters, the host allowlist, and the audit
// trail.
//
// The package was previously published as bws-webauthn-mcp and kept this state
// under ~/.config/bws-webauthn-mcp. That directory holds registered WebAuthn
// credentials, so moving to the new name blindly would orphan them and force
// re-registering every authenticator. STATE_DIR is therefore resolved once, at
// import: the new directory if it exists, else the old one if it does, else the
// new one. Reads and writes always land in the same place, so the audit trail
// never splits across two locations, and nothing is moved out from under you.
import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

const CURRENT_DIR = join(homedir(), ".config", "secrets-webauthn-mcp");
const LEGACY_DIR = join(homedir(), ".config", "bws-webauthn-mcp");

function resolveStateDir(): string {
  if (existsSync(CURRENT_DIR)) return CURRENT_DIR;
  if (existsSync(LEGACY_DIR)) return LEGACY_DIR;
  return CURRENT_DIR;
}

export const STATE_DIR = resolveStateDir();
export const CREDENTIALS_FILE = join(STATE_DIR, "credentials.json");
export const ALLOWLIST_FILE = join(STATE_DIR, "allowlist.json");
export const AUDIT_FILE = join(STATE_DIR, "audit.log");
