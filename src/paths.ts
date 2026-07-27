// Filesystem locations for the on-disk state. Everything lives under
// ~/.config/bws-webauthn-mcp. No secret material is ever written here — only
// public keys, counters, the host allowlist, and the audit trail.
import { homedir } from "node:os";
import { join } from "node:path";

export const STATE_DIR = join(homedir(), ".config", "bws-webauthn-mcp");
export const CREDENTIALS_FILE = join(STATE_DIR, "credentials.json");
export const ALLOWLIST_FILE = join(STATE_DIR, "allowlist.json");
export const AUDIT_FILE = join(STATE_DIR, "audit.log");
