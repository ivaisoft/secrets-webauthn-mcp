// Pure-logic self-check — no network, no vault, no WebAuthn hardware. Asserts the
// load-bearing invariants: allowlist decisions, credential public-key round-trip,
// env-name resolution, and HTML escaping.
import { checkHostAllowed } from "./allowlist.js";
import { base64ToPublicKey, publicKeyToBase64 } from "./credentials.js";
import { resolveEnvName } from "./envname.js";
import { escapeHtml } from "./html.js";
import type { Allowlist } from "./schemas.js";

function assert(condition: boolean, message: string): void {
  if (!condition) throw new Error(`selfcheck failed: ${message}`);
}

export function runSelfcheck(): void {
  // 1. Allowlist host check: allow / deny / unknown.
  const allowlist: Allowlist = {
    "secret-a": ["api.example.com", "eu.example.com"],
    "secret-b": ["api.example.com"],
  };
  assert(
    checkHostAllowed(allowlist, ["secret-a"], "api.example.com").ok === true,
    "allow: host listed for the secret",
  );
  assert(
    checkHostAllowed(allowlist, ["secret-a", "secret-b"], "api.example.com").ok === true,
    "allow: host listed for every requested secret",
  );
  assert(
    checkHostAllowed(allowlist, ["secret-a"], "evil.example.com").ok === false,
    "deny: host not in the secret's list",
  );
  assert(
    checkHostAllowed(allowlist, ["secret-a", "secret-b"], "eu.example.com").ok === false,
    "deny: host allowed for one secret but not all",
  );
  assert(
    checkHostAllowed(allowlist, ["secret-unknown"], "api.example.com").ok === false,
    "unknown: secret with no allowlist entry denies",
  );

  // 2. Credential publicKey base64 <-> Uint8Array round-trip.
  const publicKey = new Uint8Array([0, 1, 2, 127, 128, 250, 255]);
  const roundTrip = base64ToPublicKey(publicKeyToBase64(publicKey));
  assert(
    roundTrip.length === publicKey.length && roundTrip.every((v, i) => v === publicKey[i]),
    "publicKey base64 round-trip preserves bytes",
  );

  // 3. Env-name resolution: default is the Bitwarden key name; override wins.
  assert(
    resolveEnvName({ secretId: "s1", keyName: "STRIPE_KEY" }) === "STRIPE_KEY",
    "env-name default is the key name",
  );
  assert(
    resolveEnvName({ secretId: "s1", keyName: "STRIPE_KEY", overrides: { s1: "SK" } }) === "SK",
    "env-name override wins",
  );
  assert(
    resolveEnvName({ secretId: "s1", keyName: "STRIPE_KEY", overrides: { s2: "OTHER" } }) ===
      "STRIPE_KEY",
    "env-name override for a different secret does not apply",
  );

  // 4. HTML escaping.
  assert(
    escapeHtml('<a href="x">&\'') === "&lt;a href=&quot;x&quot;&gt;&amp;&#39;",
    "html escaping covers &<>\"'",
  );

  process.stdout.write("selfcheck ok\n");
}
