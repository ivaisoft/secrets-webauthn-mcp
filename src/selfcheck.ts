// Pure-logic self-check — no network, no vault, no WebAuthn hardware. Asserts the
// load-bearing invariants: allowlist decisions, credential public-key round-trip,
// env-name resolution, and HTML escaping.
import { checkHostAllowed } from "./allowlist.js";
import { base64ToPublicKey, publicKeyToBase64 } from "./credentials.js";
import { resolveEnvName } from "./envname.js";
import { escapeHtml } from "./html.js";
import { isAllowedRequest } from "./http-guard.js";
import { requestKey } from "./request-key.js";
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

  // 5. HTTP transport Host/Origin guard (DNS-rebinding defense for `serve --http`).
  const ports = ["127.0.0.1:8787", "localhost:8787"];
  assert(
    isAllowedRequest("127.0.0.1:8787", undefined, ports) === true,
    "allow: known host, no Origin (typical non-browser MCP client)",
  );
  assert(
    isAllowedRequest("127.0.0.1:8787", "http://127.0.0.1:8787", ports) === true,
    "allow: known host with matching Origin",
  );
  assert(
    isAllowedRequest("127.0.0.1:8787", "http://evil.example.com", ports) === false,
    "deny: matching host but a foreign Origin (the rebinding attack itself)",
  );
  assert(
    isAllowedRequest("evil.example.com", undefined, ports) === false,
    "deny: unrecognized Host even with no Origin",
  );
  assert(isAllowedRequest(undefined, undefined, ports) === false, "deny: missing Host header");

  // 6. Request-key determinism (the Gate's re-check-without-elicitation mechanism).
  const argsA = { secret_ids: ["s1"], url: "https://api.example.com/x", method: "GET" };
  const argsAReordered = { method: "GET", url: "https://api.example.com/x", secret_ids: ["s1"] };
  const argsB = { secret_ids: ["s1"], url: "https://api.example.com/y", method: "GET" };
  assert(
    requestKey("http_request", argsA) === requestKey("http_request", argsAReordered),
    "same args, different key order -> same request key",
  );
  assert(
    requestKey("http_request", argsA) !== requestKey("http_request", argsB),
    "different args -> different request key",
  );
  assert(
    requestKey("http_request", argsA) !== requestKey("run_with_secret", argsA),
    "same args, different tool -> different request key",
  );

  process.stdout.write("selfcheck ok\n");
}
