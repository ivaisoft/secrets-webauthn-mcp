// Pure-logic self-check — no network, no vault, no WebAuthn hardware. Asserts the
// load-bearing invariants: allowlist decisions, credential public-key round-trip,
// env-name resolution, and HTML escaping.
import { checkHostAllowed } from "./allowlist.js";
import { base64ToPublicKey, publicKeyToBase64 } from "./credentials.js";
import { resolveEnvName } from "./envname.js";
import { decideVerified } from "./gate.js";
import { escapeHtml } from "./html.js";
import { isAllowedRequest } from "./http-guard.js";
import { requestKey } from "./request-key.js";
import { lastPathSegment, parseSecretRef } from "./secret-ref.js";
import { formatArgv } from "./shell-format.js";
import { AwsEnvSchema, type Allowlist } from "./schemas.js";

function assert(condition: boolean, message: string): void {
  if (!condition) throw new Error(`selfcheck failed: ${message}`);
}

export function runSelfcheck(): void {
  // 1. Allowlist host check: allow / deny / unknown.
  const allowlist: Allowlist = {
    "bws:secret-a": ["api.example.com", "eu.example.com"],
    "ssm:/prod/secret-b": ["api.example.com"],
  };
  assert(
    checkHostAllowed(allowlist, ["bws:secret-a"], "api.example.com").ok === true,
    "allow: host listed for the secret",
  );
  assert(
    checkHostAllowed(allowlist, ["bws:secret-a", "ssm:/prod/secret-b"], "api.example.com").ok === true,
    "allow: host listed for every requested secret",
  );
  assert(
    checkHostAllowed(allowlist, ["bws:secret-a"], "evil.example.com").ok === false,
    "deny: host not in the secret's list",
  );
  assert(
    checkHostAllowed(allowlist, ["bws:secret-a", "ssm:/prod/secret-b"], "eu.example.com").ok === false,
    "deny: host allowed for one secret but not all",
  );
  assert(
    checkHostAllowed(allowlist, ["bws:secret-unknown"], "api.example.com").ok === false,
    "unknown: secret with no allowlist entry denies",
  );

  // 2. Credential publicKey base64 <-> Uint8Array round-trip.
  const publicKey = new Uint8Array([0, 1, 2, 127, 128, 250, 255]);
  const roundTrip = base64ToPublicKey(publicKeyToBase64(publicKey));
  assert(
    roundTrip.length === publicKey.length && roundTrip.every((v, i) => v === publicKey[i]),
    "publicKey base64 round-trip preserves bytes",
  );

  // 3. Env-name resolution: default is the Store's key name; override wins.
  assert(
    resolveEnvName({ ref: "bws:s1", keyName: "STRIPE_KEY" }) === "STRIPE_KEY",
    "env-name default is the key name",
  );
  assert(
    resolveEnvName({ ref: "bws:s1", keyName: "STRIPE_KEY", overrides: { "bws:s1": "SK" } }) === "SK",
    "env-name override wins",
  );
  assert(
    resolveEnvName({ ref: "bws:s1", keyName: "STRIPE_KEY", overrides: { "bws:s2": "OTHER" } }) ===
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
  const argsA = { secret_refs: ["bws:s1"], url: "https://api.example.com/x", method: "GET" };
  const argsAReordered = { method: "GET", url: "https://api.example.com/x", secret_refs: ["bws:s1"] };
  const argsB = { secret_refs: ["bws:s1"], url: "https://api.example.com/y", method: "GET" };
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

  // 7. Argv display formatting: plain args stay bare, anything ambiguous is
  // quoted so the boundaries a human reviews match the real argv boundaries
  // (run_with_secret always execs argv directly — this is display only).
  assert(
    formatArgv(["node", "-e", "console.log(1)"]) === "node -e 'console.log(1)'",
    "shell metacharacters get quoted",
  );
  assert(
    formatArgv(["curl", "https://example.com/a b"]) === "curl 'https://example.com/a b'",
    "an argument containing a space is quoted, not silently space-joined",
  );
  assert(
    formatArgv(["echo", "it's here"]) === "echo 'it'\\''s here'",
    "an embedded single quote is escaped correctly",
  );
  assert(formatArgv(["node", "-v"]) === "node -v", "plain args are left unquoted");

  // 8. Secret Reference grammar: `<store>:<id>[#subkey]`, prefix mandatory.
  const bwsRef = parseSecretRef("bws:9f3c-4e2a");
  assert(bwsRef.store === "bws" && bwsRef.id === "9f3c-4e2a", "bws reference parses");
  assert(bwsRef.subkey === undefined, "no '#' means no subkey");

  const ssmRef = parseSecretRef("ssm:/prod/app/STRIPE_KEY");
  assert(ssmRef.store === "ssm" && ssmRef.id === "/prod/app/STRIPE_KEY", "ssm path keeps its leading slash");

  const smRef = parseSecretRef("secretsmanager:prod/db#password");
  assert(smRef.store === "secretsmanager" && smRef.id === "prod/db", "id stops at the '#'");
  assert(smRef.subkey === "password", "subkey is read after the '#'");

  // A Secrets Manager id may be a full ARN, which contains colons: only the
  // FIRST colon separates the store, so the rest must survive intact.
  const arn = "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/db-AbCdEf";
  assert(parseSecretRef(`secretsmanager:${arn}`).id === arn, "an ARN id round-trips unchanged");

  const rejects = (raw: string, why: string): void => {
    let threw = false;
    try {
      parseSecretRef(raw);
    } catch {
      threw = true;
    }
    assert(threw, why);
  };
  // The load-bearing one: an unprefixed id is refused, never assumed to be
  // Bitwarden, so the human at the Gate always reads which Store is involved.
  rejects("9f3c-4e2a", "an unprefixed id is rejected");
  rejects("vault:9f3c", "an unknown store is rejected");
  rejects("bws:", "an empty id is rejected");
  rejects("secretsmanager:prod/db#", "an empty subkey is rejected");

  assert(lastPathSegment("/prod/app/STRIPE_KEY") === "STRIPE_KEY", "default env name is the last path segment");
  assert(lastPathSegment("FLAT_NAME") === "FLAT_NAME", "a non-hierarchical name is its own segment");

  // 9. Reuse windows (ADR 0011): bounded by time AND by remaining runs, and
  // running out of either ends the grant. This is the rule that keeps a window
  // from being a blank cheque, so it is asserted directly rather than inferred.
  const NOW = 1_000_000;
  const noGrant = decideVerified(undefined, NOW);
  assert(
    noGrant.decision.approved && !noGrant.decision.reused && noGrant.spend,
    "no window: approved once, marked as a real touch, entry consumed",
  );

  const live = decideVerified({ until: NOW + 60_000, remaining: 3 }, NOW);
  assert(
    live.decision.approved && live.decision.reused && !live.spend,
    "live window: approved, marked reused, entry kept for the remaining runs",
  );

  const lastRun = decideVerified({ until: NOW + 60_000, remaining: 1 }, NOW);
  assert(
    lastRun.decision.reused && lastRun.spend,
    "final run of a window consumes the entry — the grant ends with its last use",
  );

  const timedOut = decideVerified({ until: NOW - 1, remaining: 99 }, NOW);
  assert(
    timedOut.decision.approved && !timedOut.decision.reused && timedOut.spend,
    "expired window: runs left do not matter, it falls back to single-use",
  );

  const exhausted = decideVerified({ until: NOW + 60_000, remaining: 0 }, NOW);
  assert(
    exhausted.decision.approved && !exhausted.decision.reused && exhausted.spend,
    "exhausted window: time left does not matter, it falls back to single-use",
  );

  // 10. SSM_PATH_PREFIX must be a real path. A bare "/" would pass a
  // leading-slash-only check and produce the account-wide sweep this option
  // exists to prevent, so the guard has to be enforced, not documented.
  assert(
    AwsEnvSchema.safeParse({ SSM_PATH_PREFIX: "/prod/app" }).success,
    "a real path prefix is accepted",
  );
  assert(
    !AwsEnvSchema.safeParse({ SSM_PATH_PREFIX: "/" }).success,
    '"/" is rejected — it would enumerate the whole account',
  );
  assert(
    !AwsEnvSchema.safeParse({ SSM_PATH_PREFIX: "//" }).success,
    '"//" is rejected for the same reason',
  );
  assert(
    !AwsEnvSchema.safeParse({ SSM_PATH_PREFIX: "prod/app" }).success,
    "a prefix without a leading slash is rejected",
  );

  process.stdout.write("selfcheck ok\n");
}
