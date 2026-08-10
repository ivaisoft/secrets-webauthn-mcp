# secrets-webauthn-mcp — Build Spec

Consolidated decisions from the grill. Terms: see [CONTEXT.md](./CONTEXT.md).
Rationale for the load-bearing ones: [docs/adr](./docs/adr).

## Purpose

Let an agent **use** secrets from one or more **Stores** without ever seeing
their values, where every use is authorized by a physical WebAuthn **Approval**.

## Threat model

- **Primary (#2):** a prompt-injected agent trying to exfiltrate a secret.
- **Secondary (#1):** a confused agent acting at the wrong time — the human at the Gate is the backstop.
- **Out of scope (#3):** stolen laptop / local malware (whoever holds the credential wins — mitigated only by least-privilege scope, not by this server).

Note the boundary: #3 is about a stolen machine, **not** about the primary
adversary. A prompt-injected agent *is* a local process running as you, which is
why ambient AWS credentials are refused (ADR 0009) rather than treated as
out-of-scope.

## Architecture (ADR 0001, 0003, 0004, 0009)

- Node ESM MCP server (TypeScript, compiled to `dist/`). Runs **locally only**.
- Each Store's credential lives **only** in this process. The agent has no `bws`, no token, and no AWS credential. This server's three tools are the **sole** path to any secret. The Gate is unbypassable.
- Stores are **peers**: none bootstraps another's credential, so no single Approval can leak a key that ungates a whole Store (ADR 0009).
- On start: connect every configured Store, start a local approval HTTP server on `127.0.0.1` (auto-picked free port), connect the MCP transport.
- **Transport:** `serve` (default) connects stdio. `serve --http` (opt-in, ADR 0004) instead runs Streamable HTTP on `127.0.0.1:SECRETS_HTTP_PORT`, with every request's Host/Origin checked (`src/http-guard.ts`) before it reaches the MCP transport — the DNS-rebinding defense a loopback HTTP listener needs that stdio doesn't. Either way the Gate (WebAuthn) is unchanged and still runs on its own separate ephemeral port.

## Stores and Secret References

A **Secret Reference** addresses exactly one secret and always names its Store:

```
<store>:<id>[#subkey]

bws:9f3c4e2a-…                       Bitwarden Secrets Manager
ssm:/prod/app/STRIPE_KEY             AWS SSM Parameter Store
secretsmanager:prod/db#password      AWS Secrets Manager, one field of a JSON secret
```

- The prefix is **mandatory**. An unprefixed id is rejected, never assumed to be Bitwarden — the string a human reads at the Gate has to say where the value comes from.
- Store names are spelled out. `asm:` was rejected for AWS Secrets Manager because it differs from `ssm:` by one character, on the one screen where misreading means authorizing the wrong system.
- Only the **first** `:` separates the store, so a Secrets Manager ARN survives intact as an id.
- `#subkey` selects one top-level key of a JSON secret and works for **every** Store, not just Secrets Manager — the extraction lives in the registry (`src/store.ts`), so there is one place where a parse failure can never echo the value it failed to parse.
- Which Stores are configured is derived from the environment; any subset works, but at least one must be present.

### AWS credentials (ADR 0009)

Exactly two channels, both unreachable by the agent:

| Mode | Env | Notes |
|---|---|---|
| Static keys | `AWS_ACCESS_KEY_ID` + `AWS_SECRET_ACCESS_KEY` (+ `AWS_SESSION_TOKEN`) | Same trust model `BWS_ACCESS_TOKEN` already has |
| SSO device flow | `AWS_SSO_START_URL` + `AWS_SSO_REGION` + `AWS_SSO_ACCOUNT_ID` + `AWS_SSO_ROLE_NAME` | Run in-process, token held in memory, never writes the CLI cache |

Never `fromNodeProviderChain()`, never `fromSSO()`, never `~/.aws`. Setting
`AWS_REGION` without a credential is a startup error, so the forbidden
fall-through cannot be reached by accident.

The SSO flow is started but **not awaited** — blocking would stall the MCP
handshake behind a human walking to their browser. Until it completes, an AWS
Store call fails with the verification URL and code, the same "here is what to
do" shape the Gate itself uses (ADR 0006). Session expiry currently needs a
server restart.

## Tools

`http_request` and `run_with_secret` **require a fresh Approval** — no cache
(ADR 0002), except for an opt-in **Reuse Window** covering one byte-identical
request, bounded by time and run count and off by default (ADR 0011). Both accept a **list** of `secret_refs` (one touch authorizes
the set, which may span Stores). Secret values are never returned to the agent.
`list_secrets` is the exception: it returns no value and is deliberately ungated
(ADR 0005).

### `list_secrets` — discovery (no Approval)

- No args. Returns every `{ id, key }` it can enumerate — never a value. `id` is a full Secret Reference, directly pasteable into `secret_refs`.
- **Bitwarden only** (ADR 0010). The AWS Stores implement no listing: `ssm:DescribeParameters` and `secretsmanager:ListSecrets` have no resource-level IAM form, so enumerating would force an account-wide grant. AWS references are self-describing names, so nothing is lost.
- Requires `BWS_ORGANIZATION_ID` when Bitwarden is configured (the SDK's `list()` needs it explicitly; a machine account belongs to exactly one org).
- Both the Store implementation and the tool handler independently destructure to `{ id, key }` — never forward the raw SDK item.

### `http_request` — safe path (host allowlist)

- Args: `{ url, method?="GET", secret_refs: [...], header?="Authorization", scheme?="Bearer ", body? }`
- **Allowlist:** local `allowlist.json` maps each **Secret Reference** -> `[allowed hosts]`. Reject **before** any touch if `new URL(url).host` is not in the allowed hosts of **every** requested secret.
- Injects secret(s) into the request **header** (`header: scheme+value`). For multiple secrets, header/scheme are per-secret (allow an array form).
- Returns `HTTP <status>\n\n<body>` only. Never follows redirects — a 3xx to an off-allowlist host would otherwise forward the injected header there.
- `outputSchema` (ADR 0007): `{ status: "approval_required"|"ok"|"error", approve_url?, reason?, http_status?, body? }`.

### `run_with_secret` — flexible escape hatch (command review)

- Args: `{ argv: [bin, ...args], secret_refs: [...], env_overrides?: { secret_ref: ENV_NAME } }`
- **No shell.** Spawn `argv[0]` with `argv[1..]` verbatim (exec, not shell). What the human reads at the Gate is exactly what runs.
- Injects each secret as an **env var** into the child. Default env name = the `#subkey`, else the Bitwarden key name, else the last path segment of an AWS name (`/prod/app/STRIPE_KEY` -> `STRIPE_KEY`). `env_overrides` may set an explicit name per reference, keyed by the reference as written. Every `env_overrides` key must be one of `secret_refs` — rejected **before** Approval otherwise (a typo'd reference would silently no-op, invisible in the Approval message).
- Strips **every** Store credential from the child env (`STORE_CREDENTIAL_ENV_VARS` in `schemas.ts`), not just the Bitwarden token: a child that inherited AWS keys could read a whole Store with no Gate at all.
- Never place a secret in `argv` (would show in `ps`/logs). Env only.
- Returns child `stdout`+`stderr` and exit code.
- No allowlist (command is arbitrary); the Gate prompt shows `argv` (shell-quoted for display via `shell-format.ts` — display only, never actually run through a shell), each reference with its resolved name, and the injected env-var name, and the human approves.
- `outputSchema` (ADR 0007): `{ status: "approval_required"|"ok"|"error", approve_url?, reason?, exit_code?, stdout?, stderr? }`.

Malformed references and unknown `env_overrides` keys are rejected **before**
the Gate: they are caller bugs, not something worth spending a physical touch to
discover.

## The Gate (WebAuthn via request-key re-check — ADR 0006)

Not MCP elicitation — that depends on client support that isn't universal (a
real client, "Cowork", has no elicitation UI at all, so a tool would hang
forever waiting on it). Instead:

1. Tool computes `key = requestKey(toolName, parsedArgs)` — a deterministic hash, so the exact same call always yields the same key (`src/request-key.ts`).
2. `gate.checkApproval(key, message, ttlMs)`: if `key` has a verified pending entry, **consume it** (delete — single-use) and return `true`. Otherwise register `{message, verified:false, expiresAt: now+ttlMs}` and return `false`.
3. If `false`: the tool returns plain **tool-result text** (not elicitation) — `message` plus `${gate.origin}/approve?rid=${key}` — instructing the human to open it and then re-issue the identical call. Works with any MCP client.
4. Human opens the URL; the approve page runs `SimpleWebAuthnBrowser.startAuthentication({ optionsJSON })` → Touch ID / passkey → POST assertion. Server verifies (`@simplewebauthn/server`), updates the credential's counter, marks the pending entry `verified: true`.
5. The identical tool call, re-issued, computes the same `key`, finds it verified, `checkApproval` consumes it and returns `true` — the tool proceeds.

- `rpID = "localhost"`, `expectedOrigin = "http://localhost:<port>"`, `userVerification: "required"`.
- Pending entries are swept on every check; unapproved ones expire after `ttlMs` (`SECRETS_GATE_TIMEOUT_MS`).
- **One Approval is one assertion.** Dual / M-of-N Approval was considered and dropped — it only ever guarded a Store bootstrapping another's credential, which ADR 0009 removed.
- **Reuse Window (ADR 0011):** at the Gate the human may grant the byte-identical request a window, bounded by elapsed time *and* remaining runs — whichever ends first. Keyed on the request key, so no other call is covered. Needs two opt-ins: `SECRETS_REUSE_MAX_MS` in config, and a duration chosen on the approve page. `decideVerified` holds the rule and `selfcheck` asserts it. Audited as `reused: true`.

## Credentials (multi-authenticator)

- Store an **array** of credentials at `~/.config/secrets-webauthn-mcp/credentials.json` (each `{ id, publicKey(base64), counter, transports }`, file mode `0600`). Public key + counter only — no secret material.
- `STATE_DIR` resolves the new directory if it exists, else the legacy `~/.config/bws-webauthn-mcp`, else the new one — so the rename doesn't orphan registered authenticators, and reads and writes always land in the same place.
- Any registered credential can Approve (Touch ID on Mac + Google/Android passkey both registered).
- **Registration** only via `npm run register` (standalone mode). Serve mode does **not** serve `/register`. First credential = trust-on-first-use; adding further credentials requires an existing Approval first.

## Cross-cutting

- **Audit log:** append-only JSONL at `~/.config/secrets-webauthn-mcp/audit.log` — `{ ts, tool, secret_refs, host|argv0, verified, reused }`. Never the value; references are recorded as written, so the trail says which Store each value came from.
- **Port:** auto-pick a free port on `127.0.0.1`; the approval URL uses it.
- **Credential scope:** README instructs a dedicated **read-only** Bitwarden machine account scoped to a single project, and an AWS policy scoped to an ARN prefix with no account-wide grant.

## Config / env

Naming follows ownership: `BWS_*` configures the Bitwarden Store, `AWS_*` the
AWS Stores, `SECRETS_*` the server itself.

| Var | Default | |
|---|---|---|
| `BWS_ACCESS_TOKEN` | — | enables the Bitwarden Store |
| `BWS_ORGANIZATION_ID` | — | required **iff** `BWS_ACCESS_TOKEN` is set |
| `BWS_API_URL` / `BWS_IDENTITY_URL` | bitwarden.com | EU / self-host |
| `AWS_REGION` | — | enables the AWS Stores |
| `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` / `AWS_SESSION_TOKEN` | — | static-keys mode |
| `AWS_SSO_START_URL` / `AWS_SSO_REGION` / `AWS_SSO_ACCOUNT_ID` / `AWS_SSO_ROLE_NAME` | — | SSO device-flow mode (all four, or none) |
| `SECRETS_GATE_TIMEOUT_MS` | `120000` | pending-approval TTL (ADR 0006) |
| `SECRETS_HTTP_PORT` | `8787` | only read by `serve --http` |
| `SECRETS_REUSE_MAX_MS` | `0` (off) | longest Reuse Window grantable at the Gate (ADR 0011) |
| `SECRETS_REUSE_MAX_USES` | `5` | most runs one Reuse Window may cover |

At least one Store must be configured, or startup fails.

## Out of scope / caveats

- If a Consumer itself prints/reflects the injected secret, it returns to the agent — documented, not enforced (same as `bws run`).
- An AWS reference gets no pre-Approval existence check (ADR 0010), so a wrong path fails after the touch is spent. The reference shown at the Gate *is* the name, so a typo is at least visible to a human.
- AWS SSO session expiry needs a server restart; there is no in-session re-login.
- Cross-device Google/Android passkey approval on the Mac uses the browser's hybrid (phone) flow with `rpID=localhost`; may be finicky depending on browser.

## Verified library facts (don't re-derive)

- **`@bitwarden/sdk-napi` ^1.0.0** (only published JS binding; prebuilt `darwin-arm64`). `new BitwardenClient(settings, 4)`; `await client.auth().loginAccessToken(token)`; `await client.secrets().get(id)` → `{ key, value, ... }`. `LogLevel` is a `const enum` (not exported at runtime) → pass numeric `4` (Error).
- **`@aws-sdk/client-ssm` / `client-secrets-manager` / `client-sso-oidc` / `client-sso` ^3.1106.0.** `GetParameterCommand({ Name, WithDecryption: true })`; `GetSecretValueCommand({ SecretId })` → `{ Name, SecretString }` (binary secrets return `SecretBinary` instead and are refused). Device flow: `RegisterClient` → `StartDeviceAuthorization` → poll `CreateToken` (`AuthorizationPendingException` = keep going, `SlowDownException` = back off) → `GetRoleCredentials`. All four of those are unauthenticated operations, so the clients are constructed with a credential provider that **throws** — if a future SDK version starts signing them, it fails loudly instead of silently reaching for `~/.aws`.
- **`@modelcontextprotocol/sdk` ^1.29.0** has URL-mode elicitation (`mcp.server.elicitInput`), but the Gate does not use it — see ADR 0006.
- **`@simplewebauthn/server` ^13.3.2** + **`@simplewebauthn/browser` ^13.3.0** (serve the UMD bundle `dist/bundle/index.umd.min.js`, global `SimpleWebAuthnBrowser`, `startRegistration/startAuthentication({ optionsJSON })`). `verifyAuthenticationResponse({ response, expectedChallenge, expectedOrigin, expectedRPID, credential:{ id, publicKey:Uint8Array, counter, transports } })`. Stored credential shape `{ id: base64url, publicKey: Uint8Array, counter, transports }`.
- Not every MCP client supports elicitation (confirmed: "Cowork" does not) — this is exactly why ADR 0006 moved the Gate off it.
- V8's `JSON.parse` error messages quote the input they failed on, so `#subkey` extraction must never forward them — it would put the secret in a tool result.
