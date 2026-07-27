# bws-webauthn-mcp — Build Spec

Consolidated decisions from the grill. Terms: see [CONTEXT.md](./CONTEXT.md).
Rationale for the load-bearing ones: [docs/adr](./docs/adr).

## Purpose

Let an agent **use** Bitwarden Secrets Manager secrets without ever seeing their
values, where every use is authorized by a physical WebAuthn **Approval**.

## Threat model

- **Primary (#2):** a prompt-injected agent trying to exfiltrate a secret.
- **Secondary (#1):** a confused agent acting at the wrong time — the human at the Gate is the backstop.
- **Out of scope (#3):** stolen laptop / local malware (whoever holds the token wins — mitigated only by least-privilege token scope, not by this server).

## Architecture (ADR 0001, 0003)

- Single-file Node ESM stdio MCP server. Runs **locally only**.
- `BWS_ACCESS_TOKEN` lives **only** in this process. The agent has no `bws` and no token. This server's two tools are the **sole** path to any secret. The Gate is unbypassable.
- On start: log in to BWS, start a local approval HTTP server on `127.0.0.1` (auto-picked free port), connect stdio transport.

## Tools

Both **require a fresh Approval** — no cache, ever (ADR 0002). Both accept a
**list** of `secret_id`s (one touch authorizes the set). Secret values are never
returned to the agent.

### `http_request` — safe path (host allowlist)

- Args: `{ url, method?="GET", secret_ids: [...], header?="Authorization", scheme?="Bearer ", body? }`
- **Allowlist:** local `allowlist.json` maps each `secret_id -> [allowed hosts]`. Reject **before** any touch if `new URL(url).host` is not in the allowed hosts of **every** requested secret.
- Injects secret(s) into the request **header** (`header: scheme+value`). For multiple secrets, header/scheme are per-secret (allow an array form).
- Returns `HTTP <status>\n\n<body>` only.

### `run_with_secret` — flexible escape hatch (command review)

- Args: `{ argv: [bin, ...args], secret_ids: [...], env_overrides?: { secret_id: ENV_NAME } }`
- **No shell.** Spawn `argv[0]` with `argv[1..]` verbatim (exec, not shell). What the human reads at the Gate is exactly what runs.
- Injects each secret as an **env var** into the child. Default env name = the secret's **Bitwarden key name**; `env_overrides` may set an explicit name per secret.
- Never place a secret in `argv` (would show in `ps`/logs). Env only.
- Returns child `stdout`+`stderr` and exit code.
- No allowlist (command is arbitrary); the Gate prompt shows the full `argv` + injected env-var names + secret ids, and the human approves.

## The Gate (WebAuthn via URL-mode elicitation)

1. Tool builds an `elicitationId` (rid) + WebAuthn authentication challenge listing **all** registered credentials in `allowCredentials`; stashes pending[rid].
2. `mcp.server.elicitInput({ mode:"url", message, elicitationId: rid, url:"http://localhost:<port>/approve?rid=<rid>" }, { timeout })`. `message` states exactly what will happen (tool, secret ids, host **or** full argv).
3. Browser page runs `SimpleWebAuthnBrowser.startAuthentication({ optionsJSON })` → Touch ID / Google passkey → POST assertion.
4. Server verifies (`@simplewebauthn/server`), updates counter, marks pending[rid] verified, calls `mcp.server.createElicitationCompletionNotifier(rid)()` to auto-close the dialog.
5. Tool proceeds **only** if `pending[rid].verified === true` and the elicit action is not `decline`/`cancel`. Otherwise throw.

- `rpID = "localhost"`, `expectedOrigin = "http://localhost:<port>"`, `userVerification: "required"`.

## Credentials (multi-authenticator)

- Store an **array** of credentials at `~/.config/bws-webauthn-mcp/credentials.json` (each `{ id, publicKey(base64), counter, transports }`, file mode `0600`). Public key + counter only — no secret material.
- Any registered credential can Approve (Touch ID on Mac + Google/Android passkey both registered).
- **Registration** only via `npm run register` (standalone mode). Serve mode does **not** serve `/register`. First credential = trust-on-first-use; adding further credentials requires an existing Approval first.

## Cross-cutting

- **Audit log:** append-only JSONL at `~/.config/bws-webauthn-mcp/audit.log` — `{ ts, tool, secret_ids, host|argv0, verified }`. Never the value. (`ts` stamped by the server.)
- **Port:** auto-pick a free port on `127.0.0.1`; the approval URL uses it.
- **Token scope:** README instructs a dedicated **read-only** machine account scoped to a single project.

## Config / env

| Var | Default | |
|---|---|---|
| `BWS_ACCESS_TOKEN` | — | **required** |
| `BWS_API_URL` / `BWS_IDENTITY_URL` | bitwarden.com | EU / self-host |
| `BWS_GATE_TIMEOUT_MS` | `120000` | elicitation wait |

## Out of scope / caveats

- If a Consumer itself prints/reflects the injected secret, it returns to the agent — documented, not enforced (same as `bws run`).
- Cross-device Google/Android passkey approval on the Mac uses the browser's hybrid (phone) flow with `rpID=localhost`; may be finicky depending on browser — verify during implementation.

## Verified library facts (don't re-derive)

- **`@bitwarden/sdk-napi` ^1.0.0** (only published JS binding; prebuilt `darwin-arm64`). `new BitwardenClient(settings, 4)`; `await client.auth().loginAccessToken(token)`; `await client.secrets().get(id)` → `{ key, value, ... }`. `LogLevel` is a `const enum` (not exported at runtime) → pass numeric `4` (Error).
- **`@modelcontextprotocol/sdk` ^1.29.0** has URL-mode elicitation: `mcp.server.elicitInput` accepts `{ mode:"url", message, elicitationId, url }`; `mcp.server.createElicitationCompletionNotifier(id)`; `ElicitResult.action ∈ {accept,decline,cancel}`.
- **`@simplewebauthn/server` ^13.3.2** + **`@simplewebauthn/browser` ^13.3.0** (serve the UMD bundle `dist/bundle/index.umd.min.js`, global `SimpleWebAuthnBrowser`, `startRegistration/startAuthentication({ optionsJSON })`). `verifyAuthenticationResponse({ response, expectedChallenge, expectedOrigin, expectedRPID, credential:{ id, publicKey:Uint8Array, counter, transports } })`. Stored credential shape `{ id: base64url, publicKey: Uint8Array, counter, transports }`.
- Claude Code (this host) supports URL-mode elicitation.

## Delta vs the current spike (`index.mjs`)

The spike must be reworked, not extended: it has `get_secret` (returns the value — now forbidden), a shared 5-min cache (now forbidden), a single credential (now an array), a `call_with_secret` without allowlist, no `run_with_secret`, no audit log, no registration lockdown, fixed port.
