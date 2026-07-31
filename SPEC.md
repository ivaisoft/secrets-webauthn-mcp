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

## Architecture (ADR 0001, 0003, 0004)

- Node ESM MCP server (TypeScript, compiled to `dist/`). Runs **locally only**.
- `BWS_ACCESS_TOKEN` lives **only** in this process. The agent has no `bws` and no token. This server's two tools are the **sole** path to any secret. The Gate is unbypassable.
- On start: log in to BWS, start a local approval HTTP server on `127.0.0.1` (auto-picked free port), connect the MCP transport.
- **Transport:** `serve` (default) connects stdio. `serve --http` (opt-in, ADR 0004) instead runs Streamable HTTP on `127.0.0.1:BWS_HTTP_PORT`, with every request's Host/Origin checked (`src/http-guard.ts`) before it reaches the MCP transport — the DNS-rebinding defense a loopback HTTP listener needs that stdio doesn't. Either way the Gate (WebAuthn) is unchanged and still runs on its own separate ephemeral port.

## Tools

`http_request` and `run_with_secret` **require a fresh Approval** — no cache,
ever (ADR 0002). Both accept a **list** of `secret_id`s (one touch authorizes
the set). Secret values are never returned to the agent. `list_secrets` is the
exception: it returns no value and is deliberately ungated (ADR 0005).

### `list_secrets` — discovery (no Approval)

- No args. Returns every `{ id, key }` in the configured org — never a value.
- Requires `BWS_ORGANIZATION_ID` (the SDK's `list()` needs it explicitly; a machine account belongs to exactly one org).
- Both `bws.ts` and the tool handler independently destructure to `{ id, key }` — never forward the raw SDK item.

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
- Pending entries are swept on every check; unapproved ones expire after `ttlMs` (`BWS_GATE_TIMEOUT_MS`).

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
| `BWS_ORGANIZATION_ID` | — | **required**, only used by `list_secrets` |
| `BWS_API_URL` / `BWS_IDENTITY_URL` | bitwarden.com | EU / self-host |
| `BWS_GATE_TIMEOUT_MS` | `120000` | pending-approval TTL (ADR 0006) |
| `BWS_HTTP_PORT` | `8787` | only read by `serve --http` |

## Out of scope / caveats

- If a Consumer itself prints/reflects the injected secret, it returns to the agent — documented, not enforced (same as `bws run`).
- Cross-device Google/Android passkey approval on the Mac uses the browser's hybrid (phone) flow with `rpID=localhost`; may be finicky depending on browser — verify during implementation.

## Verified library facts (don't re-derive)

- **`@bitwarden/sdk-napi` ^1.0.0** (only published JS binding; prebuilt `darwin-arm64`). `new BitwardenClient(settings, 4)`; `await client.auth().loginAccessToken(token)`; `await client.secrets().get(id)` → `{ key, value, ... }`. `LogLevel` is a `const enum` (not exported at runtime) → pass numeric `4` (Error).
- **`@modelcontextprotocol/sdk` ^1.29.0** has URL-mode elicitation (`mcp.server.elicitInput`), but the Gate does not use it — see ADR 0006.
- **`@simplewebauthn/server` ^13.3.2** + **`@simplewebauthn/browser` ^13.3.0** (serve the UMD bundle `dist/bundle/index.umd.min.js`, global `SimpleWebAuthnBrowser`, `startRegistration/startAuthentication({ optionsJSON })`). `verifyAuthenticationResponse({ response, expectedChallenge, expectedOrigin, expectedRPID, credential:{ id, publicKey:Uint8Array, counter, transports } })`. Stored credential shape `{ id: base64url, publicKey: Uint8Array, counter, transports }`.
- Not every MCP client supports elicitation (confirmed: "Cowork" does not) — this is exactly why ADR 0006 moved the Gate off it.

## Delta vs the current spike (`index.mjs`)

The spike must be reworked, not extended: it has `get_secret` (returns the value — now forbidden), a shared 5-min cache (now forbidden), a single credential (now an array), a `call_with_secret` without allowlist, no `run_with_secret`, no audit log, no registration lockdown, fixed port.
