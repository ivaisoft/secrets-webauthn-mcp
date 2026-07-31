# bws-webauthn-mcp

MCP server for **Bitwarden Secrets Manager** that lets an agent **use** a secret
without ever seeing its value. Every use is authorized by a fresh **physical
WebAuthn Approval** (Touch ID / passkey) — via a mechanism that works with
**any** MCP client, not just ones that support elicitation (see
[ADR 0006](./docs/adr/0006-request-key-approval-replaces-elicitation.md)):

```
1st call  → not yet approved → returns instructions + an Approval URL (plain tool text, works everywhere)
          → open the URL, approve with Touch ID / passkey → server verifies
2nd call  → identical arguments → finds the Approval, consumes it (single-use) → proceeds
```

A client that understands `structuredContent` (ADR 0007) can detect
`status === "approval_required"` and read `approve_url` directly, instead of
parsing the prose.

The `BWS_ACCESS_TOKEN` lives **only** inside this server process; the agent has no
`bws` and no token. These two tools are the **sole** path to any secret, and the
Gate is unbypassable. There is **no cache** — every single use requires its own
fresh Approval (see [ADR 0002](./docs/adr/0002-no-cache-one-approval-per-use.md)).
Secret values are **never** returned to the agent, placed in `argv`, or written to
any log.

## Tools

`http_request` and `run_with_secret` require a fresh Approval and both accept a
**list** of `secret_id`s (one touch authorizes the set). Neither ever returns a
secret value. `list_secrets` is the exception — see below.

| Tool | What it does |
|---|---|
| `list_secrets()` | Lists every `{ id, key }` in the configured organization — **never a value**, and **does not require Approval** (it's discovery metadata, not secret use — see [ADR 0005](./docs/adr/0005-list-secrets-ungated-metadata-only.md)). Use the returned `id` with the other two tools. |
| `http_request({ url, method?, secret_ids, header?, scheme?, body? })` | Injects the secret(s) into request **headers** and returns only `HTTP <status>\n\n<body>`. The target host must be in every requested secret's allowlist (checked **before** any touch). Redirects are **not** followed — a 3xx is refused so the injected header can never be forwarded to an unvetted host. |
| `run_with_secret({ argv, secret_ids, env_overrides? })` | Spawns `argv[0]` with `argv[1..]` verbatim (**no shell**) and injects each secret as an **environment variable** (default name = the secret's Bitwarden key name; override per secret with `env_overrides`). Returns the child's stdout, stderr, and exit code. No allowlist — the Approval prompt shows `argv` (shell-quoted for a faithful, readable display), each secret's **real Bitwarden key name** (id + name only — never the value, same lookup `list_secrets` uses), and the injected env-var name, and the human approves. |

Reference secrets by **UUID** (get one from `list_secrets`).

`http_request`/`run_with_secret` also return `structuredContent` matching a
declared `outputSchema`: `{ status: "approval_required" | "ok" | "error", approve_url?, reason?, ... }`
(plus `http_status`/`body` for `http_request`, `exit_code`/`stdout`/`stderr` for
`run_with_secret`) — see [ADR 0007](./docs/adr/0007-structured-output-for-approval-required.md).

## Requirements

- Node 20+ (uses global `fetch`). WebAuthn works on `localhost` over http (secure
  context, rpID `localhost`).
- A Bitwarden Secrets Manager **machine-account access token**. Provision a
  **dedicated read-only machine account scoped to a single project** — this server
  does not protect against a stolen token (that is out of scope; least-privilege
  scope is the only mitigation).

## Setup

Published on npm — no clone needed:

```bash
BWS_ACCESS_TOKEN=... npx -y @ivaisoft/bws-webauthn-mcp register   # one-time per authenticator: opens the browser, binds Touch ID / passkey
```

Or from a local clone (for development):

```bash
npm install
npm run build
BWS_ACCESS_TOKEN=... npm run register
```

Credentials are stored as an **array** at
`~/.config/bws-webauthn-mcp/credentials.json` (public key + counter + transports
only, mode `0600` — no secret material). Any registered credential can Approve
(e.g. Touch ID on the Mac plus a Google/Android passkey). The first credential is
trust-on-first-use; adding further credentials requires an existing Approval.
Serve mode does **not** serve registration.

The host allowlist for `http_request` lives at
`~/.config/bws-webauthn-mcp/allowlist.json`, mapping each `secret_id` to the hosts
it may be sent to (missing entry = deny):

```json
{ "1234-secret-uuid": ["api.example.com"] }
```

## Wire into Claude Code

```bash
claude mcp add bws -- env BWS_ACCESS_TOKEN=<token> BWS_ORGANIZATION_ID=<org-id> npx -y @ivaisoft/bws-webauthn-mcp
```

or in `~/.claude/settings.json`:

```json
{
  "mcpServers": {
    "bws": {
      "command": "npx",
      "args": ["-y", "@ivaisoft/bws-webauthn-mcp"],
      "env": { "BWS_ACCESS_TOKEN": "<token>", "BWS_ORGANIZATION_ID": "<org-id>" }
    }
  }
}
```

From a local clone instead, replace `command`/`args` with
`"node"` / `["/path/to/bws-webauthn-mcp/dist/index.js", "serve"]`.

The approval server binds an **auto-picked free port** on `127.0.0.1`; the
approval URL uses it. There is no fixed port to configure.

## Streamable HTTP (opt-in, loopback-only)

stdio is the default and is the more restrictive option — only the process a
client directly spawns can talk to it. `serve --http` instead runs the MCP
session over Streamable HTTP on `127.0.0.1:BWS_HTTP_PORT` (default `8787`), so
more than one local MCP client can share a single running server:

```bash
BWS_ACCESS_TOKEN=... node dist/index.js serve --http
```

```json
{
  "mcpServers": {
    "bws": { "type": "http", "url": "http://127.0.0.1:8787/mcp" }
  }
}
```

Every request's `Host`/`Origin` is checked before it reaches the MCP transport
(see [ADR 0004](./docs/adr/0004-optional-streamable-http-transport-loopback-only.md))
— without that check, a malicious web page open in your browser could reach
this port via DNS rebinding and trigger Approval prompts. Requests with an
unrecognized `Host` or a foreign `Origin` get a `403`. This only changes how
the MCP *connection* is carried: the Gate (WebAuthn), the allowlist, and the
vault token's confinement to this process are identical to stdio mode.

## Env

| Var | Default | |
|---|---|---|
| `BWS_ACCESS_TOKEN` | — | **required**, machine-account token |
| `BWS_ORGANIZATION_ID` | — | **required**, used by `list_secrets` (a machine account belongs to exactly one org) |
| `BWS_API_URL` / `BWS_IDENTITY_URL` | bitwarden.com | set for EU / self-host |
| `BWS_GATE_TIMEOUT_MS` | `120000` | how long the tool waits for the Approval |
| `BWS_HTTP_PORT` | `8787` | only read by `serve --http` |

## What this does and does not protect

- **Protects**: the *release* of a secret. No value leaves Bitwarden without a
  fresh physical touch, and the value is never returned to the conversation — the
  agent only ever gets the HTTP response or the child's output.
- **Does not undo a Consumer that reflects the secret**: if the endpoint or command
  you invoke prints the injected value back, it returns to the agent — documented,
  not enforced (same caveat as `bws run`).
- **Local only.** The `localhost` rpID trick means this must run as a local stdio
  server. Behind a real domain, WebAuthn re-binds to that domain and the model
  changes (see [ADR 0003](./docs/adr/0003-local-stdio-only-not-clustered.md)).
- **`list_secrets` exposes names, not values, without a touch.** Any agent that
  can call it can enumerate your secret ids and key names — the same
  information your access token already exposes via `bws secret list`, just
  made convenient for the agent. If that's not acceptable for your threat
  model, don't wire this tool up (see [ADR 0005](./docs/adr/0005-list-secrets-ungated-metadata-only.md)).

## Audit log

Every `http_request`/`run_with_secret` attempt appends one JSONL line to
`~/.config/bws-webauthn-mcp/audit.log` (`{ ts, tool, secret_ids, host|argv0,
verified }`) — never the value. `list_secrets` calls are not audited: it never
touches a specific secret's value, so there's no "use" to record.

## Selfcheck

```bash
npm run selfcheck   # pure-logic checks (no vault access, no browser)
```

## Roadmap

See [ROADMAP.md](./ROADMAP.md) for planned/considered future work.
