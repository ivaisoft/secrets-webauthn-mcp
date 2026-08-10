# secrets-webauthn-mcp

MCP server for **Bitwarden Secrets Manager**, **AWS SSM Parameter Store** and
**AWS Secrets Manager** that lets an agent **use** a secret without ever seeing
its value. Every use is authorized by a fresh **physical WebAuthn Approval**
(Touch ID / passkey) — via a mechanism that works with **any** MCP client, not
just ones that support elicitation (see
[ADR 0006](./docs/adr/0006-request-key-approval-replaces-elicitation.md)):

```
1st call  → not yet approved → returns instructions + an Approval URL (plain tool text, works everywhere)
          → open the URL, approve with Touch ID / passkey → server verifies
2nd call  → identical arguments → finds the Approval, consumes it (single-use) → proceeds
```

A client that understands `structuredContent` (ADR 0007) can detect
`status === "approval_required"` and read `approve_url` directly, instead of
parsing the prose.

Every **Store** credential lives **only** inside this server process; the agent
has no `bws`, no token, and no AWS credential. These tools are the **sole** path
to any secret, and the Gate is unbypassable. By default there is **no cache** —
every single use requires its own fresh Approval
([ADR 0002](./docs/adr/0002-no-cache-one-approval-per-use.md)). You can opt into a
**Reuse Window** covering one byte-identical call, bounded by time *and* by run
count ([ADR 0011](./docs/adr/0011-reuse-window-bounded-by-time-and-runs.md)) —
off unless you enable it. Secret values are **never** returned to the agent,
placed in `argv`, or written to any log.

## Secret References

A secret is addressed as `<store>:<id>[#subkey]`. The prefix is **mandatory** —
an unprefixed id is rejected rather than assumed to be Bitwarden, because the
string you read on the Approval page has to tell you where the value is about
to come from.

```
bws:9f3c4e2a-…                    Bitwarden Secrets Manager
ssm:/prod/app/STRIPE_KEY          AWS SSM Parameter Store
secretsmanager:prod/db#password   AWS Secrets Manager, one field of a JSON secret
```

`#subkey` picks one top-level key out of a JSON secret and works for every
Store. One Approval covers all the references in a call, even across Stores.

**This server never reads `~/.aws`.** Not `credentials`, not `config`, not
`sso/cache`, and never the default credential chain — because `aws sso login`'s
cache is readable by any process running as you, including the prompt-injected
agent this whole design exists to stop
([ADR 0009](./docs/adr/0009-aws-credentials-not-ambient-not-from-a-store.md)).
AWS credentials come from this process's own environment, or from an SSO device
flow the server runs itself and keeps in memory.

## Quick start

```bash
# 1. Register once — binds Touch ID / passkey to this server (takes no credential)
npx -y @ivaisoft/secrets-webauthn-mcp register

# 2. Wire it into your MCP client (see "Wire into Claude Code" below)
```

Then just ask the agent to use a secret. It calls `list_secrets` to find the
right `id`, then `http_request` or `run_with_secret`. The first attempt
returns an Approval URL instead of doing anything; you open it and tap Touch
ID once; the agent re-issues the identical call and it succeeds — the value
never appears anywhere in the conversation. See [Use cases](#use-cases) below
for what that looks like end to end.

## Tools

`http_request` and `run_with_secret` require a fresh Approval and both accept a
**list** of Secret References (one touch authorizes the set, which may span
Stores). Neither ever returns a secret value. `list_secrets` is the exception —
see below.

| Tool | What it does |
|---|---|
| `list_secrets()` | Lists every `{ id, key }` it can enumerate — **never a value**, and **does not require Approval** (it's discovery metadata, not secret use — see [ADR 0005](./docs/adr/0005-list-secrets-ungated-metadata-only.md)). `id` comes back as a full Secret Reference, ready to paste into the other tools. A Store enumerates only if that permission can be scoped no wider than the read it already grants ([ADR 0010](./docs/adr/0010-aws-stores-are-not-enumerable.md)): Bitwarden always; SSM Parameter Store under `SSM_PATH_PREFIX`, via the resource-scopable `GetParametersByPath`; AWS Secrets Manager never, since `ListSecrets` cannot be scoped at all. Secrets that don't appear are still fully usable — AWS references are self-describing names. |
| `http_request({ url, method?, secret_refs, header?, scheme?, body? })` | Injects the secret(s) into request **headers** and returns only `HTTP <status>\n\n<body>`. The target host must be in every requested secret's allowlist (checked **before** any touch). Redirects are **not** followed — a 3xx is refused so the injected header can never be forwarded to an unvetted host. |
| `run_with_secret({ argv, secret_refs, env_overrides? })` | Spawns `argv[0]` with `argv[1..]` verbatim (**no shell**) and injects each secret as an **environment variable** (default name = the `#subkey`, else the Bitwarden key name, else the last path segment of an AWS name; override per reference with `env_overrides`). Every Store credential is stripped from the child's environment, so the command can never reach a Store directly. Returns the child's stdout, stderr, and exit code. No allowlist — the Approval prompt shows `argv` (shell-quoted for a faithful, readable display), each reference with its resolved name (never the value), and the injected env-var name, and the human approves. |

Reference secrets by **Secret Reference** — `bws:<uuid>` (get one from `list_secrets`), `ssm:/path/to/param`, or `secretsmanager:<name>[#field]`.

`http_request`/`run_with_secret` also return `structuredContent` matching a
declared `outputSchema`: `{ status: "approval_required" | "ok" | "error", approve_url?, reason?, ... }`
(plus `http_status`/`body` for `http_request`, `exit_code`/`stdout`/`stderr` for
`run_with_secret`) — see [ADR 0007](./docs/adr/0007-structured-output-for-approval-required.md).

## Use cases

Concrete examples of what an agent actually does with these tools. In every
case the agent never sees the secret value — only what's shown below — and
every call goes through the same flow: first attempt → Approval URL → you tap
Touch ID once → the agent re-issues the identical call → it succeeds.

### Call a third-party API without exposing the key

"Check the status of Stripe charge ch_123":

```json
{
  "tool": "http_request",
  "arguments": {
    "url": "https://api.stripe.com/v1/charges/ch_123",
    "secret_refs": ["bws:<stripe-secret-key-id>"]
  }
}
```

`header`/`scheme` default to `Authorization: Bearer <value>` — override them
for Basic auth or a custom header name. Needs an allowlist entry for
`api.stripe.com` (see [Setup](#setup)). The agent gets back the charge JSON;
the API key itself never enters the conversation.

### Query a database

"How many rows are in the `orders` table on prod?" — the password goes in as
an env var, never as a CLI flag (which would leak it into `ps`/shell history):

```json
{
  "tool": "run_with_secret",
  "arguments": {
    "argv": ["psql", "-h", "db.internal", "-U", "app", "-c", "select count(*) from orders;"],
    "secret_refs": ["bws:<db-password-secret-id>"],
    "env_overrides": { "bws:<db-password-secret-id>": "PGPASSWORD" }
  }
}
```

`psql` reads `PGPASSWORD` from its environment automatically.

### Use a parameter straight out of SSM

"Run the migration against staging" — the password lives in Parameter Store and
the reference is its own name, so nothing has to be looked up first:

```json
{
  "tool": "run_with_secret",
  "arguments": {
    "argv": ["psql", "-h", "staging.internal", "-U", "app", "-c", "select 1"],
    "secret_refs": ["ssm:/staging/app/DB_PASSWORD"],
    "env_overrides": { "ssm:/staging/app/DB_PASSWORD": "PGPASSWORD" }
  }
}
```

Or pull one field out of a JSON secret in Secrets Manager with `#`:

```json
{
  "tool": "run_with_secret",
  "arguments": {
    "argv": ["psql", "-h", "staging.internal", "-U", "app", "-c", "select 1"],
    "secret_refs": ["secretsmanager:staging/db#password"],
    "env_overrides": { "secretsmanager:staging/db#password": "PGPASSWORD" }
  }
}
```

> **Don't** store a long-lived AWS access key as a secret and inject it into an
> `aws` command. That credential reads a whole Store, so one waved-through
> Approval ungates every parameter behind it, permanently — which is exactly
> why no Store is allowed to bootstrap another's credential
> ([ADR 0009](./docs/adr/0009-aws-credentials-not-ambient-not-from-a-store.md)).

### Trigger an internal webhook

"Kick off the nightly sync" — a bearer token scoped by the allowlist to only
that one internal host:

```json
{
  "tool": "http_request",
  "arguments": {
    "url": "https://internal.example.com/api/sync/trigger",
    "method": "POST",
    "secret_refs": ["bws:<webhook-token-id>"]
  }
}
```

### Find the right secret first

Don't know the `id`? Ask the agent — `list_secrets` needs no Approval since it
never returns a value:

> "List the Bitwarden secrets available, then use the Stripe one to check
> charge ch_123."

## Migrating from `@ivaisoft/bws-webauthn-mcp`

The package was renamed when it stopped being Bitwarden-only. npm treats the old
name as a separate package, so nothing updates on its own.

1. **Package and binary.** `@ivaisoft/bws-webauthn-mcp` → `@ivaisoft/secrets-webauthn-mcp`, and the bin is now `secrets-webauthn-mcp`. Update `command`/`args` in your MCP client config.
2. **`secret_ids` → `secret_refs`**, and every entry needs its Store prefix: `9f3c…` becomes `bws:9f3c…`. An unprefixed id is rejected with a message naming the fix — never silently reinterpreted.
3. **`allowlist.json` keys** need the same prefix. A leftover bare key reads as "no allowlist entry for secret …" and the call is denied before any touch, which is the safe direction to fail but will look like a bug if you don't expect it.
4. **`env_overrides` keys** are Secret References too.
5. **Env vars.** `BWS_GATE_TIMEOUT_MS` → `SECRETS_GATE_TIMEOUT_MS`, `BWS_HTTP_PORT` → `SECRETS_HTTP_PORT`. `BWS_ACCESS_TOKEN` and `BWS_ORGANIZATION_ID` keep their names — they now configure the Bitwarden Store specifically, and are optional.
6. **Registered authenticators keep working.** State is read from `~/.config/secrets-webauthn-mcp` if it exists, else the old `~/.config/bws-webauthn-mcp` — one directory for both reads and writes. Nothing is moved, and no re-registration is needed; move it yourself whenever convenient.

## Requirements

- Node 20+ (uses global `fetch`). WebAuthn works on `localhost` over http (secure
  context, rpID `localhost`).
- **At least one Store**, and any subset works:
  - **Bitwarden** — a Secrets Manager machine-account access token. Provision a **dedicated read-only machine account scoped to a single project**.
  - **AWS** (Parameter Store and Secrets Manager) — `AWS_REGION` plus either static keys or SSO, with a policy scoped to an ARN prefix (see [Env](#env)).

  This server does not protect against a stolen credential — that is out of
  scope, and least-privilege scope is the only mitigation.

## Setup

Published on npm — no clone needed:

```bash
npx -y @ivaisoft/secrets-webauthn-mcp register   # one-time per authenticator: opens the browser, binds Touch ID / passkey
```

Or from a local clone (for development):

```bash
npm install
npm run build
npm run register
```

`register` takes **no Store credential** — it never reads a secret, it only
binds an authenticator (`RegisterEnvSchema` in `src/schemas.ts` reads nothing
but `BWS_API_URL`). Don't hand it a token it has no use for.

Credentials are stored as an **array** at
`~/.config/secrets-webauthn-mcp/credentials.json` (public key + counter + transports
only, mode `0600` — no secret material). Any registered credential can Approve
(e.g. Touch ID on the Mac plus a Google/Android passkey). The first credential is
trust-on-first-use; adding further credentials requires an existing Approval.
Serve mode does **not** serve registration.

The host allowlist for `http_request` lives at
`~/.config/secrets-webauthn-mcp/allowlist.json`, mapping each **Secret Reference**
to the hosts it may be sent to (missing entry = deny):

```json
{
  "bws:1234-secret-uuid": ["api.example.com"],
  "ssm:/prod/app/STRIPE_KEY": ["api.stripe.com"]
}
```

Keys are references exactly as written in a tool call, so an entry grants hosts
to one secret in one Store — never to a bare id two Stores might both claim.

## Wire into Claude Code

```bash
claude mcp add secrets -- env BWS_ACCESS_TOKEN=<token> BWS_ORGANIZATION_ID=<org-id> npx -y @ivaisoft/secrets-webauthn-mcp

# or AWS-only, no Bitwarden at all:
claude mcp add secrets -- env AWS_REGION=us-east-1 AWS_ACCESS_KEY_ID=<id> AWS_SECRET_ACCESS_KEY=<key> npx -y @ivaisoft/secrets-webauthn-mcp
```

or in `~/.claude/settings.json`:

```json
{
  "mcpServers": {
    "bws": {
      "command": "npx",
      "args": ["-y", "@ivaisoft/secrets-webauthn-mcp"],
      "env": { "BWS_ACCESS_TOKEN": "<token>", "BWS_ORGANIZATION_ID": "<org-id>" }
    }
  }
}
```

From a local clone instead, replace `command`/`args` with
`"node"` / `["/path/to/secrets-webauthn-mcp/dist/index.js", "serve"]`.

The approval server binds an **auto-picked free port** on `127.0.0.1`; the
approval URL uses it. There is no fixed port to configure.

## Wire into Postman (or any other MCP client)

The `mcpServers` block above is the standard config format, so most clients
take it as-is. In Postman, add an **MCP request** (**+** icon → **MCP** in the
sidebar), pick **STDIO**, and either enter the command directly:

```
npx -y @ivaisoft/secrets-webauthn-mcp
```

…or paste the JSON config. Use Postman **variables** rather than literal
values, and define them in the Environment tab as secrets — otherwise the
access token is stored in plain text in a collection you might share:

```json
{
  "mcpServers": {
    "secrets-webauthn-mcp": {
      "command": "npx",
      "args": ["-y", "@ivaisoft/secrets-webauthn-mcp"],
      "env": {
        "BWS_ACCESS_TOKEN": "{{bws_access_token}}",
        "BWS_ORGANIZATION_ID": "{{bws_organization_id}}"
      }
    }
  }
}
```

Then **Load Capabilities** to see the three tools. `list_secrets` returns
immediately; `http_request`/`run_with_secret` return
`status: "approval_required"` with an `approve_url` you open in a real browser
and approve with Touch ID / passkey, then re-send the identical request.

Choosing **HTTP** (`http://127.0.0.1:8787/mcp`, with `serve --http` running)
also works, with one caveat: the DNS-rebinding guard rejects any unrecognized
`Origin` with a `403`. Non-browser clients don't send one and pass fine — but
if your client does, use STDIO instead.

## Streamable HTTP (opt-in, loopback-only)

stdio is the default and is the more restrictive option — only the process a
client directly spawns can talk to it. `serve --http` instead runs the MCP
session over Streamable HTTP on `127.0.0.1:SECRETS_HTTP_PORT` (default `8787`), so
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
| `BWS_ACCESS_TOKEN` | — | machine-account token; **enables the Bitwarden Store** |
| `BWS_ORGANIZATION_ID` | — | required **iff** `BWS_ACCESS_TOKEN` is set (a machine account belongs to exactly one org) |
| `BWS_API_URL` / `BWS_IDENTITY_URL` | bitwarden.com | set for EU / self-host |
| `AWS_REGION` | — | **enables the AWS Stores** |
| `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` / `AWS_SESSION_TOKEN` | — | static-keys mode |
| `AWS_SSO_START_URL` / `AWS_SSO_REGION` / `AWS_SSO_ACCOUNT_ID` / `AWS_SSO_ROLE_NAME` | — | SSO device-flow mode — all four together, or none |
| `SSM_PATH_PREFIX` | — | enables Parameter Store listing in `list_secrets`, scoped to this path (e.g. `/prod/app`) |
| `SECRETS_GATE_TIMEOUT_MS` | `120000` | how long the tool waits for the Approval |
| `SECRETS_HTTP_PORT` | `8787` | only read by `serve --http` |
| `SECRETS_REUSE_MAX_MS` | `0` (off) | longest Reuse Window a human may grant at the Gate |
| `SECRETS_REUSE_MAX_USES` | `5` | most runs one Reuse Window may cover |

At least one Store must be configured or startup fails. Setting `AWS_REGION`
without an AWS credential is an error too — never a silent fall-through to
`~/.aws`, which is the whole point of ADR 0009.

Give the AWS credential the smallest policy that works: `ssm:GetParameter` and
`secretsmanager:GetSecretValue` on an ARN **prefix**, plus `kms:Decrypt` for the
key that encrypts them. No `DescribeParameters`, no `ListSecrets`, no
`Resource: "*"`. `GetParametersByPath` is only needed if you set `SSM_PATH_PREFIX`
to enable listing, and it scopes to the same prefix you already grant reads on.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["ssm:GetParameter", "ssm:GetParametersByPath"],
      "Resource": "arn:aws:ssm:us-east-1:123456789012:parameter/prod/app/*"
    },
    {
      "Effect": "Allow",
      "Action": ["secretsmanager:GetSecretValue"],
      "Resource": "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/*"
    },
    {
      "Effect": "Allow",
      "Action": ["kms:Decrypt"],
      "Resource": "arn:aws:kms:us-east-1:123456789012:key/<key-id>"
    }
  ]
}
```

## What this does and does not protect

- **Protects**: the *release* of a secret. No value leaves any Store without a
  fresh physical touch, and the value is never returned to the conversation — the
  agent only ever gets the HTTP response or the child's output. That holds
  because no Store's credential is reachable from the agent — including AWS,
  which is why the ambient credential chain is refused
  ([ADR 0009](./docs/adr/0009-aws-credentials-not-ambient-not-from-a-store.md)):
  an `aws sso login` cache readable by the agent would make the Gate decorative.
- **A Reuse Window trades replay for friction.** Granting "10 minutes, up to 5
  runs" authorizes up to five executions of that exact call, and you cannot know
  how many will happen. Harmless for a `select 1`; not harmless for a deploy, a
  `DELETE`, or anything that charges a card. That is why the run count exists
  alongside the clock, and why the whole feature is off until you set
  `SECRETS_REUSE_MAX_MS` ([ADR 0011](./docs/adr/0011-reuse-window-bounded-by-time-and-runs.md)).
- **Does not undo a Consumer that reflects the secret**: if the endpoint or command
  you invoke prints the injected value back, it returns to the agent — documented,
  not enforced (same caveat as `bws run`).
- **Local only.** The `localhost` rpID trick means this must run as a local stdio
  server. Behind a real domain, WebAuthn re-binds to that domain and the model
  changes (see [ADR 0003](./docs/adr/0003-local-stdio-only-not-clustered.md)).
- **`list_secrets` exposes Bitwarden names, not values, without a touch.** Any
  agent that can call it can enumerate your Bitwarden secret ids and key names —
  the same information your access token already exposes via `bws secret list`,
  just made convenient for the agent. If that's not acceptable for your threat
  model, don't wire this tool up (see [ADR 0005](./docs/adr/0005-list-secrets-ungated-metadata-only.md)).
  **SSM Parameter Store enumerates only under `SSM_PATH_PREFIX`** — never the
  whole account — and **AWS Secrets Manager never enumerates**, because its
  listing API cannot be scoped by IAM at all. So no agent can map your parameter
  tree beyond the prefix you chose, and the policy never needs an account-wide
  grant ([ADR 0010](./docs/adr/0010-aws-stores-are-not-enumerable.md)).

## Audit log

Every `http_request`/`run_with_secret` attempt appends one JSONL line to
`~/.config/secrets-webauthn-mcp/audit.log` (`{ ts, tool, secret_refs, host|argv0,
verified, reused }`) — never the value. `reused: true` marks a run covered by a
Reuse Window rather than a fresh sensor press, so the trail never claims a touch
that did not happen. `list_secrets` calls are not audited: it never
touches a specific secret's value, so there's no "use" to record.

## Selfcheck

```bash
npm run selfcheck   # pure-logic checks (no vault access, no browser)
```

## Roadmap

See [ROADMAP.md](./ROADMAP.md) for planned/considered future work.
