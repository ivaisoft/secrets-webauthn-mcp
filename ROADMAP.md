# Roadmap

Ideas for future work, not commitments or a schedule. Anything touching the
security model (the Gate, the allowlist, the audit trail) gets the same
scrutiny as the existing design — see [docs/adr](./docs/adr) for the
reasoning behind what's already here before assuming a "should" below is easy.

## Likely

- **Linux/Windows verification.** Only verified on macOS (darwin-arm64,
  where `@bitwarden/sdk-napi`'s prebuilt native binding is confirmed). CI
  currently runs on `macos-latest` for this reason (see
  [ADR 0003](./docs/adr/0003-local-stdio-only-not-clustered.md)). Widening
  this needs confirming the native binding actually resolves elsewhere first.
- **`doctor` command.** A `secrets-webauthn-mcp doctor` that checks common
  misconfiguration up front: missing `BWS_ORGANIZATION_ID`, an empty
  `allowlist.json`, no registered credentials, or — the one that actually bit
  us — a browser/OS routing WebAuthn "platform" requests through a password
  manager instead of Touch ID. It is also where a **Store connectivity probe**
  belongs: since [ADR 0012](./docs/adr/0012-stores-connect-on-first-use-not-at-startup.md)
  Stores connect on first use, so nothing checks a credential until something
  needs it. `list_secrets` covers the enumerable Stores; `doctor` could report on
  all of them at once, and deliberately, rather than dying at startup on the first
  failure the way this server used to.
- **Allowlist *read* tool.** A blocked `http_request` now offers a link to grant
  that one host for that one reference after a touch, so the file is no longer
  hand-edited in practice. What is still missing is a way to *see* the current
  mapping — a `list_secrets`-adjacent read tool, or a CLI command.
  The distinction this entry originally drew still holds and is why the grant
  is a page rather than a tool: **an agent that can edit its own allowlist is a
  different threat model.** The write exists, but the agent cannot perform it —
  it only receives a URL, and a human authorizes the change with the sensor, on
  a screen that cannot also approve a secret use.

## Under consideration

- **Audit log rotation/query.** The JSONL trail just grows; no rotation, no
  built-in way to query it beyond `grep`/`jq`.
- **Multi-organization `list_secrets`.** Currently one `BWS_ORGANIZATION_ID`
  per server instance; a machine account scoped to multiple orgs would need
  this to accept an org id per call.
- **Multi-region / multi-account AWS.** One `AWS_REGION` per server instance,
  the same shape of limit as the single org above. A reference would have to
  carry the region (`ssm:us-east-1:/prod/…`), which lengthens the string a
  human reads at the Gate — worth doing only when there is a real second region.
- **AWS SSO re-login without a restart.** The device flow runs once at startup
  and the credential lives in memory; when the session expires, AWS Store calls
  fail with "restart the server". Re-running the flow in place would mean
  surfacing a new verification code mid-session — the Gate's own port is the
  obvious place, but it is a second interactive flow to maintain.

## Explicitly not planned (by design, not oversight)

- **No cache, no standing pre-approval.** ADR 0002 exists precisely because
  this was considered and rejected for the threat model. A **Reuse Window**
  (ADR 0011) is not that: it covers one byte-identical request, bounded by time
  and by run count, and is off unless enabled in config *and* chosen at the
  Gate. A window keyed on a secret rather than a request stays rejected.
- **No `env:` Store for values already in the environment.** Proposed as
  `secret_refs: ["env:XXX_TOKEN"]`, fed by `"XXX_TOKEN": "${XXX_TOKEN}"` in the
  MCP client config. Note the substitution is the *client's* feature, not this
  server's — the server only ever sees the resolved value. Rejected because
  `${XXX_TOKEN}` expands from the shell that launched the client, and an agent
  with a shell tool reads that same environment directly: the Gate would be
  decorative for exactly the secrets it appears to protect, the ambient-credential
  problem of [ADR 0009](./docs/adr/0009-aws-credentials-not-ambient-not-from-a-store.md)
  in a new costume. And it buys little even where it holds: `run_with_secret`
  already passes the server's environment to the child by inheritance, so such a
  value reaches the command with no Gate and no new code. A Store would have
  added only the audit line and keeping it out of the transcript — not worth the
  surface, which would have needed a name allowlist (or `env:AWS_SECRET_ACCESS_KEY`
  would hand over a Store credential for one Approval) plus stripping every
  listed variable from the child env.
- **No "always allow this command" prefix rule.** Asked for as the equivalent of
  a coding agent's always-allow, e.g. trust `psql` and stop being asked.
  Rejected because the unit is wrong: approving a *binary* approves every
  argument it will ever be given, and for the tools people reach for that is
  unbounded — `psql` alone reaches `COPY ... TO PROGRAM`, `aws` reaches every
  API, `curl` reaches every host. It would be a standing grant of arbitrary
  execution with a secret injected, which is a larger hole than the cache
  ADR 0002 rejected, since a cache at least expired. The real need — iterating
  on one command without touching the sensor each time — is what a **Reuse
  Window** (ADR 0011) covers, bounded to the byte-identical call and to a run
  count; raise `SECRETS_REUSE_MAX_MS` / `SECRETS_REUSE_MAX_USES` if it is too
  tight in practice.
- **No way to bypass the Gate for automation/CI.** The physical Approval is
  the point; a headless bypass would undo it.
- **No dual / M-of-N Approval.** Raised while designing multi-Store support,
  where it would have meant one Approval to unlock the AWS credential held in
  Bitwarden and a second to read the parameter. That shape no longer exists —
  no Store bootstraps another's credential
  ([ADR 0009](./docs/adr/0009-aws-credentials-not-ambient-not-from-a-store.md)),
  so there is no second barrier for a second Approval to guard. One Approval is
  one assertion authorizing one use.
- **No ambient AWS credentials.** `aws sso login`'s cache is readable by any
  process running as you, including the agent — see ADR 0009 for why that would
  make the Gate decorative for the AWS Stores.
