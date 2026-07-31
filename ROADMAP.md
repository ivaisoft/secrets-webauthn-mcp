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
- **`doctor` command.** A `bws-webauthn-mcp doctor` that checks common
  misconfiguration up front: missing `BWS_ORGANIZATION_ID`, an empty
  `allowlist.json`, no registered credentials, or — the one that actually bit
  us — a browser/OS routing WebAuthn "platform" requests through a password
  manager instead of Touch ID.
- **Allowlist management tool.** `allowlist.json` is hand-edited today. A
  `list_secrets`-adjacent read tool (or a companion CLI command) to show the
  current mapping would remove a step, without needing a *write* tool (which
  would be a real, separate security decision — an agent that can edit its
  own allowlist is a different threat model).

## Under consideration

- **Audit log rotation/query.** The JSONL trail just grows; no rotation, no
  built-in way to query it beyond `grep`/`jq`.
- **Multi-organization `list_secrets`.** Currently one `BWS_ORGANIZATION_ID`
  per server instance; a machine account scoped to multiple orgs would need
  this to accept an org id per call.

## Explicitly not planned (by design, not oversight)

- **No cache, no standing pre-approval.** ADR 0002 exists precisely because
  this was considered and rejected for the threat model.
- **No way to bypass the Gate for automation/CI.** The physical Approval is
  the point; a headless bypass would undo it.
