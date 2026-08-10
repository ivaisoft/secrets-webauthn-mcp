# Optional Streamable HTTP transport, loopback-only, opt-in

`serve` now has an opt-in `--http` mode (`serve --http`) that carries the MCP
*session* over Streamable HTTP on `127.0.0.1:<BWS_HTTP_PORT>` instead of stdio (the variable was renamed
`SECRETS_HTTP_PORT` when the server stopped being Bitwarden-only).
stdio remains the default: it is strictly more restrictive, since only the
process a client directly spawns can speak to it, whereas an HTTP listener on
loopback can in principle be reached by any local process — including a
malicious web page's JavaScript via DNS rebinding, which carries the page's
*Origin* even when the request targets `127.0.0.1`. Every request is therefore
checked against an allowed Host/Origin list before it reaches the MCP transport
(`src/http-guard.ts`), refusing anything that doesn't match — this is
implemented directly rather than via the SDK's `enableDnsRebindingProtection`,
which is deprecated in favor of exactly this kind of external check.

This does not weaken the Gate: WebAuthn Approval is still required per secret
use regardless of transport, and (per ADR 0003) the server still only binds to
loopback — this is a new way to *carry the protocol connection*, not a new way
to reach the vault or approve a secret.
