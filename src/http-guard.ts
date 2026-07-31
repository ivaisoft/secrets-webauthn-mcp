// Pure Host/Origin allowlist check for the optional HTTP transport (see
// http-serve.ts). Kept dependency-free so selfcheck can exercise it without
// pulling in the vault binding or starting a server.
//
// Host is always required and must be an allowed host:port. Origin is checked
// only when the browser sends one — non-browser MCP clients (Claude Code, curl)
// typically omit it. This is the DNS-rebinding defense: a malicious web page's
// fetch() carries the PAGE's origin even when the request targets 127.0.0.1, so
// rejecting any unrecognized Origin blocks that page from ever reaching this
// server, regardless of what its own JS tries to send as Host.
export function isAllowedRequest(
  host: string | undefined,
  origin: string | undefined,
  allowedHostPorts: readonly string[],
): boolean {
  if (host === undefined || !allowedHostPorts.includes(host)) return false;
  if (origin === undefined) return true;
  return allowedHostPorts.some((hp) => origin === `http://${hp}`);
}
