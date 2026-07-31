# Local stdio-only; not deployed to the cluster

This server runs locally as a stdio MCP server, not on the k3s cluster like the
other MCP proxies. The WebAuthn Gate depends on the approval page being served
from `localhost` (a secure context over plain http, and a valid RP ID). Behind a
real domain the authenticator re-binds to that domain and the "physical device on
this machine" model changes. The trade-off is no remote/shared access: the Gate
and the machine that holds the token are the same machine.

This still holds for the optional HTTP transport added in
[ADR 0004](./0004-optional-streamable-http-transport-loopback-only.md): it is bound
to `127.0.0.1` only, never remote, and the Gate's RP ID stays `localhost`.
