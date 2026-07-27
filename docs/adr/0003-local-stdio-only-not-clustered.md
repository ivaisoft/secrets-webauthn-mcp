# Local stdio-only; not deployed to the cluster

This server runs locally as a stdio MCP server, not on the k3s cluster like the
other MCP proxies. The WebAuthn Gate depends on the approval page being served
from `localhost` (a secure context over plain http, and a valid RP ID). Behind a
real domain the authenticator re-binds to that domain and the "physical device on
this machine" model changes. The trade-off is no remote/shared access: the Gate
and the machine that holds the token are the same machine.
