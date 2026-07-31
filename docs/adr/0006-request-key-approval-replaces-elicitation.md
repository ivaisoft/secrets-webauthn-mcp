# Request-key re-check replaces MCP elicitation as the Gate's mechanism

The Gate originally worked by having a tool call block on
`mcpLow.elicitInput({mode:"url", ...})`, an MCP protocol round-trip that
depends on the *client* implementing elicitation and rendering the resulting
dialog. In practice, not every MCP client does — a real client ("Cowork") was
found to have no way to surface the elicitation prompt at all, so
`http_request`/`run_with_secret` simply hung forever in it: correctly-approved
secrets were unreachable, not more safely gated. A security mechanism that
silently does nothing in clients that don't support its transport isn't a
mechanism there — it's a bug that happens to look like one everywhere else.

The Gate was rewritten to not depend on any optional client capability at all:

1. `requestKey(tool, args)` (`src/request-key.ts`) deterministically hashes a
   tool call, so the exact same call always produces the same key.
2. A tool call whose key has no verified pending entry registers one and
   returns **plain tool-result text** — not an elicitation request — with the
   Approval URL and instructions to re-issue the identical call. This works
   with any MCP client, because every MCP client can display a tool's text
   result; not every one can render elicitation.
3. The human opens that URL and approves via WebAuthn, exactly as before —
   only the delivery of "please approve" changed, not the physical ceremony.
4. Re-issuing the identical call finds the key already verified, **consumes**
   it (single-use — this is not a cache; ADR 0002 still holds), and proceeds.

Considered and rejected: keeping elicitation for clients that support it and
falling back to this mechanism only for those that don't. Rejected for
maintaining two gating code paths (and two sets of tests) for a problem fully
solved by the simpler one — and the simpler one has a real advantage even for
elicitation-capable clients: the Approval URL and status survive an agent
restart or a dropped connection, since it isn't tied to a single blocked
protocol round-trip that vanishes if the client goes away.
