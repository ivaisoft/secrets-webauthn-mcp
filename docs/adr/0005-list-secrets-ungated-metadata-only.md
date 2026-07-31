# `list_secrets` is ungated — metadata only, never a value

`list_secrets` returns every secret's `id` and `key` (name) in the configured
organization and, unlike `http_request`/`run_with_secret`, does **not** require
a WebAuthn Approval. This is a deliberate exception to "every use goes through
the Gate": the Gate exists to stop a prompt-injected agent from exfiltrating a
secret *value* (ADR 0001), and `list_secrets` never fetches or returns one —
the SDK's `secrets().list()` binding doesn't even include a value field. Without
this tool, using `http_request`/`run_with_secret` requires already knowing a
secret's UUID by name, which in practice meant copying IDs out of the Bitwarden
UI/CLI by hand for every reference.

The trade-off, made consciously: secret **names** (and the fact that they
exist) are still information, and a prompt-injected agent can now enumerate
your organization's secret topology (e.g. that `STRIPE_PROD_KEY` exists)
without a touch. This is judged acceptable because it's the same category of
information Bitwarden's own UI, `bws secret list`, and the vault's own audit
log already expose to anyone with the access token — this tool adds no new
disclosure beyond what the token already grants, it just makes discovery
convenient for the agent instead of requiring a human to paste IDs in by hand.

Implementation detail worth keeping, not just a style preference: both the
`BwsGateway.listSecrets()` implementation (`bws.ts`) and the tool handler
(`tools.ts`) independently destructure the result down to `{ id, key }` rather
than forwarding whatever the SDK returns — two layers, deliberately, so a
future SDK version adding fields (or a bug in either layer) can't silently
widen what this tool exposes.
