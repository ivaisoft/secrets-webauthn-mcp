# 0012 — Stores connect on first use, not at startup

**Status:** accepted

## Context

The Bitwarden Store exchanged its access token during startup: `connectStores`
awaited `client.auth().loginAccessToken(...)` before the server registered a
single tool. Any failure there threw out of `main`, and the process exited 1
with one line on stderr.

That line is not visible to an MCP client. Both transports this server supports
carry MCP messages, not process output — stdio *is* the protocol channel, and a
server that dies before the handshake has said nothing on it. What the client
reports is the transport closing. In Postman, in full:

```
Couldn't run the request: Connection closed
```

Which is the same message that server would produce for a wrong command path, a
missing `node`, a syntax error, or a crash in an unrelated module. Nothing in it
mentions Bitwarden, credentials, or which of the configured Stores failed. This
cost a user a debugging session, and was only identified by running the
published artifact by hand and reading stderr directly.

The failure modes that reach this path are not exotic; they are the expected
lifecycle of a credential:

- a rotated or revoked `BWS_ACCESS_TOKEN`
- a malformed one (a truncated copy-paste rejected while parsing, no network involved)
- a machine that is offline, behind a proxy, or on a network that cannot reach
  `identity.bitwarden.com`
- a platform where `@bitwarden/sdk-napi` has no prebuilt

The last one had already been recognised: `connect-stores.ts` imports `bws.js`
dynamically so that an AWS-only server never loads the native binding, with a
comment saying the process would otherwise "die before speaking a single byte of
MCP". That reasoning was right and simply did not go far enough — it protected
the server only when Bitwarden was *unconfigured*, which is the case that had no
problem. Configure Bitwarden and both the binding load and the token exchange
moved back onto the startup path.

## Decision

Connecting a Store may not happen while the server is starting.

`connectStores` now builds the Bitwarden Store as a handle that does nothing.
The dynamic import and the token exchange both run on the first call that needs
Bitwarden, memoised so concurrent calls share one attempt.

Consequences of that placement:

- **A broken Store is now a tool error, not a dead transport.** It arrives on
  the call that needed it, with a message naming the Store, quoting the
  underlying reason, and saying which variable to fix.
- **Failure is isolated per Store.** A server configured for Bitwarden *and* AWS
  keeps serving `ssm:` and `secretsmanager:` references with Bitwarden broken.
  Previously one bad credential took down access to every Store.
- **A failed attempt is not memoised.** Tokens get rotated and networks come
  back; a retry costs one round trip on a call that would otherwise fail anyway.
- **`listSecrets` is declared unconditionally** on the handle. The registry
  decides what is enumerable from the method's presence (ADR 0005), and that
  decision must not wait on a network call.
- **The token is redacted** out of any relayed upstream message, in case the SDK
  ever quotes the input it rejected — the same care `selectSubkey` takes with
  `JSON.parse` errors.

## Trade-off

This reverses a stated intent. `BWS_ORGANIZATION_ID` is marked required in the
schema specifically so that "misconfiguration fails at startup, not with a
confusing error the first time list_secrets is called" — and fail-fast on a bad
credential is a defensible reading of the same principle.

The distinction we settled on is **what the check can see**:

- **Shape is checked at startup, and still is.** Whether the variables are
  present and consistent is knowable locally, instantly, and cannot change while
  the server runs. Getting it wrong is a configuration error the operator can
  fix from the message alone. The env schema keeps doing this.
- **Validity cannot be.** Whether a token is *accepted* depends on Bitwarden's
  state and the network, is not knowable without a round trip, and can change
  from valid to invalid while the server is running. It was never actually
  fail-fast — a token that expired after startup produced a first-use error
  regardless. Checking at startup bought a narrower window, not a guarantee, and
  paid for it with a failure mode that is invisible to every client.

The real cost is that a Bitwarden misconfiguration is now discovered on first
use rather than at launch. We accept it because "discovered later, with an
explanation" beats "discovered at launch, as `Connection closed`".

What partly covers the gap already is `list_secrets`: it is ungated (ADR 0005),
so it needs no Approval, and it enumerates every enumerable Store — which means
calling it is what forces the deferred sign-in and reports per-Store failures
under "Stores that failed to list". It is a probe of every Store that can
enumerate, not of every Store; `secretsmanager:` cannot be reached this way
(ADR 0010).

There is deliberately no eager probe on startup, and `selfcheck` is not one:
it is pure-logic by construction — no network, no vault, no hardware. A
connectivity check belongs in the `doctor` command on the roadmap, which is the
right shape for it, since it can report on every Store instead of dying on the
first failure.

The AWS Stores needed no change — the AWS SDK constructs clients without
contacting anything and signs on first request, which is this decision already.
