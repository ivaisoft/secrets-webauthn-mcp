# AWS credentials never come from the ambient chain, or from another Store

The Gate is only a Gate if the agent has no path to a secret that skips it
([ADR 0001](./0001-token-locked-in-server-gate-unbypassable.md)) — which is why
`BWS_ACCESS_TOKEN` lives only in this process. Adding AWS Stores asks the same
question again for AWS, and the standard answer is the wrong one. This server
therefore never calls `fromNodeProviderChain()` or `fromSSO()`, and never reads
`~/.aws/credentials`, `~/.aws/config`, or `~/.aws/sso/cache`. AWS credentials
enter by one of exactly two channels the agent cannot reach: static keys in this
process's own environment (the same trust model `BWS_ACCESS_TOKEN` already has),
or an SSO device-authorization flow this server runs itself, holding the token
in memory and never writing the CLI's cache.

## Considered options

**The ambient credential chain — `aws sso login` plus the default provider
chain.** The convenient answer, and it makes the Gate decorative for AWS.
`aws sso login` caches its token in `~/.aws/sso/cache/*.json`, readable by any
process running as the same user — and the adversary this server is built
against (SPEC's #2, a prompt-injected agent) *is* a process running as the same
user, with a shell. It would run `aws ssm get-parameter --with-decryption` and
never touch the sensor. The SPEC does exclude "local malware" from scope, but
that exclusion is about a stolen laptop, not about the primary adversary. A Gate
that a one-line shell command walks around is precisely the failure mode
[ADR 0006](./0006-request-key-approval-replaces-elicitation.md) was written
about.

**AWS credentials stored as a Bitwarden secret, fetched by this server.** This
preserves the invariant — the credential would live only in this process — and
was the initial recommendation. Rejected for the escalation it creates: that
secret is a master key, and `run_with_secret` deliberately allows arbitrary
`argv`, so a single plausible-looking Approval waved through by a tired human
leaks a credential that then reads every parameter in scope, forever, with no
Gate at all. Keeping the Stores as peers — none bootstrapping another's
credential — removes that class of bug instead of mitigating it.

## Consequences

Each Store's credential is independent, so Bitwarden stops being a required
dependency: the server runs with any subset of Stores configured.

This also retired **dual Approval** (two WebAuthn assertions per use), which was
only ever needed to guard the Bitwarden-bootstraps-AWS path — one Approval to
unlock the AWS credential, another to read the parameter. With no Store
unlocking another, there is no second barrier for a second Approval to protect,
and [CONTEXT.md](../../CONTEXT.md)'s definition stands unchanged: one Approval
is one assertion authorizing one use.

The invariant is testable, and should be tested rather than assumed: run the
server with `HOME` pointed at a directory containing a populated `~/.aws` and
assert it is ignored.
