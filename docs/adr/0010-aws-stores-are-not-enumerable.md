# The AWS Stores are not enumerable; `list_secrets` stays Bitwarden-only

`list_secrets` returns the contents of the Bitwarden Store only. The SSM
Parameter Store and Secrets Manager Stores implement no `listSecrets` at all, so
this server's AWS credential never needs a permission beyond reading the
parameters it is actually asked for.

This is a deliberate narrowing of
[ADR 0005](./0005-list-secrets-ungated-metadata-only.md), whose argument for an
ungated listing does not survive the move to AWS.

## Why 0005's reasoning does not carry

ADR 0005 justified an ungated listing on the grounds that it "adds no new
disclosure beyond what the token already grants." Two things break that on AWS:

**The IAM grant is not narrowable.** `ssm:DescribeParameters` and
`secretsmanager:ListSecrets` have no resource-level form — AWS requires
`Resource: "*"`. So supporting enumeration would force this server's policy to
carry an account-wide grant, strictly wider than the `GetParameter` /
`GetSecretValue` on an ARN prefix that reading known secrets needs. That matters
most in the static-keys mode, where the credential is a long-lived value sitting
in an environment.

**Parameter paths are an infrastructure map.** `/prod/paperclip/db/password`
and `/staging/ombrello/stripe/secret` describe environments, applications and
topology at a level a flat list of Bitwarden key names does not.

## Why nothing is lost

ADR 0005 exists because Bitwarden ids are opaque UUIDs: without the tool,
"using `http_request`/`run_with_secret` requires already knowing a secret's UUID
by name, which in practice meant copying IDs out of the Bitwarden UI by hand."
AWS references have no such problem — `ssm:/prod/app/STRIPE_KEY` *is* the name,
and in this project's case those paths are already written down in the
ExternalSecrets manifests that consume them. The discovery pressure that
justified the exception simply is not present.

## Consequences

`run_with_secret`'s Approval message resolves a Bitwarden reference's real key
name before the Gate (ADR 0005) and shows `(not found via list_secrets)` when it
cannot — a typo is visible before the touch is spent. AWS references get no such
pre-flight: a wrong path fails after the Approval is consumed. The degradation
is smaller than it looks, because the reference shown at the Gate *is* the
name — `ssm:/prod/app/STRIP_KEY` is misspelled in a way a human can see, which a
wrong UUID never was.

`SecretStore.listSecrets` is therefore optional rather than required, and the
registry skips Stores that omit it instead of treating "cannot enumerate" as an
error.
