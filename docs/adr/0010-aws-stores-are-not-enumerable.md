# Enumeration is allowed exactly as far as IAM can scope it

`list_secrets` enumerates the Bitwarden Store always, the SSM Parameter Store
under an explicitly configured path prefix, and AWS Secrets Manager never. The
rule underneath is one line: **a Store may enumerate only if the permission to
enumerate can be scoped no wider than the permission to read.**

This narrows [ADR 0005](./0005-list-secrets-ungated-metadata-only.md), whose
argument for an ungated listing does not survive the move to AWS unchanged.

> **Correction.** This ADR originally concluded that *neither* AWS Store could
> enumerate, on the grounds that `ssm:DescribeParameters` requires
> `Resource: "*"`. That is true of `DescribeParameters` and false of the call
> that should have been considered: `ssm:GetParametersByPath` **does** support
> resource-level permissions, so listing under a prefix needs no grant beyond
> the `GetParameter` on that same prefix. The conclusion below is corrected for
> SSM; it stands unchanged for Secrets Manager.

## Why 0005's reasoning does not carry unchanged

ADR 0005 justified an ungated listing on the grounds that it "adds no new
disclosure beyond what the token already grants." On AWS that is a property of
the specific API, not of the service:

| Call | Resource-level IAM | Verdict |
|---|---|---|
| `ssm:GetParametersByPath` | yes, on the **path** ARN — `parameter/prod/app`, not `parameter/prod/app/*` | enumerate, scoped to `SSM_PATH_PREFIX` |
| `ssm:DescribeParameters` | no, `Resource: "*"` | not used |
| `secretsmanager:ListSecrets` | no, `Resource: "*"` | never enumerates |

**Parameter paths are an infrastructure map.** `/prod/paperclip/db/password`
and `/staging/ombrello/stripe/secret` describe environments, applications and
topology at a level a flat list of Bitwarden key names does not. That is why SSM
listing is off unless a prefix is configured: enumerating from `/` would hand
over the whole map, which is the disclosure this ADR exists to prevent, even
though the IAM grant would technically permit scoping it.

The path ARN is the trap: `GetParameter` authorizes per parameter and matches
`parameter/prod/app/*`, while `GetParametersByPath` authorizes against the path
itself, which that wildcard does not match. A policy carrying only the wildcard
denies every list. The README grants both forms, which cover the same subtree
under either reading.

Listing uses `WithDecryption: false`, so `SecureString` values come back as KMS
ciphertext rather than plaintext — and the Store still destructures to
`{ id, key }` and never forwards the SDK item, the same two-layer discipline
ADR 0005 established.

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
