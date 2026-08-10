// The AWS Secrets Manager Store. A thin adapter: one id in, one value out.
//
// Secrets here are frequently JSON blobs holding several fields, which is what
// the `#subkey` half of a Secret Reference exists for — but the selection
// happens in the registry (store.ts), not here, so every Store treats JSON
// identically and there is one place where a parse error can never echo the
// value it failed to parse.
//
// Deliberately implements no listSecrets (ADR 0010): secretsmanager:ListSecrets
// has no resource-level form and would force an account-wide IAM grant.
import { GetSecretValueCommand, SecretsManagerClient } from "@aws-sdk/client-secrets-manager";
import type { AwsAuth } from "./aws-credentials.js";
import { lastPathSegment } from "./secret-ref.js";
import type { SecretHandle, SecretStore } from "./store.js";

export function createSecretsManagerStore(auth: AwsAuth): SecretStore {
  // Region and credentials are always explicit — never resolved from ~/.aws
  // or the default provider chain (ADR 0009).
  const client = new SecretsManagerClient({ region: auth.region, credentials: auth.credentials });

  return {
    async getSecret(id: string): Promise<SecretHandle> {
      const result = await client.send(new GetSecretValueCommand({ SecretId: id }));
      if (result.SecretString === undefined) {
        throw new Error(
          `Secrets Manager secret "${id}" holds binary data; only string secrets can be injected`,
        );
      }
      // An id may be an ARN, so prefer the friendly name AWS echoes back for the
      // default env var name; fall back to the reference's own last segment.
      return { key: lastPathSegment(result.Name ?? id), value: result.SecretString };
    },
  };
}
