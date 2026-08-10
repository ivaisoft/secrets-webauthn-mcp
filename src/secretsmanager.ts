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

/** AWS appends a random 6-character suffix to a secret's ARN — it is part of the
 *  ARN, never part of the name. Copying `…:secret:app/staging/token-vPtF1m` out
 *  of the console and using the tail as a reference is the single most common
 *  way to address a Secrets Manager secret wrongly: GetSecretValue accepts the
 *  friendly name OR the full ARN, and name-plus-suffix is neither. */
const ARN_SUFFIX = /-[A-Za-z0-9]{6}$/;

/**
 * Turn "Secrets Manager can't find the specified secret." into something that
 * says which reference was tried and, when the id carries what looks like an ARN
 * suffix, what to try instead. AWS's own message is accurate and useless: it
 * names nothing and suggests nothing.
 */
export function notFoundHint(err: unknown, id: string): unknown {
  const name = err && typeof err === "object" && "name" in err ? String((err as { name: unknown }).name) : "";
  if (name !== "ResourceNotFoundException") return err;

  const suffix = ARN_SUFFIX.exec(id);
  const base = `Secrets Manager has no secret "${id}" in this account and region.`;
  if (!suffix) {
    return new Error(`${base} Pass the secret's name, or its full ARN.`);
  }
  // Phrased as a possibility: a real name is allowed to end this way.
  return new Error(
    `${base} "${suffix[0]}" looks like the 6-character suffix AWS appends to the ` +
      `ARN, which is not part of the secret's name — try ` +
      `"${id.slice(0, -suffix[0].length)}", or pass the full ARN including "arn:aws:secretsmanager:".`,
  );
}

export function createSecretsManagerStore(auth: AwsAuth): SecretStore {
  // Region and credentials are always explicit — never resolved from ~/.aws
  // or the default provider chain (ADR 0009).
  const client = new SecretsManagerClient({ region: auth.region, credentials: auth.credentials });

  return {
    async getSecret(id: string): Promise<SecretHandle> {
      let result;
      try {
        result = await client.send(new GetSecretValueCommand({ SecretId: id }));
      } catch (err) {
        throw notFoundHint(err, id);
      }
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
