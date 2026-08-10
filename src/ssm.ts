// The AWS SSM Parameter Store Store. A thin adapter: one id in, one value out.
// `#subkey` selection is the registry's job (store.ts), so JSON parameters
// behave identically here and in every other Store.
//
// This Store enumerates, but only under an explicitly configured path prefix,
// and only via GetParametersByPath — which unlike DescribeParameters supports
// resource-level IAM, so listing needs no permission wider than the read the
// caller already has (ADR 0010).
import { GetParameterCommand, GetParametersByPathCommand, SSMClient } from "@aws-sdk/client-ssm";
import type { AwsAuth } from "./aws-credentials.js";
import { lastPathSegment } from "./secret-ref.js";
import type { SecretHandle, SecretIdentifier, SecretStore } from "./store.js";

/** GetParametersByPath returns at most 10 per page, so a wide prefix means many
 *  round trips. This is a runaway guard, not a quota: hitting it throws rather
 *  than silently returning a truncated list that reads as "this is everything". */
const MAX_PAGES = 200;

export function createSsmStore(auth: AwsAuth, pathPrefix?: string): SecretStore {
  // Region and credentials are always explicit — never resolved from ~/.aws
  // or the default provider chain (ADR 0009).
  const client = new SSMClient({ region: auth.region, credentials: auth.credentials });

  const store: SecretStore = {
    async getSecret(id: string): Promise<SecretHandle> {
      const result = await client.send(new GetParameterCommand({ Name: id, WithDecryption: true }));
      const value = result.Parameter?.Value;
      if (value === undefined) throw new Error(`SSM parameter "${id}" has no value`);
      // Default env var name is the last path segment: /prod/app/STRIPE_KEY -> STRIPE_KEY.
      return { key: lastPathSegment(id), value };
    },
  };

  // No prefix, no listing. Enumerating from "/" would be enumerating the whole
  // account, which is exactly the grant this design refuses to need.
  if (pathPrefix === undefined) return store;

  return {
    ...store,
    async listSecrets(): Promise<SecretIdentifier[]> {
      const found: SecretIdentifier[] = [];
      let nextToken: string | undefined;
      let pages = 0;

      do {
        if (++pages > MAX_PAGES) {
          throw new Error(
            `SSM listing under "${pathPrefix}" exceeded ${MAX_PAGES} pages; ` +
              `narrow SSM_PATH_PREFIX rather than trusting a truncated list`,
          );
        }
        const result = await client.send(
          new GetParametersByPathCommand({
            Path: pathPrefix,
            Recursive: true,
            // Metadata only. SecureString values come back as KMS ciphertext
            // rather than plaintext, and are never read even so — see below.
            WithDecryption: false,
            ...(nextToken !== undefined ? { NextToken: nextToken } : {}),
          }),
        );
        for (const parameter of result.Parameters ?? []) {
          if (parameter.Name === undefined) continue;
          // Explicit construction, not a spread: the SDK item carries Value
          // (ciphertext here) plus ARN, Version and dates. Only these two
          // fields may ever leave this function — the same two-layer discipline
          // ADR 0005 established for the Bitwarden Store.
          found.push({ id: parameter.Name, key: lastPathSegment(parameter.Name) });
        }
        nextToken = result.NextToken;
      } while (nextToken !== undefined);

      return found;
    },
  };
}
