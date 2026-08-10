// The AWS SSM Parameter Store Store. A thin adapter: one id in, one value out.
// `#subkey` selection is the registry's job (store.ts), so JSON parameters
// behave identically here and in every other Store.
//
// Deliberately implements no listSecrets (ADR 0010): enumerating parameters
// needs ssm:DescribeParameters, which AWS does not support at resource level
// and therefore requires Resource:"*" — an account-wide grant that reading N
// known parameters does not need.
import { GetParameterCommand, SSMClient } from "@aws-sdk/client-ssm";
import type { AwsAuth } from "./aws-credentials.js";
import { lastPathSegment } from "./secret-ref.js";
import type { SecretHandle, SecretStore } from "./store.js";

export function createSsmStore(auth: AwsAuth): SecretStore {
  // Region and credentials are always explicit — never resolved from ~/.aws
  // or the default provider chain (ADR 0009).
  const client = new SSMClient({ region: auth.region, credentials: auth.credentials });

  return {
    async getSecret(id: string): Promise<SecretHandle> {
      const result = await client.send(new GetParameterCommand({ Name: id, WithDecryption: true }));
      const value = result.Parameter?.Value;
      if (value === undefined) throw new Error(`SSM parameter "${id}" has no value`);
      // Default env var name is the last path segment: /prod/app/STRIPE_KEY -> STRIPE_KEY.
      return { key: lastPathSegment(id), value };
    },
  };
}
