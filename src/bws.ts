// The Bitwarden Secrets Manager Store. The access token lives ONLY inside this
// process; it is never returned, logged, or placed in any child environment.
//
// This is the one Store that enumerates: Bitwarden ids are opaque UUIDs, so
// without list_secrets every reference would have to be copied out of the
// Bitwarden UI by hand (ADR 0005). The AWS Stores need no equivalent — their
// references are self-describing names (ADR 0010).
import { BitwardenClient } from "@bitwarden/sdk-napi";
import type { BwsEnv } from "./schemas.js";
import type { SecretHandle, SecretIdentifier, SecretStore } from "./store.js";

// LogLevel is a `const enum` in @bitwarden/sdk-napi (not exported at runtime).
// 4 === LogLevel.Error — keeps the native binding quiet on stderr.
const LOG_LEVEL_ERROR = 4;

export async function createBwsStore(env: BwsEnv): Promise<SecretStore> {
  if (!env.BWS_ACCESS_TOKEN || !env.BWS_ORGANIZATION_ID) {
    // Unreachable via loadServeEnv (superRefine rejects this pairing), but the
    // Store must not depend on a caller having checked.
    throw new Error("the Bitwarden Store needs both BWS_ACCESS_TOKEN and BWS_ORGANIZATION_ID");
  }
  const organizationId = env.BWS_ORGANIZATION_ID;

  const client = new BitwardenClient(
    {
      apiUrl: env.BWS_API_URL,
      identityUrl: env.BWS_IDENTITY_URL,
      userAgent: "secrets-webauthn-mcp",
    },
    LOG_LEVEL_ERROR,
  );
  await client.auth().loginAccessToken(env.BWS_ACCESS_TOKEN);

  return {
    async getSecret(id: string): Promise<SecretHandle> {
      const secret = await client.secrets().get(id);
      return { key: secret.key, value: secret.value };
    },
    async listSecrets(): Promise<SecretIdentifier[]> {
      const res = await client.secrets().list(organizationId);
      // Explicit destructure, not a spread: even though this SDK's list() has no
      // `value` field today, never forward the raw item — only what we named above.
      return res.data.map((item) => ({ id: item.id, key: item.key }));
    },
  };
}
