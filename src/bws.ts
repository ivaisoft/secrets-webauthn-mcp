// Bitwarden Secrets Manager access. The access token lives ONLY inside this
// process; it is never returned, logged, or placed in any child environment.
import { BitwardenClient } from "@bitwarden/sdk-napi";
import type { ServeEnv } from "./schemas.js";

// LogLevel is a `const enum` in @bitwarden/sdk-napi (not exported at runtime).
// 4 === LogLevel.Error — keeps the native binding quiet on stderr.
const LOG_LEVEL_ERROR = 4;

export interface SecretHandle {
  /** The Bitwarden key name — used as the default env var name in run_with_secret. */
  key: string;
  /** The plaintext value. Held only transiently; never returned to the agent. */
  value: string;
}

/** Identifier only — deliberately has no `value` field, so there is nothing to
 *  mask: list_secrets destructures exactly these two fields, never the raw SDK
 *  object, so a future SDK version adding fields here can't leak through it. */
export interface SecretIdentifier {
  id: string;
  key: string;
}

export interface BwsGateway {
  getSecret(id: string): Promise<SecretHandle>;
  listSecrets(): Promise<SecretIdentifier[]>;
}

export async function connectBws(env: ServeEnv): Promise<BwsGateway> {
  const client = new BitwardenClient(
    {
      apiUrl: env.BWS_API_URL,
      identityUrl: env.BWS_IDENTITY_URL,
      userAgent: "bws-webauthn-mcp",
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
      const res = await client.secrets().list(env.BWS_ORGANIZATION_ID);
      // Explicit destructure, not a spread: even though this SDK's list() has no
      // `value` field today, never forward the raw item — only what we named above.
      return res.data.map((item) => ({ id: item.id, key: item.key }));
    },
  };
}
