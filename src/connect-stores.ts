// Build the Store registry from the environment. Each Store is independent:
// none is required, none bootstraps another's credential (ADR 0009), and the
// server runs with any subset — the env schema only insists that it is at
// least one.
//
// Kept separate from store.ts so that module stays free of the Bitwarden native
// binding: tools.ts imports only types from store.ts, which is what lets the
// test suite exercise the tools without a platform-specific binding present.
//
// bws.js is imported lazily, and that is load-bearing rather than tidiness. It
// pulls in @bitwarden/sdk-napi, a native binding with prebuilts only for
// darwin-arm64; a static import would load it even on an AWS-only server, and
// on any platform where it fails to resolve the process would die before
// speaking a single byte of MCP — the client just sees the connection close,
// with no hint that an unconfigured Store caused it. "Bitwarden is optional"
// has to be true at module load, not only in the config. index.ts already
// defers heavy modules for exactly this reason.
import { resolveAwsAuth } from "./aws-credentials.js";
import type { ServeEnv } from "./schemas.js";
import type { StoreName } from "./secret-ref.js";
import { createSecretsManagerStore } from "./secretsmanager.js";
import { createSsmStore } from "./ssm.js";
import { createStoreRegistry, type SecretStore, type StoreRegistry } from "./store.js";

export async function connectStores(
  env: ServeEnv,
  log: (line: string) => void,
): Promise<StoreRegistry> {
  const stores: Partial<Record<StoreName, SecretStore>> = {};

  if (env.BWS_ACCESS_TOKEN !== undefined) {
    const { createBwsStore } = await import("./bws.js");
    stores.bws = await createBwsStore(env);
  }

  // One AWS credential serves both AWS Stores: they are the same account and
  // the same region, and splitting them would mean two logins for one identity.
  const aws = resolveAwsAuth(env, log);
  if (aws) {
    stores.ssm = createSsmStore(aws, env.SSM_PATH_PREFIX);
    stores.secretsmanager = createSecretsManagerStore(aws);
    log(
      `AWS Stores enabled in ${aws.region} — credential: ${aws.describe()}` +
        (env.SSM_PATH_PREFIX !== undefined
          ? `; Parameter Store listing scoped to ${env.SSM_PATH_PREFIX}`
          : "; Parameter Store listing off (set SSM_PATH_PREFIX to enable)"),
    );
  }

  return createStoreRegistry(stores);
}
