// Build the Store registry from the environment. Each Store is independent:
// none is required, none bootstraps another's credential (ADR 0009), and the
// server runs with any subset — the env schema only insists that it is at
// least one.
//
// Kept separate from store.ts so that module stays free of the Bitwarden native
// binding: tools.ts imports only types from store.ts, which is what lets the
// test suite exercise the tools without a platform-specific binding present.
//
// NOTHING here may reach the network or load a native binding. Connecting a
// Store must not be able to stop the server from starting, because a server
// that dies during startup tells an MCP client nothing at all: the client sees
// only "Connection closed", with no hint of which Store failed or why. That is
// not hypothetical — it is exactly what a malformed or stale BWS_ACCESS_TOKEN
// looked like from Postman before this was deferred. So the Bitwarden Store is
// built as a handle that imports @bitwarden/sdk-napi and exchanges its token on
// FIRST USE (see lazyBwsStore), and the AWS Stores only construct SDK clients,
// which sign lazily by design.
//
// Configuration is still validated up front: the env schema rejects a token
// without an organization id, and does so before anything starts. What moved is
// only what can fail for reasons outside the config — an expired credential, an
// unreachable identity service, a missing prebuilt.
import { resolveAwsAuth } from "./aws-credentials.js";
import type { ServeEnv } from "./schemas.js";
import type { StoreName } from "./secret-ref.js";
import { createSecretsManagerStore } from "./secretsmanager.js";
import { createSsmStore } from "./ssm.js";
import {
  createStoreRegistry,
  type SecretHandle,
  type SecretIdentifier,
  type SecretStore,
  type StoreRegistry,
} from "./store.js";

const errorMessage = (e: unknown): string => (e instanceof Error ? e.message : String(e));

/** Keep the credential out of a message we are about to hand to the agent, in
 *  case an upstream error ever quotes the input it rejected. */
function redact(message: string, secret: string | undefined): string {
  return secret ? message.split(secret).join("<redacted>") : message;
}

/**
 * A Bitwarden Store that has not connected yet.
 *
 * The native binding is imported and the access token exchanged on the first
 * call rather than at startup, so neither a platform without a prebuilt nor a
 * stale token can take the whole server down. The failure instead arrives as an
 * error on the one tool call that actually needed Bitwarden — where a human can
 * read it, and where the AWS Stores keep working regardless.
 *
 * A failed attempt is deliberately not memoised: tokens get rotated and networks
 * come back, and a retry costs one round trip on a call that would otherwise
 * just fail again.
 */
function lazyBwsStore(env: ServeEnv): SecretStore {
  let connecting: Promise<SecretStore> | undefined;

  function connect(): Promise<SecretStore> {
    connecting ??= (async () => {
      let create: typeof import("./bws.js").createBwsStore;
      try {
        ({ createBwsStore: create } = await import("./bws.js"));
      } catch (e) {
        throw new Error(
          "the Bitwarden Store could not load its native binding (@bitwarden/sdk-napi) " +
            `on this platform: ${errorMessage(e)}. The AWS Stores are unaffected; ` +
            "unset BWS_ACCESS_TOKEN to run without Bitwarden.",
        );
      }
      try {
        return await create(env);
      } catch (e) {
        throw new Error(
          `Bitwarden rejected this server's credential: ` +
            `${redact(errorMessage(e), env.BWS_ACCESS_TOKEN)}. Check that BWS_ACCESS_TOKEN ` +
            `is current and that this machine can reach ${env.BWS_IDENTITY_URL}.`,
        );
      }
    })().catch((err: unknown) => {
      connecting = undefined;
      throw err;
    });
    return connecting;
  }

  // listSecrets is declared unconditionally: Bitwarden is always enumerable
  // (ADR 0005), and the registry reads that capability off the object's shape —
  // a decision that must not wait on a network call.
  return {
    async getSecret(id: string): Promise<SecretHandle> {
      return (await connect()).getSecret(id);
    },
    async listSecrets(): Promise<SecretIdentifier[]> {
      const store = await connect();
      return store.listSecrets ? store.listSecrets() : [];
    },
  };
}

export async function connectStores(
  env: ServeEnv,
  log: (line: string) => void,
): Promise<StoreRegistry> {
  const stores: Partial<Record<StoreName, SecretStore>> = {};

  if (env.BWS_ACCESS_TOKEN !== undefined) {
    stores.bws = lazyBwsStore(env);
    log("Bitwarden Store enabled — signing in on the first bws: reference, not now");
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
