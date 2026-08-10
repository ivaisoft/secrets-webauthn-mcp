// AWS credentials for the SSM / Secrets Manager Stores.
//
// ADR 0009 is the whole point of this file: the credential must arrive through
// a channel the agent cannot reach. So this module never constructs the default
// provider chain, never calls fromSSO(), and never reads ~/.aws/credentials,
// ~/.aws/config or ~/.aws/sso/cache. `aws sso login` caches its token in a file
// readable by every process running as the same user — including the
// prompt-injected agent this server exists to defend against, which would let
// it run `aws ssm get-parameter --with-decryption` and skip the Gate entirely.
//
// Exactly two channels are supported:
//   1. static keys in this process's own environment — the same trust model
//      BWS_ACCESS_TOKEN already has;
//   2. an SSO device-authorization flow this server runs itself, holding the
//      token in memory and never writing the CLI's cache.
import {
  CreateTokenCommand,
  RegisterClientCommand,
  SSOOIDCClient,
  StartDeviceAuthorizationCommand,
} from "@aws-sdk/client-sso-oidc";
import { GetRoleCredentialsCommand, SSOClient } from "@aws-sdk/client-sso";
import type { AwsEnv } from "./schemas.js";

/** Structurally what the AWS SDK v3 clients accept as explicit credentials. */
export interface AwsCredentials {
  accessKeyId: string;
  secretAccessKey: string;
  sessionToken?: string;
  expiration?: Date;
}

export type AwsCredentialProvider = () => Promise<AwsCredentials>;

export interface AwsAuth {
  region: string;
  credentials: AwsCredentialProvider;
  /** How the credential was obtained — reported by selfcheck/startup, never a value. */
  describe(): string;
}

/**
 * Refuse to resolve credentials from anywhere but the explicit provider.
 *
 * RegisterClient, StartDeviceAuthorization, CreateToken and GetRoleCredentials
 * are all unauthenticated operations, so the SDK should never ask. If a future
 * SDK version does ask, this fails loudly instead of quietly signing the
 * request with whatever `~/.aws` happens to contain — which is exactly the
 * silent fallback ADR 0009 forbids.
 */
const NO_AMBIENT_CREDENTIALS: AwsCredentialProvider = () => {
  throw new Error(
    "refusing to resolve AWS credentials from the ambient environment (ADR 0009): " +
      "this client should not require signing",
  );
};

const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

/** Narrow an SDK error to its modelled name without trusting `instanceof`. */
function errorName(err: unknown): string {
  if (err && typeof err === "object" && "name" in err) return String((err as { name: unknown }).name);
  return "";
}

type SsoState =
  | { status: "pending"; verificationUri: string; userCode: string }
  | { status: "ready"; credentials: AwsCredentials }
  | { status: "failed"; reason: string };

/**
 * Run the device-authorization flow and exchange the resulting token for role
 * credentials. Never touches disk: the OIDC client registration and the access
 * token exist only for the lifetime of this call.
 */
async function ssoDeviceFlow(
  env: Required<Pick<AwsEnv, "AWS_SSO_START_URL" | "AWS_SSO_REGION" | "AWS_SSO_ACCOUNT_ID" | "AWS_SSO_ROLE_NAME">>,
  onPrompt: (verificationUri: string, userCode: string) => void,
): Promise<AwsCredentials> {
  const oidc = new SSOOIDCClient({ region: env.AWS_SSO_REGION, credentials: NO_AMBIENT_CREDENTIALS });

  const client = await oidc.send(
    new RegisterClientCommand({
      clientName: "secrets-webauthn-mcp",
      clientType: "public",
      scopes: ["sso:account:access"],
    }),
  );

  const authorization = await oidc.send(
    new StartDeviceAuthorizationCommand({
      clientId: client.clientId,
      clientSecret: client.clientSecret,
      startUrl: env.AWS_SSO_START_URL,
    }),
  );

  const verificationUri = authorization.verificationUriComplete ?? authorization.verificationUri;
  if (!verificationUri || !authorization.userCode || !authorization.deviceCode) {
    throw new Error("AWS SSO did not return a device authorization challenge");
  }
  onPrompt(verificationUri, authorization.userCode);

  let intervalMs = (authorization.interval ?? 5) * 1000;
  const deadline = Date.now() + (authorization.expiresIn ?? 600) * 1000;

  while (Date.now() < deadline) {
    await sleep(intervalMs);
    try {
      const token = await oidc.send(
        new CreateTokenCommand({
          clientId: client.clientId,
          clientSecret: client.clientSecret,
          grantType: "urn:ietf:params:oauth:grant-type:device_code",
          deviceCode: authorization.deviceCode,
        }),
      );
      if (!token.accessToken) throw new Error("AWS SSO returned no access token");

      const sso = new SSOClient({ region: env.AWS_SSO_REGION, credentials: NO_AMBIENT_CREDENTIALS });
      const role = await sso.send(
        new GetRoleCredentialsCommand({
          accessToken: token.accessToken,
          accountId: env.AWS_SSO_ACCOUNT_ID,
          roleName: env.AWS_SSO_ROLE_NAME,
        }),
      );
      const creds = role.roleCredentials;
      if (!creds?.accessKeyId || !creds.secretAccessKey || !creds.sessionToken) {
        throw new Error("AWS SSO returned incomplete role credentials");
      }
      return {
        accessKeyId: creds.accessKeyId,
        secretAccessKey: creds.secretAccessKey,
        sessionToken: creds.sessionToken,
        ...(creds.expiration !== undefined ? { expiration: new Date(creds.expiration) } : {}),
      };
    } catch (err) {
      const name = errorName(err);
      // The human simply hasn't finished at the browser yet.
      if (name === "AuthorizationPendingException") continue;
      if (name === "SlowDownException") {
        intervalMs += 5000;
        continue;
      }
      if (name === "ExpiredTokenException") throw new Error("AWS SSO device authorization expired");
      throw err;
    }
  }
  throw new Error("AWS SSO device authorization expired before it was approved");
}

/**
 * Resolve how this server authenticates to AWS, or null when no AWS Store is
 * configured. The SSO flow is started but NOT awaited: blocking here would stall
 * the MCP handshake behind a human walking to their browser. Until it completes,
 * the provider throws a message naming the URL and code — the same shape as the
 * Gate's "not approved yet, here is what to do" text (ADR 0006), rather than a
 * tool call that hangs.
 */
export function resolveAwsAuth(env: AwsEnv, log: (line: string) => void): AwsAuth | null {
  if (!env.AWS_REGION) return null;

  if (env.AWS_ACCESS_KEY_ID && env.AWS_SECRET_ACCESS_KEY) {
    const credentials: AwsCredentials = {
      accessKeyId: env.AWS_ACCESS_KEY_ID,
      secretAccessKey: env.AWS_SECRET_ACCESS_KEY,
      ...(env.AWS_SESSION_TOKEN !== undefined ? { sessionToken: env.AWS_SESSION_TOKEN } : {}),
    };
    return {
      region: env.AWS_REGION,
      credentials: () => Promise.resolve(credentials),
      describe: () => "static keys from this process's environment",
    };
  }

  if (env.AWS_SSO_START_URL && env.AWS_SSO_REGION && env.AWS_SSO_ACCOUNT_ID && env.AWS_SSO_ROLE_NAME) {
    let state: SsoState = { status: "pending", verificationUri: env.AWS_SSO_START_URL, userCode: "…" };

    void ssoDeviceFlow(
      {
        AWS_SSO_START_URL: env.AWS_SSO_START_URL,
        AWS_SSO_REGION: env.AWS_SSO_REGION,
        AWS_SSO_ACCOUNT_ID: env.AWS_SSO_ACCOUNT_ID,
        AWS_SSO_ROLE_NAME: env.AWS_SSO_ROLE_NAME,
      },
      (verificationUri, userCode) => {
        state = { status: "pending", verificationUri, userCode };
        log(`AWS SSO login required — open ${verificationUri} and enter code ${userCode}`);
      },
    ).then(
      (credentials) => {
        state = { status: "ready", credentials };
        log("AWS SSO login complete");
      },
      (err: unknown) => {
        state = { status: "failed", reason: err instanceof Error ? err.message : String(err) };
        log(`AWS SSO login failed: ${state.status === "failed" ? state.reason : ""}`);
      },
    );

    return {
      region: env.AWS_REGION,
      credentials: () => {
        if (state.status === "failed") {
          return Promise.reject(new Error(`AWS SSO login failed: ${state.reason}`));
        }
        if (state.status === "pending") {
          return Promise.reject(
            new Error(
              `AWS SSO login is not complete. Open ${state.verificationUri} and enter code ` +
                `${state.userCode}, then re-issue this call.`,
            ),
          );
        }
        const { credentials } = state;
        if (credentials.expiration && credentials.expiration.getTime() <= Date.now()) {
          return Promise.reject(
            new Error("AWS SSO session has expired. Restart the server to log in again."),
          );
        }
        return Promise.resolve(credentials);
      },
      describe: () => `SSO device flow (${env.AWS_SSO_ROLE_NAME ?? "?"}, in memory only)`,
    };
  }

  return null;
}
