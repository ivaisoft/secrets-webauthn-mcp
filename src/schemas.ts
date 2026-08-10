// Every external input is validated here with zod before it reaches any logic.
// Nothing untrusted flows through the program as `any`.
import { z } from "zod";

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

/** Which kind of authenticator to register. Defaults to "platform" (this Mac's
 *  Touch ID / Secure Enclave) rather than leaving it unconstrained: without an
 *  explicit attachment, the browser's chooser can create an iCloud-Keychain-
 *  synced passkey instead, which prompts for the account password to unlock
 *  rather than Touch ID. "cross-platform" registers a phone/security key. */
export const AuthenticatorAttachmentSchema = z.enum(["platform", "cross-platform"]).default("platform");

// ---------------------------------------------------------------------------
// Environment
// ---------------------------------------------------------------------------

// Env naming follows who owns the setting: BWS_* configures the Bitwarden
// Store, AWS_* configures the AWS Stores, SECRETS_* configures the server
// itself. No Store is required — the server runs with any subset configured,
// as long as it is at least one.

/** The Bitwarden Store's configuration. */
export const BwsEnvSchema = z.object({
  BWS_ACCESS_TOKEN: z.string().min(1).optional(),
  /** A machine account belongs to exactly one org; list_secrets needs it explicitly
   *  (the SDK has no "list my orgs" call — required so misconfiguration fails at
   *  startup, not with a confusing error the first time list_secrets is called). */
  BWS_ORGANIZATION_ID: z.string().min(1).optional(),
  BWS_API_URL: z.string().url().default("https://api.bitwarden.com"),
  BWS_IDENTITY_URL: z.string().url().default("https://identity.bitwarden.com"),
});
export type BwsEnv = z.infer<typeof BwsEnvSchema>;

/** The AWS Stores' configuration: static keys, or the in-process SSO device flow.
 *  There is deliberately no "use my default profile" option — see ADR 0009. */
export const AwsEnvSchema = z.object({
  /** Region for SSM / Secrets Manager calls. Its presence is what enables the AWS Stores. */
  AWS_REGION: z.string().min(1).optional(),
  AWS_ACCESS_KEY_ID: z.string().min(1).optional(),
  AWS_SECRET_ACCESS_KEY: z.string().min(1).optional(),
  AWS_SESSION_TOKEN: z.string().min(1).optional(),
  /** Setting AWS_SSO_START_URL is what opts into the SSO device flow. */
  AWS_SSO_START_URL: z.string().url().optional(),
  AWS_SSO_REGION: z.string().min(1).optional(),
  AWS_SSO_ACCOUNT_ID: z.string().min(1).optional(),
  AWS_SSO_ROLE_NAME: z.string().min(1).optional(),
});
export type AwsEnv = z.infer<typeof AwsEnvSchema>;

/**
 * Every environment variable that carries a Store credential, and must therefore
 * be stripped from a run_with_secret child (tools.ts). Missing one would hand the
 * child a credential that reads a whole Store with no Gate at all — the exact
 * escalation ADR 0009 rejected when it refused to let one Store unlock another.
 * SSO-derived credentials never appear here because they only ever live in memory.
 */
export const STORE_CREDENTIAL_ENV_VARS = [
  "BWS_ACCESS_TOKEN",
  "AWS_ACCESS_KEY_ID",
  "AWS_SECRET_ACCESS_KEY",
  "AWS_SESSION_TOKEN",
] as const;

export const ServeEnvSchema = BwsEnvSchema.merge(AwsEnvSchema)
  .extend({
    SECRETS_GATE_TIMEOUT_MS: z.coerce.number().int().positive().default(120_000),
    /** Only read when `serve --http` is used; the stdio mode ignores this. */
    SECRETS_HTTP_PORT: z.coerce.number().int().positive().default(8787),
    /** Longest reuse window a human may grant at the Gate. 0 (the default)
     *  disables the feature: the approve page offers no such control and the
     *  server refuses any window. Enabling it weakens ADR 0002 deliberately —
     *  see ADR 0011 — so it must be turned on explicitly, never by default. */
    SECRETS_REUSE_MAX_MS: z.coerce.number().int().nonnegative().default(0),
    /** Most executions a single reuse window may cover. Time alone would be a
     *  blank cheque: the human cannot know how many runs they authorized. */
    SECRETS_REUSE_MAX_USES: z.coerce.number().int().positive().default(5),
  })
  .superRefine((env, ctx) => {
    const issue = (message: string): void => {
      ctx.addIssue({ code: z.ZodIssueCode.custom, message, path: [] });
    };

    const bws = env.BWS_ACCESS_TOKEN !== undefined;
    if (bws && env.BWS_ORGANIZATION_ID === undefined) {
      issue("BWS_ORGANIZATION_ID is required when BWS_ACCESS_TOKEN is set");
    }

    const staticKeys = env.AWS_ACCESS_KEY_ID !== undefined && env.AWS_SECRET_ACCESS_KEY !== undefined;
    const sso =
      env.AWS_SSO_START_URL !== undefined &&
      env.AWS_SSO_REGION !== undefined &&
      env.AWS_SSO_ACCOUNT_ID !== undefined &&
      env.AWS_SSO_ROLE_NAME !== undefined;

    // Half-configured AWS is an error, never a silent fall-through to the
    // ambient credential chain: that fall-through is what ADR 0009 forbids, so
    // it must be impossible to reach by accident.
    if (env.AWS_REGION !== undefined && !staticKeys && !sso) {
      issue(
        "AWS_REGION is set but no AWS credential is: provide AWS_ACCESS_KEY_ID + " +
          "AWS_SECRET_ACCESS_KEY, or all of AWS_SSO_START_URL + AWS_SSO_REGION + " +
          "AWS_SSO_ACCOUNT_ID + AWS_SSO_ROLE_NAME. This server never reads ~/.aws (ADR 0009).",
      );
    }
    if (env.AWS_REGION === undefined && (staticKeys || sso)) {
      issue("AWS credentials are set but AWS_REGION is not");
    }
    if (env.AWS_SSO_START_URL !== undefined && !sso) {
      issue(
        "incomplete AWS SSO configuration: AWS_SSO_START_URL also needs AWS_SSO_REGION, " +
          "AWS_SSO_ACCOUNT_ID and AWS_SSO_ROLE_NAME",
      );
    }

    const aws = env.AWS_REGION !== undefined && (staticKeys || sso);
    if (!bws && !aws) {
      issue(
        "no Store is configured: set BWS_ACCESS_TOKEN (+ BWS_ORGANIZATION_ID) for Bitwarden, " +
          "and/or AWS_REGION plus an AWS credential for SSM / Secrets Manager",
      );
    }
  });
export type ServeEnv = z.infer<typeof ServeEnvSchema>;

/** Env for register mode: no BWS access needed — registration never touches the vault. */
export const RegisterEnvSchema = z.object({
  BWS_API_URL: z.string().url().default("https://api.bitwarden.com"),
});
export type RegisterEnv = z.infer<typeof RegisterEnvSchema>;

// ---------------------------------------------------------------------------
// Credential store (~/.config/bws-webauthn-mcp/credentials.json)
// ---------------------------------------------------------------------------

/** WebAuthn transports are an open enum in the spec; keep them as constrained strings. */
export const TransportSchema = z.enum([
  "ble",
  "cable",
  "hybrid",
  "internal",
  "nfc",
  "smart-card",
  "usb",
]);

/** One stored credential: public key + counter only, never any secret material. */
export const StoredCredentialSchema = z.object({
  id: z.string().min(1), // base64url credential id
  publicKey: z.string().min(1), // base64-encoded COSE public key
  counter: z.number().int().nonnegative(),
  transports: z.array(TransportSchema).optional(),
});
export type StoredCredential = z.infer<typeof StoredCredentialSchema>;

/** The whole file is an array of credentials (multi-authenticator). */
export const CredentialsFileSchema = z.array(StoredCredentialSchema);
export type CredentialsFile = z.infer<typeof CredentialsFileSchema>;

// ---------------------------------------------------------------------------
// Allowlist (~/.config/bws-webauthn-mcp/allowlist.json)
// ---------------------------------------------------------------------------

/** Maps each secret_id -> list of hosts that secret may be sent to over HTTP. */
export const AllowlistSchema = z.record(z.string(), z.array(z.string()));
export type Allowlist = z.infer<typeof AllowlistSchema>;

// ---------------------------------------------------------------------------
// Tool arguments
// ---------------------------------------------------------------------------

/** Secret References, as raw strings. The `<store>:<id>[#subkey]` grammar is
 *  enforced by secret-ref.ts rather than here, so a malformed reference gets a
 *  message that names the known stores and suggests a fix — not a zod regex
 *  failure the caller has to decode. */
const SecretRefsSchema = z
  .array(z.string().min(1))
  .min(1, "at least one secret_ref is required");

/** A valid POSIX-ish environment variable name. */
export const EnvNameSchema = z
  .string()
  .regex(/^[A-Za-z_][A-Za-z0-9_]*$/, "not a valid environment variable name");

/** Header name / scheme may be a single value (applied to every secret) or a per-secret array. */
const StringOrStringArray = z.union([z.string(), z.array(z.string())]);

export const HttpRequestArgsSchema = z.object({
  url: z.string().url(),
  method: z.string().default("GET"),
  secret_refs: SecretRefsSchema,
  header: StringOrStringArray.default("Authorization"),
  scheme: StringOrStringArray.default("Bearer "),
  body: z.string().optional(),
});
export type HttpRequestArgs = z.infer<typeof HttpRequestArgsSchema>;

export const RunWithSecretArgsSchema = z.object({
  argv: z.array(z.string().min(1)).min(1, "argv must include the executable"),
  secret_refs: SecretRefsSchema,
  /** Keyed by Secret Reference, exactly as written in secret_refs. */
  env_overrides: z.record(z.string(), EnvNameSchema).optional(),
});
export type RunWithSecretArgs = z.infer<typeof RunWithSecretArgsSchema>;

// ---------------------------------------------------------------------------
// WebAuthn HTTP POST bodies (browser -> local approval server)
// ---------------------------------------------------------------------------

/** Shape of @simplewebauthn/browser startAuthentication() output. Validated, then
 *  handed to @simplewebauthn/server which does the cryptographic verification. */
export const AuthenticationResponseSchema = z.object({
  id: z.string().min(1),
  rawId: z.string().min(1),
  response: z.object({
    clientDataJSON: z.string().min(1),
    authenticatorData: z.string().min(1),
    signature: z.string().min(1),
    userHandle: z.string().optional(),
  }),
  authenticatorAttachment: z.enum(["cross-platform", "platform"]).optional(),
  clientExtensionResults: z.record(z.string(), z.unknown()).default({}),
  type: z.literal("public-key"),
});
export type AuthenticationResponse = z.infer<typeof AuthenticationResponseSchema>;

/** Shape of @simplewebauthn/browser startRegistration() output. */
export const RegistrationResponseSchema = z.object({
  id: z.string().min(1),
  rawId: z.string().min(1),
  response: z.object({
    clientDataJSON: z.string().min(1),
    attestationObject: z.string().min(1),
    authenticatorData: z.string().optional(),
    transports: z.array(TransportSchema).optional(),
    publicKeyAlgorithm: z.number().optional(),
    publicKey: z.string().optional(),
  }),
  authenticatorAttachment: z.enum(["cross-platform", "platform"]).optional(),
  clientExtensionResults: z.record(z.string(), z.unknown()).default({}),
  type: z.literal("public-key"),
});
export type RegistrationResponse = z.infer<typeof RegistrationResponseSchema>;

// ---------------------------------------------------------------------------
// Tool structured output (ADR 0007)
// ---------------------------------------------------------------------------

/** Shared across both gated tools so a client can act on `status` without
 *  parsing the human-readable `content` text: "approval_required" means open
 *  `approve_url` and re-issue this exact call; "error" means see `reason`. */
const ToolStatusFields = {
  status: z.enum(["approval_required", "ok", "error"]),
  approve_url: z
    .string()
    .optional()
    .describe(
      'Present when status is "approval_required". Open this URL, approve with WebAuthn ' +
        "(Touch ID / passkey), then re-issue this exact tool call with the same arguments.",
    ),
  reason: z.string().optional().describe('Present when status is "error": why the call did not proceed.'),
};

export const HttpRequestOutputSchema = {
  ...ToolStatusFields,
  http_status: z.number().optional().describe('Present when status is "ok": the HTTP response status code.'),
  body: z.string().optional().describe('Present when status is "ok": the HTTP response body.'),
};

export const RunWithSecretOutputSchema = {
  ...ToolStatusFields,
  exit_code: z
    .number()
    .nullable()
    .optional()
    .describe('Present when status is "ok": the spawned command\'s exit code.'),
  stdout: z.string().optional().describe('Present when status is "ok": the spawned command\'s stdout.'),
  stderr: z.string().optional().describe('Present when status is "ok": the spawned command\'s stderr.'),
};
