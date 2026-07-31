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

/** Env for serve mode: the access token is required (it is the sole key to the vault). */
export const ServeEnvSchema = z.object({
  BWS_ACCESS_TOKEN: z.string().min(1, "BWS_ACCESS_TOKEN is required"),
  /** A machine account belongs to exactly one org; list_secrets needs it explicitly
   *  (the SDK has no "list my orgs" call — required so misconfiguration fails at
   *  startup, not with a confusing error the first time list_secrets is called). */
  BWS_ORGANIZATION_ID: z.string().min(1, "BWS_ORGANIZATION_ID is required"),
  BWS_API_URL: z.string().url().default("https://api.bitwarden.com"),
  BWS_IDENTITY_URL: z.string().url().default("https://identity.bitwarden.com"),
  BWS_GATE_TIMEOUT_MS: z.coerce.number().int().positive().default(120_000),
  /** Only read when `serve --http` is used; the stdio mode ignores this. */
  BWS_HTTP_PORT: z.coerce.number().int().positive().default(8787),
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

const SecretIdsSchema = z
  .array(z.string().min(1))
  .min(1, "at least one secret_id is required");

/** A valid POSIX-ish environment variable name. */
export const EnvNameSchema = z
  .string()
  .regex(/^[A-Za-z_][A-Za-z0-9_]*$/, "not a valid environment variable name");

/** Header name / scheme may be a single value (applied to every secret) or a per-secret array. */
const StringOrStringArray = z.union([z.string(), z.array(z.string())]);

export const HttpRequestArgsSchema = z.object({
  url: z.string().url(),
  method: z.string().default("GET"),
  secret_ids: SecretIdsSchema,
  header: StringOrStringArray.default("Authorization"),
  scheme: StringOrStringArray.default("Bearer "),
  body: z.string().optional(),
});
export type HttpRequestArgs = z.infer<typeof HttpRequestArgsSchema>;

export const RunWithSecretArgsSchema = z.object({
  argv: z.array(z.string().min(1)).min(1, "argv must include the executable"),
  secret_ids: SecretIdsSchema,
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
