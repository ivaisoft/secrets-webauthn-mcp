// Multi-authenticator credential store. Public key + counter only — never any
// secret material. File is written 0600. Any credential may Approve.
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import type { AuthenticatorTransportFuture, WebAuthnCredential } from "@simplewebauthn/server";
import { CREDENTIALS_FILE, STATE_DIR } from "./paths.js";
import { CredentialsFileSchema, type StoredCredential } from "./schemas.js";

/** base64 <-> Uint8Array round-trip for the stored COSE public key. */
export function publicKeyToBase64(publicKey: Uint8Array): string {
  return Buffer.from(publicKey).toString("base64");
}
export function base64ToPublicKey(base64: string): Uint8Array<ArrayBuffer> {
  const buf = Buffer.from(base64, "base64");
  // Allocate a fresh ArrayBuffer-backed view (not SharedArrayBuffer) so the type
  // matches @simplewebauthn's `Uint8Array<ArrayBuffer>` credential public key.
  const out = new Uint8Array(buf.byteLength);
  out.set(buf);
  return out;
}

/** Read + validate the credential array. Returns [] when the file is absent. */
export function loadCredentials(): StoredCredential[] {
  if (!existsSync(CREDENTIALS_FILE)) return [];
  const raw: unknown = JSON.parse(readFileSync(CREDENTIALS_FILE, "utf8"));
  return CredentialsFileSchema.parse(raw);
}

/** Persist the credential array with restrictive permissions. */
export function saveCredentials(credentials: StoredCredential[]): void {
  mkdirSync(STATE_DIR, { recursive: true });
  writeFileSync(CREDENTIALS_FILE, JSON.stringify(credentials, null, 2), { mode: 0o600 });
}

/** Adapt a stored credential into the shape @simplewebauthn/server verification expects. */
export function toWebAuthnCredential(stored: StoredCredential): WebAuthnCredential {
  return {
    id: stored.id,
    publicKey: base64ToPublicKey(stored.publicKey),
    counter: stored.counter,
    transports: stored.transports as AuthenticatorTransportFuture[] | undefined,
  };
}
