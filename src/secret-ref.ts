// A Secret Reference is the address of exactly one secret, and it always names
// its Store: `<store>:<id>[#subkey]`.
//
// The prefix is mandatory. An unprefixed id is rejected rather than assumed to
// be Bitwarden — partly so the Stores stay peers (nothing is the "default"
// one), but mostly because this string is what a human reads on the Approval
// page while deciding whether to authorize. "9f3c-…" says nothing about where
// the value is about to come from; "bws:9f3c-…" does.
//
// For the same reason the store names are spelled out rather than abbreviated:
// `asm:` was considered for AWS Secrets Manager and rejected because it differs
// from `ssm:` by one character, on the one screen where a misread means
// authorizing access to the wrong system.

/** Every Store this server knows how to address. Not every one is configured. */
export const STORE_NAMES = ["bws", "ssm", "secretsmanager"] as const;
export type StoreName = (typeof STORE_NAMES)[number];

export interface SecretRef {
  store: StoreName;
  /** The store-local identifier: a Bitwarden UUID, an SSM parameter name, a
   *  Secrets Manager secret name or ARN. Never includes the subkey. */
  id: string;
  /** Optional selector into a JSON secret — the top-level key to extract. */
  subkey?: string;
  /** The reference exactly as written. This is what the Gate displays and what
   *  keys the allowlist, so it must round-trip verbatim. */
  raw: string;
}

function isStoreName(value: string): value is StoreName {
  return (STORE_NAMES as readonly string[]).includes(value);
}

const KNOWN = STORE_NAMES.join(", ");

/**
 * Parse one Secret Reference. Throws with a message safe to show the agent —
 * it only ever quotes the reference itself, which the caller supplied.
 */
export function parseSecretRef(raw: string): SecretRef {
  const colon = raw.indexOf(":");
  if (colon === -1) {
    throw new Error(
      `"${raw}" is not a secret reference: it has no store prefix. ` +
        `Expected <store>:<id> where <store> is one of ${KNOWN} (e.g. "bws:${raw}").`,
    );
  }

  const store = raw.slice(0, colon);
  if (!isStoreName(store)) {
    throw new Error(`"${raw}" names an unknown store "${store}". Known stores: ${KNOWN}.`);
  }

  // Split on the FIRST '#'. Neither Parameter Store nor Secrets Manager allows
  // '#' in a name (SSM: [a-zA-Z0-9_.-] and '/'; Secrets Manager: [a-zA-Z0-9/_+=.@-]),
  // so this can never bite a legitimate identifier.
  const rest = raw.slice(colon + 1);
  const hash = rest.indexOf("#");
  const id = hash === -1 ? rest : rest.slice(0, hash);
  const subkey = hash === -1 ? undefined : rest.slice(hash + 1);

  if (id.length === 0) throw new Error(`"${raw}" has an empty secret id.`);
  if (subkey !== undefined && subkey.length === 0) {
    throw new Error(`"${raw}" has an empty subkey after '#'. Drop the '#' to use the whole value.`);
  }

  return subkey === undefined ? { store, id, raw } : { store, id, subkey, raw };
}

/** Parse a whole list, reporting every bad reference at once rather than the first. */
export function parseSecretRefs(raws: readonly string[]): SecretRef[] {
  const refs: SecretRef[] = [];
  const errors: string[] = [];
  for (const raw of raws) {
    try {
      refs.push(parseSecretRef(raw));
    } catch (e) {
      errors.push(e instanceof Error ? e.message : String(e));
    }
  }
  if (errors.length > 0) throw new Error(errors.join(" "));
  return refs;
}

/**
 * The default environment variable name for a reference, before `env_overrides`
 * is applied. A subkey names itself; otherwise it is the Store's own name for
 * the secret — the Bitwarden key name, or the last path segment of an SSM /
 * Secrets Manager name (`/prod/app/STRIPE_KEY` -> `STRIPE_KEY`).
 *
 * The result is not guaranteed to be a valid env var name; `tools.ts` validates
 * it against EnvNameSchema and tells the caller to pass env_overrides if not.
 */
export function defaultEnvName(ref: SecretRef, storeKeyName: string): string {
  if (ref.subkey !== undefined) return ref.subkey;
  return storeKeyName;
}

/** The Store's own name for a secret, derived from a path-shaped id. */
export function lastPathSegment(id: string): string {
  const trimmed = id.endsWith("/") ? id.slice(0, -1) : id;
  const slash = trimmed.lastIndexOf("/");
  return slash === -1 ? trimmed : trimmed.slice(slash + 1);
}
