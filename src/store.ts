// A Store is a system this server reads secrets from on the human's behalf.
// Each Store's credential lives only inside this process and is independent of
// every other Store's: no Store bootstraps another (ADR 0009), so a secret in
// one can never be the key that ungates another.
//
// The registry is the only thing that turns a Secret Reference into a value. It
// routes to the right Store and applies `#subkey` extraction, so each Store
// implementation stays a thin "id in, value out" adapter.
import { parseSecretRef, type SecretRef, type StoreName } from "./secret-ref.js";

export interface SecretHandle {
  /** The Store's own name for this secret — the basis for the default env var
   *  name in run_with_secret. */
  key: string;
  /** The plaintext value. Held only transiently; never returned to the agent. */
  value: string;
}

/** Identifier only — deliberately has no `value` field, so there is nothing to
 *  mask: list_secrets destructures exactly these two fields, never a raw SDK
 *  object, so a future SDK version adding fields here can't leak through it. */
export interface SecretIdentifier {
  id: string;
  key: string;
}

export interface SecretStore {
  /** Fetch by the store-local id. Subkey selection is the registry's job, not
   *  the Store's, so every Store handles JSON secrets identically. */
  getSecret(id: string): Promise<SecretHandle>;
  /**
   * Metadata only, never a value. Optional: a Store implements this only when
   * the permission to enumerate can be scoped no wider than the permission to
   * read (ADR 0010). Bitwarden always can; SSM can, but only once a path prefix
   * is configured, so it is optional at runtime rather than at compile time;
   * AWS Secrets Manager never can, because ListSecrets has no resource-level
   * IAM form.
   */
  listSecrets?(): Promise<SecretIdentifier[]>;
}

export interface StoreRegistry {
  /** Which Stores are actually configured on this server. */
  configured: StoreName[];
  /** The subset of `configured` that can enumerate. Whether a Store lists is a
   *  runtime fact (SSM lists only when a path prefix is configured), so callers
   *  must not infer it from the Store's name. */
  enumerable: StoreName[];
  /** Resolve a reference to its value, including `#subkey` extraction. */
  get(ref: SecretRef): Promise<SecretHandle>;
  /** Every enumerable Store's contents, as full Secret References, plus which
   *  Stores failed — never a partial list passed off as complete. */
  list(): Promise<StoreListing>;
}

export interface StoreListing {
  secrets: SecretIdentifier[];
  /** Stores that were asked and failed. Kept separate from the results so the
   *  caller can say "SSM errored" instead of silently returning a short list
   *  that reads as "this is everything". */
  failures: { store: StoreName; reason: string }[];
}

/**
 * A failing Store's reason, reduced to its error name.
 *
 * The full AWS message embeds the calling principal's ARN, and this string is
 * handed to the agent. `AccessDeniedException` is the whole diagnosis anyway —
 * the expected state for anyone who set a path prefix before adding
 * GetParametersByPath to their IAM policy.
 */
function failureReason(err: unknown): string {
  if (err && typeof err === "object" && "name" in err) {
    const name = String((err as { name: unknown }).name);
    if (name === "AccessDeniedException") {
      return "AccessDeniedException — the credential lacks ssm:GetParametersByPath on that path prefix";
    }
    if (name.length > 0 && name !== "Error") return name;
  }
  return err instanceof Error ? err.message : "unknown error";
}

/**
 * Pull one top-level key out of a JSON secret.
 *
 * Every throw here builds its own message and never forwards the underlying
 * parse error: V8's JSON.parse failures quote the input they choked on
 * (`Unexpected token 'h', "hunter2" is not valid JSON`), which would put the
 * secret straight into a tool result. That is the whole reason this is one
 * function instead of an inline try/catch at each call site.
 */
function selectSubkey(handle: SecretHandle, ref: SecretRef, subkey: string): SecretHandle {
  let parsed: unknown;
  try {
    parsed = JSON.parse(handle.value);
  } catch {
    throw new Error(
      `${ref.store}:${ref.id} is not JSON, so "#${subkey}" cannot be selected. ` +
        `Drop the '#' to use the whole value.`,
    );
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error(`${ref.store}:${ref.id} is not a JSON object, so "#${subkey}" cannot be selected.`);
  }
  const selected = (parsed as Record<string, unknown>)[subkey];
  if (selected === undefined) {
    // Deliberately does NOT list the keys that do exist: those are the shape of
    // someone's credential blob, and this message is read by the agent.
    throw new Error(`${ref.store}:${ref.id} has no top-level key "${subkey}".`);
  }
  if (typeof selected === "object") {
    throw new Error(
      `"#${subkey}" of ${ref.store}:${ref.id} is an object, not a single value; ` +
        `only string, number and boolean fields can be injected.`,
    );
  }
  return { key: subkey, value: String(selected) };
}

export function createStoreRegistry(stores: Partial<Record<StoreName, SecretStore>>): StoreRegistry {
  const configured = (Object.keys(stores) as StoreName[]).filter((name) => stores[name] !== undefined);
  const enumerable = configured.filter((name) => typeof stores[name]?.listSecrets === "function");

  return {
    configured,
    enumerable,

    async get(ref: SecretRef): Promise<SecretHandle> {
      const store = stores[ref.store];
      if (!store) {
        throw new Error(
          `store "${ref.store}" is not configured on this server ` +
            `(configured: ${configured.join(", ") || "none"}).`,
        );
      }
      const handle = await store.getSecret(ref.id);
      return ref.subkey === undefined ? handle : selectSubkey(handle, ref, ref.subkey);
    },

    async list(): Promise<StoreListing> {
      const secrets: SecretIdentifier[] = [];
      const failures: StoreListing["failures"] = [];
      for (const name of configured) {
        const store = stores[name];
        if (!store?.listSecrets) continue;
        try {
          const items = await store.listSecrets();
          // Return full Secret References, not bare store-local ids: what
          // list_secrets hands back must be directly pasteable into secret_refs.
          for (const item of items) secrets.push({ id: `${name}:${item.id}`, key: item.key });
        } catch (err) {
          // One Store failing must not discard another's results. An SSM
          // AccessDenied is the expected state before the IAM policy is
          // updated, and it should not take Bitwarden's list down with it.
          failures.push({ store: name, reason: failureReason(err) });
        }
      }
      return { secrets, failures };
    },
  };
}

/** Convenience for callers holding raw strings; keeps the parse error verbatim. */
export function refOf(raw: string): SecretRef {
  return parseSecretRef(raw);
}
