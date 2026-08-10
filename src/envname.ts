// Resolve the environment variable name a secret is injected under in
// run_with_secret. Default is the Store's own name for the secret — which the
// registry has already replaced with the subkey when the Secret Reference
// selected one — and an explicit per-reference override wins.
export function resolveEnvName(args: {
  /** The Secret Reference exactly as written, which is how env_overrides is keyed. */
  ref: string;
  keyName: string;
  overrides?: Record<string, string> | undefined;
}): string {
  return args.overrides?.[args.ref] ?? args.keyName;
}
