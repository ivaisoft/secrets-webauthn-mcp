// Resolve the environment variable name a secret is injected under in
// run_with_secret. Default is the secret's Bitwarden key name; an explicit
// per-secret override wins.
export function resolveEnvName(args: {
  secretId: string;
  keyName: string;
  overrides?: Record<string, string> | undefined;
}): string {
  return args.overrides?.[args.secretId] ?? args.keyName;
}
