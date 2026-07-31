// Renders an argv array as a faithful, readable, copy-pasteable shell command
// for a human to review before Approving — quoting any element that would
// otherwise be ambiguous (spaces, quotes, shell metacharacters), so the
// displayed boundaries always match the real argv boundaries. Display only:
// run_with_secret always execs argv directly, never through a shell.
const SAFE_UNQUOTED = /^[A-Za-z0-9_@%+=:,./-]+$/;

function quoteArg(arg: string): string {
  if (SAFE_UNQUOTED.test(arg)) return arg;
  return `'${arg.replace(/'/g, `'\\''`)}'`;
}

export function formatArgv(argv: readonly string[]): string {
  return argv.map(quoteArg).join(" ");
}
