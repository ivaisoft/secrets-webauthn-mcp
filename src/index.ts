#!/usr/bin/env node
// Entry dispatch. `serve` (default) runs the MCP stdio server; `register` binds a
// new authenticator; `selfcheck` runs the pure-logic assertions. Heavy modules
// are imported lazily so selfcheck/register never load the vault binding.
const mode = process.argv[2] ?? "serve";

async function main(): Promise<void> {
  if (mode === "register") {
    const { runRegister } = await import("./register.js");
    await runRegister();
  } else if (mode === "selfcheck") {
    const { runSelfcheck } = await import("./selfcheck.js");
    runSelfcheck();
  } else if (mode === "serve") {
    const { runServe } = await import("./serve.js");
    await runServe();
  } else {
    process.stderr.write(`unknown mode "${mode}" (expected: serve | register | selfcheck)\n`);
    process.exit(2);
  }
}

main().catch((err: unknown) => {
  // Never print a stack (could reference secret-adjacent state) — message only.
  process.stderr.write(`${err instanceof Error ? err.message : String(err)}\n`);
  process.exit(1);
});
