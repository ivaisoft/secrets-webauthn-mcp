#!/usr/bin/env node
// Entry dispatch. `serve` (default) runs the MCP stdio server; `serve --http`
// opt-in runs it over Streamable HTTP on 127.0.0.1 instead (see http-serve.ts
// for why this is opt-in, not the default); `register` binds a new
// authenticator; `selfcheck` runs the pure-logic assertions. Heavy modules are
// imported lazily so selfcheck/register never load the vault binding.
import { loadServeEnv } from "./config.js";

const mode = process.argv[2] ?? "serve";
const rest = process.argv.slice(3);

async function main(): Promise<void> {
  if (mode === "register") {
    const { runRegister } = await import("./register.js");
    await runRegister();
  } else if (mode === "selfcheck") {
    const { runSelfcheck } = await import("./selfcheck.js");
    runSelfcheck();
  } else if (mode === "serve") {
    if (rest.includes("--http")) {
      const { runServeHttp } = await import("./http-serve.js");
      await runServeHttp(loadServeEnv().SECRETS_HTTP_PORT);
    } else {
      const { runServe } = await import("./serve.js");
      await runServe();
    }
  } else {
    process.stderr.write(`unknown mode "${mode}" (expected: serve [--http] | register | selfcheck)\n`);
    process.exit(2);
  }
}

main().catch((err: unknown) => {
  // Never print a stack (could reference secret-adjacent state) — message only.
  process.stderr.write(`${err instanceof Error ? err.message : String(err)}\n`);
  process.exit(1);
});
