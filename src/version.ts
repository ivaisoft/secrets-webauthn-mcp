// The MCP `initialize` response's serverInfo.version was hardcoded as a
// string literal in two places (serve.ts, http-serve.ts) and silently drifted
// from package.json's real version on every release since the first commit.
// Read it once, from the one place it's actually true — resolved relative to
// this module's own compiled location, so it works both from a local build
// (dist/version.js -> ../package.json) and the published npm package (same
// layout: package.json always ships alongside "files": ["dist", ...]).
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const pkgPath = join(dirname(fileURLToPath(import.meta.url)), "..", "package.json");
const pkg: unknown = JSON.parse(readFileSync(pkgPath, "utf8"));

function readVersion(p: unknown): string {
  if (p && typeof p === "object" && "version" in p && typeof p.version === "string") {
    return p.version;
  }
  throw new Error(`package.json at ${pkgPath} has no string "version" field`);
}

export const VERSION: string = readVersion(pkg);
