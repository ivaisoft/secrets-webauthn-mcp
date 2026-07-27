// Shared plumbing for the two local HTTP servers (approval + registration).
// No framework — Node's stdlib http on 127.0.0.1 only.
import { existsSync, readFileSync } from "node:fs";
import type { IncomingMessage, ServerResponse } from "node:http";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";

const require = createRequire(import.meta.url);

/** Locate the @simplewebauthn/browser package root. The UMD bundle subpath is not
 *  declared in the package `exports`, so resolve the entry and climb to the root. */
function browserBundlePath(): string {
  // Climb to the package root — the dir whose package.json *is* the browser package
  // (nested `script/package.json` type-markers must be skipped).
  let dir = dirname(require.resolve("@simplewebauthn/browser"));
  for (let i = 0; i < 8; i++) {
    const pkg = join(dir, "package.json");
    if (existsSync(pkg)) {
      const parsed: unknown = JSON.parse(readFileSync(pkg, "utf8"));
      if (
        parsed &&
        typeof parsed === "object" &&
        (parsed as { name?: unknown }).name === "@simplewebauthn/browser"
      ) {
        return join(dir, "dist", "bundle", "index.umd.min.js");
      }
    }
    dir = dirname(dir);
  }
  throw new Error("could not locate @simplewebauthn/browser package root");
}

/** The @simplewebauthn/browser UMD bundle, read from node_modules (no CDN). */
export const BROWSER_BUNDLE: Buffer = readFileSync(browserBundlePath());

export function send(res: ServerResponse, code: number, type: string, body: string | Buffer): void {
  res.writeHead(code, { "content-type": type });
  res.end(body);
}

export function sendJson(res: ServerResponse, code: number, obj: unknown): void {
  send(res, code, "application/json", JSON.stringify(obj));
}

/** Read a request body and JSON.parse it (empty body -> {}). */
export async function readJsonBody(req: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) chunks.push(chunk as Buffer);
  const text = Buffer.concat(chunks).toString("utf8");
  return text ? JSON.parse(text) : {};
}
