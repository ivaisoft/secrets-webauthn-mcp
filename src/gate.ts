// The Gate: a deterministic per-request key (request-key.ts) plus a localhost
// WebAuthn approval page. A tool proceeds only when the pending entry for its
// exact request-key has been verified — checkApproval both checks AND (on
// success) consumes the entry, so one physical approval authorizes exactly
// one execution of exactly one request, never more.
//
// This does NOT use MCP elicitation (see ADR 0006): not every MCP client
// implements it, and a security mechanism that silently does nothing in
// unsupporting clients isn't a mechanism, it's a bug. Instead, a tool call
// that isn't yet approved returns plain instructional text — which works with
// ANY MCP client — telling the human to open a URL and then re-issue the
// identical call; that second call finds its request-key already verified.
import { createServer, type Server as HttpServer } from "node:http";
import {
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
  type PublicKeyCredentialRequestOptionsJSON,
} from "@simplewebauthn/server";
import { loadCredentials, saveCredentials, toWebAuthnCredential } from "./credentials.js";
import { escapeHtml, page } from "./html.js";
import { BROWSER_BUNDLE, readJsonBody, send, sendJson } from "./http-util.js";
import { AuthenticationResponseSchema } from "./schemas.js";
import type { AuthenticationResponseJSON } from "@simplewebauthn/server";

const RP_ID = "localhost";

interface PendingRequest {
  message: string;
  verified: boolean;
  expiresAt: number;
  challenge?: string;
}

export interface Gate {
  origin: string;
  port: number;
  /** True (and consumes the entry — single use) if `key` was already approved
   *  via the /approve page; otherwise (re)registers `message` as pending for
   *  `key`, valid for `ttlMs`, and returns false. */
  checkApproval(key: string, message: string, ttlMs: number): boolean;
  close(): void;
}

export async function startGate(): Promise<Gate> {
  const pending = new Map<string, PendingRequest>();
  let origin = "";

  function sweepExpired(): void {
    const now = Date.now();
    for (const [key, entry] of pending) {
      if (!entry.verified && entry.expiresAt < now) pending.delete(key);
    }
  }

  const approvePage = (key: string, message: string): string =>
    page(
      "Approve secret use",
      `<pre>${escapeHtml(message)}</pre>
<button onclick="go()">Approve with Touch ID / passkey</button>
<script>
async function go(){
  var s=document.getElementById('status');
  try{
    var o=await fetch('/approve/options?rid=${encodeURIComponent(key)}').then(r=>r.json());
    var a=await SimpleWebAuthnBrowser.startAuthentication({optionsJSON:o});
    var r=await fetch('/approve/verify?rid=${encodeURIComponent(key)}',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(a)}).then(r=>r.json());
    s.textContent = r.verified ? '\\u2705 Approved. Go back and re-run the exact same command.' : '\\u274c '+(r.error||'not verified');
  }catch(e){ s.textContent='\\u274c '+e; }
}
</script>`,
    );

  const httpServer: HttpServer = createServer(async (req, res) => {
    try {
      const url = new URL(req.url ?? "/", "http://localhost");
      const path = url.pathname;

      if (path === "/health") return send(res, 200, "text/plain", "ok");
      if (path === "/browser.js") return send(res, 200, "text/javascript", BROWSER_BUNDLE);

      // Serve mode never serves /register — registration is a standalone process.
      if (path.startsWith("/register")) return send(res, 404, "text/plain", "not found");

      if (path === "/approve") {
        sweepExpired();
        const key = url.searchParams.get("rid") ?? "";
        const entry = pending.get(key);
        if (!entry)
          return send(
            res,
            404,
            "text/html",
            page("Expired", "This approval link is no longer valid. Re-run the tool call to get a fresh one."),
          );
        return send(res, 200, "text/html", approvePage(key, entry.message));
      }

      if (path === "/approve/options") {
        const entry = pending.get(url.searchParams.get("rid") ?? "");
        if (!entry) return sendJson(res, 404, { error: "unknown or expired request" });
        const credentials = loadCredentials();
        if (credentials.length === 0) return sendJson(res, 400, { error: "no credential registered" });
        const options: PublicKeyCredentialRequestOptionsJSON = await generateAuthenticationOptions({
          rpID: RP_ID,
          userVerification: "required",
          allowCredentials: credentials.map((c) => toWebAuthnCredential(c)),
        });
        entry.challenge = options.challenge;
        return sendJson(res, 200, options);
      }

      if (path === "/approve/verify" && req.method === "POST") {
        const key = url.searchParams.get("rid") ?? "";
        const entry = pending.get(key);
        if (!entry || !entry.challenge) return sendJson(res, 404, { error: "unknown or expired request" });

        const parsed = AuthenticationResponseSchema.safeParse(await readJsonBody(req));
        if (!parsed.success) return sendJson(res, 400, { error: "malformed assertion" });
        const assertion: AuthenticationResponseJSON = parsed.data;

        const credentials = loadCredentials();
        const idx = credentials.findIndex((c) => c.id === assertion.id);
        if (idx === -1) return sendJson(res, 400, { error: "unknown credential" });
        const stored = credentials[idx]!;

        const verification = await verifyAuthenticationResponse({
          response: assertion,
          expectedChallenge: entry.challenge,
          expectedOrigin: origin,
          expectedRPID: RP_ID,
          credential: toWebAuthnCredential(stored),
          requireUserVerification: true,
        });
        if (!verification.verified) return sendJson(res, 400, { verified: false });

        credentials[idx] = { ...stored, counter: verification.authenticationInfo.newCounter };
        saveCredentials(credentials);
        entry.verified = true;
        return sendJson(res, 200, { verified: true });
      }

      return send(res, 404, "text/plain", "not found");
    } catch {
      // Never surface internals (which could reference state) to the browser.
      sendJson(res, 500, { error: "internal error" });
    }
  });

  const port: number = await new Promise((resolve) => {
    httpServer.listen(0, "127.0.0.1", () => {
      const addr = httpServer.address();
      resolve(typeof addr === "object" && addr ? addr.port : 0);
    });
  });
  origin = `http://localhost:${port}`;

  function checkApproval(key: string, message: string, ttlMs: number): boolean {
    sweepExpired();
    const existing = pending.get(key);
    if (existing?.verified) {
      pending.delete(key); // single-use: consumed the moment a tool proceeds on it
      return true;
    }
    pending.set(key, { message, verified: false, expiresAt: Date.now() + ttlMs });
    return false;
  }

  return {
    origin,
    port,
    checkApproval,
    close: () => httpServer.close(),
  };
}
