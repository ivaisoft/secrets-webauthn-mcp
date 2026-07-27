// The Gate: URL-mode elicitation + a localhost WebAuthn approval page. A tool
// proceeds only when the pending entry is WebAuthn-verified AND the elicitation
// action is not decline/cancel. No approval is ever cached — one touch per use.
import { randomUUID } from "node:crypto";
import { createServer, type Server as HttpServer } from "node:http";
import type { Server as McpLowServer } from "@modelcontextprotocol/sdk/server/index.js";
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

interface PendingApproval {
  challenge: string;
  options: PublicKeyCredentialRequestOptionsJSON;
  message: string;
  verified: boolean;
  onVerified?: () => void;
}

export interface Gate {
  origin: string;
  port: number;
  /** Block until a fresh physical Approval is obtained, or throw. */
  requireApproval(mcpLow: McpLowServer, message: string, timeoutMs: number): Promise<void>;
  close(): void;
}

export async function startGate(): Promise<Gate> {
  const pending = new Map<string, PendingApproval>();
  let origin = "";

  const approvePage = (rid: string, message: string): string =>
    page(
      "Approve secret use",
      `<p>${escapeHtml(message)}</p>
<button onclick="go()">Approve with Touch ID / passkey</button>
<script>
async function go(){
  var s=document.getElementById('status');
  try{
    var o=await fetch('/approve/options?rid=${encodeURIComponent(rid)}').then(r=>r.json());
    var a=await SimpleWebAuthnBrowser.startAuthentication({optionsJSON:o});
    var r=await fetch('/approve/verify?rid=${encodeURIComponent(rid)}',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(a)}).then(r=>r.json());
    s.textContent = r.verified ? '\\u2705 Approved. Return to your agent.' : '\\u274c '+(r.error||'not verified');
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
        const rid = url.searchParams.get("rid") ?? "";
        const entry = pending.get(rid);
        if (!entry)
          return send(res, 404, "text/html", page("Expired", "This approval link is no longer valid."));
        return send(res, 200, "text/html", approvePage(rid, entry.message));
      }

      if (path === "/approve/options") {
        const entry = pending.get(url.searchParams.get("rid") ?? "");
        if (!entry) return sendJson(res, 404, { error: "unknown rid" });
        return sendJson(res, 200, entry.options);
      }

      if (path === "/approve/verify" && req.method === "POST") {
        const rid = url.searchParams.get("rid") ?? "";
        const entry = pending.get(rid);
        if (!entry) return sendJson(res, 404, { error: "unknown rid" });

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
        entry.onVerified?.();
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

  async function requireApproval(
    mcpLow: McpLowServer,
    message: string,
    timeoutMs: number,
  ): Promise<void> {
    const credentials = loadCredentials();
    if (credentials.length === 0) {
      throw new Error("No credential registered. Run `npm run register` first.");
    }

    const options = await generateAuthenticationOptions({
      rpID: RP_ID,
      userVerification: "required",
      allowCredentials: credentials.map((c) => toWebAuthnCredential(c)),
    });

    const rid = randomUUID();
    const entry: PendingApproval = {
      challenge: options.challenge,
      options,
      message,
      verified: false,
    };
    pending.set(rid, entry);

    // Auto-close the client dialog the moment WebAuthn verifies.
    const notify = mcpLow.createElicitationCompletionNotifier(rid);
    entry.onVerified = () => {
      void notify().catch(() => {});
    };

    try {
      const result = await mcpLow.elicitInput(
        { mode: "url", message, elicitationId: rid, url: `${origin}/approve?rid=${rid}` },
        { timeout: timeoutMs },
      );
      if (result.action === "decline" || result.action === "cancel") {
        throw new Error("Approval was declined at the Gate.");
      }
      if (!entry.verified) {
        throw new Error("No verified WebAuthn Approval — refusing to use the secret.");
      }
    } finally {
      pending.delete(rid);
    }
  }

  return {
    origin,
    port,
    requireApproval,
    close: () => httpServer.close(),
  };
}
