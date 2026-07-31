// Register mode: a standalone process (never part of serve mode) that binds a new
// authenticator. The FIRST credential is trust-on-first-use. Adding any further
// credential requires an existing Approval first — enforced server-side by a gate
// assertion that must verify before registration options are issued.
import { spawn } from "node:child_process";
import { createServer } from "node:http";
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from "@simplewebauthn/server";
import { loadRegisterEnv } from "./config.js";
import {
  loadCredentials,
  publicKeyToBase64,
  saveCredentials,
  toWebAuthnCredential,
} from "./credentials.js";
import { escapeHtml, page } from "./html.js";
import { BROWSER_BUNDLE, readJsonBody, send, sendJson } from "./http-util.js";
import { CREDENTIALS_FILE } from "./paths.js";
import {
  AuthenticationResponseSchema,
  AuthenticatorAttachmentSchema,
  RegistrationResponseSchema,
  TransportSchema,
} from "./schemas.js";

const RP_ID = "localhost";

export async function runRegister(): Promise<void> {
  loadRegisterEnv(); // validate env even though registration never reads the vault
  const existing = loadCredentials();
  const hasCredentials = existing.length > 0;

  let origin = "";
  let regChallenge: string | null = null;
  let gateChallenge: string | null = null;
  // TOFU: no existing credential means no Approval is needed to add the first one.
  let approvalPassed = !hasCredentials;
  let done: (() => void) | null = null;

  const registerPage = page(
    hasCredentials ? "Add another authenticator" : "Register this authenticator",
    `<p>${escapeHtml(
      hasCredentials
        ? "An existing authenticator must Approve before a new one can be added."
        : "Bind an authenticator so it can Approve secret use.",
    )}</p>
<button onclick="run('platform')">${hasCredentials ? "Approve, then register this Mac (Touch ID)" : "Register this Mac (Touch ID)"}</button>
<button onclick="run('cross-platform')">${hasCredentials ? "Approve, then register a phone / security key" : "Register a phone / security key"}</button>
<p style="font-size:.85em;color:#666">Picking a kind matters: without it, some browsers save a
password-protected iCloud Keychain passkey instead of a true Touch ID credential.</p>
<script>
var HAS_CREDS = ${hasCredentials ? "true" : "false"};
async function run(attachment){
  var s=document.getElementById('status');
  try{
    if(HAS_CREDS){
      s.textContent='Waiting for Approval from an existing authenticator...';
      var go=await fetch('/register/gate/options').then(r=>r.json());
      var ga=await SimpleWebAuthnBrowser.startAuthentication({optionsJSON:go});
      var gr=await fetch('/register/gate/verify',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(ga)}).then(r=>r.json());
      if(!gr.verified){ s.textContent='\\u274c Approval failed: '+(gr.error||'not verified'); return; }
    }
    s.textContent='Registering new authenticator...';
    var o=await fetch('/register/options?attachment='+encodeURIComponent(attachment)).then(r=>r.json());
    var att=await SimpleWebAuthnBrowser.startRegistration({optionsJSON:o});
    var r=await fetch('/register/verify',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(att)}).then(r=>r.json());
    s.textContent = r.verified ? '\\u2705 Registered. You can close this tab.' : '\\u274c '+(r.error||'not verified');
  }catch(e){ s.textContent='\\u274c '+e; }
}
</script>`,
  );

  const httpServer = createServer(async (req, res) => {
    try {
      const url = new URL(req.url ?? "/", "http://localhost");
      const path = url.pathname;

      if (path === "/health") return send(res, 200, "text/plain", "ok");
      if (path === "/browser.js") return send(res, 200, "text/javascript", BROWSER_BUNDLE);
      if (path === "/register") return send(res, 200, "text/html", registerPage);

      // ---- pre-registration Approval (only when credentials already exist) ----
      if (path === "/register/gate/options") {
        if (!hasCredentials) return sendJson(res, 400, { error: "no existing credentials" });
        const options = await generateAuthenticationOptions({
          rpID: RP_ID,
          userVerification: "required",
          allowCredentials: existing.map((c) => toWebAuthnCredential(c)),
        });
        gateChallenge = options.challenge;
        return sendJson(res, 200, options);
      }
      if (path === "/register/gate/verify" && req.method === "POST") {
        if (!hasCredentials || gateChallenge === null)
          return sendJson(res, 400, { error: "no gate in progress" });
        const parsed = AuthenticationResponseSchema.safeParse(await readJsonBody(req));
        if (!parsed.success) return sendJson(res, 400, { error: "malformed assertion" });
        const idx = existing.findIndex((c) => c.id === parsed.data.id);
        if (idx === -1) return sendJson(res, 400, { error: "unknown credential" });
        const stored = existing[idx]!;
        const verification = await verifyAuthenticationResponse({
          response: parsed.data,
          expectedChallenge: gateChallenge,
          expectedOrigin: origin,
          expectedRPID: RP_ID,
          credential: toWebAuthnCredential(stored),
          requireUserVerification: true,
        });
        if (!verification.verified) return sendJson(res, 400, { verified: false });
        existing[idx] = { ...stored, counter: verification.authenticationInfo.newCounter };
        saveCredentials(existing);
        approvalPassed = true;
        return sendJson(res, 200, { verified: true });
      }

      // ---- registration ----
      if (path === "/register/options") {
        if (!approvalPassed) return sendJson(res, 403, { error: "Approval required" });
        // Pin the attachment explicitly: without it, some browsers offer (or
        // default to) a synced iCloud Keychain passkey instead of this Mac's
        // Secure Enclave, which then prompts for the account password to
        // unlock rather than Touch ID. Falls back to "platform" on anything
        // unrecognized rather than leaving it unconstrained.
        const attachment = AuthenticatorAttachmentSchema.catch("platform").parse(
          url.searchParams.get("attachment") ?? undefined,
        );
        const options = await generateRegistrationOptions({
          rpName: "bws-webauthn-mcp",
          rpID: RP_ID,
          userName: process.env.USER ?? "operator",
          attestationType: "none",
          excludeCredentials: existing.map((c) => toWebAuthnCredential(c)),
          authenticatorSelection: {
            userVerification: "required",
            residentKey: "discouraged",
            authenticatorAttachment: attachment,
          },
        });
        regChallenge = options.challenge;
        return sendJson(res, 200, options);
      }
      if (path === "/register/verify" && req.method === "POST") {
        if (!approvalPassed) return sendJson(res, 403, { error: "Approval required" });
        if (regChallenge === null) return sendJson(res, 400, { error: "no registration in progress" });
        const parsed = RegistrationResponseSchema.safeParse(await readJsonBody(req));
        if (!parsed.success) return sendJson(res, 400, { error: "malformed attestation" });
        const verification = await verifyRegistrationResponse({
          response: parsed.data,
          expectedChallenge: regChallenge,
          expectedOrigin: origin,
          expectedRPID: RP_ID,
          requireUserVerification: true,
        });
        if (!verification.verified || !verification.registrationInfo)
          return sendJson(res, 400, { verified: false });

        const cred = verification.registrationInfo.credential;
        const transports = TransportSchema.array()
          .optional()
          .parse(cred.transports);
        const next = existing.filter((c) => c.id !== cred.id);
        next.push({
          id: cred.id,
          publicKey: publicKeyToBase64(cred.publicKey),
          counter: cred.counter,
          ...(transports ? { transports } : {}),
        });
        saveCredentials(next);
        sendJson(res, 200, { verified: true });
        done?.();
        return;
      }

      return send(res, 404, "text/plain", "not found");
    } catch {
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

  const registerUrl = `${origin}/register`;
  process.stdout.write(`Open ${registerUrl} to register your authenticator...\n`);
  if (process.platform === "darwin") spawn("open", [registerUrl], { stdio: "ignore" });

  await new Promise<void>((resolve) => {
    done = resolve;
  });
  process.stdout.write(`Credential saved -> ${CREDENTIALS_FILE}\n`);
  httpServer.close();
  process.exit(0);
}
