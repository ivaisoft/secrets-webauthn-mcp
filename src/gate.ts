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
import { randomUUID } from "node:crypto";
import { createServer, type IncomingMessage, type Server as HttpServer } from "node:http";
import {
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
  type PublicKeyCredentialRequestOptionsJSON,
} from "@simplewebauthn/server";
import { addAllowedHost } from "./allowlist.js";
import { loadCredentials, saveCredentials, toWebAuthnCredential } from "./credentials.js";
import { highlightMessage } from "./highlight.js";
import { page } from "./html.js";
import { BROWSER_BUNDLE, readJsonBody, send, sendJson } from "./http-util.js";
import { AuthenticationResponseSchema } from "./schemas.js";
import type { AuthenticationResponseJSON } from "@simplewebauthn/server";

const RP_ID = "localhost";

/** A reuse window granted at approval time: this exact request may run again
 *  without a touch, until `until`, at most `remaining` more times. Both bounds
 *  exist deliberately — time alone is a blank cheque, since the human cannot
 *  know how many executions they just authorized (ADR 0011). */
export interface ReuseGrant {
  until: number;
  remaining: number;
}

interface PendingRequest {
  message: string;
  verified: boolean;
  expiresAt: number;
  challenge?: string;
  reuse?: ReuseGrant;
}

export interface ApprovalDecision {
  approved: boolean;
  /** True when this use was covered by a reuse window rather than a fresh
   *  touch. The audit trail records it, so the log never implies a human
   *  pressed the sensor when they did not. */
  reused: boolean;
}

export interface GateOptions {
  /** Longest reuse window a human may grant. 0 disables the feature entirely:
   *  the approve page offers no such control and the server ignores any
   *  request for one. Off by default — the security posture does not change
   *  unless it is enabled in config AND chosen per approval. */
  reuseMaxMs: number;
  /** Most executions one reuse window may cover. */
  reuseMaxUses: number;
}

/** A pending request to widen the allowlist. Deliberately a separate map from
 *  the approval-pending one: granting a host and using a secret are different
 *  decisions, and keeping them apart is what stops one screen from doing both. */
interface PendingGrant {
  ref: string;
  host: string;
  expiresAt: number;
  challenge?: string;
}

export interface Gate {
  origin: string;
  port: number;
  /** Register a pending "allow this host for this reference" request and return
   *  the URL where a human can authorize it with a touch. Does NOT approve any
   *  secret use — after granting, the call must still be re-issued and pass the
   *  Gate on its own. */
  requestHostGrant(ref: string, host: string, ttlMs: number): string;
  /** Approved (and consumes the entry — single use) if `key` was already
   *  approved via the /approve page, unless a reuse window covers it, in which
   *  case the entry survives with one fewer use. Otherwise (re)registers
   *  `message` as pending for `key`, valid for `ttlMs`, and returns not-approved. */
  checkApproval(key: string, message: string, ttlMs: number): ApprovalDecision;
  close(): void;
}

const DENIED: ApprovalDecision = { approved: false, reused: false };

/**
 * What an already-verified entry authorizes right now. Pure and exported so the
 * rule that actually matters — a window is bounded by BOTH time and remaining
 * uses, and running out of either ends it — is testable without WebAuthn
 * hardware or an HTTP round trip.
 *
 * `spend` tells the caller to drop the entry: either it was single-use, or the
 * window just ran out of runs.
 */
export function decideVerified(
  reuse: ReuseGrant | undefined,
  now: number,
): { decision: ApprovalDecision; spend: boolean } {
  if (reuse && reuse.until > now && reuse.remaining > 0) {
    const remainingAfter = reuse.remaining - 1;
    return { decision: { approved: true, reused: true }, spend: remainingAfter <= 0 };
  }
  return { decision: { approved: true, reused: false }, spend: true };
}

export async function startGate(options: GateOptions): Promise<Gate> {
  const reuseMaxMs = Math.max(0, options.reuseMaxMs);
  const reuseMaxUses = Math.max(1, options.reuseMaxUses);
  const pending = new Map<string, PendingRequest>();
  const grants = new Map<string, PendingGrant>();
  let origin = "";

  function sweepExpired(): void {
    const now = Date.now();
    for (const [key, entry] of pending) {
      if (!entry.verified && entry.expiresAt < now) pending.delete(key);
      // A reuse grant that has run out is not a stale entry to keep around —
      // the authorization is over, so the entry goes with it.
      else if (entry.reuse && (entry.reuse.until <= now || entry.reuse.remaining <= 0)) {
        pending.delete(key);
      }
    }
    for (const [id, grant] of grants) {
      if (grant.expiresAt < now) grants.delete(id);
    }
  }

  const grantPage = (id: string, grant: PendingGrant): string =>
    page(
      "Allow a new host",
      `<p class="lede">This does <strong>not</strong> approve a secret use. It only adds a host to what
this secret is allowed to reach — the call still needs its own approval afterwards.</p>
<pre class="code">${highlightMessage(`Allow host "${grant.host}" for secret ${grant.ref}`)}</pre>
<p class="hint">Permanent until you edit <code>allowlist.json</code> by hand.</p>
<button id="grantBtn" class="btn btn-primary" onclick="go()">Allow with Touch ID / passkey</button>
<script>
async function go(){
  var s=document.getElementById('status');
  var btn=document.getElementById('grantBtn');
  btn.disabled=true; btn.textContent='Waiting for Touch ID / passkey…';
  try{
    var o=await fetch('/allowlist/options?gid=${encodeURIComponent(id)}').then(r=>r.json());
    var a=await SimpleWebAuthnBrowser.startAuthentication({optionsJSON:o});
    var r=await fetch('/allowlist/verify?gid=${encodeURIComponent(id)}',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(a)}).then(r=>r.json());
    s.textContent = r.granted ? '\\u2705 Host allowed. Re-run the call — it still needs its own approval.' : '\\u274c '+(r.error||'not verified');
  }catch(e){ s.textContent='\\u274c '+e; }
  finally { btn.disabled=false; btn.textContent='Allow with Touch ID / passkey'; }
}
</script>`,
    );

  /** Durations offered for a reuse window, capped by config. Fixed candidates
   *  rather than a free-text field: the human is choosing how much authority to
   *  hand over, and a short list of round numbers is easier to reason about
   *  under time pressure than an empty box. */
  const reuseChoices = (): number[] =>
    [1, 5, 10, 15, 30, 60].filter((minutes) => minutes * 60_000 <= reuseMaxMs);

  const reuseControl = (): string => {
    const choices = reuseChoices();
    if (reuseMaxMs <= 0 || choices.length === 0) return "";
    const options = choices
      .map(
        (minutes) =>
          `<option value="${minutes * 60_000}">…and again for ${minutes} min (up to ${reuseMaxUses} runs)</option>`,
      )
      .join("");
    return `<p class="hint"><label for="reuse">How long is this approved for?</label></p>
<select id="reuse" class="btn"><option value="0" selected>Just this once</option>${options}</select>
<p class="hint">A window covers only this <em>exact</em> call — any change to the command, host, or secrets needs a new approval. It does not limit how many times this same call can run, beyond the run count shown.</p>`;
  };

  /** One place where an assertion is checked and the credential's counter is
   *  advanced — shared by the two things a touch can authorize (using a secret,
   *  and widening the allowlist) so neither can drift from the other. */
  async function verifyAssertion(
    req: IncomingMessage,
    expectedChallenge: string,
  ): Promise<{ ok: true } | { ok: false; error: string }> {
    const parsed = AuthenticationResponseSchema.safeParse(await readJsonBody(req));
    if (!parsed.success) return { ok: false, error: "malformed assertion" };
    const assertion: AuthenticationResponseJSON = parsed.data;

    const credentials = loadCredentials();
    const idx = credentials.findIndex((c) => c.id === assertion.id);
    if (idx === -1) return { ok: false, error: "unknown credential" };
    const stored = credentials[idx]!;

    const verification = await verifyAuthenticationResponse({
      response: assertion,
      expectedChallenge,
      expectedOrigin: origin,
      expectedRPID: RP_ID,
      credential: toWebAuthnCredential(stored),
      requireUserVerification: true,
    });
    if (!verification.verified) return { ok: false, error: "not verified" };

    credentials[idx] = { ...stored, counter: verification.authenticationInfo.newCounter };
    saveCredentials(credentials);
    return { ok: true };
  }

  const approvePage = (key: string, message: string, expiresAt: number): string => {
    const minutesLeft = Math.max(1, Math.round((expiresAt - Date.now()) / 60000));
    return page(
      "Approve secret use",
      `<p class="lede">A tool call is waiting for your physical approval. No secret value is ever shown here.</p>
<pre class="code">${highlightMessage(message)}</pre>
<p class="hint">Valid for ~${minutesLeft} more minute${minutesLeft === 1 ? "" : "s"} — expires automatically if not approved.</p>
${reuseControl()}
<button id="approveBtn" class="btn btn-primary" onclick="go()">Approve with Touch ID / passkey</button>
<script>
async function go(){
  var s=document.getElementById('status');
  var btn=document.getElementById('approveBtn');
  var sel=document.getElementById('reuse');
  var reuse=sel?sel.value:'0';
  btn.disabled=true; btn.textContent='Waiting for Touch ID / passkey…';
  try{
    var o=await fetch('/approve/options?rid=${encodeURIComponent(key)}').then(r=>r.json());
    var a=await SimpleWebAuthnBrowser.startAuthentication({optionsJSON:o});
    var r=await fetch('/approve/verify?rid=${encodeURIComponent(key)}&reuse_ms='+encodeURIComponent(reuse),{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(a)}).then(r=>r.json());
    s.textContent = r.verified ? (r.reuse_minutes ? '\\u2705 Approved for '+r.reuse_minutes+' min / '+r.reuse_uses+' runs of this exact call.' : '\\u2705 Approved. Go back and re-run the exact same command.') : '\\u274c '+(r.error||'not verified');
  }catch(e){ s.textContent='\\u274c '+e; }
  finally { btn.disabled=false; btn.textContent='Approve with Touch ID / passkey'; }
}
</script>`,
    );
  };

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
            page(
              "Expired",
              `<p class="lede">This approval link is no longer valid. Re-run the tool call to get a fresh one.</p>`,
            ),
          );
        return send(res, 200, "text/html", approvePage(key, entry.message, entry.expiresAt));
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

        const checked = await verifyAssertion(req, entry.challenge);
        if (!checked.ok) return sendJson(res, 400, { verified: false, error: checked.error });
        entry.verified = true;

        // The window the human asked for, clamped by config. Never trust the
        // page: this is a query parameter, and the cap is the actual boundary.
        const requestedMs = Number(url.searchParams.get("reuse_ms") ?? "0");
        const grantedMs = Number.isFinite(requestedMs)
          ? Math.min(Math.max(0, Math.trunc(requestedMs)), reuseMaxMs)
          : 0;
        if (grantedMs > 0) {
          entry.reuse = { until: Date.now() + grantedMs, remaining: reuseMaxUses };
          return sendJson(res, 200, {
            verified: true,
            reuse_minutes: Math.round(grantedMs / 60_000),
            reuse_uses: reuseMaxUses,
          });
        }
        return sendJson(res, 200, { verified: true });
      }

      if (path === "/allowlist") {
        sweepExpired();
        const grant = grants.get(url.searchParams.get("gid") ?? "");
        if (!grant)
          return send(
            res,
            404,
            "text/html",
            page("Expired", `<p class="lede">This link is no longer valid. Re-run the call to get a fresh one.</p>`),
          );
        return send(res, 200, "text/html", grantPage(url.searchParams.get("gid") ?? "", grant));
      }

      if (path === "/allowlist/options") {
        const grant = grants.get(url.searchParams.get("gid") ?? "");
        if (!grant) return sendJson(res, 404, { error: "unknown or expired request" });
        const credentials = loadCredentials();
        if (credentials.length === 0) return sendJson(res, 400, { error: "no credential registered" });
        const options: PublicKeyCredentialRequestOptionsJSON = await generateAuthenticationOptions({
          rpID: RP_ID,
          userVerification: "required",
          allowCredentials: credentials.map((c) => toWebAuthnCredential(c)),
        });
        grant.challenge = options.challenge;
        return sendJson(res, 200, options);
      }

      if (path === "/allowlist/verify" && req.method === "POST") {
        const id = url.searchParams.get("gid") ?? "";
        const grant = grants.get(id);
        if (!grant?.challenge) return sendJson(res, 404, { error: "unknown or expired request" });
        const verified = await verifyAssertion(req, grant.challenge);
        if (!verified.ok) return sendJson(res, 400, { granted: false, error: verified.error });
        // Widening the allowlist is the only write here; it never approves a use.
        addAllowedHost(grant.ref, grant.host);
        grants.delete(id);
        return sendJson(res, 200, { granted: true });
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

  function checkApproval(key: string, message: string, ttlMs: number): ApprovalDecision {
    sweepExpired();
    const existing = pending.get(key);
    if (existing?.verified) {
      // The request key is what bounds a window: a call differing in ANY
      // argument hashes differently and lands here with no entry at all.
      const { decision, spend } = decideVerified(existing.reuse, Date.now());
      if (decision.reused && existing.reuse) existing.reuse.remaining -= 1;
      if (spend) pending.delete(key);
      return decision;
    }
    pending.set(key, { message, verified: false, expiresAt: Date.now() + ttlMs });
    return DENIED;
  }

  function requestHostGrant(ref: string, host: string, ttlMs: number): string {
    sweepExpired();
    const id = randomUUID();
    grants.set(id, { ref, host, expiresAt: Date.now() + ttlMs });
    return `${origin}/allowlist?gid=${id}`;
  }

  return {
    origin,
    port,
    requestHostGrant,
    checkApproval,
    close: () => httpServer.close(),
  };
}
