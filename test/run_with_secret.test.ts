// Security-behaviour test for the run_with_secret tool. No framework: bws is a
// fake, HOME is a throwaway sandbox, the child is a real `node -e` process so
// we can observe what env/argv it actually received, and the Gate is a tiny
// real implementation of the same request-key semantics as gate.ts (not just
// an always-succeeds stub) — so the two-call "not yet approved -> approve out
// of band -> identical call proceeds" flow is exercised as it works in
// production, without real WebAuthn hardware.
//
// Locks the invariants:
//   1. a not-yet-approved call returns instructions (with the approval URL)
//      instead of running anything — works with any MCP client (ADR 0006)
//   2. after out-of-band approval, the identical call proceeds; the secret
//      reaches the child as an env var (default = Bitwarden key name)
//   3. env_overrides renames it; the default name is then NOT set
//   4. the vault token (BWS_ACCESS_TOKEN) is stripped from the child env
//   5. the secret is never passed via argv, and the wrapper doesn't leak it when
//      the child stays quiet
//   6. duplicate / invalid env var names are refused
//   7. the audit log records argv0 but never the secret value
import { mkdtempSync, mkdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import assert from "node:assert/strict";

const SANDBOX = mkdtempSync(join(tmpdir(), "bws-webauthn-run-test-"));
process.env.HOME = SANDBOX;
const CFG = join(SANDBOX, ".config", "secrets-webauthn-mcp");
mkdirSync(CFG, { recursive: true });
process.env.BWS_ACCESS_TOKEN = "VAULT-TOKEN-SENTINEL"; // must NOT reach the child
process.env.AWS_ACCESS_KEY_ID = "AKIA-SENTINEL"; // ditto: a Store credential
process.env.AWS_SECRET_ACCESS_KEY = "AWS-SECRET-SENTINEL";
process.env.AWS_SESSION_TOKEN = "AWS-SESSION-SENTINEL";

const { registerTools } = await import("../src/tools.js");
const { createStoreRegistry } = await import("../src/store.js");
const { RunWithSecretArgsSchema } = await import("../src/schemas.js");
const { requestKey } = await import("../src/request-key.js");

const NODE = process.execPath;
const SECRET = "RUN-SECRET-DO-NOT-LEAK-xyz789";

let events: string[] = [];
let secretMap: Record<string, { key: string; value: string }> = {};
let ssmMap: Record<string, string> = {};
const handlers: Record<string, (a: unknown) => Promise<any>> = {};
const fakeMcp = {
  server: {},
  registerTool: (name: string, _cfg: unknown, handler: (a: any) => Promise<any>) => {
    handlers[name] = handler;
  },
} as any;

// A real (not stubbed) implementation of the Gate's request-key semantics —
// checks/consumes exactly like gate.ts's checkApproval, minus the HTTP/WebAuthn
// plumbing. `preApprove` simulates a human having approved out of band.
function makeFakeGate() {
  const approved = new Set<string>();
  return {
    origin: "http://localhost:9",
    port: 9,
    checkApproval(key: string) {
      events.push("checkApproval");
      if (approved.has(key)) {
        approved.delete(key);
        return { approved: true, reused: false };
      }
      return { approved: false, reused: false };
    },
    preApprove(key: string) {
      approved.add(key);
    },
  };
}
const fakeGate = makeFakeGate();

const fakeBwsStore = {
  getSecret: async (id: string) => {
    events.push("getSecret:" + id);
    const s = secretMap[id];
    if (!s) throw new Error("no such secret " + id);
    return s;
  },
  // Mirrors secretMap's key names — real listSecrets() never returns a value,
  // so the fake doesn't either (id -> key only), matching the ADR 0005 contract.
  listSecrets: async () => Object.entries(secretMap).map(([id, s]) => ({ id, key: s.key })),
} as any;

// A second Store, so the reference routing and the "which Store is this from"
// half of the Approval message are exercised, not just assumed.
const fakeSsmStore = {
  getSecret: async (id: string) => {
    events.push("ssm:getSecret:" + id);
    const s = ssmMap[id];
    if (!s) throw new Error("no such parameter " + id);
    return { key: id.slice(id.lastIndexOf("/") + 1), value: s };
  },
} as any;

// The REAL registry, so reference routing and #subkey extraction are covered.
const stores = createStoreRegistry({ bws: fakeBwsStore, ssm: fakeSsmStore });
registerTools({ mcp: fakeMcp, gate: fakeGate, stores, timeoutMs: 1000 });
const run = (raw: unknown) => handlers["run_with_secret"]!(RunWithSecretArgsSchema.parse(raw));
const keyFor = (raw: unknown) => requestKey("run_with_secret", RunWithSecretArgsSchema.parse(raw));
const textOf = (r: any) => r.content[0].text as string;
const echo = (js: string) => [NODE, "-e", `process.stdout.write(${js})`];
/** Most tests only care about the post-approval path — approve then run in one step. */
const runApproved = (raw: unknown) => {
  fakeGate.preApprove(keyFor(raw));
  return run(raw);
};

let passed = 0, failed = 0;
async function test(name: string, fn: () => Promise<void>) {
  events = [];
  try { await fn(); console.log("ok  -", name); passed++; }
  catch (e) { failed++; console.error("FAIL -", name, "\n   ", e instanceof Error ? e.message : e); }
}

await test("first call (not yet approved) returns instructions + URL, never spawns", async () => {
  secretMap = { s1: { key: "API_KEY", value: SECRET } };
  const args = { argv: echo("process.env.API_KEY ?? 'UNSET'"), secret_refs: ["bws:s1"] };
  const r = await run(args);
  assert.equal(r.isError, true);
  assert.match(textOf(r), /physical approval required/i);
  assert.ok(textOf(r).includes(fakeGate.origin));
  assert.ok(textOf(r).includes(keyFor(args)));
  assert.equal(events.includes("getSecret:s1"), false, "must not fetch the secret before approval");
  assert.ok(!textOf(r).includes(SECRET));
  assert.equal(r.structuredContent.status, "approval_required");
  assert.equal(typeof r.structuredContent.approve_url, "string");
});

await test("formatting: the real Bitwarden key name is shown, and an ambiguous arg is quoted", async () => {
  secretMap = { s1: { key: "MY_SECRET_KEY", value: SECRET } };
  const args = { argv: ["printf", "%s", "hello world"], secret_refs: ["bws:s1"] };
  const r = await run(args);
  assert.ok(textOf(r).includes("(MY_SECRET_KEY)"), "must show the real Bitwarden key name, not a placeholder");
  assert.ok(
    textOf(r).includes("printf %s 'hello world'"),
    "an argument containing a space must be quoted, matching the real argv boundaries",
  );
  assert.ok(!textOf(r).includes("<its Bitwarden key name>"), "no placeholder once listSecrets resolves the name");
});

await test("formatting: a secret_id not found via list_secrets falls back honestly, not to a fake name", async () => {
  secretMap = {}; // "s1" is unknown to listSecrets (and to getSecret — but approval never gets that far)
  const args = { argv: ["echo", "hi"], secret_refs: ["bws:s1"] };
  const r = await run(args);
  assert.ok(textOf(r).includes("(not found via list_secrets)"));
  assert.ok(textOf(r).includes("<its Bitwarden key name>"));
});

await test("approval is single-use: repeating the same call again is not yet approved", async () => {
  secretMap = { s1: { key: "API_KEY", value: SECRET } };
  const args = { argv: echo("'x'"), secret_refs: ["bws:s1"] };
  fakeGate.preApprove(keyFor(args));
  await run(args); // consumes the approval
  const r2 = await run(args); // same args again, nothing pre-approved this time
  assert.equal(r2.isError, true);
  assert.match(textOf(r2), /physical approval required/i);
});

await test("after approval: inject under the Bitwarden key name; child receives the value", async () => {
  secretMap = { s1: { key: "API_KEY", value: SECRET } };
  const args = { argv: echo("process.env.API_KEY ?? 'UNSET'"), secret_refs: ["bws:s1"] };
  const r = await runApproved(args);
  assert.equal(r.isError, undefined);
  assert.match(textOf(r), /\[exit 0\]/);
  assert.ok(textOf(r).includes(SECRET), "child must receive the secret under its key name");
  assert.deepEqual(events, ["checkApproval", "getSecret:s1"], "Approval check must precede the secret fetch/spawn");
  assert.equal(r.structuredContent.status, "ok");
  assert.equal(r.structuredContent.exit_code, 0);
});

await test("env_overrides renames the var; default name is unset", async () => {
  secretMap = { s1: { key: "API_KEY", value: SECRET } };
  const r = await runApproved({
    argv: echo("'C='+(process.env.CUSTOM_TOKEN ?? 'UNSET')+' A='+(process.env.API_KEY ?? 'UNSET')"),
    secret_refs: ["bws:s1"],
    env_overrides: { "bws:s1": "CUSTOM_TOKEN" },
  });
  assert.ok(textOf(r).includes(`C=${SECRET}`), "secret must be under the override name");
  assert.ok(textOf(r).includes("A=UNSET"), "the default key name must not also be set");
});

await test("every Store credential is stripped from the child env, not just Bitwarden's", async () => {
  // The load-bearing one once there is more than one Store: a child that
  // inherited AWS keys could read the whole Parameter Store with no Gate at
  // all — the exact escalation ADR 0009 refused when it kept the Stores peers.
  secretMap = { s1: { key: "API_KEY", value: SECRET } };
  const probe = [
    "'TOK='+(process.env.BWS_ACCESS_TOKEN ?? 'UNSET')",
    "'AK='+(process.env.AWS_ACCESS_KEY_ID ?? 'UNSET')",
    "'SK='+(process.env.AWS_SECRET_ACCESS_KEY ?? 'UNSET')",
    "'ST='+(process.env.AWS_SESSION_TOKEN ?? 'UNSET')",
  ].join("+' '+");
  const r = await runApproved({ argv: echo(probe), secret_refs: ["bws:s1"] });
  assert.match(textOf(r), /TOK=UNSET/, "BWS_ACCESS_TOKEN must not reach the child");
  assert.match(textOf(r), /AK=UNSET/, "AWS_ACCESS_KEY_ID must not reach the child");
  assert.match(textOf(r), /SK=UNSET/, "AWS_SECRET_ACCESS_KEY must not reach the child");
  assert.match(textOf(r), /ST=UNSET/, "AWS_SESSION_TOKEN must not reach the child");
  for (const sentinel of ["VAULT-TOKEN-SENTINEL", "AKIA-SENTINEL", "AWS-SECRET-SENTINEL", "AWS-SESSION-SENTINEL"]) {
    assert.ok(!textOf(r).includes(sentinel), `${sentinel} leaked into the child`);
  }
});

await test("an unprefixed secret_ref is rejected before Approval", async () => {
  secretMap = { s1: { key: "API_KEY", value: SECRET } };
  const r = await run({ argv: echo("'x'"), secret_refs: ["s1"] });
  assert.equal(r.isError, true);
  assert.match(textOf(r), /no store prefix/i);
  assert.match(textOf(r), /bws:s1/, "the error should suggest the fix");
  assert.equal(events.includes("checkApproval"), false, "a malformed reference is a caller bug, not something to spend a touch on");
});

await test("an SSM reference injects under its last path segment", async () => {
  secretMap = {};
  ssmMap = { "/prod/app/STRIPE_KEY": SECRET };
  const r = await runApproved({
    argv: echo("'S='+(process.env.STRIPE_KEY ?? 'UNSET')"),
    secret_refs: ["ssm:/prod/app/STRIPE_KEY"],
  });
  assert.ok(textOf(r).includes(`S=${SECRET}`), "default env name is the last path segment");
});

await test("#subkey selects one field of a JSON secret, and never echoes the blob", async () => {
  secretMap = {};
  ssmMap = { "/prod/db": JSON.stringify({ username: "app", password: SECRET }) };
  const r = await runApproved({
    argv: echo("'P='+(process.env.password ?? 'UNSET')+' U='+(process.env.username ?? 'UNSET')"),
    secret_refs: ["ssm:/prod/db#password"],
  });
  assert.ok(textOf(r).includes(`P=${SECRET}`), "the selected field is injected under the subkey name");
  assert.match(textOf(r), /U=UNSET/, "only the selected field is injected, not every field");
});

await test("#subkey on a non-JSON secret errors without echoing the value", async () => {
  secretMap = {};
  ssmMap = { "/prod/flat": SECRET };
  const r = await runApproved({ argv: echo("'x'"), secret_refs: ["ssm:/prod/flat#password"] });
  assert.equal(r.isError, true);
  assert.match(textOf(r), /is not JSON/i);
  // JSON.parse's own message quotes the input it choked on, which would put the
  // secret straight into the tool result — store.ts must build its own message.
  assert.ok(!textOf(r).includes(SECRET), "the failing value must never appear in the error");
});

await test("secret is never in argv, and not leaked when the child is quiet", async () => {
  secretMap = { s1: { key: "API_KEY", value: SECRET } };
  const r = await runApproved({ argv: echo("'ARGV:'+process.argv.slice(2).join(',')+';OUT:done'"), secret_refs: ["bws:s1"] });
  assert.match(textOf(r), /OUT:done/);
  assert.ok(!textOf(r).includes(SECRET), "secret must never appear in argv nor be leaked by the wrapper");
});

await test("env_overrides referencing an unknown secret_id is rejected before Approval", async () => {
  secretMap = { s1: { key: "API_KEY", value: SECRET } };
  const args = { argv: echo("'x'"), secret_refs: ["bws:s1"], env_overrides: { "typo-id": "SOME_NAME" } };
  const r = await run(args); // no preApprove — must fail before even checking approval
  assert.equal(r.isError, true);
  assert.match(textOf(r), /env_overrides/i);
  assert.match(textOf(r), /typo-id/);
  assert.equal(events.includes("checkApproval"), false, "must reject before requesting Approval — a typo'd override is a caller bug, not something to spend a touch confirming");
});

await test("duplicate resolved env var name is refused", async () => {
  secretMap = { a: { key: "SAME", value: "v1" }, b: { key: "SAME", value: "v2" } };
  const r = await runApproved({ argv: echo("'x'"), secret_refs: ["bws:a", "bws:b"] });
  assert.equal(r.isError, true);
  assert.match(textOf(r), /same env var name/i);
});

await test("invalid env var name is refused", async () => {
  secretMap = { s1: { key: "bad name!", value: SECRET } };
  const r = await runApproved({ argv: echo("'x'"), secret_refs: ["bws:s1"] });
  assert.equal(r.isError, true);
  assert.match(textOf(r), /invalid/i);
  assert.ok(!textOf(r).includes(SECRET));
});

await test("a reuse-window run is audited as reused, so the trail never overstates a touch", async () => {
  // The audit log is the only record of who authorized what. Once a window can
  // cover a run without a sensor press, a line that says only verified:true
  // would claim a touch that never happened (ADR 0011).
  secretMap = { s1: { key: "API_KEY", value: SECRET } };
  const reuseHandlers: Record<string, (a: unknown) => Promise<any>> = {};
  registerTools({
    mcp: { server: {}, registerTool: (n: string, _c: unknown, h: any) => { reuseHandlers[n] = h; } } as any,
    gate: { origin: "http://localhost:9", port: 9, checkApproval: () => ({ approved: true, reused: true }) } as any,
    stores,
    timeoutMs: 1000,
  });
  await reuseHandlers["run_with_secret"]!(
    RunWithSecretArgsSchema.parse({ argv: echo("'x'"), secret_refs: ["bws:s1"] }),
  );
  const line = readFileSync(join(CFG, "audit.log"), "utf8").trim().split("\n").pop()!;
  const entry = JSON.parse(line);
  assert.equal(entry.verified, true);
  assert.equal(entry.reused, true, "a window-covered run must be distinguishable from a fresh touch");
});

/** A Gate that can be told to "approve while the call waits", so the blocking
 *  path is exercised without WebAuthn hardware. */
function makeWaitingGate(approveAfterMs: number | null) {
  const approved = new Set<string>();
  return {
    origin: "http://localhost:9",
    port: 9,
    checkApproval(key: string) {
      if (approved.has(key)) {
        approved.delete(key);
        return { approved: true, reused: false };
      }
      return { approved: false, reused: false };
    },
    waitForApproval(key: string, ms: number) {
      if (approveAfterMs === null || approveAfterMs > ms) {
        return new Promise<boolean>((r) => setTimeout(() => r(false), Math.min(ms, 20)));
      }
      return new Promise<boolean>((r) =>
        setTimeout(() => {
          approved.add(key); // the human touched, out of band
          r(true);
        }, approveAfterMs),
      );
    },
  } as any;
}

function toolsWithGate(gate: any, waitForApprovalMs: number) {
  const h: Record<string, (a: unknown) => Promise<any>> = {};
  registerTools({
    mcp: { server: {}, registerTool: (n: string, _c: unknown, fn: any) => { h[n] = fn; } } as any,
    gate,
    stores,
    timeoutMs: 1000,
    waitForApprovalMs,
  });
  return h;
}

await test("waiting: one call blocks, the approval lands, and the result comes back", async () => {
  // The whole point — no second identical call, no approval_required round trip.
  secretMap = { s1: { key: "API_KEY", value: SECRET } };
  const h = toolsWithGate(makeWaitingGate(10), 500);
  const r = await h["run_with_secret"]!(
    RunWithSecretArgsSchema.parse({
      argv: echo("process.env.API_KEY ?? 'UNSET'"),
      secret_refs: ["bws:s1"],
    }),
  );
  assert.equal(r.structuredContent.status, "ok", "the call itself produced the result");
  assert.equal(r.isError, undefined);
  assert.ok((r.content[0].text as string).includes(SECRET), "the child ran with the secret injected");
});

await test("waiting: on timeout it falls back to exactly the old behaviour", async () => {
  secretMap = { s1: { key: "API_KEY", value: SECRET } };
  const h = toolsWithGate(makeWaitingGate(null), 30);
  const r = await h["run_with_secret"]!(
    RunWithSecretArgsSchema.parse({ argv: echo("'x'"), secret_refs: ["bws:s1"] }),
  );
  assert.equal(r.structuredContent.status, "approval_required", "nothing is lost — the URL is returned");
  assert.match(textOf(r), /re-run this exact tool call/i);
});

await test("waiting is off by default: no wait, immediate approval_required", async () => {
  secretMap = { s1: { key: "API_KEY", value: SECRET } };
  let waited = false;
  const gate = makeWaitingGate(1);
  const wrapped = { ...gate, waitForApproval: (...a: unknown[]) => { waited = true; return gate.waitForApproval(...(a as [string, number])); } };
  const h = toolsWithGate(wrapped, 0);
  const r = await h["run_with_secret"]!(
    RunWithSecretArgsSchema.parse({ argv: echo("'x'"), secret_refs: ["bws:s1"] }),
  );
  assert.equal(r.structuredContent.status, "approval_required");
  assert.equal(waited, false, "upgrading must not change behaviour until the option is set");
});

await test("audit records the tool + argv0 but never the secret", async () => {
  secretMap = { s1: { key: "API_KEY", value: SECRET } };
  await runApproved({ argv: echo("'x'"), secret_refs: ["bws:s1"] });
  const audit = readFileSync(join(CFG, "audit.log"), "utf8");
  assert.ok(audit.includes('"run_with_secret"'), "audit must record the tool");
  assert.ok(!audit.includes(SECRET), "audit log must never contain the secret value");
});

console.log(`\n${passed} passed, ${failed} failed`);
rmSync(SANDBOX, { recursive: true, force: true });
process.exit(failed ? 1 : 0);
