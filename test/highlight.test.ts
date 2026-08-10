// Tests for the server-side port of the design system's ApprovalScreen.jsx
// highlightLine/CodeBlock tokenizer (see docs/adr/0008). Same regexes, same
// token classes — ported to produce HTML <span> tags (server-rendered) instead
// of React elements (the mockup ran client-side). The Approval message is
// untrusted-ish (built from tool args, e.g. a host name), so the money test
// here is that highlighting can never become an injection point: every text
// fragment must still be escaped, even inside a matched capture group.
import assert from "node:assert/strict";

const { highlightMessage } = await import("../src/highlight.js");

let passed = 0, failed = 0;
function test(name: string, fn: () => void) {
  try { fn(); console.log("ok  -", name); passed++; }
  catch (e) { failed++; console.error("FAIL -", name, "\n   ", e instanceof Error ? e.message : e); }
}

test("http_request line: method, host, url tokenized distinctly", () => {
  const msg = 'http_request wants to use secret(s) [a1f9e284-72b3-4c1a-9e5f-11223e023e02] to call host "api.stripe.com" (POST https://api.stripe.com/v1/charges).';
  const html = highlightMessage(msg);
  assert.match(html, /<span class="tok-meta">a1f9e284-72b3-4c1a-9e5f-11223e023e02<\/span>/);
  assert.match(html, /<span class="tok-string">api\.stripe\.com<\/span>/);
  assert.match(html, /<span class="tok-keyword">POST<\/span>/);
  assert.match(html, /<span class="tok-string">https:\/\/api\.stripe\.com\/v1\/charges<\/span>/);
  assert.match(html, /<span class="tok-comment">http_request wants to use secret\(s\) \[<\/span>/);
});

test("run_with_secret: 'wants to run (no shell)' line is one comment span", () => {
  const html = highlightMessage("run_with_secret wants to run (no shell):");
  assert.equal(html, '<div class="code-line"><span class="tok-comment">run_with_secret wants to run (no shell):</span></div>');
});

test("run_with_secret: indented command line — binary keyword, quoted args as strings, rest as fg", () => {
  const html = highlightMessage("  node -e 'console.log(...)' 'extra arg with spaces'");
  assert.match(html, /<span class="tok-fg">  <\/span>/);
  assert.match(html, /<span class="tok-keyword">node<\/span>/);
  assert.match(html, /<span class="tok-fg"> -e<\/span>/);
  assert.match(html, /<span class="tok-string"> &#39;console\.log\(\.\.\.\)&#39;<\/span>/);
  assert.match(html, /<span class="tok-string"> &#39;extra arg with spaces&#39;<\/span>/);
});

test("Injecting line: single secret — id meta, key/arrows fg, env var name distinct", () => {
  const html = highlightMessage("Injecting as env vars: 8382e673-1234-4a2b-9c3d-abc123c332d (test) → $test");
  assert.match(html, /<span class="tok-comment">Injecting as env vars:<\/span>/);
  assert.match(html, /<span class="tok-meta">8382e673-1234-4a2b-9c3d-abc123c332d<\/span>/);
  assert.match(html, /<span class="tok-fg"> \(<\/span>/);
  assert.match(html, /<span class="tok-fg">test<\/span>/);
  assert.match(html, /<span class="tok-variable">\$test<\/span>/);
});

test("Injecting line: an AWS reference has no parenthetical name and is still decorated", () => {
  // Only Bitwarden ids are opaque enough to need a resolved name shown beside
  // them; an SSM path already IS the name. Without the optional group this
  // would hit the ADR 0008 fallback and render every AWS reference as one flat
  // line — correct, but the human loses the id/env-var distinction exactly
  // where they're deciding whether to approve.
  const html = highlightMessage("Injecting as env vars: ssm:/prod/app/STRIPE_KEY → $STRIPE_KEY");
  assert.match(html, /<span class="tok-meta">ssm:\/prod\/app\/STRIPE_KEY<\/span>/);
  assert.match(html, /<span class="tok-variable">\$STRIPE_KEY<\/span>/);
  assert.ok(!html.includes("("), "no empty parenthetical when there is no resolved name");
});

test("Injecting line: two secrets — the comma separator survives between mappings", () => {
  const html = highlightMessage(
    "Injecting as env vars: id1 (key1) → $ENV1, id2 (key2) → $ENV2",
  );
  const idxEnv1 = html.indexOf(">$ENV1<");
  const idxComma = html.indexOf(">, <");
  const idxId2 = html.indexOf(">id2<");
  assert.ok(idxEnv1 !== -1 && idxComma !== -1 && idxId2 !== -1, "all three fragments must be present");
  assert.ok(idxEnv1 < idxComma && idxComma < idxId2, "must appear in source order: $ENV1, comma, id2");
});

test("full multi-line run_with_secret message renders one code-line div per line, in order", () => {
  const msg =
    "run_with_secret wants to run (no shell):\n" +
    "  node -e 'console.log(...)' 'extra arg with spaces'\n" +
    "Injecting as env vars: 8382e673-1234-4a2b-9c3d-abc123c332d (test) → $test";
  const html = highlightMessage(msg);
  const lineCount = (html.match(/<div class="code-line">/g) ?? []).length;
  assert.equal(lineCount, 3, "one code-line div per message line");
});

test("SECURITY: a message with HTML-unsafe characters is always escaped, even inside matched capture groups", () => {
  const evil = 'http_request wants to use secret(s) [<script>x</script>] to call host "evil.com/\"><img src=x onerror=alert(1)>" (GET https://evil.com/x).';
  const html = highlightMessage(evil);
  assert.ok(!html.includes("<script>"), "must never emit a raw <script> tag from the secret-reference capture group");
  assert.ok(!html.includes("<img "), "must never emit a raw <img> tag from the host capture group");
  assert.ok(html.includes("&lt;script&gt;"), "the secret-reference fragment must be HTML-escaped");
  assert.ok(html.includes("&lt;img"), "the host fragment must be HTML-escaped");
});

test("fallback: a line matching none of the known shapes is still escaped, doesn't throw", () => {
  const html = highlightMessage('some future message shape with "quotes" & <tags>');
  assert.equal(
    html,
    '<div class="code-line"><span class="tok-fg">some future message shape with &quot;quotes&quot; &amp; &lt;tags&gt;</span></div>',
  );
});

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
