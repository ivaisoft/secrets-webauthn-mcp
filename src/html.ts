// HTML helpers for the localhost approval / registration pages. Visual design
// ported from the IvaiSoft Claude Design project (ui_kits/webauthn-approval —
// ApprovalScreen.jsx / RegisterScreen.jsx), inlined here as plain CSS custom
// properties since these pages must work fully offline (no CDN, no build
// step at request time — see docs/adr/0003, 0008).
//
// The Gate message is untrusted-ish (built from tool args) so it is always
// escaped — see highlight.ts for the one place that also renders it.

export function escapeHtml(input: string): string {
  return input.replace(
    /[&<>"']/g,
    (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c] ?? c,
  );
}

export function page(title: string, body: string): string {
  return `<!doctype html><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(title)}</title>
<script src="/browser.js"></script>
<style>
  :root{
    /* brand */
    --brand-sun:#f5d91d; --brand-green-100:#e3f2e0; --brand-green-300:#8cc98a;
    --brand-green-500:#569952; --brand-green-700:#3a6f3a; --brand-green-900:#254a24;
    --brand-river-300:#6fb3d1; --brand-navy-900:#152f3d;
    /* neutrals (warm paper tone, not cold gray) */
    --neutral-0:#fff; --neutral-50:#f8f6f0; --neutral-100:#f1ede1; --neutral-200:#e3ddcd;
    --neutral-300:#cfc7b2; --neutral-400:#a9a08a; --neutral-500:#847c68; --neutral-600:#635c4c;
    --neutral-700:#463f35; --neutral-800:#2e2822; --neutral-900:#1c1815;
    /* semantic aliases (light) */
    --fg-1:var(--neutral-900); --fg-2:var(--neutral-600); --fg-inverse:var(--neutral-0);
    --surface-page:var(--neutral-50); --surface-card:var(--neutral-0); --surface-sunken:var(--neutral-100);
    --border-subtle:var(--neutral-200); --border-strong:var(--neutral-300);
    --accent:var(--brand-green-500); --accent-hover:var(--brand-green-700);
    /* type — named fonts are a preference, not a fetch: no CDN, falls back to system fonts */
    --font-display:'Montserrat',system-ui,sans-serif; --font-body:'Inter',system-ui,sans-serif;
    --font-mono:'JetBrains Mono',ui-monospace,monospace;
    --text-xs:.75rem; --text-sm:.875rem; --text-base:1rem; --text-lg:1.125rem; --text-xl:1.375rem;
    --tracking-tight:-0.01em;
    /* spacing / shape */
    --radius-md:10px; --radius-lg:16px; --radius-pill:999px;
    --shadow-sm:0 1px 2px rgba(28,24,21,.06); --shadow-lg:0 12px 32px rgba(28,24,21,.12);
    --ease:cubic-bezier(.4,0,.2,1);
  }
  @media(prefers-color-scheme:dark){
    :root{
      --fg-1:var(--neutral-50); --fg-2:var(--neutral-300); --fg-inverse:var(--neutral-0);
      --surface-page:var(--neutral-900); --surface-card:var(--neutral-800); --surface-sunken:var(--neutral-700);
      --border-subtle:var(--neutral-700); --border-strong:var(--neutral-600);
    }
  }
  *{box-sizing:border-box}
  body{
    margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
    padding:24px 16px;background:var(--surface-page);color:var(--fg-1);
    font-family:var(--font-body);line-height:1.5;
  }
  .card{
    width:100%;max-width:460px;background:var(--surface-card);border-radius:var(--radius-lg);
    box-shadow:var(--shadow-lg);border:1px solid var(--border-subtle);overflow:hidden;
  }
  .card-header{background:var(--brand-navy-900);padding:18px 20px;display:flex;align-items:center;gap:12px}
  .card-header .brand{color:#fff;font-family:var(--font-display);font-weight:800;font-size:var(--text-lg);letter-spacing:var(--tracking-tight)}
  .card-header .sep{color:var(--neutral-400);font-size:var(--text-sm)}
  .card-header .sub{color:var(--neutral-100);font-family:var(--font-display);font-weight:700;font-size:var(--text-sm)}
  .card-body{padding:24px 20px;display:flex;flex-direction:column;gap:18px}
  h2{margin:0;font-family:var(--font-display);font-weight:800;font-size:var(--text-xl);color:var(--fg-1)}
  .lede{margin:4px 0 0;font-size:var(--text-sm);color:var(--fg-2)}
  .hint{margin:0;font-size:var(--text-xs);color:var(--fg-2);line-height:1.5}
  /* One pending request in the console list. Not .card — that is the page shell. */
  .item{
    border:1px solid var(--border-subtle);border-radius:var(--radius-md);
    padding:14px;display:flex;flex-direction:column;gap:10px;
  }
  .item + .item{margin-top:14px}
  .btn{
    font:inherit;font-family:var(--font-body);font-weight:600;width:100%;cursor:pointer;
    border-radius:var(--radius-md);border:1px solid transparent;padding:14px 22px;font-size:var(--text-lg);
    transition:background var(--duration-fast,120ms) var(--ease),transform var(--duration-fast,120ms) var(--ease);
  }
  .btn:active{transform:scale(.98)}
  .btn:disabled{opacity:.5;cursor:not-allowed;transform:none}
  .btn-primary{background:var(--accent);color:var(--fg-inverse)}
  .btn-primary:hover:not(:disabled){background:var(--accent-hover)}
  .btn-secondary{background:var(--surface-sunken);color:var(--fg-1);border-color:var(--border-strong)}
  .btn-secondary:hover:not(:disabled){background:var(--border-subtle)}
  .code{
    background:var(--brand-navy-900);border-radius:var(--radius-md);padding:14px 16px;
    overflow-x:auto;box-shadow:var(--shadow-sm);margin:0;
  }
  .code-line{white-space:pre-wrap;word-break:break-word;font-family:var(--font-mono);font-size:12px;line-height:1.7}
  .tok-comment{color:var(--neutral-500)} .tok-keyword{color:var(--brand-river-300)}
  .tok-string{color:var(--brand-sun)} .tok-variable{color:var(--brand-green-300)}
  .tok-meta{color:var(--neutral-400)} .tok-fg{color:var(--neutral-100)}
  #status{margin-top:0;font-size:var(--text-sm);color:var(--fg-2)}
</style>
<div class="card">
  <div class="card-header"><span class="brand">IvaiSoft</span><span class="sep">·</span><span class="sub">bws-webauthn-mcp</span></div>
  <div class="card-body">
    <div><h2>${escapeHtml(title)}</h2></div>
    ${body}
    <p id="status"></p>
  </div>
</div>`;
}
