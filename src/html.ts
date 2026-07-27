// Minimal HTML helpers for the localhost approval / registration pages.
// The Gate message is untrusted-ish (built from tool args) so it is always escaped.

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
  body{font:16px/1.5 system-ui,sans-serif;max-width:34rem;margin:4rem auto;padding:0 1rem;color:#111;background:#fff}
  button{font:inherit;padding:.6rem 1.1rem;border:1px solid #444;border-radius:.5rem;background:#111;color:#fff;cursor:pointer}
  pre{white-space:pre-wrap;word-break:break-word;background:#f5f5f5;padding:.75rem;border-radius:.5rem}
  #status{margin-top:1rem;color:#555}
  @media(prefers-color-scheme:dark){body{color:#eee;background:#111}button{background:#eee;color:#111;border-color:#ccc}pre{background:#1e1e1e}}
</style>
<h2>${escapeHtml(title)}</h2>
<div id="app">${body}</div>
<p id="status"></p>`;
}
