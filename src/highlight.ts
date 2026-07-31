// Server-side port of the design system's ApprovalScreen.jsx highlightLine/
// CodeBlock tokenizer (docs/adr/0008) — same regexes, same token classes,
// producing HTML instead of React elements, since the Approval message is
// rendered server-side, not in a browser component tree. The message is
// untrusted-ish (built from tool args, e.g. a host name) — every text
// fragment goes through escapeHtml before being wrapped in a span, so
// highlighting can never become an injection point.
import { escapeHtml } from "./html.js";

type Token = "comment" | "keyword" | "string" | "variable" | "meta" | "fg";

function span(text: string, token: Token): string {
  return text ? `<span class="tok-${token}">${escapeHtml(text)}</span>` : "";
}

function highlightLine(line: string): string {
  const httpMatch = line.match(
    /^(.+?wants to use secret\(s\) \[)(.+?)(\] to call host ")(.+?)(" \()(\S+)( )(.+?)(\)\.)$/,
  );
  if (httpMatch) {
    const [, a, ids, b, host, c, method, sp, url, d] = httpMatch as unknown as string[];
    return (
      span(a!, "comment") +
      span(ids!, "meta") +
      span(b!, "comment") +
      span(host!, "string") +
      span(c!, "comment") +
      span(method!, "keyword") +
      span(sp!, "comment") +
      span(url!, "string") +
      span(d!, "comment")
    );
  }

  if (line.includes("wants to run (no shell)")) return span(line, "comment");

  if (line.trim().startsWith("Injecting")) {
    const i = line.indexOf(":");
    let html = span(line.slice(0, i + 1), "comment");
    for (const part of line.slice(i + 1).split(/(,\s*)/)) {
      if (/^,\s*$/.test(part)) {
        html += span(part, "fg");
        continue;
      }
      const m = part.match(/^(\s*)(\S+)\s\(([^)]+)\)\s*(→)\s*(.+)$/);
      if (m) {
        const [, lead, id, key, arrow, envName] = m;
        html +=
          span(lead!, "fg") +
          span(id!, "meta") +
          span(" (", "fg") +
          span(key!, "fg") +
          span(") ", "fg") +
          span(`${arrow} `, "fg") +
          span(envName!, "variable");
      } else {
        html += span(part, "fg");
      }
    }
    return html;
  }

  if (line.startsWith("  ")) {
    let html = span("  ", "fg");
    const tokens = line.trim().match(/'[^']*'|\S+/g) ?? [];
    tokens.forEach((tok, i) => {
      const text = (i ? " " : "") + tok;
      html += span(text, i === 0 ? "keyword" : tok.startsWith("'") ? "string" : "fg");
    });
    return html;
  }

  return span(line, "fg");
}

/** Renders an Approval message as syntax-highlighted HTML, one `.code-line`
 *  div per source line. Only recognizes the message shapes this server
 *  actually generates (tools.ts) — anything else falls back to a single
 *  plain (still escaped) line, never throws. */
export function highlightMessage(message: string): string {
  return message
    .split("\n")
    .map((line) => `<div class="code-line">${highlightLine(line)}</div>`)
    .join("");
}
