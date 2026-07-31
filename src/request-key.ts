// A deterministic identifier for "this exact tool call" — same tool + same
// args always produces the same key, anything different produces a different
// one. This is what lets the Gate be re-checked across two separate tool
// calls (see gate.ts) instead of blocking on MCP elicitation: the first call
// registers the key as pending, a human approves it out of band, and the
// identical second call finds that same key already verified.
import { createHash } from "node:crypto";

/** Object keys sorted recursively so key insertion order — which a zod-parsed
 *  object does not guarantee is stable — can never change the resulting hash. */
function stableStringify(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(",")}]`;
  if (value !== null && typeof value === "object") {
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj).sort();
    return `{${keys.map((k) => `${JSON.stringify(k)}:${stableStringify(obj[k])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

export function requestKey(tool: string, args: unknown): string {
  return createHash("sha256").update(tool).update("\0").update(stableStringify(args)).digest("hex");
}
