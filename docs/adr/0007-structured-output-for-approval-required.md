# Structured output so a client can detect "approval required" programmatically

`http_request` and `run_with_secret` declare an `outputSchema` (`schemas.ts`)
and return matching `structuredContent` alongside the existing human-readable
`content` text. Before this, the only way to know "this call needs a physical
Approval" was to parse prose looking for a phrase and a URL — workable for an
LLM reading the text, but nothing a client could rely on as a contract.

The shape is one shared `status: "approval_required" | "ok" | "error"`
discriminator plus optional fields per branch (`approve_url`/`reason`, plus
tool-specific success fields), rather than three separate output schemas or a
`z.discriminatedUnion`. Considered the latter for stronger typing, but the
SDK's `outputSchema` is a flat raw shape (or one schema, not a per-branch
union with different shapes selected at runtime), and three states with a
couple of optional fields each is small enough that a discriminator reads
clearly without the extra machinery.

This does not change what any status *means* — `approval_required` still
requires the same out-of-band WebAuthn Approval and identical-call re-issue as
ADR 0006; this only makes that state legible in structured form, not a new
mechanism.
