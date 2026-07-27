# Access token lives only in the server; the Gate is unbypassable

The adversary is a prompt-injected agent. For a physical-approval Gate to mean
anything, the agent must have **no** path to a secret that skips it — so the
`BWS_ACCESS_TOKEN` lives only inside this server process and the agent is never
given `bws` or the token in its shell. This is why the design is *not* "a hook in
front of `bws run`" (the token would still sit in the agent's environment) and
why secrets are never returned to the conversation. The trade-off is loss of
convenience: every secret use must go through this server's two tools
(`http_request`, `run_with_secret`), each of which requires a fresh Approval.
