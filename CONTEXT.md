# bws-webauthn-mcp

An MCP server that lets an agent *use* Bitwarden Secrets Manager secrets without
ever seeing their values, where every use is authorized by a physical WebAuthn
approval. The access token lives only inside this server: it is the sole path to
the secrets.

## Language

**Gate**:
The mandatory physical WebAuthn step (Touch ID / security key) that must succeed
before a secret is used. There is no path to a secret that skips the Gate.
_Avoid_: auth, check, 2FA

**Approval**:
A single successful human verification — one WebAuthn assertion — that authorizes
exactly one secret use. Approvals are not remembered between uses.
_Avoid_: confirmation, consent

**Injection**:
Delivering a secret to its Consumer through a channel that is never logged — a
process environment variable or an HTTP request header — so the value never
appears in the conversation, in `argv`, or in any log.
_Avoid_: passing, exposing, returning

**Consumer**:
The process (a spawned command) or HTTP endpoint that receives an injected
secret and acts with it. The Consumer, not the agent, holds the value.
_Avoid_: caller, client

**Adversary**:
The threat this server is built against: a prompt-injected agent that tries to
exfiltrate a secret. A present human who reads the Gate prompt is the backstop.
_Avoid_: attacker, hacker
