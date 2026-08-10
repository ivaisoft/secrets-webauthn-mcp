# secrets-webauthn-mcp

An MCP server that lets an agent *use* secrets from one or more Stores without
ever seeing their values, where every use is authorized by a physical WebAuthn
approval. Each Store's credential lives only inside this server: it is the sole
path to that Store's secrets.

## Language

**Store**:
A system this server reads secrets from on the human's behalf — Bitwarden
Secrets Manager, AWS SSM Parameter Store, AWS Secrets Manager.
_Avoid_: vault, provider, backend, secret manager

**Secret Reference**:
The address of exactly one secret, always naming its Store —
`<store>:<id>[#subkey]`.
_Avoid_: secret id, key, path, parameter

**Gate**:
The mandatory physical WebAuthn step (Touch ID / security key) that must succeed
before a secret is used. There is no path to a secret that skips the Gate.
_Avoid_: auth, check, 2FA

**Approval**:
A single successful human verification — one WebAuthn assertion — that authorizes
one use of one exact request, or a bounded run of that same request when the
human grants a Reuse Window.
_Avoid_: confirmation, consent

**Reuse Window**:
A bounded grant, chosen at the Gate, that lets one byte-identical request run
again without a new Approval — limited by elapsed time and by remaining runs,
whichever ends first.
_Avoid_: cache, session, standing approval

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

## Relationships

- A **Store** holds many secrets; a **Secret Reference** addresses exactly one secret in exactly one **Store**
- One **Approval** authorizes one use of one set of **Secret References**, which may span **Stores**
- A **Reuse Window** covers exactly one request — never a **Store**, never a **Secret Reference**
- **Injection** delivers a secret to a **Consumer**; the value never returns to the agent
- The **Gate** is the only path from any **Store** to any **Consumer**

## Example dialogue

> **Dev:** "If one call uses a Bitwarden secret and a Parameter Store one, is that two **Approvals**?"
> **Domain expert:** "One. An **Approval** authorizes the set of **Secret References** in that call, not one per **Store**. What two **Stores** change is what the human reads at the **Gate** — each reference names the **Store** it comes from, so you can see you're about to unlock things from two different places."

## Flagged ambiguities

- "secret_id" was used to mean both "a Bitwarden UUID" and "any secret's address" — resolved: every address is a **Secret Reference** and names its **Store**; an unprefixed id is rejected rather than assumed to be Bitwarden.
- "Secrets Manager" was used to mean both this server and the AWS product — resolved: `secretsmanager:` names one **Store**; this server is named after neither.
- "cache" was used for what is now a **Reuse Window** — resolved: they are different things. A cache would let *other* calls reuse an **Approval**; a Reuse Window covers one byte-identical request and nothing else.
- "dual approval" was raised as a requirement — resolved: it is not a concept here. It only ever meant one **Approval** to unlock a **Store**'s credential and a second to read the secret, which no **Store** requires of another. An **Approval** stays exactly one assertion.
