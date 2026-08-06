# sandbroker

Let an AI coding agent **use** your credentials without those credentials ever
entering the model's context or the model provider's network traffic.

```
agent                     broker (uid: sandbroker)              1Password
  |                              |                                   |
  |  run(                        |                                   |
  |    command: 'curl -H "Authorization: Bearer $TOKEN" https://api/me',
  |    secrets: {TOKEN: "op://Dev/mercury/credential"} )              |
  |----------------------------->|                                   |
  |                              |-- resolve ----------------------->|
  |                              |<- value --------------------------|
  |                              |-- exec with TOKEN in the env      |
  |                              |-- scrub the value from the output |
  |<--- {exit_code, stdout, stderr, redactions} ---------------------|
```

The agent writes `$TOKEN`. It never holds the value, so it cannot leak it into a
prompt, a log, a commit, or a request to the model API.

## What it is

One daemon per vault. Four tools. No approvals, no login, no web UI.

| Tool | What it does |
|---|---|
| `run` | Execute a command with secrets in its environment, return scrubbed output |
| `list_items` | Item titles and references in this vault, never values |
| `list_fields` | Field names on one item, so any field can be addressed |
| `report_leak` | Raise a sticky alarm when a live credential is seen in output |

Any field of any item in the vault is usable. There is no per-field allowlist and
no capability grant: a vault the agent may reach is a vault the agent may use.

## The one guarantee

**Any value the broker resolved from the vault is removed from the output it
returns.** Literal matches on the value and on its common transport encodings:
percent-encoding, JSON escaping, HTML escaping, hex, base64 (standard and
URL-safe), and one decode pass into base64 wrappers so `Authorization: Basic
base64("user:password")` is caught.

That is the entire filter. See [what it does not do](#what-it-does-not-do).

## Requirements

* Linux with systemd
* Python 3.8+, standard library only. No pip install, no virtualenv, no
  dependencies to audit or upgrade.
* The [1Password CLI](https://developer.1password.com/docs/cli/) at
  `/usr/local/bin/op`
* A 1Password **service account** per vault, its token written to
  `/opt/sandbroker/var/tokens/<Name>.token`, mode `0400`, owned by the broker user

## Install

```bash
git clone https://github.com/312-dev/sandbroker
cd sandbroker
sudo ./install.sh          # idempotent; also the upgrade path
sandbroker-register-mcp    # as your normal user, adds one MCP server per vault
sandbroker doctor
```

`install.sh` never reads, writes or deletes anything under `var/tokens`.

## Access control

There is exactly one: **the unix socket is mode `0660`, group `claude-broker`.**
Membership in that group is permission to use the broker; the kernel enforces it
and nothing in this codebase can weaken it. No tokens, no sessions, no approval
flow.

Set `bind` in the config to also serve MCP over HTTP. The daemon **refuses any
address that is not loopback or tailnet** (`100.64.0.0/10`), because that surface
is unauthenticated by design and reachability is the whole access control.

### Sandboxed clients

Claude Code can run inside a bubblewrap sandbox and spawns its MCP servers in
there too. That sandbox breaks the unix socket four separate ways: seccomp
blocks `socket(AF_UNIX)`, the root filesystem is bound read-only so `connect()`
could not write the inode, the network namespace is unshared so host loopback is
a different loopback, and the user namespace collapses supplementary groups to
`nogroup` so the `claude-broker` membership is gone.

One thing survives: `/tmp` is bind-mounted from the host, and the sandboxed
process is still your uid. So `sandbroker bridge` runs a file queue under
`/tmp/sandbroker-bridge/<vault>/{req,resp}`, mode `0700` and owned by you, and
relays it to the sockets:

```bash
systemctl --user enable --now sandbroker-bridge    # install.sh does this for you
```

`sandbroker connect` tries the socket first and falls back to the queue on its
own, so the same MCP registration works sandboxed or not. The bridge holds no
credentials and makes no decisions: it moves bytes between a directory your uid
already owns and a socket your uid could already open. It widens nothing.

## Gating a vault

Add `"require_unlock": true` to a vault and it resolves nothing until a human
says so:

```bash
sudo sandbroker unlock Production --minutes 30
sandbroker locks                    # Production  unlocked, 28 min left
sudo sandbroker lock Production     # or let it expire
```

While locked, `run` returns an error telling the agent to ask you. Listing is
never gated: names cannot leak a value, so gating them adds friction without
safety.

**The enforcement is a file permission, not code.** The marker directory is
`0700` and owned by the broker user, so writing one requires root or the broker
-- and typing that sudo password is the approval. There is no uid check to
bypass, and no tool an agent can call to lift its own gate.

This is deliberately a daemon-side gate rather than a Claude Code hook. A hook
would be advisory: sandboxed agents are granted write access to `~/.claude`, so
anything enforced there is enforced by a file the gated party can edit.

It does not stop an agent that wants Production -- it can still ask you, and you
might say yes without reading carefully. What it buys is that Production access
becomes a deliberate, timestamped act instead of something that happens quietly
inside a task you thought was about Dev.

## Usage

Discover, then run:

```
list_items                     -> mercury-api, hetzner, cloudflare, ...
list_fields  item=mercury-api  -> credential, account_id, notes
run  command: 'curl -sS -H "Authorization: Bearer $TOK" https://api.mercury.com/api/v1/accounts | jq -r ".accounts[].name"'
     secrets: {"TOK": "op://Dev/mercury-api/credential"}
```

References may be written three ways. The vault is implied by which server you
are talking to:

```
op://Dev/mercury-api/credential      fully qualified
mercury-api/credential               vault implied
mercury-api                          vault implied, field defaults to "credential"
```

## What it does not do

Stated plainly, because a security tool that oversells itself is worse than none.

**It is not a secret detector.** It removes values it resolved. A credential
minted *during* a call -- an OAuth access token, a session cookie, a signed URL
-- was never seen by the broker and comes back in the clear. This is what
`report_leak` exists for, and agents are instructed to call it on sight.

**It is not prompt-injection proof.** An agent that wants to exfiltrate a secret
can ask the broker to `curl` it somewhere, and the broker will comply. There is
no egress filter, no command allowlist. The threat model is *accidental*
disclosure to the model provider, not a hostile agent.

**It does not protect against a compromised host.** Anything running as the
broker user or as root can read the tokens directly.

**Redaction is a backstop, not a boundary.** The boundary is that the value is
never sent to the model. Redaction catches the case where a command echoes its
own credential back at you, which happens constantly (`curl -v`, error bodies,
debug logs) and would otherwise leak on the return path.

Full reasoning in [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md).

## Leak alerts

`report_leak` writes a record and pushes to ntfy immediately. An open alert
**re-pushes every 15 minutes until a human acknowledges it on the host**:

```bash
sandbroker alerts          # what is open
sudo sandbroker ack <id>   # stop the nagging
```

No tool can acknowledge an alert. The alerts directory is `0700` and owned by the
broker user, so acknowledging requires host access. An agent that could silence
its own alarm would make the alarm worthless.

## Operating

```bash
sandbroker doctor              # config, op cli, tokens, sockets, open alerts
sandbroker doctor --deep       # also lists vault items (still no values)
systemctl status sandbroker@Dev
journalctl -u sandbroker@Dev -f
bash tests/run.sh              # no dependencies, runs anywhere
```

## History

This is the second design. The first
([`sandbroker-poc`](https://github.com/312-dev/sandbroker-poc)) put a WebAuthn
approval flow, a capability-grant system, an AI auditor and a web console in
front of the same idea. It worked, and nobody wanted to operate it. The whole
apparatus protected against a hostile agent, which was never the actual threat.

## Licence

MIT
