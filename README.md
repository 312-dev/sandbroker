# sandbroker

Let an AI coding agent **use** your credentials without those credentials ever
entering the model's context or the model provider's network traffic.

```
agent                     broker (uid: sandbroker)         1Password / Keeper
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
| `store` | Mint or capture a NEW credential into the vault, returning only a fingerprint |
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
* One password manager per vault, either:
  * the [1Password CLI](https://developer.1password.com/docs/cli/) at
    `/usr/local/bin/op`, with a 1Password **service account** per vault, its
    token written to `/opt/sandbroker/var/tokens/<Name>.token`, mode `0400`,
    owned by the broker user; or
  * [Keeper Commander](https://docs.keeper.io/en/keeperpam/commander-cli/overview)
    at `/usr/local/bin/keeper`, with a Commander config per vault in the same
    place. See [Keeper](#keeper) -- that file has to be writable, and it is
    provisioned by hand once with a human present.
* Some way to be told about a leak. Any command that exits `0` will do; see
  [the notifier is your command](#the-notifier-is-your-command)

## Install

```bash
git clone https://github.com/312-dev/sandbroker
cd sandbroker
sudo ./install.sh          # idempotent; also the upgrade path
sandbroker-register-mcp    # as your normal user, adds one MCP server per vault
sandbroker doctor
```

`install.sh` never reads, writes or deletes anything under `var/tokens`.

## Keeper

**This backend has never been run against a live Keeper account.** The flags it
uses are all in Commander's own argument parsers, but two things are inference
rather than documentation, and the parsing is deliberately forgiving because of
it: that `ls --recursive` keeps the same JSON row shape as a flat listing, and
that a failed command exits non-zero. The second one matters more, because a
Commander that exits `0` on failure would turn an error into an empty listing.
Try it against a throwaway folder first. The 1Password backend is the one in
daily use.

A vault is served from 1Password unless it says otherwise. Add `"backend":
"keeper"` and it is served from Keeper instead:

```json
"KeeperDev": {"vault": "Engineering/Dev", "token": "KeeperDev",
              "backend": "keeper", "port": 8774}
```

**`vault` is a shared folder path, not a vault name.** Keeper has no object that
means what sandbroker means by a vault: a Keeper account has exactly one vault,
and the thing that gets named, scoped and shared is a shared folder. So one
sandbroker vault is one shared folder, addressed as a path from the account's
vault root (`Engineering/Dev` for a nested one). Everything in it, including
subfolders, is in scope; nothing else is.

Setting one up, once, with a human at the keyboard:

```bash
keeper --config /opt/sandbroker/var/tokens/KeeperDev.token shell
  login broker@example.com          # approve the device when prompted
  this-device register
  this-device persistent-login on
  quit
sudo chown sandbroker: /opt/sandbroker/var/tokens/KeeperDev.token
sudo chmod 0600 /opt/sandbroker/var/tokens/KeeperDev.token
```

`0600`, not the `0400` a 1Password token gets: Commander rotates its
persistent-login clone code as it runs and writes the config back. It also keeps
a vault cache, which lands in `keeper_state_dir` (`/opt/sandbroker/var/keeper`).
**One config per daemon.** Loading the same config from a second machine revokes
both sessions and breaks persistent login.

### What is different from the 1Password path

Read [what it does not do](#what-it-does-not-do) as well; these are the Keeper
specifics.

**Vault isolation is enforced by sandbroker, not by Keeper.** A 1Password
service-account token is issued against named vaults and cannot address anything
else. Commander logs in as a *user*, and `keeper get <uid>` returns any record
that user can see, in any folder. sandbroker closes this by listing the
configured folder before every read and refusing a record the listing does not
contain -- but that is a check in a Python file, not a boundary the vault
enforces. **Give each Keeper-backed daemon its own Keeper account**, holding
nothing but the folder it serves, and the isolation is real again.

**Every read pulls the whole record into the daemon.** Keeper has no equivalent
of `op read`; nothing fetches a single field. The extra values stay in the
broker, never reach a child's environment and are never returned, but there is
more plaintext in memory than the 1Password path needs. `list_fields` is affected
the same way and discards the values, exactly as the 1Password backend does.

**It is slower.** Commander logs in and syncs the account's vault on every
invocation, and a read costs two of them: one to check the folder, one to fetch
the record.

**Commander, not `ksm`.** Keeper Secrets Manager is the closer analog of a
service account -- one-time token in, scoped config out, no device approval, no
writable state -- and it would fix the isolation paragraph above outright. It
only reaches records deliberately shared into a KSM application, though, not the
ordinary vault where credentials already live. Commander was chosen for that
reach; `ksm` would be the right second backend for anyone who can move their
secrets into an application.

**`keeper://` is overloaded.** Keeper's own notation is also spelled that way
and addresses a record uid (`keeper://<uid>/field/password`). A sandbroker
reference names the vault alias first (`keeper://Dev/item/field`), so pasting
Keeper notation here is refused as a reference to an unknown vault.

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

Only the qualified form differs on a Keeper-backed vault: the scheme is
`keeper://` and the default field is `password`, Keeper's own name for the
secret bit of a record. The two shorthands are identical on both backends,
deliberately, so nothing an agent has learned changes when a vault moves.

```
keeper://Dev/mercury-api/password    fully qualified
mercury-api/password                 vault implied
mercury-api                          vault implied, field defaults to "password"
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

**On Keeper, vault isolation is a check rather than a boundary.** Commander
authenticates as a user with access to that user's whole vault, so the
one-folder-per-daemon scope is enforced by sandbroker refusing out-of-folder
records, not by Keeper refusing to hand them over. See [Keeper](#keeper).

**Redaction is a backstop, not a boundary.** The boundary is that the value is
never sent to the model. Redaction catches the case where a command echoes its
own credential back at you, which happens constantly (`curl -v`, error bodies,
debug logs) and would otherwise leak on the return path.

Full reasoning in [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md).

## Leak alerts

`report_leak` writes a record and fires a notification immediately. An open alert
**re-fires every 15 minutes until a human acknowledges it on the host**:

```bash
sudo sandbroker alerts     # what is open
sudo sandbroker ack <id>   # stop the nagging
```

Both need root, because the alerts directory is `0700` and owned by the broker.
Run `alerts` as yourself and it says so and exits `2`; it will not tell you there
are none, because it has not looked.

No tool can acknowledge an alert. The alerts directory is `0700` and owned by the
broker user, so acknowledging requires host access. An agent that could silence
its own alarm would make the alarm worthless.

### The notifier is your command

sandbroker has no opinion about how you want to be told. Set `notify_command` to
anything that exits `0` once a human has been reached:

```jsonc
"notify_command": "/opt/sandbroker/contrib/notify-ntfy.sh"
"notify_command": "notify-send -u critical \"$SANDBROKER_ALERT_TITLE\""
"notify_command": ["/usr/local/bin/page-me", "--severity", "high"]
"notify_command": "jq -c . >> /var/log/sandbroker-leaks.jsonl"
```

A string runs under `/bin/sh`; a list is argv and skips the shell. The alert
arrives twice over: the full record as JSON on **stdin**, and the same fields as
`SANDBROKER_ALERT_*` environment variables for scripts that would rather not
parse. A non-zero exit means undelivered, so the sweeper tries again.

`where` and `detail` are written by the **agent**, and neither ever reaches the
command line. Interpolating agent-authored text into a command string would hand
the agent shell execution inside the very alarm that watches it, so the alert
travels only on stdin and in the environment, where nothing re-parses it.

`contrib/notify-ntfy.sh` is a worked example, not a dependency.

**If `notify_command` is unset, alerts are recorded to disk and nobody is told.**
`sandbroker doctor` counts that as a problem and the daemon warns at startup,
because an alarm nobody hears is worse than no alarm: it reads as safety.

## The other half: leak-alarm

The broker removes values it resolved. It says nothing about a credential it
never saw, and those are the ones that leak.

[`plugin-leak-alarm/`](plugin-leak-alarm/) is a separate Claude Code plugin in
this repository that watches tool traffic for credential shapes: it **denies** a
tool call carrying one, and **alerts** on one that arrives in tool output. It
needs no broker, no vault and no daemon, and it reuses the `notify_command`
contract above, so a notifier written for one works for the other.

It is heuristic where the broker is exact, and it can only alert rather than
filter on the inbound path. Its README is blunt about both.

```
/plugin marketplace add 312-dev/sandbroker
/plugin install leak-alarm@sandbroker-plugins
```

## Operating

```bash
sandbroker doctor              # config, backend CLIs, tokens, sockets, open alerts
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
