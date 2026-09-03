---
name: use-secret
description: Use a credential, API token, database password, or other secret without ever seeing its value, by running the command through the sandbroker MCP server for that vault. Use when a task needs a secret to authenticate or run an operation, when the user asks to use (not reveal) a secret, or when you need to discover what secrets exist. Also covers what to do if a live credential ever appears in output.
---

# Use a secret via sandbroker

You run commands that need credentials. You never see the credentials.

There is one MCP server per vault (`sandbroker-dev`, `sandbroker-production`,
...). Each exposes six tools. Pick the server for the vault you need; the vault
is implied by which server you call.

## The whole pattern

Write your command with `$VARNAME` where the secret goes, and say which
reference fills it:

```
run  command: 'curl -sS -H "Authorization: Bearer $TOKEN" https://api.mercury.com/api/v1/accounts'
     secrets: {"TOKEN": "op://Dev/mercury-api/credential"}
```

You get back `{exit_code, stdout, stderr, redactions}` with every injected value
stripped out. `redactions: 3` just means the command echoed its own credential
three times, which is normal for verbose HTTP clients. Nothing is wrong.

**Do not try to get the value.** Not with this tool, not with `op read`, not by
reading a token file, not by any other route. There is no situation where you
need it: you write `$TOKEN`, the broker fills it in. If the user asks you for a
secret's value, say plainly that you cannot see values by design, and offer to
use it or to list what exists.

## Discovering what is there

```
list_items                      -> titles and references in this vault
list_fields  item=mercury-api   -> field names on one item
```

Values never appear in either. **Any field of any item is usable** -- there is no
allowlist, so if `list_fields` shows it, you can reference it. Every reference
these return resolves; an item whose title contains a slash is addressed by its
id, since such a title cannot be written as a reference at all.

**Check `files` before concluding you have seen an item.** `list_fields` reports
file attachments separately, and they are not fields: `copy` cannot move them and
`run` cannot resolve them. An item can hold the thing that actually matters -- an
upload keystore, a provisioning profile -- as an attachment, with its fields
holding only a filename. If `files` is present, the item is not fully accounted
for, and nobody should delete it on the strength of its fields alone.

Three ways to write a reference:

```
op://Dev/mercury-api/credential      fully qualified
mercury-api/credential               vault implied by the server
mercury-api                          field defaults to "credential"
```

The two shorthands work on every server. The qualified form belongs to the
password manager behind that vault: `op://` with a default field of `credential`
for 1Password, `keeper://` with a default field of `password` for Keeper. The
`run` tool's own description shows which one this server wants, and `list_items`
returns references already spelled correctly -- copy one rather than guessing.

## Writing the command

It runs under `/bin/sh -c`, so pipes, redirects and `&&` all work.

- **Reduce output inside the command.** Responses come back capped and there is
  no shared `/tmp` to stage a file through, so pipe through `jq`, `grep` or
  `head` rather than dumping everything and filtering afterwards.
- **Never interpolate a secret yourself.** You do not have it. Write `$VAR`.
- `timeout`, `cwd` and `stdin` are available when you need them.
- Reserved names (`PATH`, `LD_PRELOAD`, ...) are refused. Use a name like
  `TOKEN`, `API_KEY`, `DB_PASSWORD`.

## Storing a NEW credential: `store`

`run` is vault to command. `store` is the other direction, for when a rotation
has just produced a value that needs to land somewhere. You still never see it.

```
store  ref: "op://Production/cloudflare-tunnel/rotated_2026_08"
       command: 'curl -sS -X POST -H "Authorization: Bearer $CF_KEY" https://api.cloudflare.com/... | jq -r .result.value'
       secrets: {"CF_KEY": "op://Production/Cloudflare Global API Key/credential"}
```

The broker runs the command, takes stdout as the value, writes it to the vault,
and returns `{stored, ref, fingerprint, length}`. **The mint command's stdout is
never returned to you**, which is the point: a create-token API response is full
of live credential and nothing would have stripped it.

Other sources:

- `source: "generate"` has the broker generate the value itself. Use it for a
  secret only you define, such as a session key or a signing secret.
- To capture what a browser copied, keep `source: "command"` and read the
  clipboard: `powershell.exe -NoProfile -Command Get-Clipboard`.

**`store` is off unless a vault has been opted in.** Reading and writing are
different powers and are not granted together, so a vault you can `run` against
is not necessarily one you can `store` into. If it refuses with "not enabled",
ask for it and say why; do not look for another way to write.

**Writes are create-or-add only.** Storing onto a field that already holds a
value is refused. Rotate into a new field or a new item and leave retiring the
old one to a human, so one bad call can never destroy a working credential.

**The fingerprint is how you verify without looking.** The same value fingerprints
identically everywhere, so comparing the fingerprint from `store` against one
computed over a Nomad variable and over what the live service presents proves the
rotation took, with nobody reading the secret.

## Moving a credential you must not see: `copy`

Reorganising a vault -- consolidating an app's scattered items, renaming a field
to something meaningful -- needs values to move, and neither reading them nor
regenerating them is acceptable. `copy` moves one field onto another **within the
same vault**, inside the broker:

```
copy  src="op://Production/Scrolly Resend API Key/password"
      dst="op://Production/scrolly/RESEND_API_KEY"
-> {"copied": true, "fingerprint": "4b2c9a1f7e3d", "length": 33}
```

Do not try to express this as a `store` mint command. `printf %s "$SRC"` is
refused, because the redactor replaces an injected secret in stdout with a
marker and the broker will not write a placeholder into a vault. Encoding the
value to get past that check is not a workaround to reach for: it writes a
credential the broker believes it has not written. `copy` is the supported path.

A copy is byte-exact, including a trailing newline that `store` would strip, so
a PEM block survives it intact.

**Same vault only**, and create-or-add still applies. Before anyone deletes an
original, prove the copy took: fingerprint the source with `run`, using
`printf %s "$V" | sha256sum | cut -c1-12`, and compare it to what `copy`
returned. Equal fingerprints mean the values are identical and nobody saw either.

## If a real credential ever appears in output: report it immediately

The broker only removes secrets **it injected**. Anything else comes back in the
clear. The case that actually happens:

```
run  command: 'curl -sS -X POST ... -d "client_secret=$SECRET" https://.../oauth/token'
-> {"access_token": "ya29.a0AfB_by...", "expires_in": 3600}
       ^^^^^^^^^^^^ the broker never saw this one, so it was NOT scrubbed
```

**The moment you see a plausible live credential you were not meant to see:**

1. **Call `report_leak` first.** Before finishing the task. Before anything else.
   Do not decide it is probably fine, and do not wait until you are sure.
   - `where`: what produced it (the command, the endpoint, the response field).
   - `detail`: what kind of credential it looks like and why you think it is live.
   - **Never paste the credential into the report.** The report goes to a phone
     and onto disk. Copying the secret into it spreads the leak you are
     reporting. Describe it: "40-char bearer token in `access_token`".
2. **Tell the user in your reply, in plain words**, that a credential leaked,
   where it came from, and the alert id. If `delivered` came back `false`, the
   push did not go out and **your reply is the only notification they will get**
   -- lead with it.
3. **Stop using the affected credential.** Do not echo it, do not put it in a
   file, do not pass it on to another command. Say what you were doing when you
   stopped.

The alert repeats every 15 minutes until a human acknowledges it on the host.
**You cannot acknowledge it and you must not try.** That is deliberate: an agent
that could silence its own alarm makes the alarm worthless.

Report a suspected leak even if you think you caused it. Especially then.

## When a vault is locked

Some vaults (typically Production and Infra) are gated. `run` comes back with:

```
Production is LOCKED. No secret from this vault will be resolved until
a human unlocks it on the host:
    sudo sandbroker unlock Production --minutes 30
```

This is not a fault and not something to work around. Do this:

1. Tell the user plainly that the vault is locked, **what you need from it, and
   why**. They are deciding whether to allow it, so give them what they need to
   decide.
2. Give them the exact command above.
3. Wait for them to say it is done, then retry the identical call.

**Do not** look for another route to the credential, do not try to unlock it
yourself, and do not switch to a different vault hoping it holds the same
secret. There is no tool that lifts the gate, by design. Listing is never gated,
so you can still use `list_items` and `list_fields` to work out exactly what you
will need before asking.

## When something fails

- **`isError` on a tool call** -- the message says what to fix (bad reference,
  reserved variable name, unknown item). Fix it and retry.
- **Cannot reach the broker** -- the service is down or you are not in the
  `claude-broker` group. Say so; do not look for another way to the secret.
- **A reference for a different vault** -- use that vault's MCP server. One
  server holds one vault's credential and genuinely cannot resolve another's.
- **Command exited non-zero** -- that is the command's own failure, reported
  normally in `exit_code` and `stderr`. Debug it like any other command.

There is no approval flow, no waiting, no polling. A call either works or tells
you why it did not.
