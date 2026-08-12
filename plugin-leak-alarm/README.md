# leak-alarm

A Claude Code plugin that notices a live credential crossing a tool boundary and
makes a human deal with it.

Two halves:

* **`PreToolUse`** sees a credential in a tool's *input* and **denies the call**.
  A token about to be written to a file, committed, or curled somewhere does not
  go.
* **`PostToolUse` / `PostToolUseFailure`** sees a credential in a tool's *output*
  and **raises an alert**. It cannot stop that one, and the next section explains
  why that is still worth doing.

Plus a **`report-leak` skill**, because the hook only catches shapes it has
patterns for and the model sees everything else.

Standalone: no broker, no 1Password, no daemon. Python 3 standard library only.

## Install

```
/plugin marketplace add 312-dev/sandbroker
/plugin install leak-alarm@sandbroker-plugins
```

Nothing else is required, but with no notifier configured the alarm can only
speak through the terminal. See [Getting told](#getting-told).

## What this is not

It is worth being blunt, because the sibling project in this repo makes a much
stronger promise and the two are easy to confuse.

**sandbroker's redactor** removes values it resolved from a vault. Exact match on
known bytes. It makes a guarantee.

**This** is a pattern matcher looking for credentials nobody told it about. It is
heuristic. It will miss things. It can be wrong. **It makes no guarantee at all.**

It is still worth having, because the credentials that actually leak are the ones
nothing was watching for: an OAuth `access_token` in a response body, a session
cookie, a signed URL, a key an agent helpfully pasted into a file.

### Detection on the output path is not prevention

A `PostToolUse` hook receives the tool's output but **cannot alter or suppress
it**. By the time this code runs, the tool has executed and the credential is
already in the model's context. Nothing can pull it back.

So the output half is not a filter. It is *rotate this now*, delivered to
somebody who can. Treat every alert as a credential that must be considered
compromised.

`PreToolUse` is the only half that prevents anything, and only in the outbound
direction.

### The agent can delete its own alert files

Alerts are recorded under your own `~/.local/state/leak-alarm/`, and the agent
runs as you. It can remove them. Any standalone plugin has this limit: without a
second uid there is nothing to enforce against.

Two things follow. First, **the notification is the load-bearing part, not the
file** - once it has left the machine it cannot be unsent. Second, if you want an
alarm an agent provably cannot silence, you need one recorded by a different
user: that is [sandbroker](../README.md), whose `report_leak` alerts re-fire every
15 minutes until a human acknowledges them on the host.

## Getting told

Set `notify_command` to anything that exits `0` once a human has been reached:

```jsonc
// ~/.config/leak-alarm/config.json
{
  "notify_command": "notify-send -u critical \"$SANDBROKER_ALERT_TITLE\""
}
```

A string runs under `/bin/sh`; a list is argv and skips the shell. The alert
arrives as JSON on **stdin** and as `SANDBROKER_ALERT_*` environment variables.

That variable prefix is not a typo. It is the same contract sandbroker's
`alert.py` uses, so **one notifier script serves both** - and if
`/opt/sandbroker/etc/sandbroker.json` already sets a `notify_command`, this
plugin inherits it and needs no configuration at all.

Nothing derived from tool traffic ever reaches the command line, so a credential
or a hostile string in a tool response cannot become shell.

**With no notifier, the alarm still fires but only into your terminal**, and the
message says `NOT DELIVERED` so you know that is all you got.

## Configuration

`~/.config/leak-alarm/config.json`, all keys optional:

| Key | Default | Meaning |
|---|---|---|
| `notify_command` | inherited from sandbroker, else none | How you get told |
| `block_tool_input` | `true` | Deny a tool call carrying a credential |
| `halt_on_detect` | `false` | End the turn when output contains a credential |
| `disabled` | `[]` | Pattern names to switch off, e.g. `["jwt"]` |
| `extra_patterns` | `[]` | `{"name": ..., "regex": ...}` of your own |
| `ignore` | `[]` | Literal strings that are known not to be live |

`LEAK_ALARM_NOTIFY` in the environment overrides `notify_command`.

`halt_on_detect` is off because ending a turn on a false positive is expensive.
Turn it on where a leaked credential is worse than an interrupted task.

## The patterns

[`rules/patterns.json`](rules/patterns.json) is deliberately **short and
prefix-anchored**. Every entry is a token format whose issuer chose a distinctive
prefix, so a match is nearly always a real credential.

There is no entropy scoring and no generic "long random string" rule. The alarm
interrupts a human, so the bar is *would I want to be paged for this at 3am*, not
*this might be a secret*. Deliberately absent, with reasons, in the file's own
header: bare AWS secret keys, `Bearer <anything>`, and generic high entropy.

Findings are identified by pattern name and a 12-character SHA-256 prefix.
**The credential itself is never written anywhere** - not to the alert, the log,
the terminal, or the notifier. A tool that reports leaks by quoting them has
become a way to leak them, and `tests/test_leak_alarm.py` enforces this.

Add your own through `extra_patterns` rather than editing the file, so an update
does not overwrite them. A malformed regex there is skipped with a note, never
fatal.

## Reviewing alerts

```bash
plugin-leak-alarm/bin/leak-alarm alerts   # what has fired
plugin-leak-alarm/bin/leak-alarm clear    # after rotating
```

## Tests

```bash
python3 tests/test_leak_alarm.py
```

Run from the repository root, alongside sandbroker's own suite via
`bash tests/run.sh`. No dependencies.
