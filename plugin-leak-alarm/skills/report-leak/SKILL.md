---
name: report-leak
description: What to do the moment a live credential appears where it should not have - in tool output, a file, a log, an error body, or a response you did not expect. Use when you see an access token, session cookie, API key, private key or signed URL that was not deliberately handed to you, when a leak-alarm hook fires, or when you are unsure whether something you just saw was a real credential.
---

# A credential just appeared. Here is what you do.

You are the sensor. The hook catches credential shapes it has patterns for, and
it will miss things: a token format nobody wrote a rule for, a password in
prose, a connection string, a private key pasted mid-file. **You see the whole
picture and it does not.** If you notice one, it is on you to say so.

## The rule

**The moment you see a plausible live credential you were not meant to see, say
so before you do anything else.** Not after you finish the task. Not once you
are sure. The cost of a false alarm is a human glancing at a notification. The
cost of a missed one is a live credential sitting in a transcript.

Do not decide it is probably fine. Do not decide it is probably a test value.
Say what you saw and let a human decide.

## Never quote the credential

This is the part that gets done wrong.

Reporting a leak by pasting the credential into your reply **spreads the leak
you are reporting**. Your reply is saved, logged, and sent to the model
provider, which is the exact exposure you are trying to flag.

**Describe it instead:**

| Do not write | Write |
|---|---|
| `the token ya29.a0AfB_byC3...` | a Google OAuth access token in the `access_token` field |
| `AKIAIOSFODNN7EXAMPLE and the secret` | an AWS access key id and secret pair, in `~/.aws/credentials` |
| the full `-----BEGIN RSA PRIVATE KEY-----` block | an unencrypted RSA private key, about 1700 characters, in `deploy/id_rsa` |

Enough for a human to find and rotate it. Nothing more.

## What to say

1. **Lead with it.** First line of your reply, before the task result. If the
   user has to scroll to find out a credential leaked, you buried it.
2. **Where it came from**: the command, the endpoint, the file, the response
   field. This is what tells them what to rotate.
3. **Why you think it is live**: the shape, the prefix, the context it appeared
   in. If you are unsure, say you are unsure and report it anyway.
4. **What you did about it.** See below.

If a `leak-alarm` alert id was shown to you, include it. If the alert says
**NOT DELIVERED**, then no notification went anywhere and **your reply is the
only warning that human will ever get**. Say that explicitly.

## Then stop using it

- Do not echo it, print it, or `cat` the file again.
- Do not copy it into another command, a file, a commit, or an environment
  variable.
- Do not "just finish the task" with it first.
- If you already used it somewhere in this session, say exactly where. That is
  the blast radius and only you know it.

If a `PreToolUse` hook denied one of your calls for carrying a credential: that
is the system working. **Do not route around it.** Do not re-encode the value,
split it across arguments, write it to a file and read it back, or find another
tool that is not covered. Tell the user what you were trying to do and why it
needs that credential.

## If you caused it

Report it anyway. Especially then.

An agent that hides its own mistake turns a rotatable credential into a
compromised one. Nobody is upset that you tripped the alarm; they would be very
upset to find out three weeks later.

## What you cannot do

You cannot acknowledge or clear an alert. That is deliberate: an agent that can
silence its own alarm makes the alarm worthless. Do not try, and do not go
looking for the state directory.

If sandbroker is in use, `report_leak` on the relevant vault's MCP server is the
stronger path, because that alert re-fires every 15 minutes until a human
acknowledges it on the host. Call it **as well as** telling the user. See the
`use-secret` skill.

## Judging what counts

Report:

- Anything with a credential prefix: `ghp_`, `sk-ant-`, `sk-`, `ya29.`, `AKIA`,
  `xoxb-`, `glpat-`, `-----BEGIN ... PRIVATE KEY-----`.
- OAuth responses: `access_token`, `refresh_token`, `id_token`.
- Session cookies, signed URLs with embedded auth, `Authorization` headers you
  did not construct.
- Connection strings with a password in them.
- Anything a service handed you that would let someone else act as you.

Do not report:

- `[redacted:NAME]` markers. That is a broker having removed a value on purpose.
- Values that are obviously placeholders: `xxxxxxxx`, `YOUR_TOKEN_HERE`,
  `<api-key>`, `AKIAIOSFODNN7EXAMPLE`.
- Public identifiers: client ids, account ids, project ids, usernames.
- A credential the user just deliberately handed you and asked you to use. That
  is not a leak, though it is worth mentioning a broker would be safer.

When you genuinely cannot tell, report it. The asymmetry is not close.
