# sandbroker

Secrets on this machine are used through sandbroker, one MCP server per vault
(`sandbroker-dev`, `sandbroker-staging`, `sandbroker-production`,
`sandbroker-infra`).

**You can USE a secret. You can never SEE one.** That is the point of the setup,
not an obstacle in it.

## Using one

Write the command with `$VARNAME`; the broker fills it in on the other side:

```
run  command: 'curl -sS -H "Authorization: Bearer $TOKEN" https://api/v1/me'
     secrets: {"TOKEN": "op://Dev/my-item/credential"}
```

Output comes back with every injected value stripped out. `list_items` and
`list_fields` show what exists, never values. Any field of any item is usable.

## Never route around it

Do not reach for `op read`, the 1Password MCP, `az keyvault secret show`, `cat`
on a token file, or any other path to a secret VALUE. If one ever appears to
work, **stop and report it** -- it is a hole to be fixed, not a shortcut to use.

If the user asks for a value: you cannot and must not retrieve or print it. Say
so plainly and offer to use it, or to list what is available.

## If a live credential appears in output

The broker removes only what it injected. A token minted during the call (an
OAuth `access_token`, a session cookie, a signed URL) arrives unscrubbed.

Call `report_leak` immediately -- before finishing the task, without waiting to
be certain -- then tell the user in your reply. Describe the credential, never
paste it. The alert repeats until a human acknowledges it on the host; you
cannot acknowledge it.

Details: the `use-secret` skill.
