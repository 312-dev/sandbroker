# Security policy

## Reporting a vulnerability

Open a [private security advisory](https://github.com/312-dev/sandbroker/security/advisories/new)
on this repository. If that is not available to you, open a public issue that
says only "security issue, please make contact" with no detail in it, and wait
to be contacted.

This is a personal project maintained by one person. Expect an acknowledgement
within a week. There is no bounty.

## What counts as a vulnerability here

The guarantee this project makes is narrow and specific:

> Any value the broker resolved from the vault is removed from the data it
> returns to the caller.

A report that breaks that guarantee is the most valuable thing you can send.
Concretely:

* An encoding or transform of a resolved secret that survives the redactor and
  reaches the caller. See `sandbroker/redact.py` for the forms already handled.
* Any path by which a caller obtains a secret **value** rather than using it:
  through `list_items`, `list_fields`, an error message, a timing signal, the
  service-account token, or a crash dump.
* A way for a caller to reach a vault it was not given, including across the
  per-vault process boundary.
* A way for a caller to lift its own `require_unlock` gate, or to acknowledge
  its own leak alert. Both are supposed to require a human on the host.
* Anything that lets a caller execute code as the broker user rather than as
  itself, or that widens the `claude-broker` group check.

## What is already known and out of scope

These are documented in [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) and in the
README's "What it does not do" section. Reports about them are not findings,
they are the design:

* **Credentials minted during a call are not redacted.** The broker only removes
  values it resolved itself. An OAuth `access_token` in a response body comes
  back in the clear. That is what `report_leak` exists for.
* **There is no egress filter and no command allowlist.** An agent that wants to
  `curl` a secret somewhere can, and the broker will help. The threat model is
  accidental disclosure to the model provider, not a hostile agent.
* **A compromised host is game over.** Anything running as root or as the broker
  user can read the service-account tokens directly.
* **The HTTP listener is unauthenticated.** That is why the daemon refuses to
  bind anything but loopback or tailnet: reachability is the access control. A
  report that the HTTP surface has no auth is a report about a documented
  decision. A report that it bound an address it should have refused is a bug.
* **Prompt injection can make an agent misuse a secret.** No part of this
  project claims otherwise.

If you think one of these should not be out of scope, that is a design argument
worth having in an issue. It is just not a vulnerability report.
