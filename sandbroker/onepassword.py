"""The 1Password side: resolve a ref to a value, and list what exists.

Each vault has its own service-account token file, readable only by the daemon
user. One daemon process serves one vault and opens only that vault's token, so
a fault in the Dev server has no path to the Production credential -- the
isolation is a process boundary, not a code path.

Agents address secrets by ALIAS (`op://Dev/mercury/token`). The alias is
rewritten to the real vault name here. Aliases stay stable when a vault gets
renamed, and they keep the real vault naming out of agent-visible strings.
"""

import os
import json
import re
import subprocess

from .redact import fingerprint

REF_RE = re.compile(r"^op://(?P<vault>[^/]+)/(?P<item>[^/]+)(?:/(?P<field>.+))?$")

# The default when a ref names an item but no field. 1Password's own convention
# for "the secret bit of this item", and the field almost every API token uses.
DEFAULT_FIELD = "credential"


class VaultError(Exception):
    """Something went wrong talking to 1Password.

    Messages here are deliberately terse and never echo the ref's field or any
    op stderr: the CLI is chatty on failure and quotes context back, and none of
    that should be able to ride out on an error path.
    """


class Vault:
    # How the rest of the daemon names this backend: in the startup log, in
    # doctor's output, and in the reference scheme the tool descriptions teach.
    backend = "1password"
    backend_label = "1Password"
    ref_scheme = "op"
    default_field = DEFAULT_FIELD

    def __init__(self, alias, real_name, token_file, op_bin, timeout=30):
        self.alias = alias
        self.real_name = real_name
        self.token_file = token_file
        self.op_bin = op_bin
        self.timeout = timeout
        self._token = None

    # -- token --------------------------------------------------------------

    def _token_value(self):
        """Read the service-account token once and keep it in memory.

        It stays in this process and is passed to `op` through the environment.
        It is never placed in a child's argv and never returned on any path.
        """
        if self._token is None:
            try:
                with open(self.token_file, "r", encoding="utf-8") as fh:
                    self._token = fh.read().strip()
            except OSError:
                raise VaultError("service-account token for %s is not readable"
                                 % self.alias)
            if not self._token:
                raise VaultError("service-account token for %s is empty" % self.alias)
        return self._token

    def service_account_token(self):
        """Exposed so the runner can scrub it from output too. It is not a vault
        secret the agent asked for, but it is the key to every vault secret, so
        an accidental env dump must not carry it out."""
        try:
            return self._token_value()
        except VaultError:
            return None

    def _env(self):
        env = dict(os.environ)
        env["OP_SERVICE_ACCOUNT_TOKEN"] = self._token_value()
        return env

    def _run(self, argv, timeout=None, stdin_data=None):
        """Run one op invocation.

        `stdin_data` exists so a secret can reach op without ever being an
        argument. /proc/<pid>/cmdline is world-readable, so an assignment
        statement on argv is visible to every process on the box for as long as
        the call runs -- op's own help warns about this and points at templates
        for exactly that reason. Two of the open leak alerts are credentials
        found sitting in a command line, so this is a demonstrated failure mode
        here, not a theoretical one.
        """
        try:
            proc = subprocess.run(
                argv,
                input=stdin_data,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,   # op echoes refs and vault context
                env=self._env(),
                timeout=timeout or self.timeout,
            )
        except subprocess.TimeoutExpired:
            raise VaultError("1Password timed out")
        except OSError:
            raise VaultError("could not execute %s" % self.op_bin)
        if proc.returncode != 0:
            raise VaultError("1Password rejected the request "
                             "(missing item or field, or token lacks access)")
        return proc.stdout.decode("utf-8", "replace")

    # -- refs ---------------------------------------------------------------

    def parse_ref(self, ref):
        """Normalise a ref and confirm it belongs to THIS vault.

        Shorthands accepted, because the server already is one vault and making
        callers repeat it is friction with no benefit:
            op://Dev/item/field   fully qualified
            item/field            vault implied
            item                  vault implied, DEFAULT_FIELD
        """
        ref = (ref or "").strip()
        if not ref:
            raise VaultError("empty reference")
        if not ref.startswith("op://"):
            ref = "op://%s/%s" % (self.alias, ref)
        match = REF_RE.match(ref)
        if not match:
            raise VaultError("malformed reference (want op://Vault/item/field)")
        vault, item, field = match.group("vault", "item", "field")
        if vault != self.alias and vault != self.real_name:
            raise VaultError(
                "reference is for vault %r but this server serves %r -- use the "
                "%s server" % (vault, self.alias, vault))
        return item, field or DEFAULT_FIELD

    def read(self, ref):
        """Resolve one ref to its value. ANY field of any item is allowed: there
        is no per-field allowlist, because a vault the agent may use is a vault
        the agent may use.

        Two mechanisms, because one is not enough. `op read` parses a secret
        REFERENCE, and its parser cannot address every legal item title --
        parentheses and colons in a title make it reject a reference for an item
        it can otherwise read perfectly well. `op item get` looks the item up by
        title and has no such limit, which is why list_fields (which uses it)
        would happily advertise a reference that read then refused.

        Discovery promising something resolution rejects is a bug in this file,
        not a puzzle for the caller, so the narrow path is tried first and the
        general one catches what it cannot express.
        """
        item, field = self.parse_ref(ref)
        real = "op://%s/%s/%s" % (self.real_name, item, field)
        try:
            value = self._run([self.op_bin, "read", "--no-newline", real])
        except VaultError:
            value = self._read_via_item(item, field)
        if not value:
            raise VaultError("reference resolved to an empty value")
        return value

    def _read_via_item(self, item, field):
        """Fallback: fetch the item and take one field.

        This pulls every field of the item into this process, where `op read`
        would have fetched exactly one. That is a real cost and the reason it is
        the fallback rather than the default: the extra values stay inside the
        daemon, are never placed in a child's environment, and are never
        returned -- but less material in memory is still better than more.
        """
        out = self._run([self.op_bin, "item", "get", item,
                         "--vault", self.real_name, "--format", "json"],
                        timeout=30)
        try:
            data = json.loads(out)
        except ValueError:
            raise VaultError("could not parse the item")
        for entry in (data.get("fields") or []) if isinstance(data, dict) else []:
            if entry.get("value") is None:
                continue
            if field in (entry.get("label"), entry.get("id")):
                return entry["value"]
        raise VaultError(
            "item %r has no field %r with a value set (list_fields shows what "
            "it does have)" % (item, field))

    # -- writing (create-or-add only) ---------------------------------------

    def _item_json(self, item):
        """The item as a dict, or None if this vault has no such item."""
        try:
            out = self._run([self.op_bin, "item", "get", item,
                             "--vault", self.real_name, "--format", "json"],
                            timeout=30)
        except VaultError:
            return None
        try:
            data = json.loads(out)
        except ValueError:
            raise VaultError("could not parse the item")
        return data if isinstance(data, dict) else None

    def write(self, ref, value):
        """Store a NEW value at ref and return its fingerprint, never the value.

        CREATE OR ADD ONLY. If the field already holds a value this refuses,
        and that refusal is the point rather than an inconvenience. A broker
        that can overwrite is a broker that can destroy every good credential in
        the vault on one bad call, which would turn a compromised agent into an
        outage. Retiring a superseded value stays a human action.

        The value travels on stdin as a JSON template, never as an assignment
        argument, so it is never present in the process table. op's own help
        recommends exactly this for sensitive values.
        """
        item, field = self.parse_ref(ref)
        if not value:
            raise VaultError("refusing to store an empty value")

        existing = self._item_json(item)
        new_field = {"label": field, "type": "CONCEALED", "value": value}

        if existing is None:
            template = {"title": item,
                        "category": "API_CREDENTIAL",
                        "fields": [new_field]}
            argv = [self.op_bin, "item", "create",
                    "--vault", self.real_name, "--format", "json"]
        else:
            for entry in existing.get("fields") or []:
                if field in (entry.get("label"), entry.get("id")) and entry.get("value"):
                    raise VaultError(
                        "field %r on item %r already holds a value; store is "
                        "create-or-add only" % (field, item))
            template = dict(existing)
            template["fields"] = list(existing.get("fields") or []) + [new_field]
            argv = [self.op_bin, "item", "edit", item,
                    "--vault", self.real_name, "--format", "json"]

        self._run(argv, stdin_data=json.dumps(template).encode("utf-8"),
                  timeout=30)
        return fingerprint(value)

    # -- discovery (metadata only, structurally value-free) -----------------

    def list_items(self):
        """Item titles and ids. `op item list` never returns a field value, so
        this path cannot leak one even if it misbehaves."""
        out = self._run([self.op_bin, "item", "list",
                         "--vault", self.real_name, "--format", "json"])
        try:
            data = json.loads(out)
        except ValueError:
            raise VaultError("could not parse the item list")
        items = []
        for entry in data if isinstance(data, list) else []:
            title = str(entry.get("title") or "")
            if not title:
                continue
            item = {
                "title": title,
                "ref": "op://%s/%s" % (self.alias, title),
                "category": str(entry.get("category") or ""),
            }
            # The UUID is not a secret, and it is the unambiguous way to address
            # an item whose title contains characters that make a reference
            # awkward. Worth carrying so a caller always has a way through.
            iid = str(entry.get("id") or "")
            if iid:
                item["id"] = iid
            items.append(item)
        return sorted(items, key=lambda i: i["title"].lower())

    def list_fields(self, item):
        """Field LABELS for one item, with values discarded here in the daemon.

        This is what makes "any field" usable rather than a guessing game: the
        agent can see that an item carries `username`, `credential` and
        `account_id` without any of them crossing the boundary.
        """
        out = self._run([self.op_bin, "item", "get", item,
                         "--vault", self.real_name, "--format", "json"])
        try:
            data = json.loads(out)
        except ValueError:
            raise VaultError("could not parse the item")
        fields = []
        seen = set()
        for field in (data.get("fields") or []) if isinstance(data, dict) else []:
            label = str(field.get("label") or field.get("id") or "")
            if not label or label in seen:
                continue
            seen.add(label)
            fields.append({
                "field": label,
                "ref": "op://%s/%s/%s" % (self.alias, item, label),
                "type": str(field.get("type") or ""),
                # Whether a value EXISTS, never what it is. Empty fields are
                # common in 1Password templates and are worth skipping.
                "populated": bool(field.get("value")),
            })
        return fields
