"""The Keeper side: the same four operations over a vault model that does not fit.

Keeper has no object that means what sandbroker means by a vault. A Keeper
account has exactly one vault; the thing that is named, scoped and shared is a
SHARED FOLDER. So a sandbroker vault maps onto one shared folder: `vault` in the
config is a folder path from the account's vault root, and one daemon serves one
folder.

That mapping is weaker than the 1Password one and the difference is worth
stating rather than hiding. A 1Password service-account token is issued against
named vaults and cannot address anything outside them, so the isolation is
enforced by 1Password. Keeper Commander authenticates as a USER, and
`keeper get <uid>` returns any record that user can see, in any folder. The
folder boundary is therefore enforced HERE: every read resolves the item against
a listing of the configured folder first, and a record the listing does not
contain is refused. That is code, not the backend, which is why the README says
to give each Keeper-backed daemon its own Keeper account.

WHY COMMANDER AND NOT SECRETS MANAGER
-------------------------------------
Keeper Secrets Manager (`ksm`) is the closer analog of a 1Password service
account: a one-time token materialises into a scoped config and the credential
is machine-to-machine from the start. Commander is what this implements because
it reaches the ordinary vault, where the credentials people already keep live,
rather than only the records deliberately shared into a KSM application. The
price is the paragraph above plus a one-time device approval by a human.

Agents address secrets by ALIAS (`keeper://Dev/mercury/password`), the same way
they do against 1Password, and the two shorthands are identical. The alias is
rewritten to the real folder path here, so folder renames stay invisible.

THE TWO COMMANDS THIS RELIES ON
-------------------------------
    keeper --config <file> --batch-mode ls --format json --recursive <folder>
    keeper --config <file> --batch-mode get <uid> --format json

Every flag above is in Commander's own argument parsers. Two things about them
are inference rather than documentation, and both are why the parsing below is
forgiving: that `--recursive` keeps the same JSON row shape as a flat listing
(uid/name/type/details/source), and that a failed command exits non-zero. This
has never been run against a live Keeper account.
"""

import json
import os
import re
import subprocess

from .onepassword import VaultError

REF_RE = re.compile(r"^keeper://(?P<vault>[^/]+)/(?P<item>[^/]+)(?:/(?P<field>.+))?$")

# The default when a ref names an item but no field. Keeper's own convention for
# "the secret bit of this record": it is the field `find-password` returns and
# the one `get --format password` prints, the way `credential` is 1Password's.
DEFAULT_FIELD = "password"

# Every key in a Commander config whose value helps open the vault. Unlike a
# 1Password service-account token this is a document, not a string, and each of
# these is worth protecting on its own, so all of them reach the redactor.
# Ordered most damaging first: the single-value hook can only carry the first.
AUTH_KEYS = ("password", "private_key", "clone_code", "device_token")

# Keys of a `get --format json` record that hold a value and are worth
# addressing. The rest of that object is metadata (uid, revision, permissions,
# attachments) and must not be advertised as a field.
LEGACY_FIELDS = ("login", "password", "login_url", "totp", "notes")

# `ls` packs a record's type into a human-readable details string. Pulling it
# back out is a convenience, not load-bearing: an unexpected shape yields "".
_RECORD_TYPE_RE = re.compile(r"\bType:\s*([^,]+)")


def _collect_auth(data):
    """Every login string in a Commander config, as (label, value).

    Walked recursively because the config has had two shapes: a flat object, and
    a newer one nesting the same keys under `users` and `devices`. Searching for
    the key names rather than the layout covers both, and covers the next
    rearrangement too.
    """
    found = {}
    stack = [data]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            for key, value in node.items():
                if key in AUTH_KEYS and isinstance(value, str) and value.strip():
                    found.setdefault(key, []).append(value.strip())
                elif isinstance(value, (dict, list)):
                    stack.append(value)
        elif isinstance(node, list):
            stack.extend(n for n in node if isinstance(n, (dict, list)))

    pairs = []
    seen = set()
    for key in AUTH_KEYS:
        for index, value in enumerate(found.get(key, [])):
            if value in seen:
                continue
            seen.add(value)
            label = "KEEPER_%s" % key.upper()
            pairs.append(("%s_%d" % (label, index + 1) if index else label, value))
    return pairs


def _payload(text, what):
    """Pull the JSON document out of Commander's stdout.

    `op` prints its JSON and nothing else. Commander is a shell wrapped around a
    login, so a sync notice or a version banner can share the stream with the
    answer. Parsing the whole buffer first keeps the clean case exact; scanning
    for the document only happens when that fails.
    """
    text = (text or "").strip()
    if not text:
        raise VaultError("Keeper returned nothing for the %s" % what)
    try:
        return json.loads(text)
    except ValueError:
        pass
    decoder = json.JSONDecoder()
    for index, char in enumerate(text):
        if char not in "[{":
            continue
        try:
            value, _end = decoder.raw_decode(text, index)
        except ValueError:
            continue
        return value
    raise VaultError("could not parse the %s" % what)


def _scalar(value):
    """One field's value as a string, or "" when it has none.

    Keeper wraps a typed field's value in a list, and a few field types (host,
    name, phone) hold an object instead of a string. Serialising the object is
    the faithful answer -- it is what the field contains -- and better than
    reporting a populated field as empty.
    """
    if isinstance(value, list):
        value = value[0] if value else None
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    return json.dumps(value, sort_keys=True)


def _walk_fields(record):
    """Every addressable field of a record, as (name, type, value).

    Three shapes arrive in the same object. A typed (v3) record carries `fields`
    and `custom` arrays of {type, label, value}, and the same object repeats
    some of those values under flat `login`/`password`/`notes` keys; a v2 record
    carries only the flat keys plus a `custom_fields` map. Emitting all three in
    a fixed order, first name winning, keeps a reference stable when a record is
    converted from one version to the other.
    """
    for group in ("fields", "custom"):
        entries = record.get(group)
        for entry in entries if isinstance(entries, list) else []:
            if not isinstance(entry, dict):
                continue
            yield (str(entry.get("label") or entry.get("type") or ""),
                   str(entry.get("type") or ""),
                   _scalar(entry.get("value")))

    for key in LEGACY_FIELDS:
        if key in record:
            yield key, "", _scalar(record.get(key))

    custom = record.get("custom_fields")
    if isinstance(custom, dict):
        for name, value in custom.items():
            yield str(name), "", _scalar(value)
    elif isinstance(custom, list):
        for entry in custom:
            if isinstance(entry, dict):
                yield (str(entry.get("name") or entry.get("label") or ""),
                       str(entry.get("type") or ""),
                       _scalar(entry.get("value")))


def _record_type(details):
    match = _RECORD_TYPE_RE.search(details or "")
    return match.group(1).strip() if match else ""


class Vault:
    # How the rest of the daemon names this backend: in the startup log, in
    # doctor's output, and in the reference scheme the tool descriptions teach.
    backend = "keeper"
    backend_label = "Keeper shared folder"
    ref_scheme = "keeper"
    default_field = DEFAULT_FIELD

    # Commander logs in and syncs the account's vault on every invocation, so
    # the 1Password backend's 30 seconds is optimistic here. This is the cost of
    # a CLI built for a human session rather than for one lookup.
    def __init__(self, alias, real_name, token_file, keeper_bin,
                 state_dir=None, timeout=90):
        self.alias = alias
        self.real_name = real_name
        self.token_file = token_file
        self.keeper_bin = keeper_bin
        self.state_dir = state_dir or os.path.join(
            os.path.dirname(token_file) or ".", "keeper-state")
        self.timeout = timeout
        self._auth = None

    # -- auth material ------------------------------------------------------

    def _auth_pairs(self):
        """Read Commander's config once and keep its login strings in memory.

        Only those strings are taken from it, and only so they can be scrubbed.
        The file reaches `keeper` as a PATH on the command line, so no part of
        its contents is ever placed in a child's argv or environment.
        """
        if self._auth is None:
            try:
                with open(self.token_file, "r", encoding="utf-8") as fh:
                    raw = fh.read()
            except OSError:
                raise VaultError("Keeper config for %s is not readable" % self.alias)
            try:
                data = json.loads(raw)
            except ValueError:
                raise VaultError("Keeper config for %s is not valid JSON" % self.alias)
            self._auth = _collect_auth(data)
            if not self._auth:
                raise VaultError("Keeper config for %s holds no login material "
                                 "(expected one of: %s)"
                                 % (self.alias, ", ".join(AUTH_KEYS)))
        return self._auth

    def service_account_token(self):
        """Exposed so the runner can scrub it from output too. It is not a vault
        secret the agent asked for, but it is a key to every vault secret, so an
        accidental `cat` of the config must not carry it out.

        There is no single such string in Keeper: Commander authenticates from a
        document holding up to four of them. This answers with the most damaging
        one, for any caller that can take only one, and auth_secrets() is what
        the runner actually uses.
        """
        try:
            pairs = self._auth_pairs()
        except VaultError:
            return None
        return pairs[0][1] if pairs else None

    def auth_secrets(self):
        """Every login string in the config, labelled, for the redactor.

        All of them, not only the one above. The command runs as the broker
        user, which is the uid that can read the config file, so `cat` on it is
        a thing that happens by accident -- and one string scrubbed out of four
        is not a boundary.
        """
        try:
            return dict(self._auth_pairs())
        except VaultError:
            return {}

    # -- process ------------------------------------------------------------

    def _state_dir(self):
        """A directory Commander may write to.

        It rotates the persistent-login clone code and caches the vault as it
        runs, and under ProtectSystem=strict the broker's home is read-only.
        Pointing HOME here means those writes land somewhere instead of failing
        part-way through a login.
        """
        try:
            os.makedirs(self.state_dir, mode=0o700)
        except OSError:
            pass
        return self.state_dir

    def _env(self):
        env = dict(os.environ)
        env["HOME"] = self._state_dir()
        return env

    def _run(self, command, timeout=None):
        """Run one Commander command and return its stdout.

        Global options must all precede the positional command: Commander
        rebuilds the command's own arguments from everything that follows it on
        the line, so a `--config` placed after `ls` is handed to `ls`.
        """
        argv = [self.keeper_bin, "--config", self.token_file,
                "--batch-mode"] + command
        try:
            proc = subprocess.run(
                argv,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,   # Commander echoes paths and titles
                env=self._env(),
                timeout=timeout or self.timeout,
            )
        except subprocess.TimeoutExpired:
            raise VaultError("Keeper timed out")
        except OSError:
            raise VaultError("could not execute %s" % self.keeper_bin)
        if proc.returncode != 0:
            raise VaultError("Keeper rejected the request (missing record or "
                             "folder, or this account cannot see it)")
        return proc.stdout.decode("utf-8", "replace")

    # -- refs ---------------------------------------------------------------

    def parse_ref(self, ref):
        """Normalise a ref and confirm it belongs to THIS vault.

        Shorthands accepted, and they are the 1Password backend's shorthands
        unchanged. An agent learns them once and they must not shift under it
        when a vault moves to another backend:
            keeper://Dev/item/field   fully qualified
            item/field                folder implied
            item                      folder implied, DEFAULT_FIELD

        Keeper's own notation is also spelled `keeper://`, but it addresses a
        record uid (`keeper://<uid>/field/password`). Pasted here it parses as a
        reference to a vault named after the uid and is refused below, which is
        the right answer: it is not a sandbroker reference.
        """
        ref = (ref or "").strip()
        if not ref:
            raise VaultError("empty reference")
        if ref.startswith("op://"):
            raise VaultError("op:// is the 1Password scheme and %s is served "
                             "from Keeper -- write keeper://%s/item/field, or "
                             "just item/field" % (self.alias, self.alias))
        if not ref.startswith("keeper://"):
            ref = "keeper://%s/%s" % (self.alias, ref)
        match = REF_RE.match(ref)
        if not match:
            raise VaultError("malformed reference (want keeper://Vault/item/field)")
        vault, item, field = match.group("vault", "item", "field")
        if vault != self.alias and vault != self.real_name:
            raise VaultError(
                "reference is for vault %r but this server serves %r -- use the "
                "%s server" % (vault, self.alias, vault))
        return item, field or DEFAULT_FIELD

    def read(self, ref):
        """Resolve one ref to its value. ANY field of any record in the folder
        is allowed: there is no per-field allowlist, because a folder the agent
        may use is a folder the agent may use.

        One mechanism, where the 1Password backend needs two. Keeper has no
        equivalent of `op read`: nothing fetches a single field, so the whole
        record is pulled into the daemon and one field taken from it. The extra
        values stay here, are never placed in a child's environment and are
        never returned, but less material in memory would still be better.

        Resolving the item to a uid first is what makes one mechanism enough.
        The 1Password fallback exists because `op read` cannot address every
        legal title; a uid has no such problem, and the same lookup is where the
        shared-folder boundary is enforced.
        """
        item, field = self.parse_ref(ref)
        record = self._record(self._resolve_uid(item))
        for name, _type, value in _walk_fields(record):
            if name == field and value:
                return value
        raise VaultError(
            "record %r has no field %r with a value set (list_fields shows what "
            "it does have)" % (item, field))

    # -- lookup -------------------------------------------------------------

    def _folder_rows(self):
        """The configured shared folder, listed recursively.

        `--recursive` so a subfolder of a shared folder counts as part of it.
        Anything it does not return is, by the rule in _resolve_uid, outside
        this server's reach.
        """
        out = self._run(["ls", "--format", "json", "--recursive", self.real_name])
        data = _payload(out, "folder listing")
        if not isinstance(data, list):
            raise VaultError("could not parse the folder listing")
        return [row for row in data if isinstance(row, dict)]

    def _records(self):
        return [(str(row.get("uid") or ""),
                 str(row.get("name") or ""),
                 _record_type(row.get("details")))
                for row in self._folder_rows()
                if str(row.get("type") or "").lower() == "record"]

    def _resolve_uid(self, item):
        """Map a title or uid to a record uid, refusing anything outside the folder.

        This is the shared-folder boundary. `keeper get <uid>` is not scoped to a
        folder and will return a record from anywhere in the account's vault, so
        the listing is consulted first and a uid it does not contain is refused.
        Costing an extra `ls` on every read is the price of that check.
        """
        records = self._records()
        for uid, _title, _type in records:
            if uid and uid == item:
                return uid
        for matches in (lambda title: title == item,
                        lambda title: title.lower() == item.lower()):
            hits = [uid for uid, title, _type in records if uid and matches(title)]
            if len(hits) == 1:
                return hits[0]
            if len(hits) > 1:
                raise VaultError("%d records in %s are titled %r -- address it "
                                 "by uid instead (list_items shows them)"
                                 % (len(hits), self.alias, item))
        raise VaultError("no record %r in %s. A record outside this shared "
                         "folder is not reachable from this server; list_items "
                         "shows what is." % (item, self.alias))

    def _record(self, uid):
        out = self._run(["get", uid, "--format", "json"])
        data = _payload(out, "record")
        if not isinstance(data, dict):
            raise VaultError("could not parse the record")
        return data

    # -- discovery (metadata only, structurally value-free) -----------------

    def list_items(self):
        """Record titles and uids. `ls` reports a record's type, title and uid
        and has no form that returns a field value, so this path cannot leak one
        even if it misbehaves."""
        items = []
        for uid, title, category in self._records():
            if not title:
                continue
            item = {
                "title": title,
                "ref": "keeper://%s/%s" % (self.alias, title),
                "category": category,
            }
            # The uid is not a secret, and it is the unambiguous way to address
            # a record whose title is duplicated or awkward to write.
            if uid:
                item["id"] = uid
            items.append(item)
        return sorted(items, key=lambda i: i["title"].lower())

    def list_fields(self, item):
        """Field names for one record, with values discarded here in the daemon.

        `keeper get --format json` returns the values whether anyone wants them
        or not -- Commander has no metadata-only form of it -- so discarding
        them here is what makes this safe, exactly as in the 1Password backend.
        Nothing below puts a value into the returned structure: _walk_fields
        yields it, and the only thing done with it is asking whether it is
        non-empty.
        """
        record = self._record(self._resolve_uid(item))
        fields = []
        seen = set()
        for name, ftype, value in _walk_fields(record):
            if not name or name in seen:
                continue
            seen.add(name)
            fields.append({
                "field": name,
                "ref": "keeper://%s/%s/%s" % (self.alias, item, name),
                "type": ftype,
                # Whether a value EXISTS, never what it is. Keeper record types
                # come with fields the owner never filled in, and those are
                # worth marking rather than hiding.
                "populated": bool(value),
            })
        return fields
