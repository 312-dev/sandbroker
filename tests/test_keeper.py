"""Resolution against a stand-in `keeper`, including the shared-folder boundary."""

import json
import os
import shutil
import stat
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sandbroker import runner  # noqa: E402
from sandbroker.keeper import Vault  # noqa: E402
from sandbroker.onepassword import VaultError  # noqa: E402

from test_runner import make_config  # noqa: E402

FOLDER = "Engineering/Dev"
MERCURY = "Mercury API Key (Sandbox)"
SIMPLE = "spotify-pullfm"
SECRET = "mercury-sandbox-secret-value-0001"
SIMPLE_SECRET = "spotify-value"

# A record that exists in the account's vault but NOT in the served folder. The
# whole point of the boundary check is that this one stays unreachable even
# though `keeper get` on its uid works perfectly well.
OUTSIDE_UID = "dddd4444"
OUTSIDE_SECRET = "production-database-password"

# Mimics Keeper Commander closely enough to pin the two things that matter:
# `ls` is scoped to a folder and returns no values, while `get` is scoped to
# nothing at all and returns the whole record. It also prints a sync notice
# before its JSON, which the real thing does and `op` does not.
FAKE_KEEPER = r'''#!/usr/bin/env python3
import json, sys
a = sys.argv[1:]
FOLDER = "Engineering/Dev"
MERCURY = "Mercury API Key (Sandbox)"

# Global options come first, exactly as Commander requires.
if a[0] != "--config":
    sys.exit(2)
config = a[1]
a = a[2:]
if a[0] == "--batch-mode":
    a = a[1:]

IN_FOLDER = [
    {"type": "record", "uid": "aaaa1111", "name": MERCURY,
     "details": "Type: login, Description: api.mercury.com"},
    {"type": "record", "uid": "bbbb2222", "name": "spotify-pullfm",
     "details": "Type: login, Description: accounts.spotify.com"},
    {"type": "record", "uid": "cccc3333", "name": "twin",
     "details": "Type: login, Description: one"},
    {"type": "record", "uid": "cccc3334", "name": "twin",
     "details": "Type: login, Description: two"},
    {"type": "folder", "uid": "ffff0000", "name": "nested",
     "details": "Flags: RW, Parent: /"},
]

RECORDS = {
    "aaaa1111": {
        "record_uid": "aaaa1111", "title": MERCURY, "record_type": "login",
        "login": "api@example.com", "password": "SECRET_PLACEHOLDER",
        "notes": "",
        "fields": [
            {"type": "login", "value": ["api@example.com"]},
            {"type": "password", "value": ["SECRET_PLACEHOLDER"]},
        ],
        "custom": [
            {"type": "text", "label": "account_id", "value": ["acct-99"]},
            {"type": "text", "label": "unused", "value": []},
        ],
    },
    "bbbb2222": {
        "record_uid": "bbbb2222", "title": "spotify-pullfm",
        "record_type": "login", "password": "SIMPLE_PLACEHOLDER",
        "fields": [{"type": "password", "value": ["SIMPLE_PLACEHOLDER"]}],
    },
    "cccc3333": {"record_uid": "cccc3333", "title": "twin", "password": "one"},
    "cccc3334": {"record_uid": "cccc3334", "title": "twin", "password": "two"},
    "dddd4444": {"record_uid": "dddd4444", "title": "prod-db",
                 "password": "OUTSIDE_PLACEHOLDER"},
}

if a[0] == "ls":
    if FOLDER not in a:
        sys.exit(1)
    sys.stdout.write("Syncing...\n")
    print(json.dumps(IN_FOLDER)); sys.exit(0)

if a[0] == "get":
    record = RECORDS.get(a[1])
    if record is None:
        sys.exit(1)
    sys.stdout.write("Syncing...\n")
    print(json.dumps(record)); sys.exit(0)

sys.exit(1)
'''

CONFIG = {
    "user": "broker@example.com",
    "server": "keepersecurity.com",
    "password": "master-password-value",
    "private_key": "device-private-key-value",
    "clone_code": "clone-code-value",
    "device_token": "device-token-value",
}


class VaultCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        keeper = os.path.join(self.tmp, "keeper")
        with open(keeper, "w", encoding="utf-8") as fh:
            fh.write(FAKE_KEEPER
                     .replace("SECRET_PLACEHOLDER", SECRET)
                     .replace("SIMPLE_PLACEHOLDER", SIMPLE_SECRET)
                     .replace("OUTSIDE_PLACEHOLDER", OUTSIDE_SECRET))
        os.chmod(keeper,
                 os.stat(keeper).st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
        config = os.path.join(self.tmp, "Dev.token")
        with open(config, "w", encoding="utf-8") as fh:
            json.dump(CONFIG, fh)
        self.vault = Vault("Dev", FOLDER, config, keeper,
                           state_dir=os.path.join(self.tmp, "state"))

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)


class TestRefs(VaultCase):
    def test_fully_qualified(self):
        self.assertEqual(("mercury", "password"),
                         self.vault.parse_ref("keeper://Dev/mercury/password"))

    def test_shorthand_item_and_field(self):
        self.assertEqual(("mercury", "token"),
                         self.vault.parse_ref("mercury/token"))

    def test_shorthand_item_alone_takes_the_default_field(self):
        """`password` is Keeper's `credential`. The shorthands behave the same
        as the 1Password backend's, which is what the use-secret skill teaches."""
        self.assertEqual(("mercury", "password"), self.vault.parse_ref("mercury"))

    def test_real_folder_name_is_accepted(self):
        self.assertEqual(("m", "f"),
                         self.vault.parse_ref("keeper://%s/m/f" % FOLDER))

    def test_field_may_contain_slashes(self):
        self.assertEqual(("my item", "API Key/v2"),
                         self.vault.parse_ref("keeper://Dev/my item/API Key/v2"))

    def test_another_vault_is_refused(self):
        with self.assertRaises(VaultError) as ctx:
            self.vault.parse_ref("keeper://Production/thing/password")
        self.assertIn("Production server", str(ctx.exception))

    def test_op_scheme_says_which_backend_this_is(self):
        with self.assertRaises(VaultError) as ctx:
            self.vault.parse_ref("op://Dev/mercury/credential")
        self.assertIn("keeper://Dev/item/field", str(ctx.exception))

    def test_nested_folder_path_survives_the_ref_parser(self):
        """A shared folder path can be nested, and the ref pattern splits on the
        first slash. Without special handling `keeper://Engineering/Dev/m/f`
        parses as vault `Engineering` and is refused with advice to use a server
        that does not exist."""
        # parse_ref never touches the filesystem, so the paths can be anything.
        nested = Vault("Dev", "Engineering/Dev", "/nonexistent", "/bin/true",
                       state_dir="/nonexistent")
        self.assertEqual(("m", "f"),
                         nested.parse_ref("keeper://Engineering/Dev/m/f"))
        self.assertEqual(("m", "password"),
                         nested.parse_ref("keeper://Engineering/Dev/m"))

    def test_malformed(self):
        for bad in ("", "   ", "keeper://", "keeper://Dev"):
            with self.assertRaises(VaultError):
                self.vault.parse_ref(bad)


class TestReading(VaultCase):
    def test_read_by_title(self):
        self.assertEqual(SECRET, self.vault.read("keeper://Dev/%s/password" % MERCURY))

    def test_read_by_uid(self):
        """A uid is not a secret and it is the unambiguous way to address a
        record, which is also how the folder check identifies one."""
        self.assertEqual(SECRET, self.vault.read("keeper://Dev/aaaa1111/password"))

    def test_read_shorthand(self):
        self.assertEqual(SIMPLE_SECRET, self.vault.read(SIMPLE))

    def test_read_a_custom_field_by_its_label(self):
        self.assertEqual("acct-99", self.vault.read("%s/account_id" % MERCURY))

    def test_title_match_is_case_insensitive(self):
        self.assertEqual(SIMPLE_SECRET, self.vault.read("SPOTIFY-PULLFM"))

    def test_missing_field_says_what_to_do(self):
        with self.assertRaises(VaultError) as ctx:
            self.vault.read("keeper://Dev/%s/nonexistent" % MERCURY)
        self.assertIn("list_fields", str(ctx.exception))

    def test_unpopulated_field_is_refused_not_returned_empty(self):
        with self.assertRaises(VaultError):
            self.vault.read("keeper://Dev/%s/unused" % MERCURY)

    def test_unknown_item_fails(self):
        with self.assertRaises(VaultError):
            self.vault.read("keeper://Dev/no-such-record/password")

    def test_duplicate_titles_point_at_the_uid(self):
        with self.assertRaises(VaultError) as ctx:
            self.vault.read("twin/password")
        self.assertIn("uid", str(ctx.exception))
        self.assertEqual("one", self.vault.read("cccc3333/password"))

    def test_a_broken_keeper_binary_raises_rather_than_returning_nothing(self):
        vault = Vault("Dev", FOLDER, self.vault.token_file,
                      os.path.join(self.tmp, "no-such-keeper"),
                      state_dir=os.path.join(self.tmp, "state"))
        with self.assertRaises(VaultError):
            vault.read(SIMPLE)


class TestFolderBoundary(VaultCase):
    """`keeper get <uid>` is not scoped to a folder, so the daemon scopes it.

    Without the check a Dev server would resolve a Production record for anyone
    who knew its uid, which is the isolation 1Password gets from the service
    account itself.
    """

    def test_record_outside_the_folder_is_refused(self):
        with self.assertRaises(VaultError) as ctx:
            self.vault.read("keeper://Dev/%s/password" % OUTSIDE_UID)
        self.assertIn("outside this shared folder", str(ctx.exception))

    def test_the_refusal_is_not_because_keeper_cannot_reach_it(self):
        """Proves the previous test is testing the check and not a dead uid: the
        same uid resolves fine once the folder is the one it lives in."""
        # pylint: disable=protected-access
        self.assertEqual(OUTSIDE_SECRET,
                         self.vault._record(OUTSIDE_UID)["password"])

    def test_list_fields_is_scoped_too(self):
        with self.assertRaises(VaultError):
            self.vault.list_fields(OUTSIDE_UID)


class TestListing(VaultCase):
    def test_list_items_shape(self):
        items = {i["title"]: i for i in self.vault.list_items()}
        self.assertEqual("aaaa1111", items[MERCURY]["id"])
        self.assertEqual("keeper://Dev/%s" % MERCURY, items[MERCURY]["ref"])
        self.assertEqual("login", items[MERCURY]["category"])

    def test_list_items_skips_folders(self):
        self.assertNotIn("nested", [i["title"] for i in self.vault.list_items()])

    def test_list_items_never_returns_a_value(self):
        blob = json.dumps(self.vault.list_items())
        self.assertNotIn(SECRET, blob)
        self.assertNotIn(SIMPLE_SECRET, blob)

    def test_list_fields_shape(self):
        fields = {f["field"]: f for f in self.vault.list_fields(MERCURY)}
        self.assertEqual("keeper://Dev/%s/password" % MERCURY,
                         fields["password"]["ref"])
        self.assertEqual("password", fields["password"]["type"])
        self.assertTrue(fields["password"]["populated"])
        self.assertFalse(fields["unused"]["populated"])

    def test_list_fields_never_returns_values(self):
        """The one that matters. `keeper get` hands the daemon every value on
        the record; none of them may cross the boundary."""
        blob = json.dumps(self.vault.list_fields(MERCURY))
        self.assertNotIn(SECRET, blob)
        self.assertNotIn("acct-99", blob)
        self.assertNotIn("api@example.com", blob)

    def test_discovery_and_resolution_agree(self):
        """Every reference list_fields advertises as populated must resolve.
        Discovery promising what resolution refuses is a bug in the backend."""
        for field in self.vault.list_fields(MERCURY):
            if field["populated"]:
                self.assertTrue(self.vault.read(field["ref"]))


class TestAuthMaterial(VaultCase):
    def test_every_login_string_reaches_the_scrubber(self):
        """Commander's credential is a document, not a token. One string
        scrubbed out of four would not be a boundary."""
        scrubbed = self.vault.auth_secrets()
        for key in ("password", "private_key", "clone_code", "device_token"):
            self.assertIn(CONFIG[key], scrubbed.values())
        self.assertEqual("KEEPER_CLONE_CODE",
                         [name for name, value in scrubbed.items()
                          if value == CONFIG["clone_code"]][0])

    def test_the_master_password_takes_the_single_value_hook(self):
        self.assertEqual(CONFIG["password"], self.vault.service_account_token())

    def test_nested_config_layouts_are_searched_too(self):
        nested = os.path.join(self.tmp, "nested.token")
        with open(nested, "w", encoding="utf-8") as fh:
            json.dump({"users": [{"user": "a@b.c", "clone_code": "nested-code"}],
                       "devices": [{"private_key": "nested-key"}]}, fh)
        vault = Vault("Dev", FOLDER, nested, self.vault.keeper_bin)
        self.assertEqual({"KEEPER_PRIVATE_KEY": "nested-key",
                          "KEEPER_CLONE_CODE": "nested-code"},
                         vault.auth_secrets())

    def test_the_config_cannot_be_read_out_through_a_command(self):
        """The command runs as the broker user, so it CAN read the config file.
        Every string in it has to come back redacted, not just the first."""
        result = runner.run(self.vault, make_config(),
                            command="cat %s" % self.vault.token_file, secrets={})
        for key in ("password", "private_key", "clone_code", "device_token"):
            self.assertNotIn(CONFIG[key], result["stdout"])
        self.assertIn("[redacted:KEEPER_PASSWORD]", result["stdout"])

    def test_an_unreadable_config_yields_no_token_rather_than_crashing(self):
        vault = Vault("Dev", FOLDER, os.path.join(self.tmp, "absent"),
                      self.vault.keeper_bin)
        self.assertIsNone(vault.service_account_token())
        self.assertEqual({}, vault.auth_secrets())


if __name__ == "__main__":
    unittest.main(verbosity=2)
