"""Resolution against a stand-in `op`, including titles `op read` cannot address."""

import json
import os
import shutil
import stat
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sandbroker.onepassword import Vault, VaultError  # noqa: E402

AWKWARD = "Mercury API Key (Sandbox)"
SIMPLE = "spotify-pullfm"
SECRET = "mercury-sandbox-secret-value-0001"

# Mimics the real CLI's split personality: `op read` parses a secret REFERENCE
# and rejects titles containing parentheses, while `op item get` looks the same
# item up by title without complaint. This asymmetry is the bug being pinned --
# list_fields used op item get and advertised a reference op read then refused.
FAKE_OP = r'''#!/usr/bin/env python3
import json, sys
a = sys.argv[1:]
AWKWARD = "Mercury API Key (Sandbox)"

if a[0] == "read":
    ref = a[-1]
    if "(" in ref or ")" in ref:
        sys.stderr.write("could not parse secret reference\n")
        sys.exit(1)
    if ref.endswith("/spotify-pullfm/password"):
        print("simple-value", end=""); sys.exit(0)
    sys.exit(1)

if a[0] == "item" and a[1] == "list":
    print(json.dumps([
        {"id": "aaaa1111", "title": AWKWARD, "category": "LOGIN"},
        {"id": "bbbb2222", "title": "spotify-pullfm", "category": "LOGIN"},
    ])); sys.exit(0)

if a[0] == "item" and a[1] == "get":
    if a[2] in (AWKWARD, "aaaa1111"):
        print(json.dumps({"fields": [
            {"id": "password", "label": "password", "type": "CONCEALED",
             "value": "SECRET_PLACEHOLDER"},
            {"id": "username", "label": "username", "type": "STRING"},
        ]})); sys.exit(0)
    sys.exit(1)

sys.exit(1)
'''


class VaultCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        op = os.path.join(self.tmp, "op")
        with open(op, "w", encoding="utf-8") as fh:
            fh.write(FAKE_OP.replace("SECRET_PLACEHOLDER", SECRET))
        os.chmod(op, os.stat(op).st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
        token = os.path.join(self.tmp, "Dev.token")
        with open(token, "w", encoding="utf-8") as fh:
            fh.write("fake-service-account-token")
        self.vault = Vault("Dev", "Acme - Dev", token, op)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)


class TestAwkwardTitles(VaultCase):
    def test_op_read_path_still_works(self):
        self.assertEqual("simple-value",
                         self.vault.read("op://Dev/%s/password" % SIMPLE))

    def test_parenthesised_title_falls_back_and_resolves(self):
        """The regression: op read rejects this reference, op item get resolves
        the very same item, and list_fields was advertising it either way."""
        self.assertEqual(SECRET,
                         self.vault.read("op://Dev/%s/password" % AWKWARD))

    def test_discovery_and_resolution_agree(self):
        """Every reference list_fields advertises as populated must resolve.
        Discovery promising what resolution refuses is the bug itself."""
        for field in self.vault.list_fields(AWKWARD):
            if field["populated"]:
                self.assertTrue(self.vault.read(field["ref"]))

    def test_missing_field_says_what_to_do(self):
        with self.assertRaises(VaultError) as ctx:
            self.vault.read("op://Dev/%s/nonexistent" % AWKWARD)
        self.assertIn("list_fields", str(ctx.exception))

    def test_unpopulated_field_is_refused_not_returned_empty(self):
        with self.assertRaises(VaultError):
            self.vault.read("op://Dev/%s/username" % AWKWARD)

    def test_unknown_item_still_fails(self):
        with self.assertRaises(VaultError):
            self.vault.read("op://Dev/no-such-item/password")


class TestListing(VaultCase):
    def test_list_items_carries_the_uuid(self):
        """A UUID is not a secret, and it is the unambiguous way to address an
        item whose title a reference cannot express."""
        items = {i["title"]: i for i in self.vault.list_items()}
        self.assertEqual("aaaa1111", items[AWKWARD]["id"])

    def test_item_can_be_addressed_by_uuid(self):
        self.assertEqual(SECRET, self.vault.read("op://Dev/aaaa1111/password"))

    def test_list_fields_never_returns_values(self):
        blob = json.dumps(self.vault.list_fields(AWKWARD))
        self.assertNotIn(SECRET, blob)
        self.assertTrue(any(f["field"] == "password" and f["populated"]
                            for f in self.vault.list_fields(AWKWARD)))


if __name__ == "__main__":
    unittest.main(verbosity=2)
