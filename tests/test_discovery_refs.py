"""Discovery must not promise what resolution rejects.

Two ways it used to. A title containing a slash cannot be written as a
reference, because `op://vault/item/field` is split on slashes, yet
`op item get` accepts such a title happily -- so list_fields succeeded and
handed back `op://Production/play/scrolly/X/notesPlain`, which parses as the
item "play" and resolves to nothing.

And an attachment carries no field, so an item whose real payload was an
uploaded keystore listed as though its fields were the whole of it. That one is
worse than an unresolvable reference: it reads as a complete inventory, and
acting on it means deleting an original that was never copied.
"""

import json
import os
import shutil
import stat
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sandbroker.onepassword import Vault, VaultError  # noqa: E402

SLASHED = "play/scrolly/UPLOAD_KEYSTORE"
SLASHED_ID = "iehxwiqvsgaa7wrj5yjwbftwhe"
PLAIN = "Ordinary Item"
PLAIN_ID = "aaaabbbbccccddddeeeeffff00"

FAKE_OP = r'''#!/usr/bin/env python3
import json, os, sys
a = sys.argv[1:]

ITEMS = {
    "SLASHED_TITLE": {
        "id": "SLASHED_ID_V", "title": "SLASHED_TITLE", "category": "LOGIN",
        "fields": [{"id": "text", "label": "text", "type": "STRING",
                    "value": "upload-keystore.jks"}],
        "files": [{"id": "file123", "name": "upload-keystore.jks",
                   "size": 2842}],
    },
    "PLAIN_TITLE": {
        "id": "PLAIN_ID_V", "title": "PLAIN_TITLE", "category": "LOGIN",
        "fields": [{"id": "password", "label": "password",
                    "type": "CONCEALED", "value": "x"}],
    },
}

if a[0] == "item" and a[1] == "list":
    print(json.dumps([
        {"id": v["id"], "title": v["title"], "category": v["category"]}
        for v in ITEMS.values()]))
    sys.exit(0)

if a[0] == "item" and a[1] == "get":
    key = a[2]
    for v in ITEMS.values():
        if key in (v["title"], v["id"]):
            print(json.dumps(v))
            sys.exit(0)
    sys.exit(1)

sys.exit(1)
'''


class DiscoveryCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        op = os.path.join(self.tmp, "op")
        body = (FAKE_OP.replace("SLASHED_TITLE", SLASHED)
                       .replace("SLASHED_ID_V", SLASHED_ID)
                       .replace("PLAIN_TITLE", PLAIN)
                       .replace("PLAIN_ID_V", PLAIN_ID))
        with open(op, "w", encoding="utf-8") as fh:
            fh.write(body)
        os.chmod(op, os.stat(op).st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
        token = os.path.join(self.tmp, "Production.token")
        with open(token, "w", encoding="utf-8") as fh:
            fh.write("fake-service-account-token")
        self.vault = Vault("Production", "Acme - Production", token, op)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)


class TestReferencesResolve(DiscoveryCase):
    def test_every_reference_list_items_returns_addresses_that_item(self):
        """The invariant, stated directly: a reference discovery hands back must
        address the item it was listed under.

        Parsing alone is too weak a check to state it with. A slashed title
        parses happily -- `op://Production/play/scrolly/X` yields the item
        "play" -- and then resolves to the wrong thing or to nothing, which is
        the failure being prevented rather than a syntax error.
        """
        for item in self.vault.list_items():
            parsed, _ = self.vault.parse_ref(item["ref"])
            self.assertIn(parsed, (item["title"], item.get("id")))

    def test_slashed_title_is_addressed_by_id(self):
        row = [i for i in self.vault.list_items() if i["title"] == SLASHED][0]
        self.assertEqual("op://Production/%s" % SLASHED_ID, row["ref"])
        self.assertEqual(SLASHED, row["title"])   # the title is still reported

    def test_ordinary_title_is_left_alone(self):
        """The id is a fallback, not a replacement: a readable reference stays
        readable."""
        row = [i for i in self.vault.list_items() if i["title"] == PLAIN][0]
        self.assertEqual("op://Production/%s" % PLAIN, row["ref"])

    def test_field_references_on_a_slashed_item_resolve(self):
        for field in self.vault.list_fields(SLASHED):
            item, name = self.vault.parse_ref(field["ref"])
            self.assertEqual(SLASHED_ID, item)
            self.assertEqual("text", name)

    def test_lookup_by_id_also_yields_resolvable_references(self):
        for field in self.vault.list_fields(SLASHED_ID):
            self.vault.parse_ref(field["ref"])


class TestAttachmentsAreVisible(DiscoveryCase):
    def test_attachment_is_reported(self):
        files = self.vault.describe(SLASHED)["files"]
        self.assertEqual(1, len(files))
        self.assertEqual("upload-keystore.jks", files[0]["name"])
        self.assertEqual(2842, files[0]["size"])

    def test_item_without_attachments_reports_none(self):
        """Positive control: a blanket 'has files' would pass the test above
        for the wrong reason."""
        self.assertEqual([], self.vault.describe(PLAIN)["files"])

    def test_attachment_content_is_never_returned(self):
        blob = json.dumps(self.vault.describe(SLASHED))
        self.assertIn("upload-keystore.jks", blob)
        self.assertNotIn("content", blob)

    def test_fields_still_work_alongside_files(self):
        described = self.vault.describe(SLASHED)
        self.assertEqual(["text"], [f["field"] for f in described["fields"]])


class TestMissingItem(DiscoveryCase):
    def test_absent_item_raises(self):
        with self.assertRaises(VaultError):
            self.vault.describe("No Such Item")


if __name__ == "__main__":
    unittest.main()
