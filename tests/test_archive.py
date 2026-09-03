"""Retiring an item, and the proof demanded before it happens.

Archiving is reversible where deleting is not, which is the only reason the
broker will do it at all. Reversible is not free though, so the protection that
matters is that nothing gets retired until the broker has shown for itself that
every value on it survives somewhere else. The agent asking for the archive is
not trusted to have copied correctly.

So the tests that count are the refusals, and above all the one where the item
is nearly duplicated: a single unmatched field has to stop the whole call, and
stop it BEFORE op is asked to archive anything.
"""

import os
import shutil
import stat
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sandbroker.onepassword import Vault, VaultError  # noqa: E402

SECRET = "resend-key-1a2b3c4d5e6f"
ACCOUNT = "billing@example.com"
ORPHAN = "value-that-was-never-copied"

OLD = "Scrolly Resend API Key"
OLD_PARTIAL = "Half Copied Item"
KEEPER = "scrolly"
WITH_FILE = "play/scrolly/UPLOAD_KEYSTORE"
# Addressed by id, because a slashed title cannot be written as a
# reference at all -- which is why discovery hands back the id for it.
WITH_FILE_ID = "file11"
EMPTY = "Nothing Set"
FILE_KEEPER = "scrolly-signing"

FAKE_OP = r'''#!/usr/bin/env python3
import json, os, sys
here = os.path.dirname(os.path.abspath(__file__))
a = sys.argv[1:]

with open(os.path.join(here, "argv.log"), "a", encoding="utf-8") as fh:
    fh.write("\x00".join(a) + "\n")

ITEMS = {
    "OLD_T": {"id": "old111", "title": "OLD_T", "category": "LOGIN", "fields": [
        {"id": "password", "label": "password", "type": "CONCEALED",
         "value": "SECRET_V"},
        {"id": "username", "label": "username", "type": "STRING",
         "value": "ACCOUNT_V"},
        {"id": "notesPlain", "label": "notesPlain", "type": "STRING"},
    ]},
    "PARTIAL_T": {"id": "part11", "title": "PARTIAL_T", "category": "LOGIN",
                  "fields": [
        {"id": "password", "label": "password", "type": "CONCEALED",
         "value": "SECRET_V"},
        {"id": "extra", "label": "extra", "type": "CONCEALED",
         "value": "ORPHAN_V"},
    ]},
    "KEEPER_T": {"id": "keep11", "title": "KEEPER_T", "category": "API_CREDENTIAL",
                 "fields": [
        {"id": "RESEND_API_KEY", "label": "RESEND_API_KEY", "type": "CONCEALED",
         "value": "SECRET_V"},
        {"id": "RESEND_ACCOUNT", "label": "RESEND_ACCOUNT", "type": "STRING",
         "value": "ACCOUNT_V"},
    ]},
    "FILE_T": {"id": "file11", "title": "FILE_T", "category": "LOGIN", "fields": [
        {"id": "text", "label": "text", "type": "STRING",
         "value": "upload-keystore.jks"},
    ], "files": [{"id": "f1", "name": "upload-keystore.jks", "size": 2842}]},
    "FILEKEEP_T": {"id": "fkeep1", "title": "FILEKEEP_T",
                   "category": "API_CREDENTIAL", "fields": [
        {"id": "PLAY_KEYSTORE_FILENAME", "label": "PLAY_KEYSTORE_FILENAME",
         "type": "STRING", "value": "upload-keystore.jks"},
    ]},
    "EMPTY_T": {"id": "mt1111", "title": "EMPTY_T", "category": "LOGIN", "fields": [
        {"id": "username", "label": "username", "type": "STRING"},
    ]},
}

if a[0] == "item" and a[1] == "get":
    for v in ITEMS.values():
        if a[2] in (v["title"], v["id"]):
            print(json.dumps(v)); sys.exit(0)
    sys.exit(1)

if a[0] == "item" and a[1] == "delete":
    print("{}"); sys.exit(0)

sys.exit(1)
'''


class ArchiveCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        op = os.path.join(self.tmp, "op")
        body = (FAKE_OP.replace("OLD_T", OLD).replace("PARTIAL_T", OLD_PARTIAL)
                       .replace("KEEPER_T", KEEPER).replace("FILE_T", WITH_FILE)
                       .replace("EMPTY_T", EMPTY).replace("FILEKEEP_T", FILE_KEEPER)
                       .replace("SECRET_V", SECRET).replace("ACCOUNT_V", ACCOUNT)
                       .replace("ORPHAN_V", ORPHAN))
        with open(op, "w", encoding="utf-8") as fh:
            fh.write(body)
        os.chmod(op, os.stat(op).st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
        token = os.path.join(self.tmp, "Production.token")
        with open(token, "w", encoding="utf-8") as fh:
            fh.write("fake-service-account-token")
        self.vault = Vault("Production", "Acme - Production", token, op)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _log(self):
        path = os.path.join(self.tmp, "argv.log")
        if not os.path.exists(path):
            return ""
        with open(path, encoding="utf-8") as fh:
            return fh.read()

    def _archive(self, item, keeper=KEEPER):
        return self.vault.archive("op://Production/%s" % item,
                                  "op://Production/%s" % keeper)


class TestFullyDuplicated(ArchiveCase):
    def test_archives_when_every_value_is_found(self):
        matched = self._archive(OLD)
        self.assertEqual(2, len(matched))
        self.assertIn("item\x00delete", self._log())
        self.assertIn("--archive", self._log())

    def test_reports_where_each_value_now_lives(self):
        """The audit trail: which field went where, by fingerprint."""
        found = {m["field"]: m["found_as"] for m in self._archive(OLD)}
        self.assertEqual("RESEND_API_KEY", found["password"])
        self.assertEqual("RESEND_ACCOUNT", found["username"])

    def test_never_deletes_only_archives(self):
        """--archive is the whole safety story; without it this is destructive."""
        self._archive(OLD)
        for line in self._log().splitlines():
            if "item\x00delete" in line:
                self.assertIn("--archive", line)

    def test_values_never_reach_argv(self):
        self._archive(OLD)
        argv = self._log()
        self.assertIn("item\x00delete", argv)   # positive control
        self.assertNotIn(SECRET, argv)
        self.assertNotIn(ACCOUNT, argv)


class TestRefusals(ArchiveCase):
    def test_one_unmatched_field_refuses_the_whole_item(self):
        """The case that matters. Most of the item is duplicated, so a check
        that stopped at 'good enough' would archive it and lose `extra`."""
        with self.assertRaises(VaultError) as caught:
            self._archive(OLD_PARTIAL)
        self.assertIn("extra", str(caught.exception))

    def test_a_refusal_archives_nothing(self):
        with self.assertRaises(VaultError):
            self._archive(OLD_PARTIAL)
        self.assertNotIn("item\x00delete", self._log())

    def test_item_with_an_attachment_is_refused(self):
        """An attachment cannot be copied, so its survival cannot be shown."""
        with self.assertRaises(VaultError) as caught:
            self._archive(WITH_FILE_ID)
        self.assertIn("attachment", str(caught.exception))

    def test_attachment_refusal_beats_a_passing_field_check(self):
        """The ordering claim, tested properly. This keeper really does hold the
        item's only field value, so field verification would pass and let it
        through. The attachment has to refuse it anyway, because what cannot be
        proven matters more than what can."""
        with self.assertRaises(VaultError) as caught:
            self.vault.archive("op://Production/%s" % WITH_FILE_ID,
                               "op://Production/%s" % FILE_KEEPER)
        self.assertIn("attachment", str(caught.exception))
        self.assertNotIn("item\x00delete", self._log())

    def test_slashed_title_cannot_be_addressed_and_fails_safe(self):
        """A slashed title parses as a different item, so it resolves to nothing
        rather than to the wrong thing. Discovery hands back the id for exactly
        this reason."""
        with self.assertRaises(VaultError):
            self._archive(WITH_FILE)
        self.assertNotIn("item\x00delete", self._log())

    def test_empty_item_is_refused(self):
        with self.assertRaises(VaultError) as caught:
            self._archive(EMPTY)
        self.assertIn("nothing to prove", str(caught.exception))

    def test_item_cannot_supersede_itself(self):
        with self.assertRaises(VaultError) as caught:
            self._archive(OLD, OLD)
        self.assertIn("supersede itself", str(caught.exception))

    def test_unknown_item_is_refused(self):
        with self.assertRaises(VaultError):
            self._archive("No Such Item")

    def test_unknown_keeper_is_refused(self):
        with self.assertRaises(VaultError):
            self._archive(OLD, "No Such Keeper")

    def test_cross_vault_is_refused(self):
        with self.assertRaises(VaultError):
            self.vault.archive("op://Dev/%s" % OLD, "op://Production/%s" % KEEPER)

    def test_cross_vault_keeper_is_refused(self):
        with self.assertRaises(VaultError):
            self.vault.archive("op://Production/%s" % OLD, "op://Dev/%s" % KEEPER)


if __name__ == "__main__":
    unittest.main()
