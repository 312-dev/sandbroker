"""Copying a field within one vault: fidelity, and the boundaries it keeps.

`copy` exists so credentials can be reorganised without being regenerated, so
the property that matters most is that what lands is byte-identical to what was
read. A trailing newline trimmed off a PEM block produces a key that looks
right in the UI and fails to parse at runtime, which is exactly the outcome a
migration cannot survive -- and it is the reason this path does not reuse
store's stdout handling, which strips.

The rest is the boundaries: same vault only, create-or-add still applies, and
the value never reaches argv.
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
from sandbroker.redact import fingerprint  # noqa: E402

SECRET = "src-value-9f8e7d6c5b4a3928"
PLAIN = "account-1234567890"
# The trailing newline is the whole point of the fidelity test, not incidental.
PEM = "-----BEGIN PRIVATE KEY-----\nMIIBVgIBADANBg\n-----END PRIVATE KEY-----\n"

SOURCE = "Old Scattered Item"
OCCUPIED = "Already Has One"
FRESH = "myapp"

FAKE_OP = r'''#!/usr/bin/env python3
import json, os, sys
here = os.path.dirname(os.path.abspath(__file__))
a = sys.argv[1:]

with open(os.path.join(here, "argv.log"), "a", encoding="utf-8") as fh:
    fh.write("\x00".join(a) + "\n")

ITEMS = {
    "SOURCE_TITLE": {
        "title": "SOURCE_TITLE",
        "category": "LOGIN",
        "fields": [
            {"id": "password", "label": "password",
             "type": "CONCEALED", "value": "SECRET_VALUE"},
            {"id": "username", "label": "username",
             "type": "STRING", "value": "PLAIN_VALUE"},
            {"id": "p8", "label": "p8",
             "type": "CONCEALED", "value": "PEM_VALUE"},
            {"id": "notesPlain", "label": "notesPlain", "type": "STRING"},
        ],
    },
    "OCCUPIED_TITLE": {
        "title": "OCCUPIED_TITLE",
        "category": "LOGIN",
        "fields": [
            {"id": "credential", "label": "credential",
             "type": "CONCEALED", "value": "the-old-live-value"},
        ],
    },
}

if a[0] == "item" and a[1] == "get":
    item = ITEMS.get(a[2])
    if item is None:
        sys.exit(1)
    print(json.dumps(item))
    sys.exit(0)

if a[0] == "item" and a[1] in ("create", "edit"):
    body = sys.stdin.read()
    with open(os.path.join(here, "stdin.log"), "a", encoding="utf-8") as fh:
        fh.write(body + "\n")
    print(json.dumps({"id": "zzzz9999"}))
    sys.exit(0)

sys.exit(1)
'''


class CopyCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        op = os.path.join(self.tmp, "op")
        body = (FAKE_OP.replace("SOURCE_TITLE", SOURCE)
                       .replace("OCCUPIED_TITLE", OCCUPIED)
                       .replace("SECRET_VALUE", SECRET)
                       .replace("PLAIN_VALUE", PLAIN)
                       .replace("PEM_VALUE", PEM.replace("\n", "\\n")))
        with open(op, "w", encoding="utf-8") as fh:
            fh.write(body)
        os.chmod(op, os.stat(op).st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
        token = os.path.join(self.tmp, "Production.token")
        with open(token, "w", encoding="utf-8") as fh:
            fh.write("fake-service-account-token")
        self.vault = Vault("Production", "Acme - Production", token, op)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _log(self, name):
        path = os.path.join(self.tmp, name)
        if not os.path.exists(path):
            return ""
        with open(path, encoding="utf-8") as fh:
            return fh.read()

    def _written(self):
        """The field this copy appended, from the template op received."""
        template = json.loads(self._log("stdin.log").strip())
        return template["fields"][-1]

    def _copy(self, src_field, dst_field):
        return self.vault.copy("op://Production/%s/%s" % (SOURCE, src_field),
                               "op://Production/%s/%s" % (FRESH, dst_field))


class TestFidelity(CopyCase):
    def test_value_arrives_unchanged(self):
        self._copy("password", "API_KEY")
        self.assertEqual(SECRET, self._written()["value"])

    def test_trailing_newline_survives(self):
        """store strips its mint command's stdout; this path must not, because a
        PEM without its final newline fails to parse where it is used."""
        self._copy("p8", "APPLE_P8")
        self.assertEqual(PEM, self._written()["value"])
        self.assertTrue(self._written()["value"].endswith("\n"))

    def test_fingerprint_matches_the_source_value(self):
        """The caller's proof that a copy is safe to retire the original for."""
        fp, length, _ = self._copy("password", "API_KEY")
        self.assertEqual(fingerprint(SECRET), fp)
        self.assertEqual(len(SECRET), length)


class TestTypeIsCarried(CopyCase):
    def test_concealed_stays_concealed(self):
        _, _, concealed = self._copy("password", "API_KEY")
        self.assertTrue(concealed)
        self.assertEqual("CONCEALED", self._written()["type"])

    def test_plain_stays_plain(self):
        """An account id copied beside its key should stay readable; concealing
        it would hide metadata the human is reorganising by."""
        _, _, concealed = self._copy("username", "ACCOUNT_ID")
        self.assertFalse(concealed)
        self.assertEqual("STRING", self._written()["type"])


class TestArgvBoundary(CopyCase):
    def test_value_never_appears_in_argv(self):
        self._copy("password", "API_KEY")
        argv = self._log("argv.log")
        # Positive control: an empty log would pass the real assertion for the
        # wrong reason.
        self.assertIn("item\x00create", argv)
        self.assertNotIn(SECRET, argv)


class TestBoundaries(CopyCase):
    def test_cross_vault_source_is_refused(self):
        with self.assertRaises(VaultError) as caught:
            self.vault.copy("op://Dev/%s/password" % SOURCE,
                            "op://Production/%s/API_KEY" % FRESH)
        self.assertIn("Dev", str(caught.exception))

    def test_cross_vault_destination_is_refused(self):
        """The direction that would matter: staging a Production secret into a
        vault with different readers is an escalation, not a reorganisation.

        Refused twice over -- copy checks both refs up front and write checks
        again -- so this passes even with copy's own check removed. The test
        below is the one that pins copy's contribution."""
        with self.assertRaises(VaultError):
            self.vault.copy("op://Production/%s/password" % SOURCE,
                            "op://Dev/%s/API_KEY" % FRESH)

    def test_bad_destination_is_refused_before_the_source_is_read(self):
        """Both refs are resolved before either is used, so a copy that cannot
        land never pulls the secret into the daemon at all. Cheap to hold, and
        it keeps a doomed call from touching plaintext."""
        with self.assertRaises(VaultError):
            self.vault.copy("op://Production/%s/password" % SOURCE,
                            "op://Dev/%s/API_KEY" % FRESH)
        self.assertNotIn("item\x00get", self._log("argv.log"))

    def test_occupied_destination_is_refused(self):
        with self.assertRaises(VaultError) as caught:
            self.vault.copy("op://Production/%s/password" % SOURCE,
                            "op://Production/%s/credential" % OCCUPIED)
        self.assertIn("create-or-add only", str(caught.exception))

    def test_refusal_writes_nothing(self):
        with self.assertRaises(VaultError):
            self.vault.copy("op://Production/%s/password" % SOURCE,
                            "op://Production/%s/credential" % OCCUPIED)
        self.assertEqual("", self._log("stdin.log"))

    def test_copying_a_field_onto_itself_is_refused(self):
        with self.assertRaises(VaultError):
            self.vault.copy("op://Production/%s/password" % SOURCE,
                            "op://Production/%s/password" % SOURCE)

    def test_missing_source_field_is_refused(self):
        with self.assertRaises(VaultError) as caught:
            self._copy("no_such_field", "API_KEY")
        self.assertIn("no_such_field", str(caught.exception))

    def test_unset_source_field_is_refused(self):
        """notesPlain exists on the item but holds nothing; copying it would
        store an empty value and look like a successful migration."""
        with self.assertRaises(VaultError):
            self._copy("notesPlain", "NOTES")

    def test_missing_source_item_is_refused(self):
        with self.assertRaises(VaultError):
            self.vault.copy("op://Production/No Such Item/password",
                            "op://Production/%s/API_KEY" % FRESH)


if __name__ == "__main__":
    unittest.main()
