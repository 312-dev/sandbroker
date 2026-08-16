"""Writing into the vault: the refusal and the argv boundary.

Two properties matter more than the happy path. The value must reach op on
stdin and never as an argument, because /proc/<pid>/cmdline is world-readable
and two open leak alerts are credentials found sitting in a command line. And
an occupied field must be refused, because a broker that can overwrite can
destroy every good credential in the vault on one bad call.
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

NEW_VALUE = "rotated-value-6f5a4b3c2d1e0f9a8b7c"
OCCUPIED = "Cloudflare API Token: Network Zone Editor"
FRESH = "cloudflare-tunnel-rotated"

# Records every invocation so the tests can assert on argv and stdin
# separately. "item get" answers for one existing item and 404s otherwise,
# which is how write() decides between create and edit.
FAKE_OP = r'''#!/usr/bin/env python3
import json, os, sys
here = os.path.dirname(os.path.abspath(__file__))
a = sys.argv[1:]

with open(os.path.join(here, "argv.log"), "a", encoding="utf-8") as fh:
    fh.write("\x00".join(a) + "\n")

if a[0] == "item" and a[1] == "get":
    if a[2] == "OCCUPIED_TITLE":
        print(json.dumps({
            "title": "OCCUPIED_TITLE",
            "category": "LOGIN",
            "fields": [
                {"id": "credential", "label": "credential",
                 "type": "CONCEALED", "value": "the-old-live-value"},
                {"id": "username", "label": "username", "type": "STRING"},
            ],
        }))
        sys.exit(0)
    sys.exit(1)

if a[0] == "item" and a[1] in ("create", "edit"):
    body = sys.stdin.read()
    with open(os.path.join(here, "stdin.log"), "a", encoding="utf-8") as fh:
        fh.write(body + "\n")
    print(json.dumps({"id": "zzzz9999"}))
    sys.exit(0)

sys.exit(1)
'''


class StoreCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        op = os.path.join(self.tmp, "op")
        with open(op, "w", encoding="utf-8") as fh:
            fh.write(FAKE_OP.replace("OCCUPIED_TITLE", OCCUPIED))
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


class TestArgvBoundary(StoreCase):
    def test_value_reaches_op_on_stdin(self):
        self.vault.write("op://Production/%s/credential" % FRESH, NEW_VALUE)
        self.assertIn(NEW_VALUE, self._log("stdin.log"))

    def test_value_never_appears_in_argv(self):
        """The one that would matter at 3am. An assignment statement would put
        this string in the process table for every uid on the box."""
        self.vault.write("op://Production/%s/credential" % FRESH, NEW_VALUE)
        argv = self._log("argv.log")
        # Positive control first: an empty log would pass the real assertion
        # for the wrong reason, which is the failure mode this whole file is
        # about.
        self.assertIn("item\x00create", argv)
        self.assertNotIn(NEW_VALUE, argv)

    def test_stdin_payload_is_a_valid_template(self):
        self.vault.write("op://Production/%s/credential" % FRESH, NEW_VALUE)
        template = json.loads(self._log("stdin.log").strip())
        labels = [f["label"] for f in template["fields"]]
        self.assertIn("credential", labels)


class TestCreateOrAddOnly(StoreCase):
    def test_absent_item_is_created(self):
        fp = self.vault.write("op://Production/%s/credential" % FRESH, NEW_VALUE)
        self.assertIn("item\x00create", self._log("argv.log"))
        self.assertEqual(fingerprint(NEW_VALUE), fp)

    def test_occupied_field_is_refused(self):
        with self.assertRaises(VaultError) as caught:
            self.vault.write("op://Production/%s/credential" % OCCUPIED, NEW_VALUE)
        self.assertIn("create-or-add only", str(caught.exception))

    def test_refusal_writes_nothing(self):
        """A refusal that still edited the item would be worse than no check."""
        with self.assertRaises(VaultError):
            self.vault.write("op://Production/%s/credential" % OCCUPIED, NEW_VALUE)
        self.assertEqual("", self._log("stdin.log"))
        self.assertNotIn("item\x00edit", self._log("argv.log"))

    def test_new_field_on_existing_item_is_added(self):
        """Adding beside an occupied field is fine; only clobbering is not."""
        fp = self.vault.write("op://Production/%s/rotated_2026_08" % OCCUPIED,
                              NEW_VALUE)
        self.assertIn("item\x00edit", self._log("argv.log"))
        template = json.loads(self._log("stdin.log").strip())
        labels = [f["label"] for f in template["fields"]]
        self.assertIn("credential", labels)      # the old one survives
        self.assertIn("rotated_2026_08", labels)
        self.assertEqual(fingerprint(NEW_VALUE), fp)

    def test_empty_value_is_refused(self):
        with self.assertRaises(VaultError):
            self.vault.write("op://Production/%s/credential" % FRESH, "")


class TestVaultBoundary(StoreCase):
    def test_other_vaults_ref_is_refused(self):
        """A write is the one direction where crossing vaults silently would be
        unrecoverable, so it reuses the same check reads get."""
        with self.assertRaises(VaultError):
            self.vault.write("op://Dev/some-item/credential", NEW_VALUE)


class TestFingerprintContract(StoreCase):
    def test_returns_fingerprint_not_value(self):
        fp = self.vault.write("op://Production/%s/credential" % FRESH, NEW_VALUE)
        self.assertNotIn(NEW_VALUE, fp)
        self.assertEqual(12, len(fp))


if __name__ == "__main__":
    unittest.main()
