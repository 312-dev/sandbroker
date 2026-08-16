"""The `store` tool at the protocol boundary.

The property under test is narrow and load-bearing: whatever the mint command
prints must not come back in the tool result. A create-token API response is
made almost entirely of live credential, and nothing in Tier 1 would strip it,
because the broker never injected it.
"""

import json
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from test_mcp import build  # noqa: E402
from test_runner import FakeVault  # noqa: E402

MINTED = "cf-minted-9f3a2b1c8d7e6f5a4b3c2d1e"
TARGET = "op://Dev/cloudflare-tunnel/rotated_2026_08"


class StoreCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.vault = FakeVault()
        self.server, self.alerter = build(self.tmp, vault=self.vault,
                                          store_enabled=True)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def call(self, **args):
        return self.server._call_tool({"name": "store", "arguments": args})

    @staticmethod
    def payload(result):
        """Everything the caller would see, as one string.

        Deliberately the whole envelope rather than the parsed body: an absence
        check has to cover error text and any stray field too, not just the
        happy-path keys.
        """
        return json.dumps(result)

    @staticmethod
    def body(result):
        """The tool's own JSON, decoded out of its text content block."""
        return json.loads(result["content"][0]["text"])


class TestMintedValueNeverReturned(StoreCase):
    def test_command_stdout_is_not_in_the_result(self):
        result = self.call(ref=TARGET, source="command",
                           command='printf %s "' + MINTED + '"')
        blob = self.payload(result)
        self.assertNotIn(MINTED, blob)

    def test_but_it_did_reach_the_vault(self):
        """Positive control. Without this, the test above would pass just as
        happily if store had quietly done nothing at all."""
        self.call(ref=TARGET, source="command",
                  command='printf %s "' + MINTED + '"')
        self.assertEqual(MINTED, self.vault.values[TARGET])

    def test_result_carries_fingerprint_and_length(self):
        result = self.call(ref=TARGET, source="command",
                           command='printf %s "' + MINTED + '"')
        body = self.body(result)
        self.assertEqual(len(MINTED), body["length"])
        self.assertEqual(12, len(body["fingerprint"]))
        self.assertTrue(body["stored"])


class TestGenerate(StoreCase):
    def test_generates_and_stores(self):
        self.call(ref=TARGET, source="generate", bytes=32)
        self.assertTrue(self.vault.values.get(TARGET))

    def test_generated_value_is_not_returned(self):
        result = self.call(ref=TARGET, source="generate", bytes=32)
        self.assertNotIn(self.vault.values[TARGET], self.payload(result))

    def test_absurd_entropy_is_refused(self):
        for n in (4, 4096, "32"):
            result = self.call(ref=TARGET, source="generate", bytes=n)
            self.assertTrue(result.get("isError"), n)


class TestNotEnabled(unittest.TestCase):
    """The default. Writing is not granted just because reading was."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.vault = FakeVault()
        self.server, _ = build(self.tmp, vault=self.vault)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_store_is_refused_by_default(self):
        result = self.server._call_tool(
            {"name": "store", "arguments": {"ref": TARGET, "source": "generate"}})
        self.assertTrue(result.get("isError"))
        self.assertIn("not enabled", json.dumps(result))
        self.assertNotIn(TARGET, self.vault.values)


class TestRefusals(StoreCase):
    def test_occupied_field_is_refused(self):
        result = self.call(ref="op://Dev/item/credential", source="generate")
        self.assertTrue(result.get("isError"))
        self.assertIn("create-or-add only", self.payload(result))

    def test_failed_mint_stores_nothing(self):
        """A partial value stored as if it were real is worse than an error:
        the next step would push it to a live service."""
        result = self.call(ref=TARGET, source="command",
                           command='printf partial; exit 3')
        self.assertTrue(result.get("isError"))
        self.assertNotIn(TARGET, self.vault.values)

    def test_failed_mint_does_not_echo_its_output(self):
        result = self.call(ref=TARGET, source="command",
                           command='printf %s "' + MINTED + '"; exit 3')
        self.assertNotIn(MINTED, self.payload(result))

    def test_empty_output_stores_nothing(self):
        result = self.call(ref=TARGET, source="command", command="true")
        self.assertTrue(result.get("isError"))
        self.assertNotIn(TARGET, self.vault.values)

    def test_missing_ref_is_refused(self):
        self.assertTrue(self.call(source="generate").get("isError"))

    def test_unknown_source_is_refused(self):
        result = self.call(ref=TARGET, source="telepathy")
        self.assertTrue(result.get("isError"))

    def test_command_source_needs_a_command(self):
        self.assertTrue(self.call(ref=TARGET, source="command").get("isError"))


if __name__ == "__main__":
    unittest.main()
