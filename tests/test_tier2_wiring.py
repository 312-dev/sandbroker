"""Tier 2 is actually connected, and `store` is deliberately exempt from it.

HeuristicRedactor shipped with its own unit tests and nothing calling it, while
the threat model told readers it was "the safety net for everything else". A
guesser that exists but never runs protects nobody, and a threat model that
claims otherwise is worse than one that admits the gap. These tests are about
the wiring rather than the matching: test_heuristic_redact.py already covers
what it catches.

The second half matters just as much and pulls the other way. `store` consumes
the mint command's stdout INSIDE the broker and writes it to the vault, so
scrubbing there would store the placeholder instead of the credential -- the
scrubber turning into the corruption. Tier 2 is off on that path, and it has to
stay off.
"""

import json
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sandbroker import runner  # noqa: E402
from test_mcp import build  # noqa: E402
from test_runner import FakeVault, make_config  # noqa: E402

# Shaped like a token a mint API would hand back. Never injected by the broker,
# so Tier 1 is structurally blind to it -- which is the whole reason for Tier 2.
MINTED = "ghp_" + "B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8s9"
TARGET = "op://Dev/rotating-item/rotated_2026_09"


class TestTier2RunsOnTheRunPath(unittest.TestCase):
    def test_an_undeclared_token_is_scrubbed_from_stdout(self):
        result = runner.run(FakeVault(), make_config(),
                            command='printf %s "' + MINTED + '"')
        self.assertNotIn(MINTED, result["stdout"])
        self.assertIn("likely-credential", result["stdout"])
        self.assertEqual(1, result["heuristic_hits"])

    def test_the_two_tiers_stay_distinguishable(self):
        # A reader must always be able to tell a guarantee from a guess, so the
        # markers must not converge.
        result = runner.run(
            FakeVault(), make_config(),
            command='printf "%s %s" "$TOKEN" "' + MINTED + '"',
            secrets={"TOKEN": "op://Dev/item/credential"})
        self.assertIn("[redacted:TOKEN]", result["stdout"])
        self.assertIn("[likely-credential:", result["stdout"])

    def test_ordinary_output_is_untouched(self):
        result = runner.run(FakeVault(), make_config(),
                            command='printf "all tests passed, commit a94f3c2"')
        self.assertEqual("all tests passed, commit a94f3c2", result["stdout"])
        self.assertEqual(0, result["heuristic_hits"])

    def test_the_config_can_switch_it_off(self):
        result = runner.run(FakeVault(), make_config(heuristic_scan=False),
                            command='printf %s "' + MINTED + '"')
        self.assertIn(MINTED, result["stdout"])
        self.assertEqual(0, result["heuristic_hits"])

    def test_entropy_pass_stays_off_by_default(self):
        # A 40-hex git SHA must survive, which is the documented reason the
        # entropy pass is not on.
        sha = "a94f3c2b1d5e6f708192a3b4c5d6e7f809213456"
        result = runner.run(FakeVault(), make_config(),
                            command='printf %s "' + sha + '"')
        self.assertIn(sha, result["stdout"])


class TestStoreIsExemptFromTier2(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.vault = FakeVault()
        self.server, _ = build(self.tmp, vault=self.vault, store_enabled=True)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def call(self, **args):
        return self.server._call_tool({"name": "store", "arguments": args})

    def test_the_credential_reaches_the_vault_unscrubbed(self):
        # The regression this exists for: with Tier 2 on this path, the vault
        # would receive "[likely-credential:sha256=...]" and every later use of
        # that credential would fail in a way nobody could debug, because the
        # value is unreadable by design.
        result = self.call(ref=TARGET, source="command",
                           command='printf %s "' + MINTED + '"')
        self.assertEqual(MINTED, self.vault.values.get(TARGET),
                         "the vault did not receive the raw minted value")

    def test_the_value_still_never_comes_back(self):
        result = self.call(ref=TARGET, source="command",
                           command='printf %s "' + MINTED + '"')
        self.assertNotIn(MINTED, json.dumps(result))


class TestStoreRefusesCorruptedValues(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.vault = FakeVault()
        self.server, _ = build(self.tmp, vault=self.vault, store_enabled=True,
                               max_output_bytes=32)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def call(self, **args):
        return self.server._call_tool({"name": "store", "arguments": args})

    def test_capped_output_is_refused_rather_than_stored_short(self):
        # A prefix of a credential is as useless as a half-written one, and the
        # store path already refuses that case on a non-zero exit.
        result = self.call(ref=TARGET, source="command",
                           command='printf %s "' + ("x" * 200) + '"')
        self.assertTrue(result.get("isError"))
        self.assertIn("truncated", json.dumps(result))
        self.assertNotIn(TARGET, self.vault.values)

    def test_a_placeholder_is_never_written_to_the_vault(self):
        result = self.call(ref=TARGET, source="command",
                           command='printf %s "[redacted:TOKEN]"')
        self.assertTrue(result.get("isError"))
        self.assertNotIn(TARGET, self.vault.values)


if __name__ == "__main__":
    unittest.main(verbosity=0 if "-q" in sys.argv else 1,
                  argv=[a for a in sys.argv if a != "-q"])
