"""Tier 2 guesses, so the tests care as much about what it leaves alone.

A filter that redacts everything would pass every "is the secret gone" test and
be useless. Each catch test here is paired with a test that it does not fire on
ordinary output.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sandbroker.redact import HeuristicRedactor, Redactor  # noqa: E402

# Shapes taken from real leak alerts rather than invented, so a regression here
# maps to an incident that actually happened.
ANTHROPIC = "sk-ant-api03-" + "aB3xY7zQ9mNpL2kR5tVwXyZ0" * 4
CLOUDFLARED = "eyJhIjoiZDQ2MzIwM2NjODRjMmVmOGViZDFiOGY2NTZlZTY2ZGIiLCJ0IjoiMWZmYjYzNmIifQ"
COOKIE_BROKER = "9f3a2b1c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c8d7e"  # 48 hex


class TestPrefixPass(unittest.TestCase):
    """Always on. These shapes are unmistakable."""

    def test_anthropic_key_is_caught(self):
        r = HeuristicRedactor()
        out = r.scrub("plugin config: apiKey=" + ANTHROPIC)
        self.assertNotIn(ANTHROPIC, out)
        self.assertIn("[likely-credential:", out)
        self.assertEqual(1, r.hits)

    def test_cloudflared_token_is_caught(self):
        """Alert 1786313954: a connector token is base64 of JSON, so it starts
        with the same eyJ as a JWT."""
        r = HeuristicRedactor()
        self.assertNotIn(CLOUDFLARED, r.scrub("--token " + CLOUDFLARED))

    def test_marker_is_distinguishable_from_tier_one(self):
        """The whole point of a separate marker: a reader must never mistake a
        guess for the guarantee."""
        tier1 = Redactor({"TOKEN": ANTHROPIC}).clean(ANTHROPIC.encode())
        tier2 = HeuristicRedactor().scrub(ANTHROPIC)
        self.assertIn("[redacted:TOKEN]", tier1)
        self.assertIn("[likely-credential:", tier2)
        self.assertNotIn("likely-credential", tier1)

    def test_prose_is_untouched(self):
        text = "Deployed mcp-gateway to the box and restarted the allocation."
        self.assertEqual(text, HeuristicRedactor().scrub(text))
        self.assertEqual(0, HeuristicRedactor().hits)


class TestEntropyPass(unittest.TestCase):
    """Off by default, because shape alone cannot separate a hex secret from a
    hex hash."""

    def test_off_by_default(self):
        r = HeuristicRedactor()
        self.assertIn(COOKIE_BROKER, r.scrub("TOKEN=" + COOKIE_BROKER))

    def test_on_catches_the_cookie_broker_token(self):
        r = HeuristicRedactor(entropy_scan=True)
        self.assertNotIn(COOKIE_BROKER, r.scrub("TOKEN=" + COOKIE_BROKER))

    def test_git_sha_survives(self):
        """40 hex is a commit id far more often than a credential. Redacting it
        would make ordinary output unreadable, so this hole is deliberate."""
        sha = "64a3cbc9f3a2b1c8d7e6f5a4b3c2d1e0f9a8b7c6"
        self.assertEqual(40, len(sha))
        r = HeuristicRedactor(entropy_scan=True)
        self.assertIn(sha, r.scrub("commit " + sha))

    def test_sha256_digest_survives(self):
        digest = "9f3a2b1c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c8d7e6f5a4b3c2d1e0f9a"
        self.assertEqual(64, len(digest))
        r = HeuristicRedactor(entropy_scan=True)
        self.assertIn(digest, r.scrub("image sha256:" + digest))

    def test_low_entropy_long_string_survives(self):
        """Long and alphanumeric is not enough. This is the test that proves the
        filter discriminates rather than redacting anything big."""
        boring = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        self.assertGreaterEqual(len(boring), 32)
        r = HeuristicRedactor(entropy_scan=True)
        self.assertIn(boring, r.scrub(boring))

    def test_digits_only_survives(self):
        """Timestamps and ids are long and numeric; neither is a credential."""
        r = HeuristicRedactor(entropy_scan=True)
        stamp = "1786313954178631395417863139541786313954"
        self.assertIn(stamp, r.scrub("id " + stamp))


class TestFingerprint(unittest.TestCase):
    """Verification without disclosure is the reason the marker carries a hash."""

    def test_same_value_same_fingerprint(self):
        self.assertEqual(
            HeuristicRedactor.fingerprint(ANTHROPIC),
            HeuristicRedactor.fingerprint(ANTHROPIC),
        )

    def test_different_values_differ(self):
        self.assertNotEqual(
            HeuristicRedactor.fingerprint(ANTHROPIC),
            HeuristicRedactor.fingerprint(COOKIE_BROKER),
        )

    def test_fingerprint_does_not_contain_the_value(self):
        fp = HeuristicRedactor.fingerprint(ANTHROPIC)
        self.assertNotIn(fp, ANTHROPIC)
        self.assertEqual(12, len(fp))


if __name__ == "__main__":
    unittest.main()
