"""Redaction is the whole product, so it gets the most tests."""

import base64
import json
import os
import sys
import unittest
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sandbroker.redact import Redactor  # noqa: E402

SECRET = "sk-live-9f3a2b1c8d7e6f5a4b3c2d1e0f9a8b7c"


class TestPlainMatches(unittest.TestCase):
    def test_exact_value_is_removed(self):
        r = Redactor({"TOKEN": SECRET})
        out = r.clean(("status ok, used " + SECRET + " today").encode())
        self.assertNotIn(SECRET, out)
        self.assertIn("[redacted:TOKEN]", out)

    def test_placeholder_names_the_variable(self):
        r = Redactor({"MERCURY_KEY": SECRET})
        self.assertIn("[redacted:MERCURY_KEY]", r.clean(SECRET.encode()))

    def test_multiple_occurrences_all_go(self):
        r = Redactor({"T": SECRET})
        out = r.clean((SECRET + "\n" + SECRET + "\n" + SECRET).encode())
        self.assertNotIn(SECRET, out)
        self.assertEqual(3, r.hits)

    def test_untouched_text_survives(self):
        r = Redactor({"T": SECRET})
        self.assertEqual("nothing to see", r.clean(b"nothing to see"))
        self.assertEqual(0, r.hits)

    def test_empty_secret_is_ignored(self):
        # An empty needle would otherwise match between every character.
        r = Redactor({"EMPTY": ""})
        self.assertEqual("hello", r.clean(b"hello"))


class TestEncodings(unittest.TestCase):
    """A secret sent as a bearer token comes back quoted, escaped or wrapped.
    Those are the same bytes in a different spelling, so they must go too."""

    def test_percent_encoded(self):
        value = "p@ss w/rd+123"
        r = Redactor({"T": value})
        out = r.clean(("redirect?k=" + urllib.parse.quote(value, safe="")).encode())
        self.assertNotIn("p%40ss", out)
        self.assertIn("[redacted:T]", out)

    def test_quote_plus_form(self):
        value = "a b c/d"
        r = Redactor({"T": value})
        out = r.clean(("q=" + urllib.parse.quote_plus(value)).encode())
        self.assertIn("[redacted:T]", out)

    def test_json_escaped(self):
        value = 'tok"en\\with/slash'
        r = Redactor({"T": value})
        body = json.dumps({"echoed": value})
        out = r.clean(body.encode())
        self.assertNotIn('tok\\"en', out)
        self.assertIn("[redacted:T]", out)

    def test_base64_of_the_value(self):
        r = Redactor({"T": SECRET})
        blob = base64.b64encode(SECRET.encode()).decode()
        out = r.clean(("payload " + blob).encode())
        self.assertNotIn(blob, out)

    def test_urlsafe_base64_and_unpadded(self):
        value = "ab?cd>ef~gh"
        b64 = base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")
        r = Redactor({"T": value})
        out = r.clean(("x=" + b64).encode())
        self.assertNotIn(b64, out)

    def test_hex_both_cases(self):
        value = "hunter2hunter2"
        r = Redactor({"T": value})
        hexed = value.encode().hex()
        self.assertNotIn(hexed, r.clean(hexed.encode()))
        self.assertNotIn(hexed.upper(), r.clean(hexed.upper().encode()))

    def test_html_escaped(self):
        value = 'a<b>&c"d'
        r = Redactor({"T": value})
        out = r.clean(b"<pre>a&lt;b&gt;&amp;c&quot;d</pre>")
        self.assertIn("[redacted:T]", out)


class TestBase64Wrapper(unittest.TestCase):
    """Basic auth concatenates before encoding, so no encoding of the password
    alone appears in the blob. One decode pass catches it."""

    def test_basic_auth_header_is_redacted(self):
        password = "s3cr3t-p@ssword-value"
        blob = base64.b64encode(("gray:" + password).encode()).decode()
        r = Redactor({"PW": password})
        out = r.clean(("Authorization: Basic " + blob).encode())
        self.assertNotIn(blob, out)
        self.assertIn("[redacted:base64]", out)

    def test_unrelated_base64_is_left_alone(self):
        blob = base64.b64encode(b"totally benign payload data here").decode()
        r = Redactor({"PW": SECRET})
        out = r.clean(("data " + blob).encode())
        self.assertIn(blob, out)

    def test_binary_base64_does_not_crash(self):
        blob = base64.b64encode(os.urandom(64)).decode()
        r = Redactor({"PW": SECRET})
        r.clean(("blob " + blob).encode())


class TestOrdering(unittest.TestCase):
    def test_longer_secret_wins_over_its_own_prefix(self):
        short, long_ = "abcd1234", "abcd1234efgh5678"
        r = Redactor({"SHORT": short, "LONG": long_})
        out = r.clean(long_.encode())
        # The long secret must be consumed whole, not chewed into
        # "[redacted:SHORT]efgh5678" which would leave half of it exposed.
        self.assertNotIn("efgh5678", out)
        self.assertIn("[redacted:LONG]", out)


class TestBytesPass(unittest.TestCase):
    def test_secret_adjacent_to_invalid_utf8_still_goes(self):
        """Decoding with errors=replace can mangle nearby bytes, so the exact
        match runs on raw bytes first."""
        r = Redactor({"T": SECRET})
        raw = b"\xff\xfe" + SECRET.encode() + b"\x80trailing"
        out = r.clean(raw)
        self.assertNotIn(SECRET, out)
        self.assertIn("[redacted:T]", out)

    def test_hits_are_counted(self):
        r = Redactor({"T": SECRET})
        r.clean((SECRET + " and " + SECRET).encode())
        self.assertGreaterEqual(r.hits, 2)


class TestNotADetector(unittest.TestCase):
    """Stated as a test so the boundary is not quietly widened later. This
    module removes what it was given and nothing else."""

    def test_an_unrelated_credential_shaped_string_passes_through(self):
        r = Redactor({"T": SECRET})
        other = "ghp_ThisLooksExactlyLikeAGitHubTokenButWasNeverInjected"
        self.assertIn(other, r.clean(other.encode()))


if __name__ == "__main__":
    unittest.main(verbosity=2)
