"""Execution: what reaches the child, and what comes back."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sandbroker import runner  # noqa: E402
from sandbroker.config import Config  # noqa: E402
from sandbroker.onepassword import VaultError  # noqa: E402
from sandbroker.runner import RunError  # noqa: E402

SECRET = "tok_live_ABCDEF0123456789abcdef"


class FakeVault:
    """Stands in for 1Password so the suite never needs a vault or a network."""

    alias = "Dev"
    ref_scheme = "op"
    default_field = "credential"

    def __init__(self, values=None, sa_token=None):
        self.values = values or {"op://Dev/item/credential": SECRET}
        self._sa = sa_token

    def read(self, ref):
        if not ref.startswith("op://"):
            ref = "op://Dev/%s" % ref
        if ref.count("/") == 3:
            ref += "/credential"
        try:
            return self.values[ref]
        except KeyError:
            raise VaultError("no such reference")

    def service_account_token(self):
        return self._sa

    # Metadata only, mirroring the real Vault: titles and field labels, never a
    # value. Present so tests can assert that listing is not gated.
    def list_items(self):
        titles = sorted({ref.split("/")[3] for ref in self.values})
        return [{"title": t, "ref": "op://Dev/%s" % t, "category": "LOGIN"}
                for t in titles]

    def list_fields(self, item):
        return [{"field": ref.split("/")[4], "ref": ref,
                 "type": "CONCEALED", "populated": True}
                for ref in sorted(self.values)
                if ref.split("/")[3] == item]


def make_config(**overrides):
    data = {
        "vaults": {"Dev": {"vault": "Real Dev", "token": "Dev"}},
        "max_output_bytes": 65536,
        "default_timeout": 10,
        "max_timeout": 30,
    }
    data.update(overrides)
    return Config(data, path="<test>")


class TestInjection(unittest.TestCase):
    def setUp(self):
        self.vault = FakeVault()
        self.cfg = make_config()

    def test_secret_reaches_the_child_environment(self):
        # Length proves the value arrived without printing it, and the printed
        # value would be scrubbed anyway.
        result = runner.run(self.vault, self.cfg,
                            command='printf %s "${#TOKEN}"',
                            secrets={"TOKEN": "op://Dev/item/credential"})
        self.assertEqual(0, result["exit_code"])
        self.assertEqual(str(len(SECRET)), result["stdout"])

    def test_echoed_secret_comes_back_scrubbed(self):
        result = runner.run(self.vault, self.cfg,
                            command='echo "$TOKEN"',
                            secrets={"TOKEN": "op://Dev/item/credential"})
        self.assertNotIn(SECRET, result["stdout"])
        self.assertIn("[redacted:TOKEN]", result["stdout"])
        self.assertEqual(1, result["redactions"])

    def test_secret_never_appears_in_argv(self):
        """/proc/<pid>/cmdline is world-readable, so this is the load-bearing
        reason secrets travel in the environment."""
        result = runner.run(
            self.vault, self.cfg,
            command='tr "\\0" " " < /proc/$$/cmdline',
            secrets={"TOKEN": "op://Dev/item/credential"})
        self.assertNotIn(SECRET, result["stdout"])
        self.assertNotIn("[redacted", result["stdout"])

    def test_stderr_is_scrubbed_too(self):
        result = runner.run(self.vault, self.cfg,
                            command='echo "$TOKEN" >&2',
                            secrets={"TOKEN": "op://Dev/item/credential"})
        self.assertNotIn(SECRET, result["stderr"])
        self.assertIn("[redacted:TOKEN]", result["stderr"])

    def test_service_account_token_is_absent_and_scrubbed(self):
        sa = "ops_serviceaccountTOKENvalue0987654321"
        vault = FakeVault(sa_token=sa)
        result = runner.run(vault, self.cfg, command="env", secrets={})
        self.assertNotIn(sa, result["stdout"])
        self.assertNotIn("OP_SERVICE_ACCOUNT_TOKEN", result["stdout"])

    def test_multiple_secrets(self):
        vault = FakeVault({
            "op://Dev/a/credential": "AAAAAAAAAAAA",
            "op://Dev/b/password": "BBBBBBBBBBBB",
        })
        result = runner.run(vault, self.cfg,
                            command='echo "$ONE:$TWO"',
                            secrets={"ONE": "op://Dev/a/credential",
                                     "TWO": "op://Dev/b/password"})
        self.assertIn("[redacted:ONE]:[redacted:TWO]", result["stdout"])

    def test_any_field_is_allowed(self):
        vault = FakeVault({"op://Dev/thing/account_id": "acct-12345678"})
        result = runner.run(vault, self.cfg, command='echo "$X"',
                            secrets={"X": "op://Dev/thing/account_id"})
        self.assertIn("[redacted:X]", result["stdout"])


class TestFailureModes(unittest.TestCase):
    def setUp(self):
        self.vault = FakeVault()
        self.cfg = make_config()

    def test_bad_reference_fails_before_running_anything(self):
        marker = "/tmp/sandbroker-should-not-exist-%d" % os.getpid()
        with self.assertRaises(RunError):
            runner.run(self.vault, self.cfg,
                       command="touch %s" % marker,
                       secrets={"T": "op://Dev/nope/credential"})
        self.assertFalse(os.path.exists(marker))

    def test_reserved_env_name_is_refused(self):
        for name in ("PATH", "LD_PRELOAD", "OP_SERVICE_ACCOUNT_TOKEN"):
            with self.assertRaises(RunError):
                runner.run(self.vault, self.cfg, command="true",
                           secrets={name: "op://Dev/item/credential"})

    def test_bad_env_name_is_refused(self):
        for name in ("2TOKEN", "my-token", "", "a b"):
            with self.assertRaises(RunError):
                runner.run(self.vault, self.cfg, command="true",
                           secrets={name: "op://Dev/item/credential"})

    def test_empty_command_is_refused(self):
        with self.assertRaises(RunError):
            runner.run(self.vault, self.cfg, command="   ")

    def test_timeout_kills_the_process_tree(self):
        result = runner.run(self.vault, self.cfg,
                            command="sleep 30", timeout=1)
        self.assertTrue(result["timed_out"])
        self.assertEqual(-1, result["exit_code"])

    def test_timeout_above_max_is_refused(self):
        with self.assertRaises(RunError):
            runner.run(self.vault, self.cfg, command="true", timeout=99999)

    def test_nonzero_exit_is_reported_not_raised(self):
        result = runner.run(self.vault, self.cfg, command="exit 42")
        self.assertEqual(42, result["exit_code"])

    def test_output_is_capped(self):
        cfg = make_config(max_output_bytes=1024)
        result = runner.run(self.vault, cfg, command="head -c 100000 /dev/zero | tr '\\0' 'x'")
        self.assertTrue(result["truncated"])
        self.assertLessEqual(len(result["stdout"]), 1024)

    def test_bad_cwd_is_refused(self):
        with self.assertRaises(RunError):
            runner.run(self.vault, self.cfg, command="pwd",
                       cwd="/definitely/not/here")


class TestPassthrough(unittest.TestCase):
    def test_stdin_is_delivered(self):
        result = runner.run(FakeVault(), make_config(),
                            command="cat", stdin="hello from stdin")
        self.assertEqual("hello from stdin", result["stdout"])

    def test_cwd_is_honoured(self):
        result = runner.run(FakeVault(), make_config(), command="pwd", cwd="/tmp")
        self.assertIn("/tmp", result["stdout"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
