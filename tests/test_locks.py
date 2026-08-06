"""Per-vault unlock gates."""

import json
import os
import shutil
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sandbroker import locks  # noqa: E402
from sandbroker.config import Config  # noqa: E402

from test_mcp import build, call, payload  # noqa: E402
from test_runner import FakeVault, SECRET  # noqa: E402


def gated_config(tmp, required=True):
    return Config({
        "vaults": {"Dev": {"vault": "Real Dev", "token": "Dev",
                           "require_unlock": required}},
        "alerts_dir": os.path.join(tmp, "var", "alerts"),
        "max_output_bytes": 65536, "default_timeout": 10, "max_timeout": 30,
    }, path="<test>")


class TestLockState(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.cfg = gated_config(self.tmp)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_gated_vault_starts_locked(self):
        unlocked, remaining = locks.status(self.cfg, "Dev")
        self.assertFalse(unlocked)
        self.assertEqual(0, remaining)

    def test_ungated_vault_is_always_open(self):
        cfg = gated_config(self.tmp, required=False)
        self.assertEqual((True, None), locks.status(cfg, "Dev"))
        self.assertIn("no unlock required", locks.describe(cfg, "Dev"))

    def test_unlock_then_lock(self):
        locks.unlock(self.cfg, "Dev", minutes=5)
        unlocked, remaining = locks.status(self.cfg, "Dev")
        self.assertTrue(unlocked)
        self.assertGreater(remaining, 240)
        self.assertTrue(locks.lock(self.cfg, "Dev"))
        self.assertFalse(locks.status(self.cfg, "Dev")[0])

    def test_unlock_expires_on_its_own(self):
        """The TTL is the point: an unlock you forget about closes itself."""
        locks.unlock(self.cfg, "Dev", minutes=1)
        path = locks.marker_path(self.cfg, "Dev")
        with open(path, "r", encoding="utf-8") as fh:
            record = json.load(fh)
        record["until"] = int(time.time()) - 1
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(record, fh)
        self.assertFalse(locks.status(self.cfg, "Dev")[0])

    def test_absurd_durations_refused(self):
        for minutes in (0, -5, locks.MAX_MINUTES + 1, "soon"):
            with self.assertRaises(locks.LockError):
                locks.unlock(self.cfg, "Dev", minutes=minutes)

    def test_locking_an_already_locked_vault_is_not_an_error(self):
        self.assertFalse(locks.lock(self.cfg, "Dev"))

    def test_marker_is_not_world_readable(self):
        locks.unlock(self.cfg, "Dev", minutes=5)
        mode = os.stat(locks.marker_path(self.cfg, "Dev")).st_mode & 0o777
        self.assertEqual(0, mode & 0o077)


class TestGateIsEnforcedOnRun(unittest.TestCase):
    """The gate has to sit in the daemon. A client-side gate would be advisory:
    the sandbox grants agents write access to ~/.claude, so anything enforced
    there is enforced by a file the gated party can edit."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.server, self.alerter = build(self.tmp)
        self.server.config = gated_config(self.tmp)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_run_is_refused_while_locked(self):
        result = call(self.server, "run", {
            "command": 'echo "$T"',
            "secrets": {"T": "op://Dev/item/credential"}})
        self.assertTrue(result.get("isError"))
        text = result["content"][0]["text"]
        self.assertIn("LOCKED", text)
        self.assertIn("sudo sandbroker unlock Dev", text)
        self.assertNotIn(SECRET, text)

    def test_run_works_once_unlocked(self):
        locks.unlock(self.server.config, "Dev", minutes=5)
        data = payload(call(self.server, "run", {
            "command": 'echo "$T"',
            "secrets": {"T": "op://Dev/item/credential"}}))
        self.assertEqual(0, data["exit_code"])
        self.assertIn("[redacted:T]", data["stdout"])

    def test_listing_is_never_gated(self):
        """list_items and list_fields cannot leak a value, so gating them would
        add friction without adding safety."""
        result = call(self.server, "list_items")
        self.assertFalse(result.get("isError"))

    def test_lock_state_is_queryable_over_the_protocol(self):
        reply = self.server.handle({"jsonrpc": "2.0", "id": 1,
                                    "method": "locks/status"})
        self.assertTrue(reply["result"]["required"])
        self.assertFalse(reply["result"]["unlocked"])

    def test_no_tool_can_unlock(self):
        """An agent that could lift its own gate would not be gated."""
        names = {t["name"] for t in
                 self.server.handle({"jsonrpc": "2.0", "id": 1,
                                     "method": "tools/list"})["result"]["tools"]}
        self.assertEqual(set(), names & {"unlock", "lock"})


if __name__ == "__main__":
    unittest.main(verbosity=2)
