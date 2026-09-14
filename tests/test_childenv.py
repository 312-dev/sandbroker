"""No child of the broker may autolaunch a D-Bus session bus.

Two things are checked here. The cheap one is that every env builder actually
sets the variable. The one that matters is a process count: run a batch of
commands through the real runner and assert the box has no more stray daemons
afterwards than before.

The stub stands in for go-dbus, which is what `op` links. It applies go-dbus's
own rule -- autolaunch when DBUS_SESSION_BUS_ADDRESS is empty or the literal
"autolaunch:", otherwise use the address given -- and leaks a detached process
the way `dbus-launch` does, so the count is a real count of real orphans. What
it cannot prove is that go-dbus still behaves that way in the version of `op`
installed on a given box. That check is live_session_bus_probe.py, which drives
a running daemon and counts what the real `op` leaves behind.
"""

import os
import subprocess
import sys
import time
import unittest
import uuid

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sandbroker import runner  # noqa: E402
from sandbroker.alert import Alerter  # noqa: E402
from sandbroker.childenv import NO_SESSION_BUS, without_session_bus  # noqa: E402
from sandbroker.config import Config  # noqa: E402
from sandbroker.keeper import Vault as KeeperVault  # noqa: E402
from sandbroker.onepassword import Vault as OnePasswordVault  # noqa: E402

CALLS = 20


def config(**over):
    data = {"vaults": {"Dev": {"vault": "Dev", "token": "dev"}}}
    data.update(over)
    return Config(data)


class FakeVault:
    alias = "Dev"

    def read(self, ref):
        raise AssertionError("this suite resolves nothing")

    def service_account_token(self):
        return None


# go-dbus autolaunches only for these two values. Anything else it tries and
# fails on, which is the whole mechanism the fix relies upon.
AUTOLAUNCH_TRIGGERS = ("", "autolaunch:")

# Mimics go-dbus deciding whether to autolaunch, and dbus-launch's habit of
# leaving behind a daemon that outlives its caller. Stdio is detached so the
# orphan does not hold the runner's pipes open.
STUB = r"""
case "${DBUS_SESSION_BUS_ADDRESS-}" in
  ""|autolaunch:) sh -c 'sleep 120 # %s' </dev/null >/dev/null 2>&1 & ;;
esac
echo ok
"""


def strays(marker):
    """Live processes carrying our marker, however they were reparented."""
    found = []
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        try:
            with open("/proc/%s/cmdline" % entry, "rb") as fh:
                cmd = fh.read().replace(b"\0", b" ").decode("utf-8", "replace")
        except OSError:
            continue
        if marker in cmd and "sleep" in cmd:
            found.append(int(entry))
    return found


class SessionBusIsNeverLaunched(unittest.TestCase):

    def test_every_env_builder_sets_it(self):
        """One missed builder is one more path that leaks, so check them all."""
        vault = OnePasswordVault("Dev", "Dev", "/nonexistent/token",
                                 "/bin/true")
        vault._token = "sa-token"
        keeper = KeeperVault("Dev", "Dev", "/nonexistent/token", "/bin/true",
                             state_dir="/tmp")
        alerter = Alerter(config(notify_command="true"))

        builders = {
            "onepassword": vault._env(),
            "keeper": keeper._env(),
            "runner": runner._base_env(),
            "alert": alerter._notify_env({}, "t", "b"),
        }
        for name, env in builders.items():
            with self.subTest(builder=name):
                self.assertEqual(env.get("DBUS_SESSION_BUS_ADDRESS"),
                                 NO_SESSION_BUS)

    def test_the_address_is_one_go_dbus_will_not_autolaunch_on(self):
        self.assertNotIn(NO_SESSION_BUS, AUTOLAUNCH_TRIGGERS)
        self.assertTrue(NO_SESSION_BUS.startswith("unix:path=/"),
                        "an absolute unix path fails connect() immediately")

    def test_a_caller_cannot_rebind_it(self):
        """It is broker plumbing. Binding a secret to it would undo the fix."""
        with self.assertRaises(runner.RunError):
            runner.run(FakeVault(), config(), "true",
                       secrets={"DBUS_SESSION_BUS_ADDRESS": "op://Dev/x/y"})

    def test_the_process_count_is_flat_across_a_batch(self):
        marker = "sandbroker-test-%s" % uuid.uuid4().hex[:12]
        command = STUB % marker
        self.addCleanup(self._reap, marker)

        before = len(strays(marker))
        for _ in range(CALLS):
            result = runner.run(FakeVault(), config(), command)
            self.assertEqual(result["exit_code"], 0)
        time.sleep(0.5)
        after = strays(marker)

        self.assertEqual(
            len(after), before,
            "%d call(s) out of %d left a detached process behind (pids %s)"
            % (len(after) - before, CALLS, after))

    def test_the_stub_would_notice_a_leak(self):
        """The counting test is only worth its runtime if it can go red.

        Same batch, same stub, with the guard taken back out of the child's
        environment. If this does not leak, the test above proves nothing.
        """
        marker = "sandbroker-test-%s" % uuid.uuid4().hex[:12]
        self.addCleanup(self._reap, marker)

        env = runner._base_env()
        del env["DBUS_SESSION_BUS_ADDRESS"]
        for _ in range(3):
            subprocess.run(["/bin/sh", "-c", STUB % marker], env=env,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(0.5)

        self.assertEqual(len(strays(marker)), 3)

    def test_the_helper_leaves_the_rest_of_the_environment_alone(self):
        env = without_session_bus({"PATH": "/bin", "HOME": "/home/x"})
        self.assertEqual(env["PATH"], "/bin")
        self.assertEqual(env["HOME"], "/home/x")

    def _reap(self, marker):
        for pid in strays(marker):
            try:
                os.kill(pid, 9)
            except OSError:
                pass


if __name__ == "__main__":
    unittest.main(verbosity=2)
