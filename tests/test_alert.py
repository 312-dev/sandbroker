"""Alerting: the transport is a command, and the agent cannot reach through it.

The alarm is the only thing standing between a credential the broker never saw
and a human who needs to rotate it, so these tests care about two things: that a
notification actually goes out, and that nothing an agent writes can turn the
notifier into a shell it controls.
"""

import json
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sandbroker.alert import Alerter, AlertsUnreadable  # noqa: E402
from sandbroker.config import Config  # noqa: E402


def make_config(tmpdir, **overrides):
    data = {
        "vaults": {"Dev": {"vault": "Real Dev", "token": "Dev"}},
        "alerts_dir": os.path.join(tmpdir, "alerts"),
    }
    data.update(overrides)
    return Config(data, path="<test>")


class AlertTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="sandbroker-alert-")
        self.sink = os.path.join(self.tmp, "sink")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def sink_contents(self):
        try:
            with open(self.sink, "r", encoding="utf-8") as fh:
                return fh.read()
        except OSError:
            return ""


class TestTransport(AlertTestCase):
    def test_string_command_runs_under_a_shell(self):
        cfg = make_config(self.tmp, notify_command="cat > %s" % self.sink)
        record, delivered = Alerter(cfg).raise_alert("Dev", "curl", "a bearer token")
        self.assertTrue(delivered)
        payload = json.loads(self.sink_contents())
        self.assertEqual(record["id"], payload["id"])
        self.assertEqual("Dev", payload["vault"])

    def test_list_command_is_argv_and_skips_the_shell(self):
        # The metacharacters survive as literal argv, which is the whole point
        # of accepting a list: nothing re-parses them.
        cfg = make_config(self.tmp, notify_command=[
            "/bin/sh", "-c", 'printf %s "$SANDBROKER_ALERT_VAULT" > ' + self.sink])
        _, delivered = Alerter(cfg).raise_alert("Prod; rm -rf /", "where", "detail")
        self.assertTrue(delivered)
        self.assertEqual("Prod; rm -rf /", self.sink_contents())

    def test_alert_fields_reach_the_environment(self):
        cfg = make_config(self.tmp, notify_command=(
            'printf "%s|%s|%s" "$SANDBROKER_ALERT_VAULT" '
            '"$SANDBROKER_ALERT_WHERE" "$SANDBROKER_ALERT_DETAIL" > ' + self.sink))
        Alerter(cfg).raise_alert("Infra", "oauth exchange", "40-char bearer")
        self.assertEqual("Infra|oauth exchange|40-char bearer", self.sink_contents())

    def test_title_and_body_name_the_ack_command(self):
        cfg = make_config(self.tmp,
                          notify_command='printf %s "$SANDBROKER_ALERT_BODY" > ' + self.sink)
        record, _ = Alerter(cfg).raise_alert("Dev", "where", "detail")
        body = self.sink_contents()
        self.assertIn("sudo sandbroker ack %s" % record["id"], body)

    def test_no_command_configured_means_recorded_but_undelivered(self):
        cfg = make_config(self.tmp)
        record, delivered = Alerter(cfg).raise_alert("Dev", "where", "detail")
        self.assertFalse(delivered)
        # Still on disk. A silent transport must not also lose the alert.
        self.assertEqual([record["id"]], [r["id"] for r in Alerter(cfg).open_alerts()])

    def test_failing_notifier_is_not_delivered(self):
        cfg = make_config(self.tmp, notify_command="exit 3")
        _, delivered = Alerter(cfg).raise_alert("Dev", "where", "detail")
        self.assertFalse(delivered)

    def test_notifier_that_cannot_be_executed_does_not_raise(self):
        # An alert that cannot be delivered must never take down the call that
        # was trying to report a leak.
        cfg = make_config(self.tmp, notify_command=["/nonexistent/notifier"])
        _, delivered = Alerter(cfg).raise_alert("Dev", "where", "detail")
        self.assertFalse(delivered)


class TestAgentTextIsNeverCode(AlertTestCase):
    """`where` and `detail` are written by the agent. If either could reach a
    shell as code, the alarm would be an execution primitive for the thing it
    exists to watch."""

    def test_shell_metacharacters_in_detail_do_not_execute(self):
        canary = os.path.join(self.tmp, "pwned")
        cfg = make_config(self.tmp,
                          notify_command='printf %s "$SANDBROKER_ALERT_DETAIL" > ' + self.sink)
        hostile = '"; touch %s; #' % canary
        Alerter(cfg).raise_alert("Dev", "where", hostile)
        self.assertFalse(os.path.exists(canary), "agent text reached the shell")
        self.assertEqual(hostile, self.sink_contents())

    def test_command_substitution_in_where_does_not_execute(self):
        canary = os.path.join(self.tmp, "pwned")
        cfg = make_config(self.tmp,
                          notify_command='printf %s "$SANDBROKER_ALERT_WHERE" > ' + self.sink)
        hostile = "$(touch %s)" % canary
        Alerter(cfg).raise_alert("Dev", hostile, "detail")
        self.assertFalse(os.path.exists(canary), "agent text reached the shell")
        self.assertEqual(hostile, self.sink_contents())


class TestStickiness(AlertTestCase):
    def test_sweep_repushes_only_stale_alerts(self):
        counter = os.path.join(self.tmp, "count")
        cfg = make_config(self.tmp, notify_command="printf x >> " + counter)
        alerter = Alerter(cfg)
        alerter.raise_alert("Dev", "where", "detail")
        self.assertEqual(1, len(self.read_count(counter)))

        # Just pushed, so the sweeper leaves it alone.
        self.assertEqual(0, alerter.sweep())
        self.assertEqual(1, len(self.read_count(counter)))

        # Age it past the repeat window and it goes out again.
        self.age_alerts(cfg)
        self.assertEqual(1, alerter.sweep())
        self.assertEqual(2, len(self.read_count(counter)))

    def test_acknowledged_alerts_stop_being_pushed(self):
        counter = os.path.join(self.tmp, "count")
        cfg = make_config(self.tmp, notify_command="printf x >> " + counter)
        alerter = Alerter(cfg)
        record, _ = alerter.raise_alert("Dev", "where", "detail")
        alerter.acknowledge(record["id"])
        self.age_alerts(cfg)
        self.assertEqual(0, alerter.sweep())
        self.assertEqual([], alerter.open_alerts())

    def read_count(self, path):
        try:
            with open(path, "r", encoding="utf-8") as fh:
                return fh.read()
        except OSError:
            return ""

    def age_alerts(self, cfg):
        """Backdate every alert past REPEAT_AFTER so the sweeper considers it
        stale, without making the test sleep for fifteen minutes."""
        for name in os.listdir(cfg.alerts_dir):
            path = os.path.join(cfg.alerts_dir, name)
            with open(path, "r", encoding="utf-8") as fh:
                record = json.load(fh)
            record["last_push"] = 0
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(record, fh)


class TestUnreadableIsNotEmpty(AlertTestCase):
    """`sandbroker alerts` reported "no open leak alerts" when run by a user who
    could not read the 0700 broker-owned directory. An alarm that answers "none"
    to a question it did not ask is worse than one that errors."""

    def test_missing_directory_is_genuinely_zero(self):
        # Created on the first alert raised, so absent really does mean none.
        cfg = make_config(self.tmp)
        self.assertEqual([], Alerter(cfg).open_alerts())

    def test_unreadable_directory_raises_instead_of_claiming_none(self):
        if os.geteuid() == 0:
            self.skipTest("root reads through mode bits, so this cannot fail here")
        cfg = make_config(self.tmp, notify_command="true")
        alerter = Alerter(cfg)
        record, _ = alerter.raise_alert("Dev", "where", "detail")
        self.assertEqual([record["id"]], [r["id"] for r in alerter.open_alerts()])

        os.chmod(cfg.alerts_dir, 0o000)
        try:
            with self.assertRaises(AlertsUnreadable):
                alerter.open_alerts()
        finally:
            os.chmod(cfg.alerts_dir, 0o700)

    def test_sweep_cannot_silently_repush_nothing(self):
        if os.geteuid() == 0:
            self.skipTest("root reads through mode bits, so this cannot fail here")
        cfg = make_config(self.tmp, notify_command="true")
        alerter = Alerter(cfg)
        alerter.raise_alert("Dev", "where", "detail")
        os.chmod(cfg.alerts_dir, 0o000)
        try:
            with self.assertRaises(AlertsUnreadable):
                alerter.sweep()
        finally:
            os.chmod(cfg.alerts_dir, 0o700)


class TestRetiredKeys(unittest.TestCase):
    def test_ntfy_keys_are_reported_as_retired(self):
        # The failure this catches is an operator upgrading, keeping their old
        # ntfy config, and never being told the alarm has gone quiet.
        cfg = Config({"vaults": {"Dev": {"vault": "v", "token": "t"}},
                      "ntfy_url": "https://ntfy.example.com/x"}, path="<test>")
        self.assertEqual(["ntfy_url"], cfg.retired)

    def test_a_current_config_reports_nothing_retired(self):
        cfg = Config({"vaults": {"Dev": {"vault": "v", "token": "t"}},
                      "notify_command": "true"}, path="<test>")
        self.assertEqual([], cfg.retired)


if __name__ == "__main__":
    unittest.main(verbosity=0 if "-q" in sys.argv else 1,
                  argv=[a for a in sys.argv if a != "-q"])
