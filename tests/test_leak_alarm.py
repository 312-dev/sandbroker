"""The leak-alarm hook: does it fire, does it stay quiet, and does it stay shut.

Three properties matter here and they pull against each other. It has to catch
a real credential, it has to not cry wolf on documentation and placeholders, and
it must never write the credential it found into anything it produces. The last
one is the easiest to regress and the worst to ship.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOOK_DIR = os.path.join(ROOT, "plugin-leak-alarm", "hooks")
sys.path.insert(0, HOOK_DIR)

import leak_alarm  # noqa: E402

# Shaped like the real thing, generated for this file, live nowhere.
GITHUB = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
GOOGLE = "ya29." + "a0AfB1CdEfGhIjKlMnOpQrStUvWxYz0123456789"
ANTHROPIC = "sk-ant-" + "api03-Zz9Yy8Xx7Ww6Vv5Uu4Tt3Ss2Rr1Qq0Pp"
AWS = "AKIA" + "QRSTUVWX2345YZAB"


class HookTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="leak-alarm-")
        # Point every piece of on-disk state at the sandbox, so the suite never
        # reads the developer's real config or writes their real alerts.
        self._saved = {k: os.environ.get(k) for k in
                       ("XDG_CONFIG_HOME", "XDG_STATE_HOME", "SANDBROKER_CONFIG",
                        "LEAK_ALARM_NOTIFY")}
        os.environ["XDG_CONFIG_HOME"] = os.path.join(self.tmp, "config")
        os.environ["XDG_STATE_HOME"] = os.path.join(self.tmp, "state")
        os.environ["SANDBROKER_CONFIG"] = os.path.join(self.tmp, "no-sandbroker.json")
        os.environ.pop("LEAK_ALARM_NOTIFY", None)
        self._reload()

    def tearDown(self):
        for key, value in self._saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        self._reload()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _reload(self):
        """Module-level paths are computed at import, so re-resolve them."""
        if sys.version_info >= (3, 4):
            import importlib
            importlib.reload(leak_alarm)

    def read(self, path):
        with open(path, "r", encoding="utf-8") as fh:
            return fh.read()

    def write_config(self, **data):
        path = os.path.join(os.environ["XDG_CONFIG_HOME"], "leak-alarm")
        os.makedirs(path, exist_ok=True)
        with open(os.path.join(path, "config.json"), "w", encoding="utf-8") as fh:
            json.dump(data, fh)
        self._reload()

    def run_hook(self, event):
        """Drive the hook as Claude Code does: JSON on stdin, JSON on stdout."""
        proc = subprocess.run(
            [sys.executable, os.path.join(HOOK_DIR, "leak_alarm.py")],
            input=json.dumps(event).encode("utf-8"),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=dict(os.environ))
        out = proc.stdout.decode("utf-8").strip()
        return (json.loads(out) if out else None), proc.stderr.decode("utf-8")

    def post(self, response, **extra):
        event = {"hook_event_name": "PostToolUse", "tool_name": "Bash",
                 "session_id": "test-session", "tool_response": response}
        event.update(extra)
        return event

    def pre(self, tool_input, **extra):
        event = {"hook_event_name": "PreToolUse", "tool_name": "Write",
                 "session_id": "test-session", "tool_input": tool_input}
        event.update(extra)
        return event


class TestDetection(HookTestCase):
    def test_credential_in_tool_output_is_reported(self):
        out, _ = self.run_hook(self.post('{"access_token": "%s"}' % GOOGLE))
        self.assertIsNotNone(out)
        self.assertIn("google-oauth-token", out["systemMessage"])

    def test_several_formats_are_recognised(self):
        for value, expected in ((GITHUB, "github-pat-classic"),
                                (ANTHROPIC, "anthropic-api-key"),
                                (AWS, "aws-access-key-id")):
            out, _ = self.run_hook(self.post("token=%s" % value,
                                             session_id="s-%s" % expected))
            self.assertIsNotNone(out, "%s went unnoticed" % expected)
            self.assertIn(expected, out["systemMessage"])

    def test_private_key_block_is_reported(self):
        out, _ = self.run_hook(self.post("-----BEGIN RSA PRIVATE KEY-----\nMIIE"))
        self.assertIsNotNone(out)
        self.assertIn("private-key-block", out["systemMessage"])

    def test_failure_payloads_are_scanned_too(self):
        # An error body quoting the request back is the likeliest place for a
        # token to surface, so PostToolUseFailure must not be a blind spot.
        event = {"hook_event_name": "PostToolUseFailure", "tool_name": "Bash",
                 "session_id": "fail", "tool_error": "401 for token %s" % GITHUB}
        out, _ = self.run_hook(event)
        self.assertIsNotNone(out)
        self.assertIn("github-pat-classic", out["systemMessage"])

    def test_ordinary_output_is_silent(self):
        for benign in ("All tests passed", "commit a94f3c2b1d", "user_id: 88213",
                       '{"status": "ok", "count": 42}', ""):
            out, _ = self.run_hook(self.post(benign, session_id="benign"))
            self.assertIsNone(out, "false positive on %r" % benign)


class TestNoiseControl(HookTestCase):
    def test_placeholders_do_not_fire(self):
        for placeholder in ("ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
                            "AKIAIOSFODNN7EXAMPLE",
                            "sk-ant-YOUR_API_KEY_HERE_PLEASE_REPLACE",
                            "ya29.<your-access-token-goes-here>"):
            out, _ = self.run_hook(self.post("key = %s" % placeholder,
                                             session_id="ph"))
            self.assertIsNone(out, "placeholder %r paged a human" % placeholder)

    def test_broker_redaction_markers_do_not_fire(self):
        out, _ = self.run_hook(self.post("Authorization: Bearer [redacted:TOKEN]"))
        self.assertIsNone(out)

    def test_reading_the_rules_file_does_not_trip_the_alarm(self):
        # The ruleset is a file full of credential patterns. An alarm that goes
        # off when you read its own source is an alarm people switch off.
        rules = os.path.join(ROOT, "plugin-leak-alarm", "rules", "patterns.json")
        with open(rules, "r", encoding="utf-8") as fh:
            body = fh.read()
        event = self.post(body, tool_name="Read")
        event["tool_input"] = {"file_path": rules}
        out, _ = self.run_hook(event)
        self.assertIsNone(out)

    def test_the_same_credential_pages_once_per_session(self):
        first, _ = self.run_hook(self.post("t=%s" % GITHUB, session_id="dedup"))
        second, _ = self.run_hook(self.post("t=%s" % GITHUB, session_id="dedup"))
        self.assertIsNotNone(first)
        self.assertIsNone(second, "repeat sighting paged a second time")

    def test_a_disabled_pattern_stays_quiet(self):
        self.write_config(disabled=["github-pat-classic"])
        out, _ = self.run_hook(self.post("t=%s" % GITHUB, session_id="disabled"))
        self.assertIsNone(out)


class TestNeverEchoesTheSecret(HookTestCase):
    """The one property that must never regress: a tool that reports leaks by
    quoting them has become a way to leak them."""

    def test_the_value_is_absent_from_every_output_channel(self):
        self.write_config(notify_command="cat > %s" % os.path.join(self.tmp, "note"))
        event = self.post('{"access_token": "%s"}' % GOOGLE, session_id="echo")
        out, stderr = self.run_hook(event)
        self.assertIsNotNone(out)

        surfaces = {
            "hook stdout": json.dumps(out),
            "hook stderr": stderr,
            "notifier stdin": self.read(os.path.join(self.tmp, "note")),
        }
        for name, blob in surfaces.items():
            self.assertNotIn(GOOGLE, blob, "credential leaked into %s" % name)
            # The distinctive body, not just the prefix, must be gone too.
            self.assertNotIn(GOOGLE.split(".", 1)[1], blob,
                             "credential body leaked into %s" % name)

    def test_the_value_is_absent_from_the_recorded_alert(self):
        self.run_hook(self.post("t=%s" % GITHUB, session_id="record"))
        alerts = os.path.join(os.environ["XDG_STATE_HOME"], "leak-alarm", "alerts")
        blobs = [self.read(os.path.join(alerts, n)) for n in os.listdir(alerts)]
        self.assertTrue(blobs, "no alert was recorded")
        for blob in blobs:
            self.assertNotIn(GITHUB, blob)

    def test_findings_carry_a_stable_non_reversible_id(self):
        one = leak_alarm.fingerprint(GITHUB)
        self.assertEqual(one, leak_alarm.fingerprint(GITHUB))
        self.assertNotEqual(one, leak_alarm.fingerprint(GOOGLE))
        self.assertEqual(12, len(one))
        self.assertNotIn(one, GITHUB)


class TestBlockingHalf(HookTestCase):
    def test_a_credential_in_tool_input_is_denied(self):
        out, _ = self.run_hook(self.pre({"file_path": "/tmp/x",
                                         "content": "TOKEN=%s" % GITHUB}))
        self.assertIsNotNone(out)
        decision = out["hookSpecificOutput"]
        self.assertEqual("PreToolUse", decision["hookEventName"])
        self.assertEqual("deny", decision["permissionDecision"])
        self.assertIn("github-pat-classic", decision["permissionDecisionReason"])
        self.assertNotIn(GITHUB, json.dumps(out))

    def test_clean_input_is_allowed_through_silently(self):
        out, _ = self.run_hook(self.pre({"command": "ls -la /etc"}))
        self.assertIsNone(out)

    def test_blocking_can_be_turned_off_but_still_alerts(self):
        self.write_config(block_tool_input=False)
        out, _ = self.run_hook(self.pre({"content": GITHUB}))
        self.assertIsNotNone(out)
        self.assertNotIn("hookSpecificOutput", out)
        self.assertIn("github-pat-classic", out["systemMessage"])

    def test_every_attempt_is_denied_not_just_the_first(self):
        # Dedup is right for reporting and wrong for blocking: the fortieth
        # attempt to move a credential deserves the same refusal as the first.
        for _ in range(3):
            out, _ = self.run_hook(self.pre({"content": GITHUB}))
            self.assertEqual("deny", out["hookSpecificOutput"]["permissionDecision"])


class TestNotification(HookTestCase):
    def test_notifier_receives_the_alert_and_marks_it_delivered(self):
        sink = os.path.join(self.tmp, "sink")
        self.write_config(notify_command="cat > %s" % sink)
        out, _ = self.run_hook(self.post("t=%s" % GOOGLE, session_id="notify"))
        payload = json.loads(self.read(sink))
        self.assertEqual(["google-oauth-token"], payload["patterns"])
        self.assertNotIn("NOT DELIVERED", out["systemMessage"])

    def test_the_recorded_alert_knows_it_was_delivered(self):
        # The recorded copy is what `leak-alarm alerts` reads back. Writing it
        # before the notifier runs and never updating it made every delivered
        # alert display as NOT DELIVERED.
        self.write_config(notify_command="cat > %s" % os.path.join(self.tmp, "sink"))
        self.run_hook(self.post("t=%s" % GOOGLE, session_id="delivered"))
        alerts = os.path.join(os.environ["XDG_STATE_HOME"], "leak-alarm", "alerts")
        records = [json.loads(self.read(os.path.join(alerts, n)))
                   for n in os.listdir(alerts)]
        self.assertEqual([True], [r.get("delivered") for r in records])

    def test_the_recorded_alert_knows_it_was_not_delivered(self):
        self.write_config(notify_command="exit 1")
        self.run_hook(self.post("t=%s" % GOOGLE, session_id="undelivered"))
        alerts = os.path.join(os.environ["XDG_STATE_HOME"], "leak-alarm", "alerts")
        records = [json.loads(self.read(os.path.join(alerts, n)))
                   for n in os.listdir(alerts)]
        self.assertEqual([False], [r.get("delivered") for r in records])

    def test_missing_notifier_says_so_in_the_message(self):
        out, _ = self.run_hook(self.post("t=%s" % GOOGLE, session_id="nonotify"))
        self.assertIn("NOT DELIVERED", out["systemMessage"])

    def test_agent_text_cannot_reach_the_notifier_shell(self):
        # Everything in an alert is derived from tool traffic, which an agent
        # controls. None of it may be parsed as code.
        canary = os.path.join(self.tmp, "pwned")
        self.write_config(
            notify_command='printf %s "$SANDBROKER_ALERT_WHERE" > /dev/null')
        event = self.post("t=%s" % GITHUB, session_id="inject")
        event["tool_name"] = '"; touch %s; #' % canary
        self.run_hook(event)
        self.assertFalse(os.path.exists(canary), "tool-supplied text reached a shell")

    def test_a_failing_notifier_does_not_break_the_hook(self):
        self.write_config(notify_command="exit 7")
        out, _ = self.run_hook(self.post("t=%s" % GOOGLE, session_id="failnotify"))
        self.assertIn("NOT DELIVERED", out["systemMessage"])

    def test_sandbroker_notifier_is_inherited_when_present(self):
        sink = os.path.join(self.tmp, "inherited")
        broker = os.path.join(self.tmp, "sandbroker.json")
        with open(broker, "w", encoding="utf-8") as fh:
            json.dump({"notify_command": "cat > %s" % sink}, fh)
        os.environ["SANDBROKER_CONFIG"] = broker
        out, _ = self.run_hook(self.post("t=%s" % AWS, session_id="inherit"))
        self.assertTrue(os.path.exists(sink), "did not inherit sandbroker's notifier")
        self.assertNotIn("NOT DELIVERED", out["systemMessage"])


class TestNeverBreaksTheSession(HookTestCase):
    def test_malformed_stdin_exits_clean(self):
        proc = subprocess.run(
            [sys.executable, os.path.join(HOOK_DIR, "leak_alarm.py")],
            input=b"not json at all", stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, env=dict(os.environ))
        self.assertEqual(0, proc.returncode)
        self.assertEqual(b"", proc.stdout.strip())

    def test_empty_event_exits_clean(self):
        out, _ = self.run_hook({})
        self.assertIsNone(out)

    def test_a_broken_user_pattern_is_skipped_not_fatal(self):
        self.write_config(extra_patterns=[{"name": "bad", "regex": "([unclosed"}])
        out, _ = self.run_hook(self.post("t=%s" % GITHUB, session_id="badregex"))
        self.assertIsNotNone(out, "one bad user regex disabled the whole hook")

    def test_a_huge_payload_is_bounded(self):
        out, _ = self.run_hook(self.post("x" * (leak_alarm.SCAN_LIMIT * 2),
                                         session_id="huge"))
        self.assertIsNone(out)


if __name__ == "__main__":
    unittest.main(verbosity=0 if "-q" in sys.argv else 1,
                  argv=[a for a in sys.argv if a != "-q"])
