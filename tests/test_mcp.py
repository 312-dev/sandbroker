"""Protocol surface, leak alerting, and the socket transport."""

import json
import os
import shutil
import socket
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sandbroker import server as server_mod  # noqa: E402
from sandbroker.alert import Alerter  # noqa: E402
from sandbroker.mcp import Server  # noqa: E402

from test_runner import FakeVault, make_config, SECRET  # noqa: E402


def _unix_sockets_available():
    """Some sandboxes (Claude Code's, for one) block socket(AF_UNIX) at the
    seccomp layer. These tests exercise a real socket, so skip rather than fail:
    a red suite that means "wrong environment" trains you to ignore red suites."""
    import socket
    try:
        socket.socket(socket.AF_UNIX, socket.SOCK_STREAM).close()
        return True
    except OSError:
        return False


HAVE_UNIX = _unix_sockets_available()
SKIP_REASON = "AF_UNIX is blocked in this environment (sandbox seccomp)"


class StubAlerter(Alerter):
    """Records pushes instead of sending them, so the suite never touches ntfy."""

    def __init__(self, config, delivered=True):
        Alerter.__init__(self, config)
        self.sent = []
        self._delivered = delivered

    def push(self, title, body, priority="urgent", tags="rotating_light"):
        self.sent.append((title, body))
        return self._delivered


def build(tmpdir, delivered=True, vault=None):
    cfg = make_config(alerts_dir=os.path.join(tmpdir, "alerts"))
    alerter = StubAlerter(cfg, delivered=delivered)
    return Server(vault or FakeVault(), cfg, alerter), alerter


def call(server, name, arguments=None, msg_id=1):
    response = server.handle({"jsonrpc": "2.0", "id": msg_id,
                              "method": "tools/call",
                              "params": {"name": name,
                                         "arguments": arguments or {}}})
    return response["result"]


def payload(result):
    return json.loads(result["content"][0]["text"])


class TestProtocol(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.server, self.alerter = build(self.tmp)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_initialize_advertises_tools(self):
        result = self.server.handle({"jsonrpc": "2.0", "id": 1,
                                     "method": "initialize",
                                     "params": {"protocolVersion": "2025-06-18"}})
        self.assertIn("tools", result["result"]["capabilities"])
        self.assertEqual("2025-06-18", result["result"]["protocolVersion"])
        self.assertIn("sandbroker-dev", result["result"]["serverInfo"]["name"])

    def test_initialize_echoes_client_protocol_version(self):
        result = self.server.handle({"jsonrpc": "2.0", "id": 1,
                                     "method": "initialize",
                                     "params": {"protocolVersion": "2024-11-05"}})
        self.assertEqual("2024-11-05", result["result"]["protocolVersion"])

    def test_notifications_get_no_reply(self):
        # Replying to a notification is a protocol violation and hangs clients.
        self.assertIsNone(self.server.handle(
            {"jsonrpc": "2.0", "method": "notifications/initialized"}))

    def test_tools_list_has_exactly_the_four_tools(self):
        result = self.server.handle({"jsonrpc": "2.0", "id": 1,
                                     "method": "tools/list"})
        names = sorted(t["name"] for t in result["result"]["tools"])
        self.assertEqual(["list_fields", "list_items", "report_leak", "run"], names)

    def test_unknown_method_is_an_error(self):
        result = self.server.handle({"jsonrpc": "2.0", "id": 1, "method": "nope"})
        self.assertEqual(-32601, result["error"]["code"])

    def test_resources_and_prompts_probe_cleanly(self):
        for method, key in (("resources/list", "resources"),
                            ("prompts/list", "prompts")):
            result = self.server.handle({"jsonrpc": "2.0", "id": 1,
                                         "method": method})
            self.assertEqual([], result["result"][key])

    def test_ping(self):
        result = self.server.handle({"jsonrpc": "2.0", "id": 7, "method": "ping"})
        self.assertEqual({}, result["result"])


class TestTools(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.server, self.alerter = build(self.tmp)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_run_returns_scrubbed_output(self):
        data = payload(call(self.server, "run", {
            "command": 'echo "$TOKEN"',
            "secrets": {"TOKEN": "op://Dev/item/credential"}}))
        self.assertEqual(0, data["exit_code"])
        self.assertNotIn(SECRET, data["stdout"])
        self.assertEqual(1, data["redactions"])

    def test_run_surfaces_a_bad_reference_as_a_tool_error(self):
        result = call(self.server, "run", {
            "command": "true", "secrets": {"T": "op://Dev/missing/credential"}})
        self.assertTrue(result.get("isError"))

    def test_unknown_tool_is_a_tool_error(self):
        self.assertTrue(call(self.server, "does_not_exist").get("isError"))

    def test_list_fields_requires_an_item(self):
        self.assertTrue(call(self.server, "list_fields", {}).get("isError"))


class TestLeakAlerting(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.server, self.alerter = build(self.tmp)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_report_leak_pushes_and_persists(self):
        data = payload(call(self.server, "report_leak", {
            "where": "GET /v1/session response body",
            "detail": "looks like a live bearer token"}))
        self.assertTrue(data["delivered"])
        self.assertTrue(data["repeating"])
        self.assertEqual(1, len(self.alerter.sent))
        self.assertEqual(1, len(self.alerter.open_alerts()))

    def test_report_leak_requires_where(self):
        self.assertTrue(call(self.server, "report_leak", {}).get("isError"))

    def test_undeliverable_alert_tells_the_agent_to_speak_up(self):
        server, alerter = build(self.tmp, delivered=False)
        data = payload(call(server, "report_leak", {"where": "somewhere"}))
        self.assertFalse(data["delivered"])
        self.assertIn("could NOT be delivered", data["message"])

    def test_alert_repeats_until_acknowledged(self):
        call(self.server, "report_leak", {"where": "x"})
        record = self.alerter.open_alerts()[0]

        # Nothing to do while it is fresh.
        self.assertEqual(0, self.alerter.sweep())

        record["last_push"] = 0
        self.alerter._write(record)
        self.assertEqual(1, self.alerter.sweep())
        self.assertEqual(2, len(self.alerter.sent))

        self.alerter.acknowledge(record["id"])
        self.assertEqual([], self.alerter.open_alerts())
        self.assertEqual(0, self.alerter.sweep())

    def test_no_tool_can_acknowledge(self):
        """Acknowledging must require host access. An agent that could silence
        its own alarm makes the alarm worthless."""
        names = {t["name"] for t in
                 self.server.handle({"jsonrpc": "2.0", "id": 1,
                                     "method": "tools/list"})["result"]["tools"]}
        self.assertNotIn("ack", names)
        self.assertNotIn("acknowledge", names)


@unittest.skipUnless(HAVE_UNIX, SKIP_REASON)
class TestSocketTransport(unittest.TestCase):
    def test_round_trip_over_the_unix_socket(self):
        tmp = tempfile.mkdtemp()
        try:
            server_obj, _ = build(tmp)
            path = os.path.join(tmp, "run", "dev.sock")
            listener = server_mod.serve_unix(server_obj, path, "nosuchgroup",
                                             lambda *a: None)
            thread = threading.Thread(target=listener.serve_forever, daemon=True)
            thread.start()
            try:
                conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                conn.connect(path)
                conn.sendall(json.dumps({"jsonrpc": "2.0", "id": 1,
                                         "method": "tools/list"}).encode() + b"\n")
                data = conn.makefile("rb").readline()
                conn.close()
                names = sorted(t["name"] for t in
                               json.loads(data)["result"]["tools"])
                self.assertIn("run", names)
            finally:
                listener.shutdown()
                listener.server_close()
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_socket_is_not_world_accessible(self):
        tmp = tempfile.mkdtemp()
        try:
            server_obj, _ = build(tmp)
            path = os.path.join(tmp, "run", "dev.sock")
            listener = server_mod.serve_unix(server_obj, path, "nosuchgroup",
                                             lambda *a: None)
            try:
                mode = os.stat(path).st_mode & 0o777
                self.assertEqual(0, mode & 0o007, "socket must not be world-usable")
            finally:
                listener.server_close()
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
