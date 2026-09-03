"""The file queue, which is the only channel a sandboxed client has."""

import json
import os
import shutil
import sys
import tempfile
import threading
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sandbroker import bridge  # noqa: E402
from sandbroker import server as server_mod  # noqa: E402

from test_mcp import build  # noqa: E402
from test_runner import SECRET  # noqa: E402


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


class QueueHarness:
    """A live daemon on a unix socket plus a bridge watching a temp queue."""

    def __init__(self, tmp):
        self.tmp = tmp
        self.base = os.path.join(tmp, "queue")
        self.mcp_server, self.alerter = build(tmp)
        cfg = self.mcp_server.config
        cfg._d["socket_dir"] = os.path.join(tmp, "run")
        self.cfg = cfg
        self.listener = server_mod.serve_unix(
            self.mcp_server, cfg.socket_path("Dev"), "nosuchgroup", lambda *a: None)
        threading.Thread(target=self.listener.serve_forever, daemon=True).start()
        self.stop = threading.Event()
        threading.Thread(
            target=bridge.serve_queues,
            args=(cfg, lambda *a: None, self.stop, self.base),
            daemon=True).start()
        time.sleep(0.2)

    def close(self):
        self.stop.set()
        self.listener.shutdown()
        self.listener.server_close()

    def send(self, message, timeout=15):
        """Act as the sandboxed client: drop a request, wait for the reply."""
        req_dir, resp_dir = bridge.queue_dirs(self.base, "Dev")
        rid = "test-%d" % int(time.time() * 1e6)
        bridge._write_atomic(os.path.join(req_dir, rid + ".json"), message)
        resp = os.path.join(resp_dir, rid + ".json")
        deadline = time.time() + timeout
        while time.time() < deadline:
            if os.path.exists(resp):
                with open(resp, "r", encoding="utf-8") as fh:
                    return json.load(fh)
            time.sleep(0.02)
        raise AssertionError("no reply within %ss" % timeout)


@unittest.skipUnless(HAVE_UNIX, SKIP_REASON)
class TestQueueRoundTrip(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.harness = QueueHarness(self.tmp)

    def tearDown(self):
        self.harness.close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_tools_list_round_trips(self):
        reply = self.harness.send({"jsonrpc": "2.0", "id": 1,
                                   "method": "tools/list"})
        names = sorted(t["name"] for t in reply["result"]["tools"])
        self.assertEqual(["copy", "list_fields", "list_items", "report_leak",
                          "run", "store"], names)

    def test_run_is_redacted_through_the_queue(self):
        """The redaction guarantee must hold on this path too, not just on the
        socket -- this is the path a sandboxed agent actually uses."""
        reply = self.harness.send({
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": "run",
                       "arguments": {"command": 'echo "$TOKEN"',
                                     "secrets": {"TOKEN": "op://Dev/item/credential"}}}})
        data = json.loads(reply["result"]["content"][0]["text"])
        self.assertNotIn(SECRET, data["stdout"])
        self.assertIn("[redacted:TOKEN]", data["stdout"])

    def test_notification_gets_the_no_reply_sentinel(self):
        """A JSON-RPC notification must not be answered. The bridge still writes
        a file so the client is not left polling forever; the client drops it."""
        reply = self.harness.send({"jsonrpc": "2.0",
                                   "method": "notifications/initialized"})
        self.assertTrue(reply.get("__sandbroker_no_reply__"))

    def test_request_file_is_consumed(self):
        self.harness.send({"jsonrpc": "2.0", "id": 3, "method": "ping"})
        req_dir, _ = bridge.queue_dirs(self.harness.base, "Dev")
        self.assertEqual([], [n for n in os.listdir(req_dir) if n.endswith(".json")])


@unittest.skipUnless(HAVE_UNIX, SKIP_REASON)
class TestConcurrency(unittest.TestCase):
    """Every request must get exactly one reply, even under load.

    The original dispatch loop re-listed the queue every 50ms and only deleted a
    request after a worker had opened it, so the same request could be handed to
    two workers. The loser returned without writing a response, silently losing
    the reply. Four MCP servers handshaking at once made that near-certain, and
    it presented as 'three failed, one connected'. Sequential tests never saw it.
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.harness = QueueHarness(self.tmp)

    def tearDown(self):
        self.harness.close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_every_concurrent_request_gets_a_reply(self):
        count = 40
        req_dir, resp_dir = bridge.queue_dirs(self.harness.base, "Dev")
        ids = ["c%03d" % i for i in range(count)]

        # Write them all at once, the way four servers starting together do.
        for rid in ids:
            bridge._write_atomic(os.path.join(req_dir, rid + ".json"),
                                 {"jsonrpc": "2.0", "id": rid, "method": "ping"})

        deadline = time.time() + 45
        missing = set(ids)
        while missing and time.time() < deadline:
            missing = {r for r in missing
                       if not os.path.exists(os.path.join(resp_dir, r + ".json"))}
            if missing:
                time.sleep(0.05)
        self.assertEqual(set(), missing,
                         "%d of %d replies were lost" % (len(missing), count))

    def test_no_request_is_left_behind(self):
        req_dir, resp_dir = bridge.queue_dirs(self.harness.base, "Dev")
        for i in range(15):
            bridge._write_atomic(os.path.join(req_dir, "l%02d.json" % i),
                                 {"jsonrpc": "2.0", "id": i, "method": "ping"})
        deadline = time.time() + 30
        while time.time() < deadline:
            left = [n for n in os.listdir(req_dir)]
            if not left:
                break
            time.sleep(0.05)
        self.assertEqual([], os.listdir(req_dir),
                         "claimed requests were not cleaned up")


@unittest.skipUnless(HAVE_UNIX, SKIP_REASON)
class TestHeartbeat(unittest.TestCase):
    """Without liveness, a client whose bridge is down queues into the void and
    waits out CLIENT_TIMEOUT, which an MCP client renders as 'connecting...'
    forever with no diagnosis. The heartbeat makes that an immediate error."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.harness = QueueHarness(self.tmp)

    def tearDown(self):
        self.harness.close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_running_bridge_is_alive(self):
        deadline = time.time() + 10
        while time.time() < deadline and not bridge.bridge_alive(self.harness.base):
            time.sleep(0.1)
        self.assertTrue(bridge.bridge_alive(self.harness.base))

    def test_absent_heartbeat_reads_as_dead(self):
        self.assertFalse(bridge.bridge_alive(os.path.join(self.tmp, "nowhere")))

    def test_stale_heartbeat_reads_as_dead(self):
        deadline = time.time() + 10
        while time.time() < deadline and not bridge.bridge_alive(self.harness.base):
            time.sleep(0.1)
        path = bridge.heartbeat_path(self.harness.base)
        old = time.time() - (bridge.HEARTBEAT_STALE + 60)
        os.utime(path, (old, old))
        self.assertFalse(bridge.bridge_alive(self.harness.base))


class TestQueuePermissions(unittest.TestCase):
    def test_queue_is_owner_only(self):
        """0700 is the access control: the sandbox drops supplementary groups,
        so uid ownership is the only thing left that still gates access."""
        tmp = tempfile.mkdtemp()
        try:
            req, resp = bridge.ensure_queue(os.path.join(tmp, "q"), "Dev")
            for path in (req, resp):
                mode = os.stat(path).st_mode & 0o777
                self.assertEqual(0o700, mode, "%s is %o" % (path, mode))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


@unittest.skipUnless(HAVE_UNIX, SKIP_REASON)
class TestBrokerDown(unittest.TestCase):
    def test_unreachable_socket_returns_an_error_not_a_hang(self):
        tmp = tempfile.mkdtemp()
        try:
            mcp_server, _ = build(tmp)
            cfg = mcp_server.config
            cfg._d["socket_dir"] = os.path.join(tmp, "nowhere")
            os.makedirs(cfg._d["socket_dir"], exist_ok=True)
            stop = threading.Event()
            base = os.path.join(tmp, "queue")
            threading.Thread(target=bridge.serve_queues,
                             args=(cfg, lambda *a: None, stop, base),
                             daemon=True).start()
            time.sleep(0.2)
            req_dir, resp_dir = bridge.queue_dirs(base, "Dev")
            rid = "down-%d" % int(time.time() * 1e6)
            bridge._write_atomic(os.path.join(req_dir, rid + ".json"),
                                 {"jsonrpc": "2.0", "id": 1, "method": "ping"})
            resp = os.path.join(resp_dir, rid + ".json")
            deadline = time.time() + 10
            while time.time() < deadline and not os.path.exists(resp):
                time.sleep(0.02)
            self.assertTrue(os.path.exists(resp), "no error reply written")
            with open(resp, "r", encoding="utf-8") as fh:
                self.assertIn("unreachable", json.load(fh)["error"]["message"])
            stop.set()
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
