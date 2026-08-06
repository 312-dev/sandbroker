"""Transports.

Two ways in, one Server object behind both:

  unix socket   the default and the only one enabled out of the box. Mode 0660,
                group-owned by `claude-broker`, so group membership IS the
                authorisation. No network, no token, nothing to misconfigure.

  HTTP          off unless `bind` is set, and refused unless that address is
                loopback or tailnet (see config.bind_address). This is the
                "MCP server per vault on the tailnet" surface for hosts that
                actually have a tailnet address of their own.

Both speak the same JSON-RPC. The socket framing is newline-delimited JSON,
which is what MCP stdio uses, so the client-side bridge in `bridge.py` is a
straight byte relay with no parsing.
"""

import grp
import json
import os
import socket
import socketserver
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MAX_LINE = 4 * 1024 * 1024   # a request line cap; commands are capped far lower


def _dispatch_line(server, raw, log):
    """Decode one framed message, hand it to the Server, return bytes to send
    back (or b"" for a notification)."""
    try:
        message = json.loads(raw)
    except ValueError:
        response = {"jsonrpc": "2.0", "id": None,
                    "error": {"code": -32700, "message": "invalid JSON"}}
    else:
        # A batch is legal JSON-RPC. Claude Code does not send them, but
        # answering correctly costs three lines and avoids a silent hang.
        if isinstance(message, list):
            replies = [r for r in (server.handle(m) for m in message) if r]
            if not replies:
                return b""
            return (json.dumps(replies) + "\n").encode("utf-8")
        response = server.handle(message)
    if response is None:
        return b""
    return (json.dumps(response) + "\n").encode("utf-8")


# -- unix socket -----------------------------------------------------------

class _SocketHandler(socketserver.StreamRequestHandler):
    def handle(self):
        server = self.server.mcp_server
        log = self.server.log
        while True:
            try:
                raw = self.rfile.readline(MAX_LINE)
            except OSError:
                return
            if not raw:
                return
            raw = raw.strip()
            if not raw:
                continue
            try:
                out = _dispatch_line(server, raw, log)
            except Exception as exc:                        # noqa: BLE001
                log("dispatch failed: %r" % (exc,))
                return
            if out:
                try:
                    self.wfile.write(out)
                    self.wfile.flush()
                except OSError:
                    return


class _UnixServer(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 32


def serve_unix(mcp_server, path, group, log):
    """Bind the unix socket with the permissions that carry the access control.

    0660 root/daemon:claude-broker means: members of claude-broker may talk to
    the broker, nobody else may. That is the whole auth model, and it is
    enforced by the kernel rather than by anything in this file.
    """
    directory = os.path.dirname(path)
    os.makedirs(directory, mode=0o750, exist_ok=True)
    if os.path.exists(path):
        os.unlink(path)

    # Create the socket with a tight umask, then widen to the group. Doing it in
    # this order means there is no window where the socket is world-writable.
    old_umask = os.umask(0o177)
    try:
        server = _UnixServer(path, _SocketHandler)
    finally:
        os.umask(old_umask)

    try:
        gid = grp.getgrnam(group).gr_gid
    except KeyError:
        log("group %r does not exist; socket stays owner-only" % group)
    else:
        os.chown(path, -1, gid)
        os.chmod(path, 0o660)

    server.mcp_server = mcp_server
    server.log = log
    log("listening on unix:%s (group %s)" % (path, group))
    return server


# -- HTTP (tailnet) --------------------------------------------------------

class _HTTPHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "sandbroker/1.0"

    def log_message(self, fmt, *args):
        self.server.log("http %s" % (fmt % args))

    def do_GET(self):
        # Streamable HTTP allows a GET for a server-initiated SSE stream. This
        # server never initiates anything, so declining is correct and clients
        # fall back to plain request/response.
        self._send_json(405, {"error": "this server only accepts POST /mcp"})

    def do_POST(self):
        if self.path.rstrip("/") not in ("/mcp", ""):
            self._send_json(404, {"error": "not found"})
            return
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            self._send_json(400, {"error": "bad Content-Length"})
            return
        if length <= 0 or length > MAX_LINE:
            self._send_json(400, {"error": "empty or oversized body"})
            return
        body = self.rfile.read(length)
        out = _dispatch_line(self.server.mcp_server, body, self.server.log)
        if not out:
            self.send_response(202)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    def _send_json(self, status, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class _HTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def serve_http(mcp_server, address, port, log):
    server = _HTTPServer((address, port), _HTTPHandler)
    server.mcp_server = mcp_server
    server.log = log
    log("listening on http://%s:%d/mcp" % (address, port))
    return server


# -- run both --------------------------------------------------------------

def run_forever(servers):
    """Serve every listener; each network server gets its own thread and the
    last one runs on the main thread so Ctrl-C and SIGTERM behave."""
    if not servers:
        raise RuntimeError("no listeners configured")
    threads = []
    for server in servers[:-1]:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        threads.append(thread)
    try:
        servers[-1].serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        for server in servers:
            server.shutdown()
            server.server_close()


# -- client-side stdio bridge ----------------------------------------------

def bridge_stdio(socket_path):
    """Relay MCP stdio to the daemon's unix socket.

    Runs as the AGENT's uid, which is the point: it holds no credentials and can
    read no token file. Claude Code speaks stdio to this, this speaks the same
    newline-delimited JSON to the daemon, and the bytes pass through untouched.
    """
    try:
        conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        conn.connect(socket_path)
    except OSError as exc:
        sys.stderr.write(
            "sandbroker: cannot reach the broker at %s (%s).\n"
            "Is the service running, and are you in the claude-broker group?\n"
            % (socket_path, exc.strerror))
        return 1

    def pump_up():
        try:
            while True:
                chunk = sys.stdin.buffer.readline()
                if not chunk:
                    break
                conn.sendall(chunk)
        except OSError:
            pass
        finally:
            try:
                conn.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    thread = threading.Thread(target=pump_up, daemon=True)
    thread.start()
    try:
        while True:
            data = conn.recv(65536)
            if not data:
                break
            sys.stdout.buffer.write(data)
            sys.stdout.buffer.flush()
    except OSError:
        pass
    finally:
        conn.close()
    return 0
