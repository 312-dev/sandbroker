"""A file queue in /tmp, for clients that cannot open a unix socket.

WHY THIS EXISTS
---------------
Claude Code can run inside a bubblewrap sandbox, and it spawns its MCP servers
inside that sandbox too. Four separate properties of that sandbox each
independently break a unix socket:

    apply-seccomp     socket(AF_UNIX, ...) returns EPERM
    --ro-bind / /     the socket inode is read-only, so connect() would fail
    --unshare-net     host loopback is a different loopback, so TCP is out
    --unshare-user    supplementary groups collapse to `nogroup`, so the
                      claude-broker membership that authorises the socket is gone

One thing does survive: `--bind /tmp /tmp`. The sandbox shares the host's /tmp,
and the sandboxed process is still uid gray. So a directory in /tmp owned by
that uid, mode 0700, is both reachable and correctly access-controlled -- the
same person, reached through the only door left open.

HOW IT WORKS
------------
    /tmp/sandbroker-bridge/<vault>/req/<id>.json     client writes a JSON-RPC message
    /tmp/sandbroker-bridge/<vault>/resp/<id>.json    bridge writes the reply

Writes are tmp+rename, so a reader never sees a partial file. The bridge relays
each request to that vault's unix socket and writes the reply back.

WHAT IT DOES NOT CHANGE
-----------------------
The bridge holds no credentials and makes no decisions. It moves bytes between a
directory only uid gray can open and a socket only claude-broker can open, both
of which that user already had. Nothing here widens access: a process that can
write the queue could have talked to the socket directly if it were not
sandboxed.
"""

import json
import os
import socket
import sys
import threading
import time
import uuid

DEFAULT_BASE = os.environ.get("SANDBROKER_BRIDGE_DIR", "/tmp/sandbroker-bridge")

POLL_INTERVAL = 0.05
# Generous because `run` may legitimately take max_timeout (default 600s) plus
# the command's own startup. Better to wait than to abandon a live request.
CLIENT_TIMEOUT = 900.0

# handle() returns None for a JSON-RPC notification, which must not be answered.
# The bridge still writes a file so the client is never left polling for a reply
# that is never coming; the client recognises this and emits nothing.
NO_REPLY = {"__sandbroker_no_reply__": True}


def queue_dirs(base, vault):
    root = os.path.join(base, vault.lower())
    return os.path.join(root, "req"), os.path.join(root, "resp")


def ensure_queue(base, vault):
    """Create the queue owner-only.

    0700 is the access control. The sandboxed client runs as the same uid, so
    ownership lets it in; every other user on the box is excluded, matching what
    the socket's group check would have done.
    """
    req, resp = queue_dirs(base, vault)
    for path in (req, resp):
        os.makedirs(path, mode=0o700, exist_ok=True)
        try:
            os.chmod(path, 0o700)
        except OSError:
            pass
    return req, resp


def _write_atomic(path, payload):
    tmp = "%s.%s.tmp" % (path, os.getpid())
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(payload, fh)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)      # readers only ever glob *.json


# -- client side (runs sandboxed, as the agent) ----------------------------

def client_stdio(base, vault, log=None):
    """Speak MCP stdio to the client, relay each message through the queue.

    One thread per message: Claude Code may have a slow `run` in flight while it
    sends a `tools/list`, and serialising those would stall the session. JSON-RPC
    matches replies by id, so out-of-order returns are fine.
    """
    log = log or (lambda *a: None)
    try:
        req_dir, resp_dir = ensure_queue(base, vault)
    except OSError as exc:
        sys.stderr.write("sandbroker: cannot use the bridge queue at %s (%s)\n"
                         % (base, exc.strerror))
        return 1

    out_lock = threading.Lock()
    threads = []

    def relay(raw):
        try:
            message = json.loads(raw)
        except ValueError:
            return
        rid = uuid.uuid4().hex
        try:
            _write_atomic(os.path.join(req_dir, rid + ".json"), message)
        except OSError as exc:
            log("queue write failed: %s" % exc)
            return

        resp_path = os.path.join(resp_dir, rid + ".json")
        deadline = time.time() + CLIENT_TIMEOUT
        while time.time() < deadline:
            if os.path.exists(resp_path):
                try:
                    with open(resp_path, "r", encoding="utf-8") as fh:
                        reply = json.load(fh)
                except (OSError, ValueError):
                    time.sleep(POLL_INTERVAL)      # writer may still be renaming
                    continue
                try:
                    os.unlink(resp_path)
                except OSError:
                    pass
                if reply.get("__sandbroker_no_reply__"):
                    return
                with out_lock:
                    sys.stdout.write(json.dumps(reply) + "\n")
                    sys.stdout.flush()
                return
            time.sleep(POLL_INTERVAL)

        # Timing out silently would hang the client forever. A JSON-RPC error
        # lets the agent see what happened and retry.
        with out_lock:
            sys.stdout.write(json.dumps({
                "jsonrpc": "2.0", "id": message.get("id"),
                "error": {"code": -32000,
                          "message": "sandbroker bridge timed out; is "
                                     "`sandbroker bridge` running on the host?"},
            }) + "\n")
            sys.stdout.flush()

    while True:
        line = sys.stdin.buffer.readline()
        if not line:
            break
        line = line.strip()
        if not line:
            continue
        thread = threading.Thread(target=relay, args=(line,), daemon=True)
        thread.start()
        threads.append(thread)
        threads = [t for t in threads if t.is_alive()]
    return 0


# -- host side (runs unsandboxed, as the human) ----------------------------

def _expects_reply(message):
    """JSON-RPC: a message with no `id` is a notification and gets no response.

    This has to be decided from the REQUEST, not by waiting to see whether one
    arrives. The daemon correctly stays silent and holds the connection open for
    more input, so a bridge that waited would block until its timeout on every
    `notifications/initialized` -- which is the first thing every MCP client
    sends after initialize.
    """
    return not (isinstance(message, dict) and "id" not in message)


def _to_socket(socket_path, message, timeout=900.0):
    conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    conn.settimeout(timeout)
    try:
        conn.connect(socket_path)
        conn.sendall(json.dumps(message).encode("utf-8") + b"\n")
        if not _expects_reply(message):
            return NO_REPLY
        buf = b""
        while b"\n" not in buf:
            chunk = conn.recv(65536)
            if not chunk:
                break
            buf += chunk
    finally:
        conn.close()
    line = buf.decode("utf-8", "replace").strip()
    if not line:
        return NO_REPLY
    return json.loads(line)


def serve_queues(config, log, stop=None, base=None):
    """Watch every vault's queue and relay to its socket. Blocks.

    `base` is a parameter rather than a module constant so tests can point it at
    a temp directory: a suite that quietly writes the real /tmp queue would both
    disturb a running bridge and pass for the wrong reason.
    """
    base = base or DEFAULT_BASE
    vaults = sorted(config.vaults)
    for vault in vaults:
        ensure_queue(base, vault)
    log("bridging %s via %s" % (", ".join(vaults), base))

    def handle(vault, req_path, resp_path):
        try:
            with open(req_path, "r", encoding="utf-8") as fh:
                message = json.load(fh)
        except (OSError, ValueError):
            _safe_unlink(req_path)
            return
        _safe_unlink(req_path)
        try:
            reply = _to_socket(config.socket_path(vault), message)
        except (OSError, ValueError) as exc:
            reply = {"jsonrpc": "2.0", "id": message.get("id"),
                     "error": {"code": -32000,
                               "message": "broker unreachable: %s"
                                          % (getattr(exc, "strerror", None) or exc)}}
        try:
            _write_atomic(resp_path, reply)
        except OSError as exc:
            log("could not write reply: %s" % exc)

    while stop is None or not stop.is_set():
        idle = True
        for vault in vaults:
            req_dir, resp_dir = queue_dirs(base, vault)
            try:
                names = os.listdir(req_dir)
            except OSError:
                # /tmp cleaners exist. Rebuild and carry on rather than dying.
                try:
                    ensure_queue(base, vault)
                except OSError:
                    pass
                continue
            for name in names:
                if not name.endswith(".json"):
                    continue
                idle = False
                rid = name[:-len(".json")]
                threading.Thread(
                    target=handle,
                    args=(vault, os.path.join(req_dir, name),
                          os.path.join(resp_dir, rid + ".json")),
                    daemon=True,
                ).start()
        time.sleep(POLL_INTERVAL if not idle else POLL_INTERVAL * 4)


def _safe_unlink(path):
    try:
        os.unlink(path)
    except OSError:
        pass
