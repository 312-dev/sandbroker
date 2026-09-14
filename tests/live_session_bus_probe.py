#!/usr/bin/env python3
"""Drive a RUNNING daemon and count the session-bus daemons its cgroup gains.

test_childenv.py proves the broker sets DBUS_SESSION_BUS_ADDRESS and that a
client obeying go-dbus's rule then launches nothing. This proves the same thing
against the `op` actually installed, which is the part a stub cannot vouch for.

Not named test_* on purpose: tests/run.sh must stay runnable on a bare box, and
this needs a live daemon, a real vault and membership of claude-broker. Run it
by hand after a deploy.

    python3 tests/live_session_bus_probe.py /opt/sandbroker/run/dev.sock \
            sandbroker@Dev.service 20

Pick a vault nothing else is using. The count is scoped to one unit's cgroup, so
a second vault's traffic does not disturb it, but a second client on the SAME
vault will. list_items is metadata only -- it cannot return a field value -- so
this is safe to point at a production vault.
"""

import json
import os
import socket
import sys
import time

CGROUP = "/sys/fs/cgroup/system.slice/system-sandbroker.slice/%s/cgroup.procs"


def bus_daemons(unit):
    """PIDs of session-bus daemons inside this vault's cgroup.

    Read from the cgroup rather than by scanning for the parent process: the
    daemons call setsid() and reparent to pid 1, so ancestry says nothing about
    which vault caused them. Cgroup membership survives that and is what makes
    one vault countable while another is busy.
    """
    found = set()
    try:
        with open(CGROUP % unit) as fh:
            pids = fh.read().split()
    except OSError:
        sys.exit("no cgroup for %s -- is the unit running?" % unit)
    for pid in pids:
        try:
            with open("/proc/%s/cmdline" % pid, "rb") as fh:
                cmd = fh.read().replace(b"\0", b" ").decode("utf-8", "replace")
        except OSError:
            continue
        if "dbus-daemon" in cmd and "--session" in cmd:
            found.add(int(pid))
    return found


def request(sock, mid, method, params):
    sock.sendall((json.dumps({"jsonrpc": "2.0", "id": mid, "method": method,
                              "params": params}) + "\n").encode())
    buf = b""
    while not buf.endswith(b"\n"):
        chunk = sock.recv(1 << 20)
        if not chunk:
            sys.exit("daemon closed the connection")
        buf += chunk
    return json.loads(buf)


def main(argv):
    if len(argv) < 3:
        sys.exit(__doc__)
    path, unit = argv[1], argv[2]
    calls = int(argv[3]) if len(argv) > 3 else 20

    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(path)
    request(sock, 0, "initialize", {})

    before = bus_daemons(unit)
    print("before: %d session-bus daemon(s) in %s" % (len(before), unit))

    started = time.time()
    for i in range(calls):
        reply = request(sock, i + 1, "tools/call",
                        {"name": "list_items", "arguments": {}})
        if "error" in reply:
            sys.exit("call %d failed: %s" % (i + 1, reply["error"]))
    elapsed = time.time() - started

    # dbus-launch's daemon appears a beat after the op process that caused it.
    time.sleep(1.5)
    leaked = sorted(bus_daemons(unit) - before)

    print("after:  %d  (%d calls in %.1fs)"
          % (len(before) + len(leaked), calls, elapsed))
    if leaked:
        print("LEAKING: %d new daemon(s), pids %s" % (len(leaked), leaked))
        return 1
    print("FLAT: no session bus was launched")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
