"""Command line: serve a vault, bridge to one, sweep alerts, acknowledge one.

    sandbroker serve   --vault Dev     run the daemon (as the broker user)
    sandbroker connect --vault Dev     stdio bridge for Claude Code (as you)
    sandbroker sweep                   re-push unacknowledged leak alerts
    sandbroker ack <id>                close a leak alert
    sandbroker doctor                  check the install without touching a secret
"""

import argparse
import json
import os
import socket
import sys
import time

from . import bridge
from . import config as config_mod
from . import locks
from . import mcp
from . import server as server_mod
from .alert import Alerter, AlertsUnreadable
from .keeper import Vault as KeeperVault
from .mcp import Server
from .onepassword import Vault as OnePasswordVault


def _log(stream=sys.stderr):
    def log(message):
        stream.write("%s sandbroker: %s\n"
                     % (time.strftime("%Y-%m-%dT%H:%M:%S"), message))
        stream.flush()
    return log


def _load(args):
    return config_mod.load(getattr(args, "config", None))


def _vault(cfg, alias):
    """The one place a backend is chosen. Everything downstream -- the runner,
    the MCP surface, the server -- takes whatever this returns and asks it the
    same five questions."""
    spec = cfg.vault(alias)
    if cfg.backend(alias) == "keeper":
        return KeeperVault(alias=alias, real_name=spec["vault"],
                           token_file=cfg.token_file(alias),
                           keeper_bin=cfg.keeper_bin,
                           state_dir=cfg.keeper_state_dir)
    return OnePasswordVault(alias=alias, real_name=spec["vault"],
                            token_file=cfg.token_file(alias), op_bin=cfg.op_bin)


# -- serve ------------------------------------------------------------------

def cmd_serve(args):
    cfg = _load(args)
    log = _log()

    # Say this at startup as well as in doctor. An operator who upgrades and
    # keeps an old config would otherwise learn that their leak alarm is mute
    # at the worst possible moment, which is the first time it needed to ring.
    for key in getattr(cfg, "retired", []):
        log("WARNING: config key %r is no longer read (%s)"
            % (key, config_mod.RETIRED_KEYS[key]))
    if not getattr(cfg, "notify_command", None):
        log("WARNING: notify_command is not set -- leak alerts will be recorded "
            "to disk and nobody will be told")

    vault = _vault(cfg, args.vault)
    mcp_server = Server(vault, cfg, Alerter(cfg), log=log)

    listeners = [server_mod.serve_unix(mcp_server, cfg.socket_path(args.vault),
                                       cfg.socket_group, log)]

    address = cfg.bind_address()
    port = cfg.port(args.vault)
    if address and port:
        listeners.append(server_mod.serve_http(mcp_server, address, int(port), log))
    elif address and not port:
        log("bind is set but vault %s has no port; HTTP listener skipped"
            % args.vault)

    log("serving vault %s (%s: %s)"
        % (vault.alias, vault.backend_label, vault.real_name))
    server_mod.run_forever(listeners)
    return 0


# -- connect ----------------------------------------------------------------

def cmd_connect(args):
    """Stdio bridge for an MCP client. Socket when possible, file queue when not.

    The fallback is not a nicety: inside Claude Code's sandbox the socket is
    unreachable four different ways (see bridge.py), and the file queue is the
    only channel left. Trying the socket first keeps the fast path fast for
    unsandboxed sessions.
    """
    cfg = _load(args)
    sock = cfg.socket_path(args.vault)
    if not args.force_bridge:
        try:
            probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            probe.connect(sock)
            probe.close()
        except OSError:
            pass
        else:
            return server_mod.bridge_stdio(sock)
    return bridge.client_stdio(bridge.DEFAULT_BASE, args.vault)


def cmd_bridge(args):
    """Relay the file queues to the sockets. Runs as the human, unsandboxed."""
    cfg = _load(args)
    log = _log()
    try:
        bridge.serve_queues(cfg, log)
    except KeyboardInterrupt:
        pass
    return 0


# -- alerts -----------------------------------------------------------------

def cmd_sweep(args):
    cfg = _load(args)
    try:
        count = Alerter(cfg).sweep()
    except AlertsUnreadable as exc:
        # The sweeper is what makes an alert sticky. If it cannot read the
        # directory it re-pushes nothing, so it has to fail the unit rather than
        # exit 0 and let `systemctl status` show a timer that is working.
        sys.stderr.write("sandbroker: sweep found nothing because it could not "
                         "look: %s\n" % exc)
        return 1
    if count:
        sys.stderr.write("sandbroker: re-pushed %d open leak alert(s)\n" % count)
    return 0


def cmd_ack(args):
    cfg = _load(args)
    record = Alerter(cfg).acknowledge(args.alert_id)
    if record is None:
        sys.stderr.write("sandbroker: no alert %r\n" % args.alert_id)
        return 1
    print("acknowledged %s (raised %s, %d push(es))"
          % (record["id"],
             time.strftime("%Y-%m-%d %H:%M", time.localtime(record["created"])),
             record.get("pushes", 0)))
    return 0


def cmd_unlock(args):
    """Unlock, then CONFIRM WITH THE DAEMON that it actually took.

    Writing the marker and it being usable are different things: the writer is
    root and the reader is the broker, so a permissions mistake can leave a
    perfectly successful write that the daemon cannot see. Reporting success on
    the strength of the write alone once meant an unlock that printed
    "unlocked until 22:23" while every call kept failing as LOCKED. Ground truth
    is what the daemon says, so ask it.
    """
    cfg = _load(args)
    try:
        until = locks.unlock(cfg, args.vault, args.minutes)
    except locks.LockError as exc:
        sys.stderr.write("sandbroker: %s\n" % exc)
        return 1

    sock = cfg.socket_path(args.vault)
    if os.path.exists(sock):
        reply, err = _probe(sock, {"jsonrpc": "2.0", "id": 1,
                                   "method": "locks/status"})
        result = (reply or {}).get("result") or {}
        if not result.get("unlocked"):
            sys.stderr.write(
                "sandbroker: the marker was written but the daemon still reports "
                "%s LOCKED%s.\n"
                "The broker user cannot read the unlock marker. Check ownership "
                "of\n  %s\nIt must be readable by the user the daemon runs as.\n"
                % (args.vault,
                   "" if not err else " (%s)" % err,
                   os.path.dirname(locks.marker_path(cfg, args.vault))))
            return 1
    else:
        sys.stderr.write("sandbroker: warning, sandbroker@%s is not running, so "
                         "this unlock could not be confirmed.\n" % args.vault)

    print("%s unlocked until %s (%d min), confirmed by the daemon"
          % (args.vault, time.strftime("%H:%M", time.localtime(until)), args.minutes))
    return 0


def cmd_lock(args):
    cfg = _load(args)
    try:
        removed = locks.lock(cfg, args.vault)
    except locks.LockError as exc:
        sys.stderr.write("sandbroker: %s\n" % exc)
        return 1
    print("%s locked%s" % (args.vault, "" if removed else " (was already locked)"))
    return 0


def cmd_locks(args):
    """Ask each daemon, rather than reading the markers.

    The marker directory is 0700 and owned by the broker, so a normal user
    cannot read it -- which is the whole point. The daemon can, so it answers.
    """
    cfg = _load(args)
    for alias in sorted(cfg.vaults):
        sock = cfg.socket_path(alias)
        if not os.path.exists(sock):
            print("%-12s daemon DOWN" % alias)
            continue
        reply, err = _probe(sock, {"jsonrpc": "2.0", "id": 1,
                                   "method": "locks/status"})
        result = (reply or {}).get("result")
        print("%-12s %s" % (alias, result["summary"] if result
                            else "unknown (%s)" % (err or "no answer")))
    return 0


def cmd_alerts(args):
    cfg = _load(args)
    try:
        open_alerts = Alerter(cfg).open_alerts()
    except AlertsUnreadable as exc:
        # Exit non-zero: "I cannot tell" is not "all clear", and a script that
        # gates on this command must not read it as one.
        sys.stderr.write("sandbroker: %s\n" % exc)
        return 2
    if not open_alerts:
        print("no open leak alerts")
        return 0
    for record in open_alerts:
        print("%s  vault=%s  pushes=%d\n    where:  %s\n    detail: %s"
              % (record["id"], record.get("vault"), record.get("pushes", 0),
                 record.get("where"), record.get("detail") or "(none)"))
    return 1


# -- doctor -----------------------------------------------------------------

def _probe(socket_path, message, timeout=20):
    """Send one JSON-RPC message to a running daemon and return its reply.

    doctor talks to the broker as a CLIENT rather than inspecting its private
    files. That is the only honest check available to a normal user: the token
    directory is 0700 and owned by the broker, so a non-broker uid genuinely
    cannot tell an absent token from an unreadable one -- and guessing produces
    a confident, wrong diagnosis.
    """
    try:
        conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        conn.settimeout(timeout)
        conn.connect(socket_path)
    except OSError as exc:
        return None, exc.strerror or str(exc)
    try:
        conn.sendall(json.dumps(message).encode("utf-8") + b"\n")
        line = conn.makefile("rb").readline()
    except OSError as exc:
        return None, exc.strerror or str(exc)
    finally:
        conn.close()
    if not line:
        return None, "no response"
    try:
        return json.loads(line), None
    except ValueError:
        return None, "unreadable response"


def cmd_doctor(args):
    """Check the install end to end without ever resolving a value.

    Everything here is metadata: config, the backend binaries, a live handshake
    with each daemon, and optionally an item listing. Neither `op item list` nor
    `keeper ls` can return a field value, so a green --deep run proves the whole
    path works without a single secret being read.
    """
    problems = 0
    try:
        cfg = _load(args)
    except config_mod.ConfigError as exc:
        print("config: FAIL %s" % exc)
        return 1
    print("config: %s" % cfg.path)

    # Only the backends actually in use. A 1Password-only install should not be
    # told off for having no Keeper CLI, and vice versa.
    binaries = {"1password": ("op cli", cfg.op_bin),
                "keeper": ("keeper cli", cfg.keeper_bin)}
    for backend in sorted(set(cfg.backend(a) for a in cfg.vaults)):
        label, binary = binaries[backend]
        if not (os.path.isfile(binary) and os.access(binary, os.X_OK)):
            print("%s: FAIL not executable at %s" % (label, binary))
            problems += 1
        else:
            print("%s: ok (%s)" % (label, binary))

    try:
        address = cfg.bind_address()
        print("http listener: %s" % (("%s (tailnet/loopback)" % address)
                                     if address else "disabled, unix socket only"))
    except config_mod.ConfigError as exc:
        print("http listener: FAIL %s" % exc)
        problems += 1

    # An alarm nobody hears is worse than no alarm, because it reads as safety.
    # This is a counted problem rather than a note for exactly that reason.
    notify = getattr(cfg, "notify_command", None)
    if not notify:
        print("leak notifier: FAIL notify_command is not set -- leak alerts "
              "will be written to disk and NOBODY WILL BE TOLD")
        problems += 1
    else:
        shown = notify if isinstance(notify, str) else " ".join(notify)
        print("leak notifier: %s" % shown)
        if isinstance(notify, (list, tuple)) and notify:
            target = notify[0]
        else:
            target = str(notify).split()[0]
        # Only checkable when it names a path. A shell one-liner or a command on
        # PATH is left alone rather than guessed at.
        if target.startswith("/") and not os.access(target, os.X_OK):
            print("               FAIL %s is not executable" % target)
            problems += 1

    for key in getattr(cfg, "retired", []):
        print("config: FAIL %r is no longer read (%s)"
              % (key, config_mod.RETIRED_KEYS[key]))
        problems += 1

    # Only meaningful when doctor happens to run as root or as the broker; from
    # any other uid the directory is not traversable and every answer would be a
    # false negative, so the question is not asked at all.
    tokens_visible = os.access(cfg.tokens_dir, os.R_OK | os.X_OK)

    for alias in sorted(cfg.vaults):
        sock = cfg.socket_path(alias)
        keeper = cfg.backend(alias) == "keeper"
        bits = ["keeper"] if keeper else []

        if not os.path.exists(sock):
            bits.append("socket DOWN (systemctl status sandbroker@%s)" % alias)
            problems += 1
        else:
            reply, err = _probe(sock, {"jsonrpc": "2.0", "id": 1,
                                       "method": "initialize",
                                       "params": {"protocolVersion": mcp.PROTOCOL_VERSION}})
            if err or not reply or "result" not in reply:
                bits.append("daemon NOT RESPONDING (%s)" % (err or "bad reply"))
                problems += 1
            else:
                bits.append("daemon up")

        if tokens_visible:
            # Same file, two different things in it: a service-account token or
            # a Commander config. Naming which one keeps the fix obvious.
            bits.append("%s %s"
                        % ("config" if keeper else "token",
                           "present" if os.path.exists(cfg.token_file(alias))
                           else "MISSING"))
            if not os.path.exists(cfg.token_file(alias)):
                problems += 1

        if locks.requires_unlock(cfg, alias):
            bits.append(locks.describe(cfg, alias)
                        if tokens_visible else "gated (unlock required)")

        if args.deep and os.path.exists(sock):
            # Through the daemon, not by loading the token here: this uid cannot
            # read it, and going through the socket is what users actually do.
            reply, err = _probe(sock, {"jsonrpc": "2.0", "id": 2,
                                       "method": "tools/call",
                                       "params": {"name": "list_items",
                                                  "arguments": {}}}, timeout=45)
            backend_label = "Keeper" if keeper else "1Password"
            result = (reply or {}).get("result") or {}
            if err or result.get("isError") or "content" not in result:
                detail = err or (result.get("content") or [{}])[0].get("text", "failed")
                bits.append("%s FAIL (%s)" % (backend_label, str(detail)[:80]))
                problems += 1
            else:
                try:
                    count = len(json.loads(result["content"][0]["text"])["items"])
                    bits.append("%d item(s)" % count)
                except (ValueError, KeyError, IndexError):
                    bits.append("%s ok, unreadable listing" % backend_label)

        print("vault %-12s %s" % (alias, "; ".join(bits)))

    if not tokens_visible:
        print("\n(tokens are 0700 and owned by the broker, so this uid cannot "
              "see them -- that is correct. `doctor --deep` proves they work.)")

    unchecked = False
    try:
        open_alerts = Alerter(cfg).open_alerts()
    except AlertsUnreadable:
        # Not a problem in itself -- running doctor as yourself is the normal
        # case -- but it must not disappear into an "all good" either. This box
        # carried five unacknowledged alerts for six days while every
        # unprivileged doctor run said none open and all good.
        unchecked = True
        print("leak alerts: UNKNOWN -- this uid cannot read %s; "
              "re-run as root to find out" % cfg.alerts_dir)
    else:
        if open_alerts:
            print("leak alerts: %d OPEN -- run `sudo sandbroker alerts`"
                  % len(open_alerts))
            problems += 1
        else:
            print("leak alerts: none open")

    if problems:
        summary = "%d problem(s)" % problems
    elif unchecked:
        summary = "no problems found, but leak alerts were NOT checked"
    else:
        summary = "all good"
    print("\n%s" % summary)
    return 1 if problems else 0


# -- entry point ------------------------------------------------------------

def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="sandbroker",
        description="Use secrets without seeing them.")
    parser.add_argument("--config", help="path to sandbroker.json")
    sub = parser.add_subparsers(dest="command", required=True)

    serve = sub.add_parser("serve", help="run the broker for one vault")
    serve.add_argument("--vault", required=True)
    serve.set_defaults(func=cmd_serve)

    connect = sub.add_parser("connect", help="stdio bridge for an MCP client")
    connect.add_argument("--vault", required=True)
    connect.add_argument("--force-bridge", action="store_true",
                         help="skip the socket and use the file queue "
                              "(for testing the sandboxed path)")
    connect.set_defaults(func=cmd_connect)

    bridge_cmd = sub.add_parser(
        "bridge", help="relay sandboxed clients' file queues to the sockets")
    bridge_cmd.set_defaults(func=cmd_bridge)

    sweep = sub.add_parser("sweep", help="re-push open leak alerts")
    sweep.set_defaults(func=cmd_sweep)

    ack = sub.add_parser("ack", help="acknowledge a leak alert")
    ack.add_argument("alert_id")
    ack.set_defaults(func=cmd_ack)

    unlock = sub.add_parser("unlock", help="unlock a gated vault (needs sudo)")
    unlock.add_argument("vault")
    unlock.add_argument("--minutes", "-m", type=int, default=locks.DEFAULT_MINUTES)
    unlock.set_defaults(func=cmd_unlock)

    lock_cmd = sub.add_parser("lock", help="re-lock a gated vault (needs sudo)")
    lock_cmd.add_argument("vault")
    lock_cmd.set_defaults(func=cmd_lock)

    locks_cmd = sub.add_parser("locks", help="show each vault's lock state")
    locks_cmd.set_defaults(func=cmd_locks)

    alerts = sub.add_parser("alerts", help="list open leak alerts")
    alerts.set_defaults(func=cmd_alerts)

    doctor = sub.add_parser("doctor", help="check the install")
    doctor.add_argument("--deep", action="store_true",
                        help="also list items from each vault (still no values)")
    doctor.set_defaults(func=cmd_doctor)

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except config_mod.ConfigError as exc:
        sys.stderr.write("sandbroker: %s\n" % exc)
        return 2
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
