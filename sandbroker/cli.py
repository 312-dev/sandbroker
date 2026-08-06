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

from . import config as config_mod
from . import mcp
from . import server as server_mod
from .alert import Alerter
from .mcp import Server
from .onepassword import Vault


def _log(stream=sys.stderr):
    def log(message):
        stream.write("%s sandbroker: %s\n"
                     % (time.strftime("%Y-%m-%dT%H:%M:%S"), message))
        stream.flush()
    return log


def _load(args):
    return config_mod.load(getattr(args, "config", None))


def _vault(cfg, alias):
    spec = cfg.vault(alias)
    return Vault(alias=alias, real_name=spec["vault"],
                 token_file=cfg.token_file(alias), op_bin=cfg.op_bin)


# -- serve ------------------------------------------------------------------

def cmd_serve(args):
    cfg = _load(args)
    log = _log()
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

    log("serving vault %s (1Password: %s)" % (vault.alias, vault.real_name))
    server_mod.run_forever(listeners)
    return 0


# -- connect ----------------------------------------------------------------

def cmd_connect(args):
    cfg = _load(args)
    return server_mod.bridge_stdio(cfg.socket_path(args.vault))


# -- alerts -----------------------------------------------------------------

def cmd_sweep(args):
    cfg = _load(args)
    count = Alerter(cfg).sweep()
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


def cmd_alerts(args):
    cfg = _load(args)
    open_alerts = Alerter(cfg).open_alerts()
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

    Everything here is metadata: config, the op binary, a live handshake with
    each daemon, and optionally an item listing. `op item list` cannot return a
    field value, so a green --deep run proves the whole path works without a
    single secret being read.
    """
    problems = 0
    try:
        cfg = _load(args)
    except config_mod.ConfigError as exc:
        print("config: FAIL %s" % exc)
        return 1
    print("config: %s" % cfg.path)

    if not (os.path.isfile(cfg.op_bin) and os.access(cfg.op_bin, os.X_OK)):
        print("op cli: FAIL not executable at %s" % cfg.op_bin)
        problems += 1
    else:
        print("op cli: ok (%s)" % cfg.op_bin)

    try:
        address = cfg.bind_address()
        print("http listener: %s" % (("%s (tailnet/loopback)" % address)
                                     if address else "disabled, unix socket only"))
    except config_mod.ConfigError as exc:
        print("http listener: FAIL %s" % exc)
        problems += 1

    # Only meaningful when doctor happens to run as root or as the broker; from
    # any other uid the directory is not traversable and every answer would be a
    # false negative, so the question is not asked at all.
    tokens_visible = os.access(cfg.tokens_dir, os.R_OK | os.X_OK)

    for alias in sorted(cfg.vaults):
        sock = cfg.socket_path(alias)
        bits = []

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
            bits.append("token %s"
                        % ("present" if os.path.exists(cfg.token_file(alias))
                           else "MISSING"))
            if not os.path.exists(cfg.token_file(alias)):
                problems += 1

        if args.deep and os.path.exists(sock):
            # Through the daemon, not by loading the token here: this uid cannot
            # read it, and going through the socket is what users actually do.
            reply, err = _probe(sock, {"jsonrpc": "2.0", "id": 2,
                                       "method": "tools/call",
                                       "params": {"name": "list_items",
                                                  "arguments": {}}}, timeout=45)
            result = (reply or {}).get("result") or {}
            if err or result.get("isError") or "content" not in result:
                detail = err or (result.get("content") or [{}])[0].get("text", "failed")
                bits.append("1Password FAIL (%s)" % str(detail)[:80])
                problems += 1
            else:
                try:
                    count = len(json.loads(result["content"][0]["text"])["items"])
                    bits.append("%d item(s)" % count)
                except (ValueError, KeyError, IndexError):
                    bits.append("1Password ok, unreadable listing")

        print("vault %-12s %s" % (alias, "; ".join(bits)))

    if not tokens_visible:
        print("\n(tokens are 0700 and owned by the broker, so this uid cannot "
              "see them -- that is correct. `doctor --deep` proves they work.)")

    open_alerts = Alerter(cfg).open_alerts()
    if open_alerts:
        print("leak alerts: %d OPEN -- run `sandbroker alerts`" % len(open_alerts))
        problems += 1
    else:
        print("leak alerts: none open")

    print("\n%s" % ("all good" if not problems else "%d problem(s)" % problems))
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
    connect.set_defaults(func=cmd_connect)

    sweep = sub.add_parser("sweep", help="re-push open leak alerts")
    sweep.set_defaults(func=cmd_sweep)

    ack = sub.add_parser("ack", help="acknowledge a leak alert")
    ack.add_argument("alert_id")
    ack.set_defaults(func=cmd_ack)

    alerts = sub.add_parser("alerts", help="list open leak alerts")
    alerts.set_defaults(func=cmd_alerts)

    doctor = sub.add_parser("doctor", help="check the install")
    doctor.add_argument("--deep", action="store_true",
                        help="also list items from 1Password (still no values)")
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
