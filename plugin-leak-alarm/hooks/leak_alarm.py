#!/usr/bin/env python3
"""Notice a live credential crossing a tool boundary, and make a human deal with it.

WHAT THIS IS, AND WHAT IT IS NOT
--------------------------------
sandbroker's redactor removes values it resolved from a vault. It is an exact
match on known bytes and it makes a guarantee. This is the opposite kind of
thing: a pattern matcher looking for credentials nobody told it about, which
means it is heuristic, it will miss things, and it can be wrong. It makes no
guarantee at all.

That is worth having anyway, because the credentials that actually leak are the
ones nothing was watching for: an OAuth `access_token` in a response body, a
session cookie, a signed URL, a key pasted into a file by a well-meaning agent.

WHY IT CANNOT PREVENT ANYTHING ON THE WAY OUT
---------------------------------------------
A PostToolUse hook receives `tool_response` but cannot alter or suppress it. By
the time this code runs, the tool has executed and its output is already in the
model's context. So detection on that path is not prevention, it is
`rotate this credential now`, delivered to a human who can.

PreToolUse is the half that can actually stop something: a credential in tool
INPUT is a credential about to be written to a file, committed, or curled
somewhere, and that call can be denied before it happens.

WHAT IT NEVER DOES
------------------
It never writes the credential anywhere. Not to the alert, not to the log, not
to stdout, not to the message shown to the user. A finding is identified by its
pattern name and a truncated SHA-256, which is enough to recognise the same
token twice and useless for anything else. A tool that reports leaks by quoting
them has become a way to leak them.
"""

import hashlib
import json
import os
import re
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
PLUGIN_ROOT = os.path.dirname(HERE)
RULES_FILE = os.path.join(PLUGIN_ROOT, "rules", "patterns.json")

CONFIG_HOME = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
STATE_HOME = os.environ.get("XDG_STATE_HOME") or os.path.expanduser("~/.local/state")
CONFIG_FILE = os.path.join(CONFIG_HOME, "leak-alarm", "config.json")
STATE_DIR = os.path.join(STATE_HOME, "leak-alarm")

# Where an existing sandbroker install keeps its notify_command, so a box that
# already has one configured needs no second configuration to get alerts here.
SANDBROKER_CONFIG = os.environ.get("SANDBROKER_CONFIG",
                                   "/opt/sandbroker/etc/sandbroker.json")

# Scanning is on the critical path of every tool call, so it is bounded. A
# credential in the first quarter-megabyte is the realistic case; a build log
# long enough to hit this is not where tokens hide.
SCAN_LIMIT = 262144
NOTIFY_TIMEOUT = 15

# Runs that scream "template", not "credential". Checked before alerting so a
# README full of ghp_xxxxxxxx does not page anybody.
PLACEHOLDER = re.compile(
    r"(?:x{6,}|X{6,}|0{6,}|1234567890|EXAMPLE|PLACEHOLDER|YOUR[_-]?|"
    r"REPLACE[_-]?ME|<[^>]{3,}>|\.\.\.|\*{4,})")

# sandbroker's own redaction marker. Seeing one means the broker did its job.
REDACTED = re.compile(r"\[redacted:[^\]]*\]")


def log(message):
    """Diagnostics go to stderr, which Claude Code routes to the debug log and
    not into the model's context. Never put a finding's matched text here."""
    sys.stderr.write("leak-alarm: %s\n" % message)


# -- configuration ----------------------------------------------------------

def read_json(path):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {}


def load_config():
    cfg = read_json(CONFIG_FILE)
    if not cfg.get("notify_command"):
        # Inherit sandbroker's notifier when there is one. Same contract, so
        # whatever script already works for broker leak alerts works here.
        cfg["notify_command"] = read_json(SANDBROKER_CONFIG).get("notify_command")
    if os.environ.get("LEAK_ALARM_NOTIFY"):
        cfg["notify_command"] = os.environ["LEAK_ALARM_NOTIFY"]
    return cfg


def load_patterns(cfg):
    """Compile the ruleset once per invocation.

    A bad regex in the user's own `extra_patterns` is skipped with a note rather
    than allowed to take down the hook. Failing closed here would mean failing
    every tool call in the session over a typo in a config file.
    """
    rules = read_json(RULES_FILE)
    disabled = set(cfg.get("disabled") or [])
    entries = list(rules.get("patterns") or []) + list(cfg.get("extra_patterns") or [])
    compiled = []
    for entry in entries:
        name = str(entry.get("name") or "")
        source = entry.get("regex")
        if not name or not source or name in disabled:
            continue
        try:
            compiled.append((name, re.compile(source)))
        except re.error as exc:
            log("ignoring pattern %r: %s" % (name, exc))
    ignore = set(rules.get("ignore") or []) | set(cfg.get("ignore") or [])
    return compiled, ignore


# -- detection --------------------------------------------------------------

def fingerprint(value):
    """A stable, non-reversible id for one credential.

    Twelve hex characters is enough to recognise the same token across tool
    calls and far too little to attack the value behind it. This is the ONLY
    representation of a matched secret that leaves this process.
    """
    return hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:12]


def looks_like_placeholder(value):
    return bool(PLACEHOLDER.search(value))


def scan(text, patterns, ignore):
    """Every distinct credential-shaped run in `text`, as (pattern, fingerprint).

    Deduplicated by fingerprint so one token repeated forty times in a verbose
    log produces one finding, not forty.
    """
    if not text:
        return []
    if len(text) > SCAN_LIMIT:
        text = text[:SCAN_LIMIT]
    # A redaction marker is proof the broker already handled that value, and
    # blanking them first stops a marker from anchoring a spurious match.
    text = REDACTED.sub(" ", text)
    found = {}
    for name, regex in patterns:
        for match in regex.finditer(text):
            value = match.group(0)
            if value in ignore or looks_like_placeholder(value):
                continue
            found.setdefault(fingerprint(value), name)
    return sorted((name, fp) for fp, name in found.items())


def stringify(payload):
    """Flatten a tool input or response to text for scanning.

    Tool responses are variously strings, dicts, lists of content blocks, or
    nested combinations. Serialising the whole thing is cruder than walking it
    and catches structures this code has never seen, which is the point.
    """
    if payload is None:
        return ""
    if isinstance(payload, str):
        return payload
    try:
        return json.dumps(payload, ensure_ascii=False, default=str)
    except (TypeError, ValueError):
        return str(payload)


def scanning_own_rules(event):
    """True when the tool call is just reading this plugin's own files.

    The ruleset is a file full of credential patterns, so reading it matches
    every one of them. An alarm that fires on its own source teaches people to
    ignore the alarm.
    """
    blob = stringify(event.get("tool_input"))
    return PLUGIN_ROOT in blob or RULES_FILE in blob


# -- alerting ---------------------------------------------------------------

def already_seen(session, fingerprints):
    """Filter out findings this session has already reported.

    Without this, one leaked token in a file the agent reads repeatedly pages a
    human on every read. State is per session and best-effort: if it cannot be
    written, the cost is a duplicate alert, which is the right way to fail.
    """
    path = os.path.join(STATE_DIR, "seen-%s.json" % re.sub(r"\W", "", session)[:40])
    seen = set(read_json(path).get("fingerprints") or [])
    fresh = [f for f in fingerprints if f[1] not in seen]
    if not fresh:
        return []
    try:
        os.makedirs(STATE_DIR, mode=0o700, exist_ok=True)
        seen.update(f[1] for f in fresh)
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump({"fingerprints": sorted(seen), "updated": int(time.time())}, fh)
        os.replace(tmp, path)
    except OSError as exc:
        log("could not record seen findings: %s" % exc)
    return fresh


def record(alert):
    """Persist the alert so `leak-alarm alerts` can list it later.

    Best-effort on purpose. The notification is the load-bearing part; the file
    is a convenience, and losing it must not stop the human being told.
    """
    try:
        os.makedirs(os.path.join(STATE_DIR, "alerts"), mode=0o700, exist_ok=True)
        path = os.path.join(STATE_DIR, "alerts", "%s.json" % alert["id"])
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(alert, fh, indent=2, sort_keys=True)
        os.chmod(path, 0o600)
    except OSError as exc:
        log("could not record alert: %s" % exc)


def notify(cfg, alert, title, body):
    """Hand the alert to the operator's command. Returns True if it exited 0.

    Same contract as sandbroker's alert.py, so one notifier script serves both:
    the record as JSON on stdin, the fields as SANDBROKER_ALERT_* environment
    variables, and nothing whatsoever on the command line. Every string in the
    alert is derived from tool traffic, so none of it is allowed near a shell.
    """
    command = cfg.get("notify_command")
    if not command:
        return False
    if isinstance(command, (list, tuple)):
        argv, shell = [str(part) for part in command], False
    else:
        argv, shell = str(command), True
    env = dict(os.environ)
    env.update({
        "SANDBROKER_ALERT_ID": alert["id"],
        "SANDBROKER_ALERT_VAULT": alert["source"],
        "SANDBROKER_ALERT_WHERE": alert["where"],
        "SANDBROKER_ALERT_DETAIL": alert["detail"],
        "SANDBROKER_ALERT_REPORTED_BY": alert["reported_by"],
        "SANDBROKER_ALERT_CREATED": str(alert["created"]),
        "SANDBROKER_ALERT_PUSHES": "1",
        "SANDBROKER_ALERT_TITLE": title,
        "SANDBROKER_ALERT_BODY": body,
    })
    try:
        proc = subprocess.run(
            argv, shell=shell,
            input=json.dumps(alert, sort_keys=True).encode("utf-8"),
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            env=env, timeout=NOTIFY_TIMEOUT)
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        log("notifier failed: %s" % exc)
        return False
    return proc.returncode == 0


def raise_alarm(cfg, event, findings, phase):
    """Build, record and send one alert covering every finding in a tool call."""
    names = sorted(set(name for name, _ in findings))
    summary = ", ".join("%s (%s)" % (name, fp) for name, fp in findings)
    alert = {
        "id": "%d-%s" % (int(time.time()), os.urandom(4).hex()),
        "source": "leak-alarm",
        "phase": phase,
        "where": "%s tool: %s" % (phase, event.get("tool_name") or "unknown"),
        "detail": summary,
        "patterns": names,
        "fingerprints": [fp for _, fp in findings],
        "reported_by": "leak-alarm hook",
        "session_id": str(event.get("session_id") or ""),
        "cwd": str(event.get("cwd") or ""),
        "created": int(time.time()),
    }
    title = "CREDENTIAL SEEN: %s" % ", ".join(names)
    body = (
        "A credential-shaped value crossed a tool boundary.\n\n"
        "where: %s\n"
        "patterns: %s\n"
        "session: %s\n"
        "cwd: %s\n\n"
        "The value itself is not recorded anywhere; the parenthesised ids are\n"
        "truncated hashes so you can tell two sightings apart.\n\n"
        "If it is live, rotate it."
        % (alert["where"], summary, alert["session_id"] or "(unknown)",
           alert["cwd"] or "(unknown)")
    )
    # Write before notifying so a notifier that hangs or kills the process still
    # leaves a trace, then write again with the outcome. Recording only once, up
    # front, is how `leak-alarm alerts` ends up reporting NOT DELIVERED for
    # alerts that went out fine, and a status display nobody believes is worse
    # than none.
    record(alert)
    alert["delivered"] = notify(cfg, alert, title, body)
    record(alert)
    return alert


def user_message(alert, blocked):
    lead = ("BLOCKED: a credential was about to be sent through %s."
            if blocked else
            "LEAK: a credential appeared in output from %s.")
    return ("%s\n  %s\n  %s\n  Alert %s%s"
            % (lead % (alert["where"].split(": ", 1)[-1]),
               alert["detail"],
               "It is already in this conversation's context; rotate it."
               if not blocked else "The call was denied. Nothing was sent.",
               alert["id"],
               "" if alert.get("delivered") else
               " (NOT DELIVERED -- no notify_command, so this message is the "
               "only warning you get)"))


# -- entry point ------------------------------------------------------------

def handle(event):
    """Return the hook's JSON response for one event, or None to stay silent."""
    cfg = load_config()
    phase = event.get("hook_event_name") or ""

    if scanning_own_rules(event):
        return None

    patterns, ignore = load_patterns(cfg)
    if not patterns:
        return None

    if phase == "PreToolUse":
        findings = scan(stringify(event.get("tool_input")), patterns, ignore)
        if not findings:
            return None
        # No dedup on this path. Every attempt to move a credential is worth
        # denying, even the fortieth attempt with the same one.
        alert = raise_alarm(cfg, event, findings, "PreToolUse")
        if cfg.get("block_tool_input", True) is False:
            return {"systemMessage": user_message(alert, blocked=False)}
        return {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": (
                    "leak-alarm: this call carries what looks like a live "
                    "credential (%s). Sending it onward would spread the leak. "
                    "Use a secret broker so the value never passes through you, "
                    "and tell the user the credential needs rotating."
                    % ", ".join(sorted(set(n for n, _ in findings)))),
            },
            "systemMessage": user_message(alert, blocked=True),
        }

    # PostToolUse carries `tool_response`; PostToolUseFailure spells the payload
    # differently and is the likelier of the two to hold a credential, because
    # an error body quoting the request back is how tokens usually surface.
    # Scanning every plausible key beats tracking which event named it what.
    blob = " ".join(stringify(event.get(key)) for key in
                    ("tool_response", "tool_error", "error", "tool_result")
                    if event.get(key) is not None)
    findings = scan(blob, patterns, ignore)
    findings = already_seen(str(event.get("session_id") or "none"), findings)
    if not findings:
        return None
    alert = raise_alarm(cfg, event, findings, phase or "PostToolUse")
    response = {"systemMessage": user_message(alert, blocked=False)}
    if cfg.get("halt_on_detect"):
        # Off by default. Stopping the turn keeps the agent from using or
        # copying the credential, at the cost of ending the turn on a false
        # positive, so it is the operator's call rather than ours.
        response["continue"] = False
        response["stopReason"] = (
            "leak-alarm halted the turn: a credential appeared in tool output. "
            "Alert %s." % alert["id"])
    return response


def main():
    try:
        event = json.loads(sys.stdin.read() or "{}")
    except ValueError:
        return 0
    try:
        response = handle(event)
    except Exception as exc:                                  # noqa: BLE001
        # A hook that crashes is a hook that gets disabled. Whatever went wrong
        # here matters far less than the session continuing to work.
        log("internal error: %s" % exc)
        return 0
    if response:
        sys.stdout.write(json.dumps(response))
    return 0


if __name__ == "__main__":
    sys.exit(main())
