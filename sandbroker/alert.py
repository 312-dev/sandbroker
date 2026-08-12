"""Leak alerting: shout through a command of the operator's choosing, and keep
shouting until a human says stop.

The broker's filter only removes secrets it resolved itself. A credential minted
during a call -- an OAuth access token, a session cookie, a signed URL -- is
invisible to it and will come back in the clear. The agent is told to report any
such sighting here immediately.

The design point is that an alert is STICKY. A single push at 03:00 is a push
that gets missed. An open alert re-fires on a timer until someone acknowledges
it on the host, which is the only signal that a human actually looked.

Deliberately absent: any way for the agent to acknowledge. The alerts directory
is owned by the daemon user with mode 0700, so acknowledging requires being root
or the daemon user on the box. An agent that could silence its own alarm would
make the alarm worthless.

WHY THE TRANSPORT IS A COMMAND
------------------------------
This module knows nothing about how you want to be told. It execs
`notify_command` from the config and hands it the alert; whether that ends up as
a phone push, a desktop notification, a Slack message, an SMS or a line in a log
is entirely the operator's business. Delivering notifications is not a problem
this codebase is qualified to have opinions about, and every opinion it held was
one more thing to keep working.

THE ALERT REACHES THE COMMAND ON STDIN AND IN THE ENVIRONMENT, NEVER IN ARGV
---------------------------------------------------------------------------
`detail` and `where` are written by the AGENT. Interpolating agent-authored text
into a command string would hand the agent shell execution inside the very alarm
that exists to police it. So the command is taken verbatim from the config, and
the alert travels separately: the full record as JSON on stdin, and the same
fields as SANDBROKER_ALERT_* environment variables for scripts that would rather
not parse. Nothing the agent wrote is ever parsed as code.
"""

import json
import os
import subprocess
import time

# How stale an open alert has to be before the sweeper pushes it again.
REPEAT_AFTER = 900  # 15 minutes

# A notifier that hangs must not wedge the report_leak call waiting on it, nor
# the sweeper behind it. Overshooting this is a failed delivery, which is a
# retry, which is the behaviour we want anyway.
NOTIFY_TIMEOUT = 15


class AlertsUnreadable(Exception):
    """This uid cannot see the alerts directory, so it cannot answer the
    question. Distinct from finding it empty, and the two must never render the
    same way: one means nothing is wrong, the other means nobody knows."""


class Alerter:
    def __init__(self, config):
        self.config = config
        self.dir = config.alerts_dir

    # -- transport ----------------------------------------------------------

    def _notify_env(self, record, title, body):
        """The alert as environment variables, for scripts that skip the JSON.

        Values are passed through execve, so they are never word-split, globbed
        or re-parsed by a shell. An agent that writes `; rm -rf /` into `detail`
        produces a notification containing that text and nothing more.
        """
        env = dict(os.environ)
        env.update({
            "SANDBROKER_ALERT_ID": str(record.get("id") or ""),
            "SANDBROKER_ALERT_VAULT": str(record.get("vault") or ""),
            "SANDBROKER_ALERT_WHERE": str(record.get("where") or ""),
            "SANDBROKER_ALERT_DETAIL": str(record.get("detail") or ""),
            "SANDBROKER_ALERT_REPORTED_BY": str(record.get("reported_by") or ""),
            "SANDBROKER_ALERT_CREATED": str(record.get("created") or ""),
            "SANDBROKER_ALERT_PUSHES": str(record.get("pushes") or 0),
            "SANDBROKER_ALERT_TITLE": title,
            "SANDBROKER_ALERT_BODY": body,
        })
        return env

    def push(self, record, title, body):
        """Run the notify command for one alert. Returns True on delivery.

        Never raises: an alert that cannot be delivered must not also take down
        the call that was trying to report a problem. Delivery failure is
        recorded on the alert record instead, and the sweeper will retry.

        Delivery means the command exited zero. A notifier that cannot reach its
        service should exit non-zero so the sweeper keeps trying; one that exits
        zero is asserting the human was told.
        """
        command = getattr(self.config, "notify_command", None)
        if not command:
            return False
        # A list is argv and skips the shell entirely, which is the better form.
        # A string gets /bin/sh so an operator can write a pipeline in one line.
        if isinstance(command, (list, tuple)):
            argv, shell = [str(part) for part in command], False
        else:
            argv, shell = str(command), True
        try:
            proc = subprocess.run(
                argv,
                shell=shell,
                input=json.dumps(record, sort_keys=True).encode("utf-8"),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env=self._notify_env(record, title, body),
                timeout=NOTIFY_TIMEOUT,
            )
        except (OSError, ValueError, subprocess.SubprocessError):
            return False
        return proc.returncode == 0

    # -- persistence --------------------------------------------------------

    def _ensure_dir(self):
        os.makedirs(self.dir, mode=0o700, exist_ok=True)

    def _path(self, alert_id):
        return os.path.join(self.dir, "%s.json" % alert_id)

    def open_alerts(self):
        """Every unacknowledged alert.

        An empty list means there are none. It must never also mean "I could not
        look", which is what returning [] on any OSError used to do: the alerts
        directory is 0700 and owned by the broker, so `sandbroker alerts` run by
        an ordinary user hit PermissionError and cheerfully reported no open
        alerts while a real one sat there unread.

        A missing directory genuinely is zero alerts -- it is created on the
        first one raised. Anything else is a failure to see, and the caller has
        to be told the difference.
        """
        try:
            names = sorted(os.listdir(self.dir))
        except FileNotFoundError:
            return []
        except OSError as exc:
            raise AlertsUnreadable(
                "cannot read %s (%s). It is 0700 and owned by the broker, so "
                "this must run as root or the broker user -- and until it does, "
                "whether any alert is open is UNKNOWN, not none."
                % (self.dir, exc.strerror or exc))
        out = []
        for name in names:
            if not name.endswith(".json"):
                continue
            try:
                with open(os.path.join(self.dir, name), "r", encoding="utf-8") as fh:
                    record = json.load(fh)
            except (OSError, ValueError):
                continue
            if not record.get("acknowledged"):
                out.append(record)
        return out

    def raise_alert(self, vault, where, detail, reported_by=None):
        """Record a leak report and push it immediately.

        `detail` is written by the agent, so it is truncated hard and it is the
        agent's own responsibility not to paste the credential into it. Say so
        loudly in the skill: quoting the token into the alert defeats the point.
        """
        self._ensure_dir()
        alert_id = "%d-%s" % (int(time.time()), os.urandom(4).hex())
        record = {
            "id": alert_id,
            "vault": vault,
            "where": str(where or "")[:400],
            "detail": str(detail or "")[:2000],
            "reported_by": str(reported_by or "")[:200],
            "created": int(time.time()),
            "last_push": 0,
            "pushes": 0,
            "acknowledged": False,
        }
        delivered = self.notify(record)
        self._write(record)
        return record, delivered

    def notify(self, record):
        """Push one alert record and stamp the attempt onto it.

        The title and body are rendered here rather than left to the notifier so
        that every transport says the same thing, including the ack command. A
        notifier that wants to build its own message has the structured record
        on stdin and can ignore both.
        """
        title = "SANDBROKER LEAK: %s" % (record.get("vault") or "unknown vault")
        body = (
            "A live credential was seen in broker output.\n\n"
            "where: %s\n"
            "detail: %s\n"
            "reported by: %s\n"
            "alert id: %s\n\n"
            "This repeats every %d minutes until acknowledged on the host:\n"
            "  sudo sandbroker ack %s"
            % (record.get("where") or "(unspecified)",
               record.get("detail") or "(none)",
               record.get("reported_by") or "(unknown agent)",
               record["id"], REPEAT_AFTER // 60, record["id"])
        )
        delivered = self.push(record, title, body)
        record["last_push"] = int(time.time())
        record["pushes"] = int(record.get("pushes", 0)) + 1
        record["last_delivered"] = bool(delivered)
        return delivered

    def sweep(self):
        """Re-push every open alert that has gone quiet. Driven by a systemd
        timer; returns the number of alerts re-pushed."""
        now = int(time.time())
        count = 0
        for record in self.open_alerts():
            if now - int(record.get("last_push", 0)) < REPEAT_AFTER:
                continue
            self.notify(record)
            self._write(record)
            count += 1
        return count

    def acknowledge(self, alert_id):
        """Close an alert. Callable only by a uid that can write the alerts
        directory, i.e. not the agent."""
        path = self._path(alert_id)
        try:
            with open(path, "r", encoding="utf-8") as fh:
                record = json.load(fh)
        except (OSError, ValueError):
            return None
        record["acknowledged"] = True
        record["acknowledged_at"] = int(time.time())
        self._write(record)
        return record

    def _write(self, record):
        self._ensure_dir()
        path = self._path(record["id"])
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(record, fh, indent=2, sort_keys=True)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
