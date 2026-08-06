"""Leak alerting: shout via ntfy, and keep shouting until a human says stop.

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
"""

import json
import os
import time
import urllib.error
import urllib.request

# How stale an open alert has to be before the sweeper pushes it again.
REPEAT_AFTER = 900  # 15 minutes


class Alerter:
    def __init__(self, config):
        self.config = config
        self.dir = config.alerts_dir

    # -- transport ----------------------------------------------------------

    def _token(self):
        path = self.config.ntfy_token_file
        if not path:
            return None
        try:
            with open(path, "r", encoding="utf-8") as fh:
                return fh.read().strip() or None
        except OSError:
            return None

    def push(self, title, body, priority="urgent", tags="rotating_light"):
        """Fire one notification. Returns True on delivery.

        Never raises: an alert that cannot be delivered must not also take down
        the call that was trying to report a problem. Delivery failure is
        recorded on the alert record instead, and the sweeper will retry.
        """
        url = self.config.ntfy_url
        if not url:
            return False
        request = urllib.request.Request(
            url,
            data=body.encode("utf-8"),
            method="POST",
            headers={
                "Title": title,
                "Priority": priority,
                "Tags": tags,
            },
        )
        token = self._token()
        if token:
            request.add_header("Authorization", "Bearer %s" % token)
        try:
            with urllib.request.urlopen(request, timeout=10) as resp:
                return 200 <= resp.status < 300
        except (urllib.error.URLError, OSError, ValueError):
            return False

    # -- persistence --------------------------------------------------------

    def _ensure_dir(self):
        os.makedirs(self.dir, mode=0o700, exist_ok=True)

    def _path(self, alert_id):
        return os.path.join(self.dir, "%s.json" % alert_id)

    def open_alerts(self):
        try:
            names = sorted(os.listdir(self.dir))
        except OSError:
            return []
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
        """Push one alert record and stamp the attempt onto it."""
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
        delivered = self.push(title, body)
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
