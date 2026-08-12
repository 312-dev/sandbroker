#!/usr/bin/env bash
# Send a sandbroker leak alert to ntfy.
#
# This is an EXAMPLE notifier, not a required one. sandbroker itself has no
# opinion about how you want to be told: set `notify_command` in the config to
# this script, to `notify-send`, to a Slack webhook, to a pager, or to anything
# else that exits 0 when a human has been told.
#
# Install:
#   cp contrib/notify-ntfy.sh /opt/sandbroker/contrib/
#   chmod 0755 /opt/sandbroker/contrib/notify-ntfy.sh
#   printf 'NTFY_URL=https://ntfy.example.com/my-alerts\n' \
#       > /opt/sandbroker/etc/notify-ntfy.conf
#   chmod 0640 /opt/sandbroker/etc/notify-ntfy.conf
#   chown root:sandbroker /opt/sandbroker/etc/notify-ntfy.conf
# then set in sandbroker.json:
#   "notify_command": "/opt/sandbroker/contrib/notify-ntfy.sh"
#
# The alert arrives two ways and this script uses the environment form. The full
# record is also on stdin as JSON if you would rather reshape it.
#
# Exit status is the delivery signal: 0 means the human was told, anything else
# means they were not and the sweeper should try again in 15 minutes. Do not
# exit 0 on a failed curl, or the alert will be marked delivered and go quiet.

set -uo pipefail

CONF="${SANDBROKER_NTFY_CONF:-/opt/sandbroker/etc/notify-ntfy.conf}"
# shellcheck disable=SC1090
[ -r "$CONF" ] && . "$CONF"

: "${NTFY_URL:=}"
: "${NTFY_TOKEN_FILE:=/opt/sandbroker/etc/ntfy.token}"

if [ -z "$NTFY_URL" ]; then
  echo "notify-ntfy: NTFY_URL is not set (looked in $CONF)" >&2
  exit 1
fi

auth=()
if [ -r "$NTFY_TOKEN_FILE" ]; then
  token="$(tr -d '[:space:]' < "$NTFY_TOKEN_FILE")"
  # The token goes in an argv element, not into the URL or a log line. curl
  # exposes argv to anyone who can read /proc, so this is only as private as the
  # box; that is the same trust boundary the broker already assumes.
  [ -n "$token" ] && auth=(-H "Authorization: Bearer $token")
fi

# --fail so an HTTP error becomes a non-zero exit, which is what marks the alert
# undelivered. Without it curl happily exits 0 after a 500 and the alarm goes
# quiet while looking healthy.
curl --fail --silent --show-error --max-time 10 \
  "${auth[@]}" \
  -H "Title: ${SANDBROKER_ALERT_TITLE:-SANDBROKER LEAK}" \
  -H "Priority: urgent" \
  -H "Tags: rotating_light" \
  -d "${SANDBROKER_ALERT_BODY:-a credential leaked; see sandbroker alerts}" \
  "$NTFY_URL" >/dev/null
