#!/usr/bin/env bash
#
# Install sandbroker. Run as root from a checkout:
#
#     sudo ./install.sh
#
# Idempotent. Safe to re-run after every pull -- that is the intended upgrade
# path, and there is no separate upgrade script to keep in sync.
#
# WHAT IT NEVER TOUCHES
#   $VAR_DIR/tokens        the 1Password service-account tokens
#   $ETC_DIR/ntfy.token    the alert transport token
# Those are provisioned once, by hand, and losing them means re-issuing service
# accounts. Nothing here writes or deletes them, on any code path.

set -euo pipefail

PREFIX="${PREFIX:-/opt/sandbroker}"
LIB_DIR="$PREFIX/lib"
ETC_DIR="$PREFIX/etc"
VAR_DIR="$PREFIX/var"
RUN_DIR="$PREFIX/run"
BIN="/usr/local/bin/sandbroker"
UNIT_DIR="/etc/systemd/system"
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

BROKER_USER="sandbroker"
CLIENT_GROUP="claude-broker"

say()  { printf '\033[1m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m warn\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31mfatal\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "run as root (sudo ./install.sh)"
command -v systemctl >/dev/null || die "systemd is required"
command -v python3   >/dev/null || die "python3 is required"

# ---------------------------------------------------------------- accounts --
say "accounts"
getent group "$CLIENT_GROUP" >/dev/null || groupadd --system "$CLIENT_GROUP"
if ! id "$BROKER_USER" >/dev/null 2>&1; then
  useradd --system --home-dir "$PREFIX" --shell /usr/sbin/nologin "$BROKER_USER"
fi
# The broker must be able to hand its socket to the client group.
usermod -aG "$CLIENT_GROUP" "$BROKER_USER"

# Whoever invoked sudo is the human who will use this, so put them in the group
# now rather than leaving a puzzling permission error for later.
CALLER="${SUDO_USER:-}"
if [ -n "$CALLER" ] && ! id -nG "$CALLER" | tr ' ' '\n' | grep -qx "$CLIENT_GROUP"; then
  usermod -aG "$CLIENT_GROUP" "$CALLER"
  warn "added $CALLER to $CLIENT_GROUP -- log out and back in for it to take effect"
fi

# ------------------------------------------------------------- retire v0 ----
# The proof-of-concept daemon and its grant-apply watcher. Stopped and disabled,
# never deleted: its var/ still holds the tokens this install reuses.
for unit in sandbrokerd.service sandbroker-grant-apply.path sandbroker-grant-apply.service; do
  if systemctl list-unit-files "$unit" >/dev/null 2>&1 && \
     systemctl is-enabled "$unit" >/dev/null 2>&1; then
    say "retiring $unit (proof-of-concept)"
    systemctl disable --now "$unit" >/dev/null 2>&1 || true
  fi
done
# Its socket outlives the daemon and looks like a live listener to anyone
# reading the directory. Only removed once nothing is listening on it.
if [ -S "$RUN_DIR/sandbroker.sock" ] && ! systemctl is-active --quiet sandbrokerd.service; then
  rm -f "$RUN_DIR/sandbroker.sock"
fi

# ------------------------------------------------------------------ layout --
say "layout under $PREFIX"
install -d -m 0755 -o root           -g root          "$PREFIX" "$ETC_DIR"
install -d -m 0750 -o "$BROKER_USER" -g "$CLIENT_GROUP" "$RUN_DIR"
install -d -m 0700 -o "$BROKER_USER" -g "$BROKER_USER"  "$VAR_DIR"
install -d -m 0700 -o "$BROKER_USER" -g "$BROKER_USER"  "$VAR_DIR/alerts"
# Created only if absent. If it exists it already holds the tokens, and its
# ownership and mode are left exactly as they are.
[ -d "$VAR_DIR/tokens" ] || \
  install -d -m 0700 -o "$BROKER_USER" -g "$BROKER_USER" "$VAR_DIR/tokens"

# ------------------------------------------------------------------- code ----
say "code"
rm -rf "$LIB_DIR/sandbroker"
install -d -m 0755 "$LIB_DIR/sandbroker"
install -m 0644 "$SRC"/sandbroker/*.py "$LIB_DIR/sandbroker/"
# Remove first rather than installing over. The proof-of-concept left $BIN as a
# SYMLINK into its virtualenv, and writing through a symlink would silently
# update the link's target instead of replacing the link -- leaving a working
# command with a baffling layout that breaks the day the venv is cleaned up.
rm -f "$BIN" /usr/local/bin/sandbroker-register-mcp
install -m 0755 "$SRC/bin/sandbroker" "$BIN"
# Run by the human, not by root: it edits ~/.claude.json.
install -m 0755 "$SRC/bin/sandbroker-register-mcp" /usr/local/bin/sandbroker-register-mcp
chown -R root:root "$LIB_DIR"

# ----------------------------------------------------------------- config ----
CONFIG="$ETC_DIR/sandbroker.json"
if [ -f "$CONFIG" ]; then
  say "config exists, leaving it alone ($CONFIG)"
else
  say "config -> $CONFIG"
  install -m 0444 -o root -g root "$SRC/etc/sandbroker.json.example" "$CONFIG"
  warn "review $CONFIG: vault names, ntfy url, and bind"
fi

# op has to be reachable by a service that cannot traverse a private home
# directory, so it lives in /usr/local/bin. Copy, never symlink.
if [ ! -x /usr/local/bin/op ]; then
  FOUND="$(command -v op || true)"
  if [ -n "$FOUND" ] && [ "$FOUND" != /usr/local/bin/op ]; then
    say "copying op to /usr/local/bin/op (a service cannot read a 0750 home)"
    install -m 0755 -o root -g root "$FOUND" /usr/local/bin/op
  else
    warn "no 'op' binary found -- install the 1Password CLI to /usr/local/bin/op"
  fi
fi

# ------------------------------------------------------------------ units ----
say "units"
install -m 0644 "$SRC/systemd/sandbroker@.service"      "$UNIT_DIR/"
install -m 0644 "$SRC/systemd/sandbroker-sweep.service" "$UNIT_DIR/"
install -m 0644 "$SRC/systemd/sandbroker-sweep.timer"   "$UNIT_DIR/"
# A USER unit, so it goes in the system-wide user-unit directory and each human
# enables it for themselves. It must not run as root: the queue it owns is
# reached by uid, and that uid has to be the person running the agent.
install -d -m 0755 /etc/systemd/user
install -m 0644 "$SRC/systemd/sandbroker-bridge.service" /etc/systemd/user/
systemctl daemon-reload

# One service per vault, read straight from the config so adding a vault is a
# config edit plus a re-run, with no unit list to keep in sync by hand.
VAULTS="$(python3 -c '
import json, sys
with open(sys.argv[1]) as fh:
    print(" ".join(sorted(json.load(fh).get("vaults", {}))))' "$CONFIG")"
[ -n "$VAULTS" ] || die "no vaults in $CONFIG"

for vault in $VAULTS; do
  token_name="$(python3 -c '
import json, sys
with open(sys.argv[1]) as fh:
    print(json.load(fh)["vaults"][sys.argv[2]]["token"])' "$CONFIG" "$vault")"
  if [ ! -f "$VAR_DIR/tokens/$token_name.token" ]; then
    warn "vault $vault has no service-account token installed; skipping"
    systemctl disable --now "sandbroker@$vault" >/dev/null 2>&1 || true
    continue
  fi
  say "starting sandbroker@$vault"
  systemctl enable "sandbroker@$vault" >/dev/null
  systemctl restart "sandbroker@$vault"
done

systemctl enable --now sandbroker-sweep.timer >/dev/null

# ------------------------------------------------------------------ verify ---
sleep 1
say "verify"
"$BIN" doctor || true

# The bridge belongs to the human, so enable it for whoever invoked sudo rather
# than making them remember a second command.
if [ -n "$CALLER" ]; then
  CALLER_UID="$(id -u "$CALLER")"
  if [ -d "/run/user/$CALLER_UID" ]; then
    say "enabling the sandboxed-client bridge for $CALLER"
    loginctl enable-linger "$CALLER" >/dev/null 2>&1 || true
    sudo -u "$CALLER" \
      XDG_RUNTIME_DIR="/run/user/$CALLER_UID" \
      DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$CALLER_UID/bus" \
      systemctl --user enable --now sandbroker-bridge.service >/dev/null 2>&1 \
      || warn "could not enable it automatically; run: systemctl --user enable --now sandbroker-bridge"
  else
    warn "no user session for $CALLER; run: systemctl --user enable --now sandbroker-bridge"
  fi
fi

cat <<'DONE'

Next, as your normal user (not root):

    sandbroker-register-mcp          # add one MCP server per vault to Claude Code
    sandbroker doctor --deep         # daemons up, vaults resolving

If you were just added to the claude-broker group, log out and back in first.
DONE
