"""Per-vault unlock gates.

A vault marked `"require_unlock": true` resolves no secret until a human has
unlocked it, and the unlock expires on its own.

WHERE THE ENFORCEMENT ACTUALLY LIVES
------------------------------------
In the filesystem, not in this code. The marker directory is 0700 and owned by
the broker user, so writing a marker requires being root or the broker. In
practice that means `sudo sandbroker unlock <Vault>`, and typing that password IS
the approval. There is no uid check here to get wrong or to bypass: the attempt
either succeeds or fails on permissions.

That distinction matters. A gate in the MCP client, or in a Claude Code hook,
would be advisory: the sandbox grants agents write access to ~/.claude, so
anything enforced there is enforced by a file the gated party can edit. A gate in
the daemon holds regardless of which client calls, what the client is configured
to do, or what an agent rewrites.

WHAT IT IS NOT
--------------
It is not a defence against an agent that wants Production. The agent can simply
ask you to unlock, and you might say yes without reading carefully. What it buys
is that Production access becomes a deliberate, timestamped act instead of
something that happens quietly inside a task you thought was about Dev.
"""

import json
import os
import time

# A ceiling on how long an unlock can last, so "just for a minute" cannot be
# typo'd into a week.
DEFAULT_MINUTES = 30
MAX_MINUTES = 480


class LockError(Exception):
    pass


def unlocks_dir(config):
    return os.path.join(config.alerts_dir, os.pardir, "unlocks")


def _dir(config):
    return os.path.normpath(unlocks_dir(config))


def marker_path(config, vault):
    return os.path.join(_dir(config), "%s.json" % vault)


def _broker_owner(config):
    """The uid/gid the daemon runs as.

    Taken from a directory the installer created for the broker rather than
    hardcoding a user name, so this keeps working if the account is ever renamed.
    """
    for path in (config.alerts_dir,
                 os.path.dirname(os.path.normpath(config.alerts_dir)),
                 config.tokens_dir):
        try:
            info = os.stat(path)
        except OSError:
            continue
        return info.st_uid, info.st_gid
    return None


def _hand_to_broker(config, *paths):
    """Give root-created markers to the broker.

    Writing a marker requires root (that IS the gate), but READING it is the
    daemon's job, and the daemon is not root. Without this the marker lands
    root:root 0600 inside a root:root 0700 directory, the daemon cannot even
    traverse to it, status() fails closed, and `unlock` reports success while
    the vault stays locked -- a success message for something that did not work,
    which is worse than an error.
    """
    if os.geteuid() != 0:
        return                      # already running as the broker; nothing to do
    owner = _broker_owner(config)
    if owner is None:
        return
    for path in paths:
        try:
            os.chown(path, owner[0], owner[1])
        except OSError:
            pass


def requires_unlock(config, vault):
    try:
        return bool(config.vault(vault).get("require_unlock"))
    except Exception:                                   # unknown vault
        return False


def status(config, vault):
    """Return (unlocked, seconds_remaining). A vault that does not require an
    unlock is always (True, None)."""
    if not requires_unlock(config, vault):
        return True, None
    try:
        with open(marker_path(config, vault), "r", encoding="utf-8") as fh:
            until = int(json.load(fh).get("until", 0))
    except (OSError, ValueError, TypeError):
        return False, 0
    remaining = until - int(time.time())
    return (remaining > 0), max(0, remaining)


def unlock(config, vault, minutes=DEFAULT_MINUTES):
    """Write the marker. Raises LockError with an actionable message when the
    caller lacks permission, which is the normal case for a plain user and is
    exactly how the gate is enforced."""
    if not requires_unlock(config, vault):
        raise LockError("%s does not require unlocking" % vault)
    try:
        minutes = int(minutes)
    except (TypeError, ValueError):
        raise LockError("minutes must be a whole number")
    if minutes < 1 or minutes > MAX_MINUTES:
        raise LockError("minutes must be between 1 and %d" % MAX_MINUTES)

    directory = _dir(config)
    until = int(time.time()) + minutes * 60
    try:
        os.makedirs(directory, mode=0o700, exist_ok=True)
        path = marker_path(config, vault)
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump({"vault": vault, "until": until,
                       "granted": int(time.time())}, fh)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
        # Root wrote it; the broker has to be able to read it.
        _hand_to_broker(config, directory, path)
    except PermissionError:
        raise LockError(
            "permission denied writing the unlock marker.\n"
            "That is the gate working: only root or the broker user may unlock "
            "a vault.\nTry:  sudo sandbroker unlock %s --minutes %d"
            % (vault, minutes))
    except OSError as exc:
        raise LockError("could not write the unlock marker: %s" % exc)
    return until


def lock(config, vault):
    """Revoke early. Removing a marker that is not there is not an error: the
    caller asked for it to be locked, and it is."""
    try:
        os.unlink(marker_path(config, vault))
    except FileNotFoundError:
        return False
    except PermissionError:
        raise LockError("permission denied. Try:  sudo sandbroker lock %s" % vault)
    except OSError as exc:
        raise LockError("could not remove the unlock marker: %s" % exc)
    return True


def describe(config, vault):
    """One human-readable line for `sandbroker locks` and doctor."""
    if not requires_unlock(config, vault):
        return "open (no unlock required)"
    unlocked, remaining = status(config, vault)
    if not unlocked:
        return "LOCKED"
    return "unlocked, %d min left" % max(1, (remaining + 59) // 60)
