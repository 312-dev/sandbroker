"""Configuration: where the vaults are, where the sockets go, where alerts fire.

One JSON file, root-owned and world-readable. It holds no secrets -- only vault
names, token FILENAMES, ports and paths -- so it is safe for the agent to read,
and reading it is how the agent learns what exists.
"""

import json
import os

DEFAULT_PATH = os.environ.get("SANDBROKER_CONFIG", "/opt/sandbroker/etc/sandbroker.json")

# Backends a vault may be served from. A vault that names none is 1Password, so
# every config written before Keeper existed keeps working untouched.
BACKENDS = ("1password", "keeper")
DEFAULT_BACKEND = "1password"

DEFAULTS = {
    "op_bin": "/usr/local/bin/op",
    "keeper_bin": "/usr/local/bin/keeper",
    # Keeper Commander rotates its clone code and caches the vault as it runs,
    # so unlike `op` it needs somewhere writable of its own.
    "keeper_state_dir": "/opt/sandbroker/var/keeper",
    "tokens_dir": "/opt/sandbroker/var/tokens",
    "socket_dir": "/opt/sandbroker/run",
    "alerts_dir": "/opt/sandbroker/var/alerts",
    "socket_group": "claude-broker",
    # Absent means "no network listener at all", which is the default and the
    # tightest setting. See bind_address() for why an address is refused unless
    # it is loopback or tailnet.
    "bind": None,
    # How a leak alert reaches a human. A string runs under /bin/sh, a list is
    # argv. The alert arrives on stdin as JSON and in SANDBROKER_ALERT_* env
    # vars; exit zero means delivered. Absent means alerts are recorded to disk
    # and nothing is sent, which `doctor` reports as a problem because a silent
    # alarm is worse than no alarm.
    "notify_command": None,
    "max_output_bytes": 1048576,
    "default_timeout": 60,
    "max_timeout": 600,
    "vaults": {},
}


class ConfigError(Exception):
    pass


# Keys that used to mean something and no longer do. Leaving one in place is not
# fatal -- refusing to start every vault over a notification setting would be a
# worse failure than the one it prevents -- but it MUST be loud, because the
# symptom is an alarm that has quietly stopped ringing.
RETIRED_KEYS = {
    "ntfy_url": "replaced by notify_command; see contrib/notify-ntfy.sh",
    "ntfy_token_file": "replaced by notify_command; see contrib/notify-ntfy.sh",
}


# Tailscale hands out 100.64.0.0/10 (CGNAT). Loopback is tighter still. Anything
# else is a public or LAN interface and this daemon will not sit on one: there is
# no authentication in front of it by design, so reachability IS authorisation.
def _is_tailnet(addr):
    if not addr.startswith("100."):
        return False
    try:
        second = int(addr.split(".")[1])
    except (IndexError, ValueError):
        return False
    return 64 <= second <= 127


def _is_loopback(addr):
    return addr == "127.0.0.1" or addr == "::1" or addr.startswith("127.")


class Config:
    def __init__(self, data, path=DEFAULT_PATH):
        self.path = path
        merged = dict(DEFAULTS)
        merged.update(data or {})
        self._d = merged
        self.retired = sorted(key for key in (data or {}) if key in RETIRED_KEYS)
        if not isinstance(self.vaults, dict) or not self.vaults:
            raise ConfigError("config has no vaults")
        for alias, spec in self.vaults.items():
            for key in ("vault", "token"):
                if not spec.get(key):
                    raise ConfigError("vault %s is missing %r" % (alias, key))
            backend = spec.get("backend") or DEFAULT_BACKEND
            if backend not in BACKENDS:
                raise ConfigError("vault %s names backend %r, which does not "
                                  "exist (known: %s)"
                                  % (alias, backend, ", ".join(BACKENDS)))

    def __getattr__(self, name):
        try:
            return self._d[name]
        except KeyError:
            raise AttributeError(name)

    # -- vault lookup -------------------------------------------------------

    def vault(self, alias):
        try:
            return self.vaults[alias]
        except KeyError:
            raise ConfigError("unknown vault %r (known: %s)"
                              % (alias, ", ".join(sorted(self.vaults))))

    def backend(self, alias):
        return self.vault(alias).get("backend") or DEFAULT_BACKEND

    def token_file(self, alias):
        """The file that authenticates this vault's backend.

        One name for two things: a 1Password service-account token, or a Keeper
        Commander config. Both are the single credential the daemon opens, and
        both live under the same 0700 directory, so they share the accessor.
        """
        return os.path.join(self.tokens_dir, "%s.token" % self.vault(alias)["token"])

    def socket_path(self, alias):
        return os.path.join(self.socket_dir, "%s.sock" % alias.lower())

    def port(self, alias):
        return self.vault(alias).get("port")

    # -- listener policy ----------------------------------------------------

    def bind_address(self):
        """The address the HTTP listener may use, or None for socket-only.

        Refusing anything outside loopback/tailnet is the entire network access
        control. There is no token and no login on the HTTP surface: if you can
        route to it you can use it, so the daemon must never be routable from
        somewhere the operator did not intend.
        """
        addr = self._d.get("bind")
        if not addr:
            return None
        if not (_is_loopback(addr) or _is_tailnet(addr)):
            raise ConfigError(
                "refusing to bind %s: only loopback or tailnet (100.64.0.0/10) "
                "addresses are allowed, because the HTTP surface is "
                "unauthenticated by design" % addr)
        return addr


def load(path=None):
    path = path or DEFAULT_PATH
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        raise ConfigError("no config at %s" % path)
    except ValueError as exc:
        raise ConfigError("config at %s is not valid JSON: %s" % (path, exc))
    return Config(data, path)
