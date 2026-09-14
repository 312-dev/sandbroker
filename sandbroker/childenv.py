"""What the daemon's children get in their environment, and why.

Every child this daemon starts -- `op`, Keeper Commander, a caller's command,
the notify hook -- goes through one of a handful of small env builders. This
module holds the settings all of them must share, so a new builder cannot
quietly miss one.

NO SESSION BUS
--------------
`op` links the 99designs/keyring library, whose Linux backend talks to the
secret service over D-Bus. When DBUS_SESSION_BUS_ADDRESS is unset, the go-dbus
client does not give up: it runs `dbus-launch --autolaunch`, which starts a
private `dbus-daemon --fork --session`. That daemon calls setsid(), outlives the
`op` process that caused it, and is never anybody's child again.

The daemon user has no login session and so has no session bus, so every single
`op` invocation autolaunched a fresh one. Measured 2026-09-13: 20 brokered
list_items calls left exactly 20 orphaned dbus-daemons behind, one per call, and
a night of ordinary use had accumulated 99 of them at ~2.4 MB each. They stay
inside the unit's cgroup, so a restart does collect them and TasksMax caps the
damage, but between restarts the growth is linear in the number of calls and
the unit walks toward its task limit for no reason.

Setting the variable to an address that cannot connect is what stops it. go-dbus
autolaunches only when the variable is empty or the literal "autolaunch:"; given
anything else it tries that address, fails immediately, and reports the session
bus as unavailable -- which is the truth here. The keyring falls back to its
file backend, and nothing the broker does needs the bus: authentication is a
service-account token read from a file, not a stored login session.

Blocking a bus that never existed removes no capability, from the daemon or
from a caller's command. It only stops each of them from manufacturing one.
"""

# Absolute, and deliberately somewhere that cannot exist: ProtectSystem=strict
# leaves / read-only for this unit, so nothing can appear here later and turn a
# dead address into a live one. connect() returns ENOENT at once, with no
# timeout to wait out.
NO_SESSION_BUS = "unix:path=/nonexistent/sandbroker-has-no-session-bus"


def without_session_bus(env):
    """Point a child's D-Bus address at nothing. Mutates and returns `env`."""
    env["DBUS_SESSION_BUS_ADDRESS"] = NO_SESSION_BUS
    return env
