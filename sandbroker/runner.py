"""Run a command with secrets in its environment, return scrubbed output.

The shape of the deal:

    command  "curl -sS -H \"Authorization: Bearer $TOKEN\" https://api/x"
    secrets  {"TOKEN": "op://Dev/mercury/credential"}

The broker resolves each ref, puts the value in the child's environment under
the name the caller chose, runs the command, and scrubs every resolved value out
of stdout and stderr before returning them.

WHY THE ENVIRONMENT AND NOT THE COMMAND STRING
----------------------------------------------
Substituting a secret into the command text would put it in the child's argv,
and /proc/<pid>/cmdline is world-readable on Linux -- any uid on the box could
poll for it. /proc/<pid>/environ is 0400 owned by the process user. The
environment is the only channel here that is not observable by the agent's own
uid, so it is the only one used.

A consequence worth stating: the agent writes `$TOKEN` itself and never holds
the value, so it cannot get the substitution wrong in a way that leaks. There is
nothing to get wrong.
"""

import errno
import os
import signal
import subprocess

from .redact import HeuristicRedactor, Redactor
from .onepassword import VaultError

# Environment variable names the caller may bind a secret to. Restrictive on
# purpose: PATH, LD_PRELOAD and friends must not be assignable, and a name that
# is not a plain identifier cannot be referenced from the shell anyway.
import re
ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")

RESERVED_ENV = frozenset({
    "PATH", "HOME", "SHELL", "IFS", "ENV", "BASH_ENV", "PWD", "USER", "LOGNAME",
    "LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT", "PYTHONPATH", "PYTHONSTARTUP",
    "OP_SERVICE_ACCOUNT_TOKEN", "OP_CONNECT_TOKEN",
})

MAX_SECRETS = 16
MAX_COMMAND_CHARS = 16384


class RunError(Exception):
    pass


def _base_env():
    """A clean, small environment for the child.

    Built from scratch rather than inherited: the daemon's own environment holds
    the 1Password service-account token, and nothing downstream should ever see
    it. Only what a command plausibly needs to function is passed through.

    A Keeper-backed daemon keeps its credential in a file rather than the
    environment, which this does nothing about -- the command runs as the broker
    user and could read that file. The redactor is what covers it.
    """
    env = {
        "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        "HOME": os.environ.get("HOME", "/tmp"),
        "LANG": os.environ.get("LANG", "C.UTF-8"),
        "LC_ALL": os.environ.get("LC_ALL", "C.UTF-8"),
        "TERM": "dumb",
        "TMPDIR": os.environ.get("TMPDIR", "/tmp"),
    }
    env.pop("OP_SERVICE_ACCOUNT_TOKEN", None)
    return env


def _validate(command, secrets, timeout, config):
    if not isinstance(command, str) or not command.strip():
        raise RunError("command must be a non-empty string")
    if len(command) > MAX_COMMAND_CHARS:
        raise RunError("command is longer than %d characters" % MAX_COMMAND_CHARS)
    if not isinstance(secrets, dict):
        raise RunError("secrets must be an object of {ENV_NAME: reference}")
    if len(secrets) > MAX_SECRETS:
        raise RunError("at most %d secrets per call" % MAX_SECRETS)
    for name in secrets:
        if not ENV_NAME_RE.match(name or ""):
            raise RunError("%r is not a usable environment variable name" % name)
        if name.upper() in RESERVED_ENV:
            raise RunError("%s is reserved and cannot hold a secret" % name)
    limit = config.max_timeout
    if timeout is not None:
        try:
            timeout = int(timeout)
        except (TypeError, ValueError):
            raise RunError("timeout must be a whole number of seconds")
        if timeout < 1 or timeout > limit:
            raise RunError("timeout must be between 1 and %d seconds" % limit)
    return timeout or config.default_timeout


def run(vault, config, command, secrets=None, timeout=None, cwd=None, stdin=None,
        heuristic=True):
    """Resolve, execute, scrub. Returns a dict safe to hand back to the agent.

    `heuristic` runs the Tier 2 pass over what Tier 1 has already cleaned. It
    defaults on because a minted credential is invisible to Tier 1, having
    never been injected. Callers that CONSUME the output inside the broker
    rather than returning it -- `store`, which writes stdout straight into the
    vault -- must pass False: scrubbing there would store the placeholder
    instead of the credential.
    """
    secrets = secrets or {}
    timeout = _validate(command, secrets, timeout, config)

    if cwd is not None and not os.path.isdir(cwd):
        raise RunError("cwd %r is not a directory" % cwd)

    # Resolve first: if a ref is wrong, fail before running anything at all.
    resolved = {}
    for name, ref in secrets.items():
        try:
            resolved[name] = vault.read(ref)
        except VaultError as exc:
            raise RunError("could not resolve %s (%s): %s" % (name, ref, exc))

    # The backend's own credential is not a requested secret, but it opens every
    # one of them, so it goes into the scrubber regardless. 1Password's is a
    # single token and arrives through service_account_token(). Keeper's is a
    # JSON document holding several strings, each of which opens the vault on
    # its own, so that backend hands over a labelled set and the single-value
    # hook is skipped as a duplicate.
    scrub_targets = dict(resolved)
    scrub_targets.update(getattr(vault, "auth_secrets", dict)())
    sa_token = vault.service_account_token()
    if sa_token and sa_token not in scrub_targets.values():
        scrub_targets["OP_SERVICE_ACCOUNT_TOKEN"] = sa_token

    env = _base_env()
    env.update(resolved)

    redactor = Redactor(scrub_targets)
    cap = config.max_output_bytes

    try:
        proc = subprocess.Popen(
            ["/bin/sh", "-c", command],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            cwd=cwd,
            # Own process group, so a timeout kills the whole tree rather than
            # just the shell and orphaning whatever it spawned.
            start_new_session=True,
        )
    except OSError as exc:
        raise RunError("could not start the command: %s" % exc.strerror)

    timed_out = False
    try:
        out, err = proc.communicate(
            input=(stdin or "").encode("utf-8") if stdin else None,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        timed_out = True
        _kill_group(proc)
        out, err = proc.communicate()
    finally:
        # Drop the plaintext as soon as the child has it. Python strings are
        # immutable so this is not a wipe, only a shortened lifetime -- worth
        # doing, not worth claiming as a guarantee.
        resolved.clear()
        env.clear()

    truncated = len(out) > cap or len(err) > cap
    stdout = redactor.clean(out[:cap])
    stderr = redactor.clean(err[:cap])

    # Tier 2 runs second and only over what Tier 1 has already cleaned, so a
    # declared secret is removed by the exact-match rule and never reaches the
    # guesser. The two markers stay distinguishable in the output, which is the
    # point: a reader must always be able to tell a guarantee from a guess.
    heuristic_hits = 0
    if heuristic and getattr(config, "heuristic_scan", True):
        guesser = HeuristicRedactor(
            entropy_scan=bool(getattr(config, "heuristic_entropy_scan", False)))
        stdout = guesser.scrub(stdout)
        stderr = guesser.scrub(stderr)
        heuristic_hits = guesser.hits

    return {
        "exit_code": -1 if timed_out else proc.returncode,
        "stdout": stdout,
        "stderr": stderr,
        "timed_out": timed_out,
        "truncated": truncated,
        "redactions": redactor.hits,
        # Non-zero means something credential-shaped that the broker never
        # injected reached the boundary. Unlike `redactions`, that is worth
        # reporting rather than shrugging at.
        "heuristic_hits": heuristic_hits,
    }


def _kill_group(proc):
    """SIGKILL the child's whole process group; it is already past its deadline."""
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError) as exc:
        if getattr(exc, "errno", None) != errno.ESRCH:
            try:
                proc.kill()
            except OSError:
                pass
