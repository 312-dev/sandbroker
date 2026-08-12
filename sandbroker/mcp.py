"""The MCP surface: four tools, one vault, no ceremony.

Hand-rolled JSON-RPC rather than the MCP SDK. The protocol subset a tools-only
server needs is small enough that a dependency would cost more in upgrade churn
than it saves in code, and this daemon holding vault credentials is exactly the
place to keep the dependency count at zero.
"""

import json
import traceback

from . import locks
from . import runner
from .onepassword import VaultError
from .runner import RunError

PROTOCOL_VERSION = "2025-06-18"

# JSON-RPC error codes
PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603


def tool_definitions(alias, scheme="op", default_field="credential"):
    """Tool schemas, phrased for the agent that will read them.

    The descriptions carry the operating rules -- use $VAR, never ask for a
    value, report a sighting -- because the tool list is the one piece of
    documentation an agent is guaranteed to have loaded.

    `scheme` and `default_field` describe the backend serving this alias, so the
    worked examples match it. An agent copying `op://Dev/item/credential` at a
    Keeper-backed server would be copying a reference that server refuses.
    """
    qualified = "%s://%s" % (scheme, alias)
    return [
        {
            "name": "run",
            "description": (
                "Run a shell command with %s secrets injected as environment "
                "variables, and get back its output with those secrets removed.\n\n"
                "Write the command referencing $VARNAME. You never see the value "
                "and never need to: the broker resolves each reference and puts "
                "it in the environment before the command starts.\n\n"
                "  command: curl -sS -H \"Authorization: Bearer $TOKEN\" https://api.x/v1/me\n"
                "  secrets: {\"TOKEN\": \"%s/my-item/%s\"}\n\n"
                "stdout and stderr come back scrubbed of every injected value, so "
                "verbose output that echoes a header is safe. Anything the broker "
                "did NOT inject is NOT scrubbed: if a response hands back a NEW "
                "live credential (an OAuth access token, a session cookie, a "
                "signed URL), that arrives in the clear. Call report_leak the "
                "moment you see one." % (alias, qualified, default_field)
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "description": "Shell command, run with /bin/sh -c. "
                                       "Reference secrets as $VARNAME.",
                    },
                    "secrets": {
                        "type": "object",
                        "description": "Map of environment variable name to "
                                       "reference, e.g. {\"TOKEN\": "
                                       "\"%s/item/field\"}. The item and "
                                       "field shorthand \"item/field\" also "
                                       "works. Any field of any item is "
                                       "allowed." % qualified,
                        "additionalProperties": {"type": "string"},
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Seconds before the command is killed.",
                    },
                    "cwd": {
                        "type": "string",
                        "description": "Working directory for the command.",
                    },
                    "stdin": {
                        "type": "string",
                        "description": "Text to write to the command's stdin.",
                    },
                },
                "required": ["command"],
            },
        },
        {
            "name": "list_items",
            "description": (
                "List the items in the %s vault: titles and references, never "
                "values. Start here when you do not know what is available."
                % alias
            ),
            "inputSchema": {"type": "object", "properties": {}},
        },
        {
            "name": "list_fields",
            "description": (
                "List the field names on one %s item, so you can pick the right "
                "reference. Returns labels and whether each field has a value "
                "set, never the values themselves. Any field can be used."
                % alias
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "item": {
                        "type": "string",
                        "description": "Item title or id, as shown by list_items.",
                    },
                },
                "required": ["item"],
            },
        },
        {
            "name": "report_leak",
            "description": (
                "Raise an alarm because a live credential appeared in output "
                "that was supposed to be clean. Use it the instant you see a "
                "plausible real token, key, password or session cookie you were "
                "not meant to see -- do not finish the task first, and do not "
                "wait to be sure.\n\n"
                "Describe WHERE it came from. Do NOT paste the credential into "
                "the report: the report is delivered to a phone and stored on "
                "disk, and copying the secret into it spreads the leak you are "
                "reporting.\n\n"
                "The alert repeats until a human acknowledges it on the host. "
                "You cannot acknowledge it, and you should not try."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "where": {
                        "type": "string",
                        "description": "What produced it: the command, the API, "
                                       "the field of the response.",
                    },
                    "detail": {
                        "type": "string",
                        "description": "What kind of credential it looks like "
                                       "and why you think it is live. No values.",
                    },
                },
                "required": ["where"],
            },
        },
    ]


class Server:
    """Protocol handling for one vault. Transport-agnostic on purpose: the same
    object is driven by the unix socket, by stdio and by HTTP."""

    def __init__(self, vault, config, alerter, log=None):
        self.vault = vault
        self.config = config
        self.alerter = alerter
        self.log = log or (lambda *a, **k: None)
        self.name = "sandbroker-%s" % vault.alias.lower()

    # -- dispatch -----------------------------------------------------------

    def handle(self, message):
        """Take a decoded JSON-RPC message, return a response dict or None.

        None means "this was a notification"; JSON-RPC forbids replying to one.
        """
        if not isinstance(message, dict):
            return _error(None, INVALID_REQUEST, "message must be an object")

        method = message.get("method")
        msg_id = message.get("id")
        params = message.get("params") or {}

        if method is None:
            return _error(msg_id, INVALID_REQUEST, "missing method")
        if msg_id is None and method.startswith("notifications/"):
            return None

        try:
            if method == "initialize":
                return _ok(msg_id, self._initialize(params))
            if method == "ping":
                return _ok(msg_id, {})
            if method == "tools/list":
                return _ok(msg_id, {"tools": tool_definitions(
                    self.vault.alias, self.vault.ref_scheme,
                    self.vault.default_field)})
            if method == "tools/call":
                return _ok(msg_id, self._call_tool(params))
            if method == "locks/status":
                unlocked, remaining = locks.status(self.config, self.vault.alias)
                return _ok(msg_id, {
                    "vault": self.vault.alias,
                    "required": locks.requires_unlock(self.config, self.vault.alias),
                    "unlocked": unlocked,
                    "remaining_seconds": remaining,
                    "summary": locks.describe(self.config, self.vault.alias),
                })
            if method in ("resources/list", "prompts/list"):
                # Claude Code probes these even when not advertised; an empty
                # list is friendlier than an error it has to swallow.
                key = "resources" if method.startswith("resources") else "prompts"
                return _ok(msg_id, {key: []})
        except VaultError as exc:
            return _ok(msg_id, _tool_error(str(exc)))
        except Exception:                                  # noqa: BLE001
            # Tracebacks stay in the daemon log. They can quote local paths and
            # argument fragments, and none of that needs to travel to the agent.
            self.log("unhandled error in %s:\n%s" % (method, traceback.format_exc()))
            return _error(msg_id, INTERNAL_ERROR, "internal error")

        if msg_id is None:
            return None
        return _error(msg_id, METHOD_NOT_FOUND, "unknown method %r" % method)

    def _initialize(self, params):
        # Echo the client's protocol version when it names one. Claude Code and
        # this server move on different release schedules and the tools-only
        # subset has been stable across every revision so far.
        requested = params.get("protocolVersion")
        version = requested if isinstance(requested, str) else PROTOCOL_VERSION
        return {
            "protocolVersion": version,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": self.name, "version": "1.0.0"},
            "instructions": (
                "Secrets for the %s vault. Use `run` to execute a command with a "
                "secret in its environment as $VARNAME; you will never see the "
                "value, and you do not need it. If a real credential ever appears "
                "in output, call report_leak immediately."
                % self.vault.alias
            ),
        }

    # -- tools --------------------------------------------------------------

    def _call_tool(self, params):
        name = params.get("name")
        args = params.get("arguments") or {}
        if not isinstance(args, dict):
            return _tool_error("arguments must be an object")

        handlers = {
            "run": self._tool_run,
            "list_items": self._tool_list_items,
            "list_fields": self._tool_list_fields,
            "report_leak": self._tool_report_leak,
        }
        handler = handlers.get(name)
        if handler is None:
            return _tool_error("no such tool: %r" % name)
        try:
            return handler(args)
        except (RunError, VaultError) as exc:
            return _tool_error(str(exc))

    def _tool_run(self, args):
        # The gate sits here rather than on the whole server: list_items and
        # list_fields return names only and cannot leak a value, so locking them
        # would add friction without adding safety. `run` is the only path that
        # resolves plaintext, so it is the only one worth gating.
        unlocked, _ = locks.status(self.config, self.vault.alias)
        if not unlocked:
            return _tool_error(
                "%s is LOCKED. No secret from this vault will be resolved until "
                "a human unlocks it on the host:\n"
                "    sudo sandbroker unlock %s --minutes 30\n"
                "Ask them to run it, say why you need it, then retry this exact "
                "call. Do not look for another way to the credential."
                % (self.vault.alias, self.vault.alias))

        result = runner.run(
            self.vault,
            self.config,
            command=args.get("command"),
            secrets=args.get("secrets"),
            timeout=args.get("timeout"),
            cwd=args.get("cwd"),
            stdin=args.get("stdin"),
        )
        self.log("run vault=%s exit=%s redactions=%d"
                 % (self.vault.alias, result["exit_code"], result["redactions"]))
        return _tool_json(result)

    def _tool_list_items(self, _args):
        return _tool_json({"vault": self.vault.alias,
                           "items": self.vault.list_items()})

    def _tool_list_fields(self, args):
        item = args.get("item")
        if not item:
            return _tool_error("item is required")
        return _tool_json({"vault": self.vault.alias, "item": item,
                           "fields": self.vault.list_fields(item)})

    def _tool_report_leak(self, args):
        where = args.get("where")
        if not where:
            return _tool_error("where is required: say what produced the credential")
        record, delivered = self.alerter.raise_alert(
            vault=self.vault.alias,
            where=where,
            detail=args.get("detail"),
            reported_by=self.name,
        )
        self.log("LEAK REPORTED id=%s delivered=%s where=%.200s"
                 % (record["id"], delivered, where))
        return _tool_json({
            "alert_id": record["id"],
            "delivered": delivered,
            "repeating": True,
            "message": (
                "Alert raised and it will repeat until a human acknowledges it "
                "on the host. Tell the user now, in your reply, that a "
                "credential leaked and that the alert id is %s. Stop using the "
                "affected credential." % record["id"]
                if delivered else
                "Alert RECORDED but the push could NOT be delivered. Tell the "
                "user immediately and directly in your reply -- they have not "
                "been notified any other way. Alert id %s." % record["id"]
            ),
        })


# -- JSON-RPC / MCP envelope helpers ---------------------------------------

def _ok(msg_id, result):
    return {"jsonrpc": "2.0", "id": msg_id, "result": result}


def _error(msg_id, code, message):
    return {"jsonrpc": "2.0", "id": msg_id,
            "error": {"code": code, "message": message}}


def _tool_json(payload):
    """A successful tool result. MCP carries tool output as content blocks, so
    structured data goes out as pretty JSON text the agent can read directly."""
    return {"content": [{"type": "text",
                         "text": json.dumps(payload, indent=2, sort_keys=True)}]}


def _tool_error(message):
    """A tool-level failure.

    isError keeps it inside the result rather than raising a protocol error, so
    the agent sees the reason and can correct itself instead of getting an
    opaque transport failure.
    """
    return {"isError": True, "content": [{"type": "text", "text": message}]}
