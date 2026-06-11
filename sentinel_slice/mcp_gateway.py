"""Sentinel as an MCP gateway.

The agent (Claude) speaks plain MCP. This server presents the menu's
capabilities as MCP tools; but every `tools/call` is NOT just executed — it is
turned into a Sentinel Order and run through the cashier (scope -> role ->
rate -> replay), executed by the ephemeral chef, and recorded as a signed,
hash-chained receipt. So Sentinel rides on MCP's transport and adds the two
things MCP itself doesn't do:

  1. PER-CALL governance — MCP's "always allow" is a blank check for a whole
     tool; here every call is re-checked against policy on its actual
     arguments (only threads in scope, within rate, no replay).
  2. VERIFIABLE RECEIPTS — every call, fulfilled OR refused, leaves a signed
     receipt a third party can verify. A refused call is the money artifact:
     the agent tried, and there is tamper-evident proof it was stopped.

This is a MINIMAL MCP server (stdlib JSON-RPC 2.0 over newline-delimited
stdio): it implements initialize / tools/list / tools/call / ping. It does NOT
implement resources, prompts, or sampling — it's the gateway pattern, not full
spec coverage. Flagged honestly; the governance is the point.

No new dependencies (json + stdlib). No LLM here either — the model lives in
the host; this is the counter the host's tool calls pass through.
"""

import json
import re
import sys
import uuid
from datetime import datetime, timezone

from sentinel_slice.spine.types import Order

# A protocol version to advertise if the client doesn't request one. We echo
# the client's requested version when present (common, tolerant behavior).
_DEFAULT_PROTOCOL_VERSION = "2025-06-18"


def _tool_name(capability_id: str) -> str:
    """MCP tool names are restricted; capability ids contain dots. Map
    deterministically to a safe name (and back via the live menu)."""
    return re.sub(r"[^a-zA-Z0-9_-]", "_", capability_id)


class McpGateway:
    """Translates MCP JSON-RPC requests into governed Sentinel orders.

    Holds a SentinelLoop (the cashier key, ledger, menu, chef wiring) and the
    identity the connected agent acts as (principal + role). Stateless across
    requests except for what the loop persists (ledger, rate window)."""

    def __init__(self, loop, *, principal: str, role: str,
                 server_name: str = "sentinel-loop",
                 version: str = "0.11", consumer=None) -> None:
        self._loop = loop
        self._principal = principal
        self._role = role
        self._server_name = server_name
        self._version = version
        # Optional ConsumerLoop over the SAME SentinelLoop: when present,
        # every call additionally passes the personal-permission gate
        # (Allow / Ask -> ON-DEVICE dialog / Block). This is the only viable
        # human gate here — stdio belongs to the protocol, so a terminal
        # prompt is structurally impossible.
        self._consumer = consumer

    # ---- JSON-RPC plumbing ----
    def handle(self, request) -> dict | None:
        """Handle one JSON-RPC message. Returns a response dict, or None for
        notifications (no id) which must not be answered."""
        if not isinstance(request, dict) or request.get("jsonrpc") != "2.0":
            return _error(None, -32600, "invalid JSON-RPC request")
        method = request.get("method")
        req_id = request.get("id")
        is_notification = "id" not in request

        if method == "initialize":
            return _ok(req_id, self._initialize(request.get("params") or {}))
        if method == "ping":
            return _ok(req_id, {})
        if method == "tools/list":
            return _ok(req_id, self._tools_list())
        if method == "tools/call":
            return _ok(req_id, self._tools_call(request.get("params") or {}))
        if method == "notifications/initialized" or (
            isinstance(method, str) and method.startswith("notifications/")
        ):
            return None  # notifications are not answered
        if is_notification:
            return None
        return _error(req_id, -32601, "method not found: {}".format(method))

    # ---- MCP methods ----
    def _initialize(self, params) -> dict:
        protocol = params.get("protocolVersion") or _DEFAULT_PROTOCOL_VERSION
        return {
            "protocolVersion": protocol,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": self._server_name, "version": self._version},
            "instructions": (
                "Every tool call is governed by Sentinel policy (scope, role, "
                "rate) and leaves a signed receipt. Refused calls return an "
                "error and are still recorded."
                + (" High-stakes calls additionally require the user's "
                   "on-device approval; a denial is recorded too."
                   if self._consumer is not None else "")
            ),
        }

    def _menu_map(self) -> dict:
        """Fresh tool-name -> capability map from the current (enabled) menu."""
        return {_tool_name(cap.id): cap for cap in self._loop.menu.values()}

    def _tools_list(self) -> dict:
        tools = []
        for tname, cap in sorted(self._menu_map().items()):
            props, required = {}, []
            for key in cap.inputs:
                props[key] = {
                    "type": "string",
                    "description": "scoped resource id (e.g. <owner>/<item>)"
                    if key == cap.scoped_input else key,
                }
                required.append(key)
            tools.append({
                "name": tname,
                "description": (cap.description or cap.name)
                + "  [governed: {} risk; every call scope-checked and "
                "receipted]".format(cap.risk_class),
                "inputSchema": {
                    "type": "object",
                    "properties": props,
                    "required": required,
                },
            })
        return {"tools": tools}

    def _tools_call(self, params) -> dict:
        name = params.get("name")
        arguments = params.get("arguments") or {}
        if not isinstance(arguments, dict):
            return _tool_error("arguments must be an object")
        cap = self._menu_map().get(name)
        if cap is None:
            return _tool_error("unknown tool: {}".format(name))

        order = Order(
            order_id="ord-" + uuid.uuid4().hex,
            principal=self._principal,
            role=self._role,
            capability_id=cap.id,
            args=arguments,
            nonce="nonce-" + uuid.uuid4().hex,
            ts=datetime.now(timezone.utc).isoformat(),
        )
        if self._consumer is not None:
            return self._tools_call_confirmed(order)

        outcome = self._loop.place(order)

        # Refused by the cashier: per-call governance MCP doesn't do. The
        # refusal is a signed, chained receipt — the money artifact.
        if not outcome.accepted:
            return _tool_error(
                "Refused by policy: {}. A signed rejection receipt was "
                "recorded ({}).".format(
                    outcome.reason_code, outcome.receipt.receipt_id))

        chef = self._loop.last_chef
        receipt = chef.receipt
        if chef.returncode == 0 and chef.draft_bytes is not None:
            return _fulfilled_result(chef.draft_bytes.decode("utf-8"), receipt)
        return _tool_error(
            "Execution failed ({}). Receipt: {}.".format(
                receipt.reason_code, receipt.receipt_id))

    def _tools_call_confirmed(self, order) -> dict:
        """The confirm-mode path: cashier authorization, then the personal-
        permission gate (Allow / on-device Ask / Block), then the chef. Every
        outcome — including the user saying no — is a chained receipt."""
        out = self._consumer.place(order)
        if out.status == "REJECTED_BY_POLICY":
            return _tool_error(
                "Refused by policy: {}. A signed rejection receipt was "
                "recorded ({}).".format(out.reason_code, out.receipt.receipt_id))
        if out.status == "BLOCKED_BY_USER":
            return _tool_error(
                "Blocked by the user's standing permissions (USER_BLOCKED). "
                "A signed rejection receipt was recorded ({}).".format(
                    out.receipt.receipt_id))
        if out.status == "DENIED_BY_USER":
            return _tool_error(
                "The user declined this action on-device (USER_DENIED). "
                "A signed rejection receipt was recorded ({}).".format(
                    out.receipt.receipt_id))
        if out.status == "FULFILLED":
            return _fulfilled_result(out.draft.decode("utf-8"), out.receipt)
        return _tool_error(
            "Execution failed ({}). Receipt: {}.".format(
                out.receipt.reason_code, out.receipt.receipt_id))

    # ---- stdio serve loop ----
    def serve(self, instream, outstream) -> None:
        """Read newline-delimited JSON-RPC messages from instream, write
        responses to outstream. One JSON object per line (MCP stdio
        transport). Blocks until EOF."""
        for line in instream:
            # Tolerate a UTF-8 BOM (Windows shells prepend one to the first
            # piped line) — same courtesy preferences.load extends.
            if line.startswith(chr(0xFEFF)):
                line = line[1:]
            line = line.strip()
            if not line:
                continue
            try:
                request = json.loads(line)
            except (ValueError, TypeError):
                _write(outstream, _error(None, -32700, "parse error"))
                continue
            response = self.handle(request)
            if response is not None:
                _write(outstream, response)


def _ok(req_id, result):
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def _error(req_id, code, message):
    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}


def _fulfilled_result(output: str, receipt) -> dict:
    note = (
        "[Sentinel receipt {} | status {} | result digest {}.. | "
        "verifiable in the ledger]".format(
            receipt.receipt_id, receipt.status,
            (receipt.result_digest or "")[:12]))
    return {
        "content": [
            {"type": "text", "text": output},
            {"type": "text", "text": note},
        ],
        "isError": False,
    }


def _tool_error(message):
    """An MCP tool-level error (the call ran the governance path and was
    refused/failed) — distinct from a JSON-RPC protocol error."""
    return {"content": [{"type": "text", "text": message}], "isError": True}


def _write(outstream, obj) -> None:
    outstream.write(json.dumps(obj) + "\n")
    outstream.flush()


def main(argv=None) -> int:
    import argparse

    parser = argparse.ArgumentParser(
        prog="sentinel-mcp",
        description="Sentinel MCP gateway: governs an agent's tool calls "
        "(scope/role/rate) and records a signed receipt for each. stdio.",
    )
    parser.add_argument("--principal", default="user.kenji",
                        help="identity the connected agent acts as")
    parser.add_argument("--role", default="account_manager")
    parser.add_argument("--ledger", default=None,
                        help="ledger db (default: the app home's ledger if "
                        "sentinel-init ran, else ./ledger.db)")
    parser.add_argument("--keys", default=None)
    parser.add_argument("--window", default=None)
    parser.add_argument("--home", default=None,
                        help="app home (default: platform per-user dir or "
                        "$SENTINEL_HOME)")
    parser.add_argument("--confirm", action="store_true",
                        help="route every call through the personal-"
                        "permission gate: Ask capabilities pop an ON-DEVICE "
                        "dialog (requires a display; refuses to start "
                        "without one — the gate never fails open)")
    args = parser.parse_args(argv)

    from sentinel_slice.apphome import resolve_runtime_paths
    from sentinel_slice.loop import build_default
    from sentinel_slice.menu.catalog import CUSTOM_CAPABILITIES_DIR, load_catalog

    # Explicit args win; an initialized app home (sentinel-init) provides the
    # defaults; a plain dev checkout keeps its pre-v0.10 behavior.
    paths = resolve_runtime_paths(
        ledger=args.ledger, keys=args.keys, window=args.window, home=args.home)
    if paths.initialized:
        # stdout is the JSON-RPC channel — operational notes go to stderr.
        print("sentinel-mcp: using app home " + paths.home, file=sys.stderr)

    try:
        loop = build_default(
            paths.ledger, window_root=paths.window_root, keys_dir=paths.keys_dir)
    except FileNotFoundError as exc:
        print(exc, file=sys.stderr)
        return 2
    # Expose operator-created capabilities as tools too.
    loop.menu = load_catalog(
        custom_dir=paths.custom_capabilities_dir or CUSTOM_CAPABILITIES_DIR)

    consumer = None
    if args.confirm:
        import os

        from sentinel_slice.consumer.loop import ConsumerLoop
        from sentinel_slice.consumer.native import NativeApprover, native_available
        from sentinel_slice.consumer.preferences import Preferences

        # stdio belongs to JSON-RPC, so the ONLY possible prompt is an
        # on-device dialog. No display -> refuse to start rather than fail
        # open (silently allowing) or fail weird (minting USER_DENIED
        # receipts no user ever saw).
        if not native_available():
            print(
                "sentinel-mcp: --confirm needs a display for on-device "
                "approval dialogs and none is available; refusing to start "
                "(the confirmation gate must not fail open).",
                file=sys.stderr)
            return 2
        prefs_path = paths.preferences_path or os.path.abspath(
            "sentinel_permissions.json")
        consumer = ConsumerLoop(
            loop, approver=NativeApprover(),
            preferences=Preferences.load(prefs_path))
        print("sentinel-mcp: on-device confirmation gate active "
              "(permissions: " + prefs_path + ")", file=sys.stderr)

    gateway = McpGateway(loop, principal=args.principal, role=args.role,
                         consumer=consumer)
    # MCP stdio is UTF-8 JSON; make the streams explicit.
    try:
        sys.stdin.reconfigure(encoding="utf-8")
        sys.stdout.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass
    gateway.serve(sys.stdin, sys.stdout)
    return 0


def cli() -> None:
    sys.exit(main())


if __name__ == "__main__":
    sys.exit(main())
