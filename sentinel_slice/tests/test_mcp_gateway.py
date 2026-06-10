"""Sentinel-as-MCP-gateway (v0.9).

The gateway speaks MCP JSON-RPC, but every tools/call is governed and
receipted. Tests pin: protocol handshake, tools derived from the menu, a
fulfilled call returns the output AND a receipt reference with a FULFILLED
ledger row, and — the differentiators MCP lacks — an out-of-scope call and an
ungranted-role call are REFUSED with a chained rejection receipt (per-call
governance + verifiable evidence). Plus notifications get no reply, unknown
methods are JSON-RPC errors, the stdio loop works, and the chain the gateway
produced verifies standalone.
"""

import io
import json
import subprocess
import sys
import uuid
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sentinel_slice.attestor.mock import MockAttestor
from sentinel_slice.cashier.policy import Policy, PolicySet
from sentinel_slice.cashier.store import CashierStore
from sentinel_slice.ledger.receipts import Ledger
from sentinel_slice.loop import SentinelLoop
from sentinel_slice.mcp_gateway import McpGateway, _tool_name
from sentinel_slice.menu.catalog import load_catalog
from sentinel_slice.spine.types import Order  # noqa: F401 (kept for parity)

SENTINEL_DIR = Path(__file__).resolve().parents[1]
REPO_ROOT = Path(__file__).resolve().parents[2]
MAILBOX = SENTINEL_DIR / "kitchen" / "fixtures" / "mailbox"
VERIFIER = SENTINEL_DIR / "verify_ledger.py"

DRAFT = "cap.email.draft_reply.v1"
PAY = "cap.payment.initiate.v1"
DRAFT_TOOL = _tool_name(DRAFT)


def _gateway(tmp_path, allowed=(DRAFT,)):
    priv = Ed25519PrivateKey.generate()
    pub = tmp_path / "pub.pem"
    pub.write_bytes(priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo))
    loop = SentinelLoop(
        private_key=priv, ledger=Ledger(str(tmp_path / "ledger.db"), priv),
        menu=load_catalog(),
        policy_set=PolicySet([Policy(role="account_manager",
                                     allowed_capabilities=tuple(allowed),
                                     rate_limit_per_hour=5)]),
        store=CashierStore(), public_key_pem_path=str(pub),
        fixtures_root=str(MAILBOX), attestor=MockAttestor(),
        window_root=str(tmp_path / "win"))
    gw = McpGateway(loop, principal="user.kenji", role="account_manager")
    return gw, pub


def _req(method, params=None, req_id=1):
    r = {"jsonrpc": "2.0", "id": req_id, "method": method}
    if params is not None:
        r["params"] = params
    return r


def test_initialize_handshake(tmp_path):
    gw, _ = _gateway(tmp_path)
    resp = gw.handle(_req("initialize", {"protocolVersion": "2025-06-18"}))
    assert resp["id"] == 1
    assert resp["result"]["protocolVersion"] == "2025-06-18"
    assert resp["result"]["serverInfo"]["name"] == "sentinel-loop"
    assert "tools" in resp["result"]["capabilities"]


def test_tools_list_from_menu(tmp_path):
    gw, _ = _gateway(tmp_path)
    tools = gw.handle(_req("tools/list"))["result"]["tools"]
    by_name = {t["name"]: t for t in tools}
    assert DRAFT_TOOL in by_name
    schema = by_name[DRAFT_TOOL]["inputSchema"]
    assert schema["required"] == ["thread_id"]
    assert "governed" in by_name[DRAFT_TOOL]["description"]


def test_tools_call_fulfilled_returns_output_and_receipt(tmp_path):
    gw, _ = _gateway(tmp_path)
    resp = gw.handle(_req("tools/call", {
        "name": DRAFT_TOOL,
        "arguments": {"thread_id": "user.kenji/t-001"},
    }))
    result = resp["result"]
    assert result["isError"] is False
    assert result["content"][0]["text"].startswith("Re: Acme Corp Q3 onboarding")
    assert "Sentinel receipt" in result["content"][1]["text"]
    # A FULFILLED receipt is on the ledger.
    rows = gw._loop.read_receipts()
    assert len(rows) == 1 and rows[-1].status == "FULFILLED"


def test_out_of_scope_call_refused_with_receipt(tmp_path):
    """MCP's 'allow tool' is a blank check; the gateway checks THIS call's
    args. Another user's thread is refused, and the refusal is receipted."""
    gw, _ = _gateway(tmp_path)
    resp = gw.handle(_req("tools/call", {
        "name": DRAFT_TOOL,
        "arguments": {"thread_id": "user.victim/t-009"},
    }))
    result = resp["result"]
    assert result["isError"] is True
    assert "OUT_OF_SCOPE" in result["content"][0]["text"]
    rows = gw._loop.read_receipts()
    assert len(rows) == 1
    assert rows[-1].status == "REJECTED" and rows[-1].reason_code == "OUT_OF_SCOPE"


def test_ungranted_capability_refused_with_receipt(tmp_path):
    # Payment exists in the menu (a tool) but the role isn't granted it.
    gw, _ = _gateway(tmp_path, allowed=(DRAFT,))
    resp = gw.handle(_req("tools/call", {
        "name": _tool_name(PAY),
        "arguments": {"thread_id": "user.kenji/t-001"},
    }))
    result = resp["result"]
    assert result["isError"] is True
    assert "ROLE_NOT_PERMITTED" in result["content"][0]["text"]
    assert gw._loop.read_receipts()[-1].reason_code == "ROLE_NOT_PERMITTED"


def test_rate_limit_refused_with_receipt(tmp_path):
    gw, _ = _gateway(tmp_path)  # rate_limit_per_hour=5
    for _ in range(5):
        ok = gw.handle(_req("tools/call", {
            "name": DRAFT_TOOL, "arguments": {"thread_id": "user.kenji/t-001"}}))
        assert ok["result"]["isError"] is False
    sixth = gw.handle(_req("tools/call", {
        "name": DRAFT_TOOL, "arguments": {"thread_id": "user.kenji/t-001"}}))
    assert sixth["result"]["isError"] is True
    assert "RATE_LIMITED" in sixth["result"]["content"][0]["text"]


def test_unknown_tool_is_tool_error(tmp_path):
    gw, _ = _gateway(tmp_path)
    resp = gw.handle(_req("tools/call", {"name": "no_such_tool", "arguments": {}}))
    assert resp["result"]["isError"] is True
    assert "unknown tool" in resp["result"]["content"][0]["text"]


def test_notifications_get_no_response(tmp_path):
    gw, _ = _gateway(tmp_path)
    assert gw.handle({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None


def test_unknown_method_is_jsonrpc_error(tmp_path):
    gw, _ = _gateway(tmp_path)
    resp = gw.handle(_req("does/not/exist"))
    assert resp["error"]["code"] == -32601


def test_stdio_serve_loop(tmp_path):
    gw, _ = _gateway(tmp_path)
    instream = io.StringIO(
        json.dumps(_req("initialize", {}, 1)) + "\n"
        + json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n"
        + json.dumps(_req("tools/call", {
            "name": DRAFT_TOOL, "arguments": {"thread_id": "user.kenji/t-001"}}, 2)) + "\n"
    )
    out = io.StringIO()
    gw.serve(instream, out)
    lines = [ln for ln in out.getvalue().splitlines() if ln.strip()]
    # initialize -> 1 response, notification -> none, tools/call -> 1 response.
    assert len(lines) == 2
    assert json.loads(lines[0])["id"] == 1
    assert json.loads(lines[1])["id"] == 2


def test_chain_verifies_after_gateway_calls(tmp_path):
    gw, pub = _gateway(tmp_path)
    gw.handle(_req("tools/call", {
        "name": DRAFT_TOOL, "arguments": {"thread_id": "user.kenji/t-001"}}))
    gw.handle(_req("tools/call", {
        "name": DRAFT_TOOL, "arguments": {"thread_id": "user.victim/x"}}))  # refused
    proc = subprocess.run(
        [sys.executable, str(VERIFIER), str(tmp_path / "ledger.db"), str(pub)],
        capture_output=True, text=True, cwd=str(REPO_ROOT))
    assert proc.returncode == 0, (proc.stdout, proc.stderr)
    assert proc.stdout.strip() == "OK verified=2"
