# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Yasir Qureshi
"""MCP gateway confirm mode (v0.11) — on-device approval inside the gateway.

The agent speaks MCP; a high-stakes tools/call now pops the user's on-device
dialog before the chef runs. Pinned: a denied dialog returns an MCP tool
error naming USER_DENIED and the exact receipt, and the ledger row matches; a
BLOCK preference auto-denies with NO dialog (USER_BLOCKED); an allowed dialog
fulfills with the draft + receipt note; 'Always allow' persists to the
permissions file and the next call shows no dialog; low-stakes calls never
prompt; the cashier still runs FIRST (policy refusals never reach the
dialog); the whole confirm-mode session verifies standalone; and --confirm
startup fails CLOSED (exit 2) when no display is available.
"""

import json
import subprocess
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sentinel_slice.attestor.mock import MockAttestor
from sentinel_slice.cashier.policy import Policy, PolicySet
from sentinel_slice.cashier.store import CashierStore
from sentinel_slice.consumer.loop import ConsumerLoop
from sentinel_slice.consumer.native import (
    ALLOW_ALWAYS,
    ALLOW_ONCE,
    DENY,
    NativeApprover,
)
from sentinel_slice.consumer.preferences import BLOCK, Preferences
from sentinel_slice.ledger.receipts import Ledger
from sentinel_slice.loop import SentinelLoop
from sentinel_slice.mcp_gateway import McpGateway, _tool_name
from sentinel_slice.menu.catalog import load_catalog

SENTINEL_DIR = Path(__file__).resolve().parents[1]
REPO_ROOT = Path(__file__).resolve().parents[2]
MAILBOX = SENTINEL_DIR / "kitchen" / "fixtures" / "mailbox"
VERIFIER = SENTINEL_DIR / "verify_ledger.py"

DRAFT = "cap.email.draft_reply.v1"
PAY = "cap.payment.initiate.v1"


def _confirm_gateway(tmp_path, *, verdicts, preferences=None):
    """A gateway in confirm mode whose 'dialog' replays `verdicts` in order
    (failing loudly if asked more often)."""
    priv = Ed25519PrivateKey.generate()
    pub = tmp_path / "pub.pem"
    pub.write_bytes(priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo))
    loop = SentinelLoop(
        private_key=priv, ledger=Ledger(str(tmp_path / "ledger.db"), priv),
        menu=load_catalog(),
        policy_set=PolicySet([Policy(role="account_manager",
                                     allowed_capabilities=(DRAFT, PAY),
                                     rate_limit_per_hour=20)]),
        store=CashierStore(), public_key_pem_path=str(pub),
        fixtures_root=str(MAILBOX), attestor=MockAttestor(),
        window_root=str(tmp_path / "win"))
    queue = list(verdicts)

    def scripted_dialog(_spec):
        if not queue:
            raise AssertionError("dialog shown more often than expected")
        return queue.pop(0)

    approver = NativeApprover(show_fn=scripted_dialog)
    consumer = ConsumerLoop(loop, approver=approver, preferences=preferences)
    gw = McpGateway(loop, principal="user.kenji", role="account_manager",
                    consumer=consumer)
    return gw, approver, pub


def _call(gw, capability_id, thread="user.kenji/t-001"):
    return gw.handle({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": _tool_name(capability_id),
                   "arguments": {"thread_id": thread}}})["result"]


def test_denied_dialog_is_tool_error_with_user_denied_receipt(tmp_path):
    gw, approver, _ = _confirm_gateway(tmp_path, verdicts=[DENY])

    result = _call(gw, PAY)

    rows = gw._loop.read_receipts()
    assert len(rows) == 1
    assert rows[0].status == "REJECTED"
    assert rows[0].reason_code == "USER_DENIED"
    assert rows[0].order_meta["capability_id"] == PAY
    assert result["isError"] is True
    assert result["content"][0]["text"] == (
        "The user declined this action on-device (USER_DENIED). "
        "A signed rejection receipt was recorded ({}).".format(
            rows[0].receipt_id))
    assert len(approver.prompts) == 1  # the dialog really fired, once


def test_block_preference_auto_denies_without_any_dialog(tmp_path):
    prefs = Preferences({PAY: BLOCK})
    gw, approver, _ = _confirm_gateway(tmp_path, verdicts=[], preferences=prefs)

    result = _call(gw, PAY)

    rows = gw._loop.read_receipts()
    assert rows[0].status == "REJECTED"
    assert rows[0].reason_code == "USER_BLOCKED"
    assert result["isError"] is True
    assert result["content"][0]["text"] == (
        "Blocked by the user's standing permissions (USER_BLOCKED). "
        "A signed rejection receipt was recorded ({}).".format(
            rows[0].receipt_id))
    assert approver.prompts == []  # BLOCK means no dialog at all


def test_allowed_dialog_fulfills_with_draft_and_receipt_note(tmp_path):
    gw, approver, _ = _confirm_gateway(tmp_path, verdicts=[ALLOW_ONCE])

    result = _call(gw, PAY)

    rows = gw._loop.read_receipts()
    assert len(rows) == 1 and rows[0].status == "FULFILLED"
    assert result["isError"] is False
    assert "PAYMENT REQUEST" in result["content"][0]["text"]
    assert result["content"][1]["text"].startswith(
        "[Sentinel receipt " + rows[0].receipt_id)
    assert len(approver.prompts) == 1


def test_always_allow_persists_and_second_call_shows_no_dialog(tmp_path):
    prefs_path = str(tmp_path / "permissions.json")
    gw, approver, _ = _confirm_gateway(
        tmp_path, verdicts=[ALLOW_ALWAYS],
        preferences=Preferences.load(prefs_path))

    first = _call(gw, PAY)
    second = _call(gw, PAY)

    assert first["isError"] is False and second["isError"] is False
    assert len(approver.prompts) == 1
    with open(prefs_path, encoding="utf-8") as fh:
        assert json.load(fh) == {PAY: "allow"}


def test_low_stakes_call_never_prompts(tmp_path):
    gw, approver, _ = _confirm_gateway(tmp_path, verdicts=[])
    result = _call(gw, DRAFT)
    assert result["isError"] is False
    assert approver.prompts == []


def test_policy_refusal_happens_before_the_dialog(tmp_path):
    """The cashier still runs FIRST: an out-of-scope call is refused by
    policy and the user is never bothered with a dialog for it."""
    gw, approver, _ = _confirm_gateway(tmp_path, verdicts=[])
    result = _call(gw, PAY, thread="user.victim/t-009")
    assert result["isError"] is True
    assert "OUT_OF_SCOPE" in result["content"][0]["text"]
    assert gw._loop.read_receipts()[0].reason_code == "OUT_OF_SCOPE"
    assert approver.prompts == []


def test_confirm_session_chain_verifies_standalone(tmp_path):
    gw, _, pub = _confirm_gateway(tmp_path, verdicts=[ALLOW_ONCE, DENY])
    _call(gw, PAY)                              # FULFILLED (allowed once)
    _call(gw, PAY)                              # REJECTED / USER_DENIED
    _call(gw, PAY, thread="user.victim/x")      # REJECTED / OUT_OF_SCOPE
    proc = subprocess.run(
        [sys.executable, str(VERIFIER), str(tmp_path / "ledger.db"), str(pub)],
        capture_output=True, text=True, cwd=str(REPO_ROOT))
    assert proc.returncode == 0, (proc.stdout, proc.stderr)
    assert proc.stdout.strip() == "OK verified=3"


def test_confirm_startup_fails_closed_without_a_display(tmp_path, monkeypatch, capsys):
    """No display -> --confirm refuses to start (exit 2). The gate must not
    fail open, and must not mint USER_DENIED receipts no user ever saw."""
    import sentinel_slice.consumer.native as native
    import sentinel_slice.mcp_gateway as mcp_gateway
    from sentinel_slice.init_app import main as init_main

    home = str(tmp_path / "home")
    assert init_main(["--home", home], print_fn=lambda *_: None) == 0
    monkeypatch.setattr(native, "native_available", lambda: False)

    rc = mcp_gateway.main(["--confirm", "--home", home])

    assert rc == 2
    err = capsys.readouterr().err
    assert "refusing to start" in err
    assert "fail open" in err
