"""On-device approval prompts (v0.11).

The prompt content and the verdict mapping are pure and pinned exactly; the
NativeApprover is driven through the REAL ConsumerLoop (an 'Always allow'
upgrades the preference, persists it to disk, and the second identical action
does not prompt; a raised show_fn fails CLOSED). The actual tkinter dialog
runs only under SENTINEL_TEST_GUI=1 (it needs a display) — there the genuine
button .invoke() path produces the verdict.
"""

import json
import os
import uuid

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pathlib import Path

from sentinel_slice.attestor.mock import MockAttestor
from sentinel_slice.cashier.policy import Policy, PolicySet
from sentinel_slice.cashier.store import CashierStore
from sentinel_slice.consumer.approval import ApprovalDecision, CliApprover
from sentinel_slice.consumer.loop import ConsumerLoop
from sentinel_slice.consumer.native import (
    ALLOW_ALWAYS,
    ALLOW_ONCE,
    DENY,
    NativeApprover,
    PromptSpec,
    build_prompt,
    decision_from_verdict,
    default_approver,
)
from sentinel_slice.consumer.preferences import Preferences
from sentinel_slice.ledger.receipts import Ledger
from sentinel_slice.loop import SentinelLoop
from sentinel_slice.menu.catalog import load_catalog
from sentinel_slice.spine.types import Order

SENTINEL_DIR = Path(__file__).resolve().parents[1]
MAILBOX = SENTINEL_DIR / "kitchen" / "fixtures" / "mailbox"

DRAFT = "cap.email.draft_reply.v1"
PAY = "cap.payment.initiate.v1"


def _loop(tmp_path):
    priv = Ed25519PrivateKey.generate()
    pub = tmp_path / "pub.pem"
    pub.write_bytes(priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo))
    policy = PolicySet([Policy(role="account_manager",
                               allowed_capabilities=(DRAFT, PAY),
                               rate_limit_per_hour=20)])
    return SentinelLoop(
        private_key=priv, ledger=Ledger(str(tmp_path / "ledger.db"), priv),
        menu=load_catalog(), policy_set=policy, store=CashierStore(),
        public_key_pem_path=str(pub), fixtures_root=str(MAILBOX),
        attestor=MockAttestor(), window_root=str(tmp_path / "win"))


def _order(capability_id):
    return Order(order_id="ord-" + uuid.uuid4().hex, principal="user.kenji",
                 role="account_manager", capability_id=capability_id,
                 args={"thread_id": "user.kenji/t-001"},
                 nonce="nonce-" + uuid.uuid4().hex,
                 ts="2026-06-11T00:00:00+00:00")


# ---- pure pieces, exact ----

def test_build_prompt_exact_content():
    cap = load_catalog()[PAY]
    spec = build_prompt(_order(PAY), cap)
    assert spec == PromptSpec(
        title="Sentinel — approval needed",
        heading="Your agent wants to: {}".format(cap.name),
        lines=(
            "agent (principal): user.kenji",
            "capability: cap.payment.initiate.v1",
            "risk: {} · side effects: {}".format(
                cap.risk_class, cap.side_effects),
            "on: {'thread_id': 'user.kenji/t-001'}",
        ))


def test_verdict_mapping_is_exact_and_fails_closed():
    assert decision_from_verdict(ALLOW_ONCE) == ApprovalDecision(
        allow=True, remember=False)
    assert decision_from_verdict(ALLOW_ALWAYS) == ApprovalDecision(
        allow=True, remember=True)
    assert decision_from_verdict(DENY) == ApprovalDecision(
        allow=False, remember=False)
    # Window closed / garbage / anything unknown -> deny.
    assert decision_from_verdict(None) == ApprovalDecision(
        allow=False, remember=False)
    assert decision_from_verdict("yes please") == ApprovalDecision(
        allow=False, remember=False)


def test_show_fn_exception_fails_closed():
    def broken(_spec):
        raise RuntimeError("display went away")
    approver = NativeApprover(show_fn=broken)
    cap = load_catalog()[PAY]
    decision = approver.decide(order=_order(PAY), capability=cap)
    assert decision == ApprovalDecision(allow=False, remember=False)


def test_default_approver_picks_native_else_cli(monkeypatch):
    import sentinel_slice.consumer.native as native
    monkeypatch.setattr(native, "native_available", lambda: True)
    assert isinstance(native.default_approver(), NativeApprover)
    monkeypatch.setattr(native, "native_available", lambda: False)
    assert isinstance(native.default_approver(), CliApprover)


# ---- through the real ConsumerLoop ----

def test_dialog_deny_blocks_with_user_denied_receipt(tmp_path):
    approver = NativeApprover(show_fn=lambda spec: DENY)
    consumer = ConsumerLoop(_loop(tmp_path), approver=approver)

    out = consumer.place(_order(PAY))

    assert out.status == "DENIED_BY_USER"
    assert out.reason_code == "USER_DENIED"
    assert out.draft is None
    rows = consumer.read_receipts()
    assert rows[-1].status == "REJECTED"
    assert rows[-1].reason_code == "USER_DENIED"
    # The dialog was shown exactly once, with the payment prompt.
    assert len(approver.prompts) == 1
    assert approver.prompts[0].heading.startswith("Your agent wants to: ")
    assert approver.prompts[0].lines[1] == "capability: " + PAY


def test_always_allow_persists_to_disk_and_stops_prompting(tmp_path):
    prefs_path = str(tmp_path / "permissions.json")
    prefs = Preferences.load(prefs_path)  # missing file -> defaults, file-backed
    approver = NativeApprover(show_fn=lambda spec: ALLOW_ALWAYS)
    consumer = ConsumerLoop(_loop(tmp_path), approver=approver,
                            preferences=prefs)

    first = consumer.place(_order(PAY))
    second = consumer.place(_order(PAY))

    assert first.status == "FULFILLED" and first.confirmation_asked is True
    assert second.status == "FULFILLED" and second.confirmation_asked is False
    assert len(approver.prompts) == 1  # asked once, remembered
    # "Always" outlived the object: the file says allow, exactly.
    with open(prefs_path, encoding="utf-8") as fh:
        assert json.load(fh) == {PAY: "allow"}


def test_in_memory_preferences_still_work_without_a_file(tmp_path):
    approver = NativeApprover(show_fn=lambda spec: ALLOW_ALWAYS)
    consumer = ConsumerLoop(_loop(tmp_path), approver=approver,
                            preferences=Preferences())
    out = consumer.place(_order(PAY))
    assert out.status == "FULFILLED"  # save_if_persistent was a no-op, no crash


# ---- the real tkinter dialog (needs a display; env-gated like the
# container sandbox test) ----

@pytest.mark.skipif(os.environ.get("SENTINEL_TEST_GUI") != "1",
                    reason="real GUI dialog; set SENTINEL_TEST_GUI=1 on a "
                    "machine with a display")
def test_real_dialog_button_path_returns_verdict():
    from sentinel_slice.consumer.native import show_dialog
    cap = load_catalog()[PAY]
    spec = build_prompt(_order(PAY), cap)
    # _test_autoclick schedules a real .invoke() on the real button.
    assert show_dialog(spec, _test_autoclick=ALLOW_ONCE) == ALLOW_ONCE
    assert show_dialog(spec, _test_autoclick=DENY) == DENY
