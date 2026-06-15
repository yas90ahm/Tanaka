# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Yasir Qureshi
"""Personal permissions (v0.6) — Allow / Ask / Block, no JSON for the user.

Pins the defaults (ASK for confirmation-required caps, ALLOW otherwise),
explicit overrides, persistence round-trip, the BLOCK gate end-to-end (auto-
deny, no prompt, chained USER_BLOCKED receipt), and the permissions editor
turning a numbered choice into a saved setting.
"""

import uuid
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sentinel_slice.attestor.mock import MockAttestor
from sentinel_slice.cashier.policy import Policy, PolicySet
from sentinel_slice.cashier.store import CashierStore
from sentinel_slice.consumer.approval import ApprovalDecision, ScriptedApprover
from sentinel_slice.consumer.loop import ConsumerLoop
from sentinel_slice.consumer import permissions as perms_cli
from sentinel_slice.consumer.preferences import ALLOW, ASK, BLOCK, Preferences
from sentinel_slice.ledger.receipts import Ledger
from sentinel_slice.loop import SentinelLoop
from sentinel_slice.menu.catalog import load_catalog
from sentinel_slice.spine.types import Order

SENTINEL_DIR = Path(__file__).resolve().parents[1]
MAILBOX = SENTINEL_DIR / "kitchen" / "fixtures" / "mailbox"

DRAFT = "cap.email.draft_reply.v1"
PAY = "cap.payment.initiate.v1"


def test_default_states_follow_capability_risk():
    cat = load_catalog()
    prefs = Preferences()
    # Low-stakes default ALLOW; confirmation-required default ASK.
    assert prefs.effective_state(cat[DRAFT]) == ALLOW
    assert prefs.effective_state(cat[PAY]) == ASK
    # No explicit settings yet.
    assert prefs.explicit(DRAFT) is None


def test_explicit_override_and_persistence(tmp_path):
    cat = load_catalog()
    prefs = Preferences()
    prefs.set(DRAFT, BLOCK)      # block even a low-stakes cap if you want
    prefs.set(PAY, ALLOW)
    assert prefs.effective_state(cat[DRAFT]) == BLOCK
    assert prefs.effective_state(cat[PAY]) == ALLOW

    path = tmp_path / "perms.json"
    prefs.save(str(path))
    reloaded = Preferences.load(str(path))
    assert reloaded.as_dict() == {DRAFT: BLOCK, PAY: ALLOW}


def test_load_missing_file_is_empty(tmp_path):
    prefs = Preferences.load(str(tmp_path / "nope.json"))
    assert prefs.as_dict() == {}


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
    key = "thread_id"
    return Order(order_id="ord-" + uuid.uuid4().hex, principal="user.kenji",
                 role="account_manager", capability_id=capability_id,
                 args={key: "user.kenji/t-001"}, nonce="n-" + uuid.uuid4().hex,
                 ts="2026-06-10T00:00:00+00:00")


def test_block_auto_denies_without_prompt(tmp_path):
    prefs = Preferences({DRAFT: BLOCK})
    # Approver would ALLOW if ever consulted — it must NOT be consulted.
    approver = ScriptedApprover(ApprovalDecision(allow=True))
    consumer = ConsumerLoop(_loop(tmp_path), approver=approver, preferences=prefs)

    out = consumer.place(_order(DRAFT))

    assert out.status == "BLOCKED_BY_USER"
    assert out.reason_code == "USER_BLOCKED"
    assert out.confirmation_asked is False
    assert approver.prompts == []        # never asked — BLOCK is silent-deny
    rows = consumer.read_receipts()
    assert len(rows) == 1
    assert rows[-1].status == "REJECTED"
    assert rows[-1].reason_code == "USER_BLOCKED"
    assert rows[-1].order_meta["capability_id"] == DRAFT


def test_allow_pref_runs_high_risk_without_prompt(tmp_path):
    # User pre-approved payments -> no prompt even though it's confirm-required.
    prefs = Preferences({PAY: ALLOW})
    approver = ScriptedApprover(ApprovalDecision(allow=False))  # would deny if asked
    consumer = ConsumerLoop(_loop(tmp_path), approver=approver, preferences=prefs)

    out = consumer.place(_order(PAY))

    assert out.status == "FULFILLED"
    assert approver.prompts == []


def test_permissions_editor_sets_and_saves(tmp_path):
    path = str(tmp_path / "perms.json")
    cat = load_catalog()
    caps = perms_cli.ordered_caps(cat)
    pay_index = str(caps.index(cat[PAY]) + 1)

    # Script: pick the payment cap, set it to Block, then blank to save & quit.
    answers = iter([pay_index, "b", ""])
    printed = []
    rc = perms_cli.main([path],
                        input_fn=lambda _prompt: next(answers),
                        print_fn=lambda *a: printed.append(" ".join(map(str, a))))
    assert rc == 0
    saved = Preferences.load(path)
    assert saved.explicit(PAY) == BLOCK
    assert any("saved" in line for line in printed)
