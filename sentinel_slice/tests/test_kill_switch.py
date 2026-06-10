"""Kill switch (v0.3) - the operator's instant "stop this now".

A paused capability must, through the REAL loop: spawn NO chef, leave a
chained REJECTED/CAPABILITY_PAUSED receipt (so the pause is auditable), and
write no draft. Un-pausing restores fulfillment on the next order. The pause
is per (role, capability): a different role's grant is unaffected.
"""

import uuid
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sentinel_slice.attestor.mock import MockAttestor
from sentinel_slice.cashier.policy import Policy, PolicySet
from sentinel_slice.cashier.store import CashierStore
from sentinel_slice.ledger.receipts import Ledger
from sentinel_slice.loop import SentinelLoop
from sentinel_slice.menu.catalog import load_catalog
from sentinel_slice.spine.types import Order

SENTINEL_DIR = Path(__file__).resolve().parents[1]
MAILBOX = SENTINEL_DIR / "kitchen" / "fixtures" / "mailbox"

CAP = "cap.email.draft_reply.v1"


def _policy_set(paused=()):
    return PolicySet([
        Policy(
            role="account_manager",
            allowed_capabilities=(CAP,),
            rate_limit_per_hour=5,
            paused_capabilities=tuple(paused),
        )
    ])


def _build_loop(tmp_path, policy_set):
    tmp_path.mkdir(parents=True, exist_ok=True)
    priv = Ed25519PrivateKey.generate()
    pub = tmp_path / "pub.pem"
    pub.write_bytes(
        priv.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    ledger = Ledger(str(tmp_path / "ledger.db"), priv)
    return SentinelLoop(
        private_key=priv,
        ledger=ledger,
        menu=load_catalog(),
        policy_set=policy_set,
        store=CashierStore(),
        public_key_pem_path=str(pub),
        fixtures_root=str(MAILBOX),
        attestor=MockAttestor(),
        window_root=str(tmp_path / "win"),
    )


def _order(**kw):
    base = dict(
        order_id="ord-" + uuid.uuid4().hex,
        principal="user.kenji",
        role="account_manager",
        capability_id=CAP,
        args={"thread_id": "user.kenji/t-001"},
        nonce="nonce-" + uuid.uuid4().hex,
        ts="2026-06-10T11:00:00+00:00",
    )
    base.update(kw)
    return Order(**base)


def test_paused_capability_rejected_no_chef_no_draft(tmp_path):
    loop = _build_loop(tmp_path, _policy_set(paused=(CAP,)))

    order = _order()
    outcome = loop.place(order)

    assert outcome.accepted is False
    assert outcome.reason_code == "CAPABILITY_PAUSED"
    assert outcome.ticket is None
    # No chef ran on a rejection.
    assert loop.last_chef is None
    # The pause is on the record: one chained CAPABILITY_PAUSED receipt.
    rows = loop.read_receipts()
    assert len(rows) == 1
    assert rows[-1].status == "REJECTED"
    assert rows[-1].reason_code == "CAPABILITY_PAUSED"
    assert rows[-1].ticket_id is None
    assert rows[-1].order_meta["capability_id"] == CAP
    # No draft written.
    assert not (tmp_path / "win" / order.order_id / "draft.txt").exists()


def test_unpausing_restores_fulfillment(tmp_path):
    # Paused first: rejected.
    paused_loop = _build_loop(tmp_path / "a", _policy_set(paused=(CAP,)))
    assert paused_loop.place(_order()).reason_code == "CAPABILITY_PAUSED"

    # Same setup, not paused: fulfilled.
    live_loop = _build_loop(tmp_path / "b", _policy_set(paused=()))
    outcome = live_loop.place(_order())
    assert outcome.accepted is True
    assert live_loop.last_chef.receipt.status == "FULFILLED"
