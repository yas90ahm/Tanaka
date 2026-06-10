"""SPEC acceptance #2 — OFF_MENU.

An order naming a capability that is not in the catalog is rejected with
reason_code OFF_MENU at pipeline step 2, after the nonce is consumed at
step 1. No ticket is minted, the spawn hook is NEVER called, a single
REJECTED receipt is appended, and the resulting chain verifies standalone.
"""

import subprocess
import sys
import uuid
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sentinel_slice.cashier.engine import process_order
from sentinel_slice.cashier.policy import load_policy_set
from sentinel_slice.cashier.store import CashierStore
from sentinel_slice.ledger.receipts import Ledger
from sentinel_slice.menu.catalog import load_catalog
from sentinel_slice.spine.types import Order

REPO_ROOT = Path(__file__).resolve().parents[2]
VERIFIER = Path(__file__).resolve().parents[1] / "verify_ledger.py"


class SpawnSpy:
    def __init__(self):
        self.calls = []

    def __call__(self, ticket):
        self.calls.append(ticket)


def _write_pub_pem(priv, tmp_path):
    pem = tmp_path / "pub.pem"
    pem.write_bytes(
        priv.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    return pem


def _run_verifier(db, pem):
    return subprocess.run(
        [sys.executable, str(VERIFIER), str(db), str(pem)],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
    )


def _order(*, principal, role, capability_id, args, nonce=None, order_id=None):
    return Order(
        order_id=order_id or f"ord-{uuid.uuid4().hex}",
        principal=principal,
        role=role,
        capability_id=capability_id,
        args=args,
        nonce=nonce or f"nonce-{uuid.uuid4().hex}",
        ts="2026-06-09T00:00:00+00:00",
    )


def test_at02_off_menu(tmp_path):
    priv = Ed25519PrivateKey.generate()
    db = tmp_path / "ledger.db"
    ledger = Ledger(str(db), priv)
    pem = _write_pub_pem(priv, tmp_path)

    menu = load_catalog()
    policy_set = load_policy_set()
    store = CashierStore()
    spy = SpawnSpy()

    principal = "user.kenji"
    order = _order(
        principal=principal,
        role="account_manager",
        capability_id="forward_inbox",  # NOT in the catalog
        args={"thread_id": f"{principal}/t1"},
    )

    result = process_order(
        order,
        menu=menu,
        policy_set=policy_set,
        store=store,
        ledger=ledger,
        private_key=priv,
        spawn=spy,
    )

    assert result.accepted is False
    assert result.reason_code == "OFF_MENU"
    assert result.ticket is None

    assert len(spy.calls) == 0

    rows = ledger.read_all()
    assert len(rows) == 1
    assert rows[-1].status == "REJECTED"
    assert rows[-1].reason_code == "OFF_MENU"
    assert rows[-1].ticket_id is None
    assert rows[-1].result_digest is None
    assert rows[-1].attestation is None
    assert rows[-1].order_id == order.order_id
    assert result.receipt.this_hash == rows[-1].this_hash

    res = _run_verifier(db, pem)
    assert res.returncode == 0, (res.stdout, res.stderr)
    assert res.stdout.strip() == "OK verified=1"
