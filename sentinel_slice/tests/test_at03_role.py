"""SPEC acceptance #3 — ROLE_NOT_PERMITTED.

An on-menu capability requested by a role with no policy entry ("intern")
is rejected at pipeline step 3 (role), BEFORE the scope step. The args are
deliberately chosen so that scope WOULD pass (owner == principal), proving
the role step short-circuits ahead of scope. One REJECTED receipt; chain
verifies.
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


def test_at03_role(tmp_path):
    priv = Ed25519PrivateKey.generate()
    db = tmp_path / "ledger.db"
    ledger = Ledger(str(db), priv)
    pem = _write_pub_pem(priv, tmp_path)

    menu = load_catalog()
    policy_set = load_policy_set()
    store = CashierStore()
    spy = SpawnSpy()

    order = Order(
        order_id=f"ord-{uuid.uuid4().hex}",
        principal="intern.x",
        role="intern",  # no policy entry
        capability_id="cap.email.draft_reply.v1",  # on-menu
        args={"thread_id": "intern.x/t1"},  # scope WOULD pass
        nonce=f"nonce-{uuid.uuid4().hex}",
        ts="2026-06-09T00:00:00+00:00",
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
    assert result.reason_code == "ROLE_NOT_PERMITTED"
    assert result.ticket is None
    assert len(spy.calls) == 0

    rows = ledger.read_all()
    assert len(rows) == 1
    assert rows[-1].status == "REJECTED"
    assert rows[-1].reason_code == "ROLE_NOT_PERMITTED"
    assert rows[-1].ticket_id is None
    assert rows[-1].order_id == order.order_id
    assert result.receipt.this_hash == rows[-1].this_hash

    res = _run_verifier(db, pem)
    assert res.returncode == 0, (res.stdout, res.stderr)
    assert res.stdout.strip() == "OK verified=1"
