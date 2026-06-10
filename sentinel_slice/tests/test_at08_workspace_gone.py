"""SPEC acceptance #8 — the ephemeral workspace is destroyed after the run.

After a successful run_chef, the chef's cwd workspace tempdir does NOT
exist, while the PERSISTENT serving-window draft DOES — proving the two
paths are distinct and the workspace is torn down on every path.
"""

import os
import uuid
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sentinel_slice.cashier.engine import process_order
from sentinel_slice.cashier.policy import load_policy_set
from sentinel_slice.cashier.store import CashierStore
from sentinel_slice.chef.runner import run_chef
from sentinel_slice.attestor.mock import MockAttestor
from sentinel_slice.ledger.receipts import Ledger
from sentinel_slice.menu.catalog import load_catalog
from sentinel_slice.spine.types import Order

FIXTURES_ROOT = Path(__file__).resolve().parents[1] / "kitchen" / "fixtures" / "mailbox"


def _write_pub_pem(priv, tmp_path):
    pem = tmp_path / "pub.pem"
    pem.write_bytes(
        priv.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    return pem


def test_at08_workspace_gone(tmp_path):
    priv = Ed25519PrivateKey.generate()
    ledger = Ledger(str(tmp_path / "ledger.db"), priv)
    pem = _write_pub_pem(priv, tmp_path)

    menu = load_catalog()
    policy_set = load_policy_set()
    store = CashierStore()

    order = Order(
        order_id=f"ord-{uuid.uuid4().hex}",
        principal="user.kenji",
        role="account_manager",
        capability_id="cap.email.draft_reply.v1",
        args={"thread_id": "user.kenji/t-001"},
        nonce=f"nonce-{uuid.uuid4().hex}",
        ts="2026-06-09T00:00:00+00:00",
    )

    outcome = process_order(
        order,
        menu=menu,
        policy_set=policy_set,
        store=store,
        ledger=ledger,
        private_key=priv,
        spawn=None,
    )
    assert outcome.accepted is True

    attestor = MockAttestor()
    res = run_chef(
        outcome.ticket,
        ledger=ledger,
        public_key_pem_path=str(pem),
        fixtures_root=str(FIXTURES_ROOT),
        attestor=attestor,
        window_root=str(tmp_path / "win"),
    )

    assert res.returncode == 0
    assert isinstance(res.workspace_path, str) and res.workspace_path != ""
    # The ephemeral workspace is GONE after fulfillment.
    assert not os.path.exists(res.workspace_path)
    # The PERSISTENT serving window survived — distinct path.
    assert os.path.isfile(res.draft_path)
