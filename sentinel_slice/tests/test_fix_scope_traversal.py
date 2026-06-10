"""Regression: cross-tenant scope escape via a crafted thread_id (review #1).

A thread_id like "user.kenji/../victim/secret" must NOT let the acting
principal read another tenant's mailbox. Two independent layers must reject it:
  - the cashier scope gate (no ticket is minted -> OUT_OF_SCOPE), and
  - the chef's own owner-dir confinement (exit 4, nothing read), even if a
    forged ticket carrying such scoped_args reaches it directly.
"""

import base64
import json
import os
import subprocess
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sentinel_slice.cashier.engine import process_order
from sentinel_slice.cashier.policy import load_policy_set
from sentinel_slice.cashier.store import CashierStore
from sentinel_slice.ledger.receipts import Ledger
from sentinel_slice.menu.catalog import load_catalog
from sentinel_slice.spine.types import Order

SENTINEL_DIR = Path(__file__).resolve().parents[1]
CHEF_MAIN = SENTINEL_DIR / "chef" / "chef_main.py"

CANONICAL = dict(sort_keys=True, separators=(",", ":"))


def _order(principal, thread_id, nonce):
    return Order(
        order_id="ord-" + nonce,
        principal=principal,
        role="account_manager",
        capability_id="cap.email.draft_reply.v1",
        args={"thread_id": thread_id},
        nonce=nonce,
        ts="2026-06-10T00:00:00+00:00",
    )


def test_cashier_rejects_traversal_thread_id(tmp_path):
    priv = Ed25519PrivateKey.generate()
    ledger = Ledger(str(tmp_path / "l.db"), priv)
    menu, pset, store = load_catalog(), load_policy_set(), CashierStore()

    # Each of these keeps owner == principal but smuggles a traversal/sub-path
    # into the local segment. All must be OUT_OF_SCOPE with NO ticket minted.
    for i, tid in enumerate([
        "user.kenji/../victim/secret",
        "user.kenji/..",
        "user.kenji/sub/thread",
        "user.kenji/a\\b",
    ]):
        out = process_order(
            _order("user.kenji", tid, f"n{i}"),
            menu=menu, policy_set=pset, store=store, ledger=ledger, private_key=priv,
        )
        assert out.accepted is False, tid
        assert out.reason_code == "OUT_OF_SCOPE", tid
        assert out.ticket is None, tid
        assert out.receipt.status == "REJECTED"
        assert out.receipt.reason_code == "OUT_OF_SCOPE"

    # Sanity: the benign single-segment thread_id is still accepted.
    ok = process_order(
        _order("user.kenji", "user.kenji/t-001", "nok"),
        menu=menu, policy_set=pset, store=store, ledger=ledger, private_key=priv,
    )
    assert ok.accepted is True
    assert ok.ticket.scoped_args == {"thread_id": "user.kenji/t-001"}


def test_chef_confines_read_to_owner_dir(tmp_path):
    # Two tenants under one fixtures root; victim holds a secret.
    root = tmp_path / "mailbox"
    (root / "user.kenji").mkdir(parents=True)
    (root / "user.kenji" / "t-001.txt").write_text("Subject: hi\n\nbody\n", encoding="utf-8")
    (root / "victim").mkdir(parents=True)
    secret = "TOP-SECRET-VICTIM-PAYLOAD-9f3a"
    (root / "victim" / "secret.txt").write_text(f"Subject: {secret}\n\n{secret}\n", encoding="utf-8")

    priv = Ed25519PrivateKey.generate()
    pub = tmp_path / "pub.pem"
    pub.write_bytes(priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ))

    # Forge a VALIDLY-SIGNED ticket whose scoped_args traverses to the victim.
    scoped_args = {"thread_id": "user.kenji/../victim/secret"}
    signable = {
        "ticket_id": "tkt-x",
        "order_id": "ord-x",
        "capability_id": "cap.email.draft_reply.v1",
        "scoped_args": scoped_args,
        "issued_ts": "2026-06-10T00:00:00+00:00",
    }
    sig = priv.sign(json.dumps(signable, **CANONICAL).encode("utf-8"))
    wire = dict(signable, cashier_sig=base64.b64encode(sig).decode("ascii"))

    out_dir = tmp_path / "out"
    proc = subprocess.run(
        [sys.executable, str(CHEF_MAIN), str(pub), str(root), str(out_dir)],
        input=json.dumps(wire), capture_output=True, text=True,
    )

    # Confined: exit 4, no draft written, and the victim secret never surfaces.
    assert proc.returncode == 4, (proc.stdout, proc.stderr)
    assert not (out_dir / "draft.txt").exists()
    assert secret not in proc.stdout
    assert secret not in proc.stderr
