"""Forged-signature refusal: the chef verifies the cashier signature BEFORE
any side effect, so a tampered ticket exits with the FROZEN signature-
failure code 3 and touches NOTHING — no out_dir created, no draft written.

Two forgeries are exercised: (a) re-signing the signable with a WRONG key,
and (b) flipping one byte of the genuine signature. Both must reject.
"""

import base64
import json
import os
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

CHEF_MAIN = Path(__file__).resolve().parents[1] / "chef" / "chef_main.py"
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


def _mint_valid_wire(priv, tmp_path):
    """Mint a genuine, well-formed wire ticket dict via the real cashier."""
    ledger = Ledger(str(tmp_path / "mint_ledger.db"), priv)
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
    t = outcome.ticket
    return {
        "ticket_id": t.ticket_id,
        "order_id": t.order_id,
        "capability_id": t.capability_id,
        "behavior": t.behavior,
        "scoped_args": t.scoped_args,
        "issued_ts": t.issued_ts,
        "cashier_sig": base64.b64encode(t.cashier_sig).decode("ascii"),
    }


def _invoke_chef(wire, pem, out_dir):
    return subprocess.run(
        [sys.executable, str(CHEF_MAIN), str(pem), str(FIXTURES_ROOT), str(out_dir)],
        input=json.dumps(wire),
        capture_output=True,
        text=True,
    )


def test_chef_forged_sig(tmp_path):
    """Forgery (a): re-sign the 5-key signable with a DIFFERENT key."""
    priv = Ed25519PrivateKey.generate()
    pem = _write_pub_pem(priv, tmp_path)
    wire = _mint_valid_wire(priv, tmp_path)

    # Re-sign the exact 5-key signable with a wrong key.
    import sentinel_slice.spine.canonical as canon

    wrong = Ed25519PrivateKey.generate()
    signable = {
        "ticket_id": wire["ticket_id"],
        "order_id": wire["order_id"],
        "capability_id": wire["capability_id"],
        "scoped_args": wire["scoped_args"],
        "issued_ts": wire["issued_ts"],
    }
    forged = wrong.sign(canon.canonical_bytes(signable))
    wire["cashier_sig"] = base64.b64encode(forged).decode("ascii")

    out_dir = tmp_path / "win" / wire["order_id"]
    assert not os.path.exists(str(out_dir))

    proc = _invoke_chef(wire, pem, out_dir)

    assert proc.returncode == 3
    assert not os.path.exists(os.path.join(str(out_dir), "output.txt"))
    assert not os.path.exists(str(out_dir))
    assert "signature" in proc.stderr.lower()


def test_chef_forged_sig_byteflip(tmp_path):
    """Forgery (b): flip one byte of the genuine signature."""
    priv = Ed25519PrivateKey.generate()
    pem = _write_pub_pem(priv, tmp_path)
    wire = _mint_valid_wire(priv, tmp_path)

    bad = bytearray(base64.b64decode(wire["cashier_sig"]))
    bad[0] ^= 0x01
    wire["cashier_sig"] = base64.b64encode(bytes(bad)).decode("ascii")

    out_dir = tmp_path / "win" / wire["order_id"]
    assert not os.path.exists(str(out_dir))

    proc = _invoke_chef(wire, pem, out_dir)

    assert proc.returncode == 3
    assert not os.path.exists(os.path.join(str(out_dir), "output.txt"))
    assert not os.path.exists(str(out_dir))
    assert "signature" in proc.stderr.lower()
